using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ThreeDS.Data;
using ThreeDS.Headers;

namespace ThreeDS
{
    public class ThreeDSTool
    {
        /// <summary>
        /// Name of the input 3DS file
        /// </summary>
        private readonly string filename;

        /// <summary>
        /// Flag to detrmine if development keys should be used
        /// </summary>
        private readonly bool development;

        public ThreeDSTool(string filename, bool development)
        {
            this.filename = filename;
            this.development = development;
        }

        /// <summary>
        /// Attempt to decrypt a 3DS file
        /// </summary>
        public void Decrypt()
        {
            if (!File.Exists(filename))
                return;

            Console.WriteLine(filename);

            using (BinaryReader f = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            using (BinaryWriter g = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
            {
                NCSDHeader header = NCSDHeader.Read(f);
                if (header == null)
                {
                    Console.WriteLine("Error: Not a 3DS Rom!");
                    return;
                }

                // Iterate over all 8 NCCH partitions
                for (int p = 0; p < 8; p++)
                {
                    if (!header.PartitionsTable[p].IsValid())
                    {
                        Console.WriteLine($"Partition {p} Not found... Skipping...");
                        continue;
                    }

                    // Seek to the beginning of the NCCH partition
                    f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize), SeekOrigin.Begin);

                    NCCHHeader partitionHeader = NCCHHeader.Read(f);
                    if (partitionHeader == null)
                    {
                        Console.WriteLine($"Partition {p} Unable to read NCCH header");
                        continue;
                    }

                    // Check if the 'NoCrypto' bit is set
                    if ((partitionHeader.Flags.BitMasks & BitMasks.NoCrypto) != 0)
                    {
                        Console.WriteLine($"Partition {p}: Already Decrypted?...");
                        continue;
                    }

                    // Determine the Keys to be used
                    GetEncryptionKeys(partitionHeader.RSA2048Signature, partitionHeader.Flags.BitMasks, partitionHeader.Flags.CryptoMethod, p,
                        out BigInteger KeyX, out BigInteger KeyX2C, out BigInteger KeyY, out BigInteger NormalKey, out BigInteger NormalKey2C);

                    // Decrypted extended header, if it exists
                    if (partitionHeader.ExtendedHeaderSizeInBytes > 0)
                    {
                        // Seek to the partition start and skip first part of the header
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);

                        var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), partitionHeader.PlainIV));

                        Console.WriteLine($"Partition {p} ExeFS: Decrypting: ExHeader");

                        g.Write(exefsctrmode2C.ProcessBytes(f.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                        g.Flush();
                    }

                    // Decrypt the ExeFS, if it exists
                    if (partitionHeader.ExeFSSizeInBytes > 0)
                    {
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);

                        var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), partitionHeader.ExeFSIV));

                        g.Write(exefsctrmode2C.ProcessBytes(f.ReadBytes((int)header.SectorSize)));
                        g.Flush();

                        Console.WriteLine($"Partition {p} ExeFS: Decrypting: ExeFS Filename Table");

                        if (partitionHeader.Flags.CryptoMethod != CryptoMethod.Original)
                        {
                            f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                            ExeFSHeader exefsHeader = ExeFSHeader.Read(f);
                            if (exefsHeader != null)
                            {
                                foreach (ExeFSFileHeader fileHeader in exefsHeader.FileHeaders)
                                {
                                    if (!fileHeader.IsCodeBinary)
                                        continue;

                                    uint datalenM = ((fileHeader.FileSize) / (1024 * 1024));
                                    uint datalenB = ((fileHeader.FileSize) % (1024 * 1024));
                                    uint ctroffset = ((fileHeader.FileOffset + header.SectorSize) / 0x10);

                                    byte[] exefsIVWithOffsetForHeader = AddToByteArray(partitionHeader.ExeFSIV, (int)ctroffset);

                                    var exefsctrmode = CipherUtilities.GetCipher("AES/CTR");
                                    exefsctrmode.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey)), exefsIVWithOffsetForHeader));

                                    exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                                    exefsctrmode2C.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), exefsIVWithOffsetForHeader));

                                    f.BaseStream.Seek((((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) + 1) * header.SectorSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                                    g.BaseStream.Seek((((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) + 1) * header.SectorSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                                    if (datalenM > 0)
                                    {
                                        for (int i = 0; i < datalenM; i++)
                                        {
                                            g.Write(exefsctrmode2C.ProcessBytes(exefsctrmode.ProcessBytes(f.ReadBytes(1024 * 1024))));
                                            g.Flush();
                                            Console.Write($"\rPartition {p} ExeFS: Decrypting: {fileHeader.ReadableFileName}... {i} / {datalenM + 1} mb...");
                                        }
                                    }

                                    if (datalenB > 0)
                                    {
                                        g.Write(exefsctrmode2C.DoFinal(exefsctrmode.DoFinal(f.ReadBytes((int)datalenB))));
                                        g.Flush();
                                    }

                                    Console.Write($"\rPartition {p} ExeFS: Decrypting: {fileHeader.ReadableFileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
                                }
                            }
                        }

                        // decrypt exefs
                        int exefsSizeM = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) / (1024 * 1024);
                        int exefsSizeB = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) % (1024 * 1024);
                        int ctroffsetE = (int)(header.SectorSize / 0x10);

                        byte[] exefsIVWithOffset = AddToByteArray(partitionHeader.ExeFSIV, ctroffsetE);

                        exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), exefsIVWithOffset));

                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits + 1) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits + 1) * header.SectorSize, SeekOrigin.Begin);
                        if (exefsSizeM > 0)
                        {
                            for (int i = 0; i < exefsSizeM; i++)
                            {
                                g.Write(exefsctrmode2C.ProcessBytes(f.ReadBytes(1024 * 1024)));
                                g.Flush();
                                Console.Write($"\rPartition {p} ExeFS: Decrypting: {i} / {exefsSizeM + 1} mb");
                            }
                        }
                        if (exefsSizeB > 0)
                        {
                            g.Write(exefsctrmode2C.DoFinal(f.ReadBytes(exefsSizeB)));
                            g.Flush();
                        }

                        Console.Write($"\rPartition {p} ExeFS: Decrypting: {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
                    }
                    else
                    {
                        Console.WriteLine($"Partition {p} ExeFS: No Data... Skipping...");
                    }

                    if (partitionHeader.RomFSOffsetInMediaUnits != 0)
                    {
                        int romfsSizeM = (int)(partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) / (1024 * 1024);
                        int romfsSizeB = (int)(partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) % (1024 * 1024);

                        var romfsctrmode = CipherUtilities.GetCipher("AES/CTR");
                        romfsctrmode.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey)), partitionHeader.RomFSIV));

                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        if (romfsSizeM > 0)
                        {
                            for (int i = 0; i < romfsSizeM; i++)
                            {
                                g.Write(romfsctrmode.ProcessBytes(f.ReadBytes(1024 * 1024)));
                                g.Flush();
                                Console.Write($"\rPartition {p} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                            }
                        }
                        if (romfsSizeB > 0)
                        {
                            g.Write(romfsctrmode.DoFinal(f.ReadBytes(romfsSizeB)));
                            g.Flush();
                        }

                        Console.Write($"\rPartition {p} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
                    }
                    else
                    {
                        Console.WriteLine($"Partition {p} RomFS: No Data... Skipping...");
                    }

                    // Write the new CryptoMethod
                    g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x18B, SeekOrigin.Begin);
                    g.Write((byte)CryptoMethod.Original);
                    g.Flush();

                    // Write the new BitMasks flag
                    g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x18F, SeekOrigin.Begin);
                    BitMasks flag = partitionHeader.Flags.BitMasks;
                    flag = flag & (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
                    flag = (flag | BitMasks.NoCrypto);
                    g.Write((byte)flag);
                    g.Flush();
                }

                Console.WriteLine("Press Enter to Exit...");
                Console.Read();
            }
        }

        /// <summary>
        /// Attempt to encrypt a 3DS file
        /// </summary>
        public void Encrypt()
        {
            if (!File.Exists(filename))
                return;

            Console.WriteLine(filename);

            using (BinaryReader f = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            using (BinaryWriter g = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
            {
                NCSDHeader header = NCSDHeader.Read(f);
                if (header == null)
                {
                    Console.WriteLine("Error: Not a 3DS Rom!");
                    return;
                }

                // Get the backup flags
                f.BaseStream.Seek(0x1188, SeekOrigin.Begin);
                NCCHHeaderFlags backupFlags = NCCHHeaderFlags.Read(f);

                // Iterate over all 8 NCCH partitions
                for (int p = 0; p < 8; p++)
                {
                    if (!header.PartitionsTable[p].IsValid())
                    {
                        Console.WriteLine($"Partition {p} Not found... Skipping...");
                        continue;
                    }

                    // Seek to the beginning of the NCCH partition
                    f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize), SeekOrigin.Begin);

                    NCCHHeader partitionHeader = NCCHHeader.Read(f);
                    if (partitionHeader == null)
                    {
                        Console.WriteLine($"Partition {p} Unable to read NCCH header");
                        continue;
                    }

                    // Check if the 'NoCrypto' bit is not set
                    if ((partitionHeader.Flags.BitMasks & BitMasks.NoCrypto) == 0)
                    {
                        Console.WriteLine($"Partition {p}: Already Encrypted?...");
                        continue;
                    }

                    // Determine the Keys to be used
                    GetEncryptionKeys(partitionHeader.RSA2048Signature, backupFlags.BitMasks, backupFlags.CryptoMethod, p,
                        out BigInteger KeyX, out BigInteger KeyX2C, out BigInteger KeyY, out BigInteger NormalKey, out BigInteger NormalKey2C);

                    // Encrypt extended header, if it exists
                    if (partitionHeader.ExtendedHeaderSizeInBytes > 0)
                    {
                        // Seek to the partition start and skip first part of the header
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);

                        var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), partitionHeader.PlainIV));

                        Console.WriteLine($"Partition {p} ExeFS: Encrypting: ExHeader");

                        g.Write(exefsctrmode2C.ProcessBytes(f.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                        g.Flush();
                    }

                    // Encrypt the ExeFS, if it exists
                    if (partitionHeader.ExeFSSizeInBytes > 0)
                    {
                        if (backupFlags.CryptoMethod != CryptoMethod.Original)
                        {
                            f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                            ExeFSHeader exefsHeader = ExeFSHeader.Read(f);
                            if (exefsHeader != null)
                            {
                                foreach (ExeFSFileHeader fileHeader in exefsHeader.FileHeaders)
                                {
                                    if (!fileHeader.IsCodeBinary)
                                        continue;

                                    uint datalenM = ((fileHeader.FileSize) / (1024 * 1024));
                                    uint datalenB = ((fileHeader.FileSize) % (1024 * 1024));
                                    uint ctroffset = ((fileHeader.FileOffset + header.SectorSize) / 0x10);

                                    byte[] exefsIVWithOffsetForHeader = AddToByteArray(partitionHeader.ExeFSIV, (int)ctroffset);

                                    var exefsctrmode = CipherUtilities.GetCipher("AES/CTR");
                                    exefsctrmode.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey)), exefsIVWithOffsetForHeader));

                                    var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                                    exefsctrmode2C.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), exefsIVWithOffsetForHeader));

                                    f.BaseStream.Seek((((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) + 1) * header.SectorSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                                    g.BaseStream.Seek((((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) + 1) * header.SectorSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                                    if (datalenM > 0)
                                    {
                                        for (int i = 0; i < datalenM; i++)
                                        {
                                            g.Write(exefsctrmode2C.ProcessBytes(exefsctrmode.ProcessBytes(f.ReadBytes(1024 * 1024))));
                                            g.Flush();
                                            Console.Write($"\rPartition {p} ExeFS: Encrypting: {fileHeader.ReadableFileName}... {i} / {datalenM + 1} mb...");
                                        }
                                    }

                                    if (datalenB > 0)
                                    {
                                        g.Write(exefsctrmode2C.DoFinal(exefsctrmode.DoFinal(f.ReadBytes((int)datalenB))));
                                        g.Flush();
                                    }

                                    Console.Write($"\rPartition {p} ExeFS: Encrypting: {fileHeader.ReadableFileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
                                }
                            }
                        }

                        // encrypt exefs filename table
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);

                        var exefsctrmode2C_2 = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C_2.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), partitionHeader.ExeFSIV));

                        g.Write(exefsctrmode2C_2.ProcessBytes(f.ReadBytes((int)header.SectorSize)));
                        g.Flush();

                        Console.WriteLine($"Partition {p} ExeFS: Encrypting: ExeFS Filename Table");

                        // encrypt exefs
                        int exefsSizeM = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) / (1024 * 1024);
                        int exefsSizeB = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) % (1024 * 1024);
                        int ctroffsetE = (int)(header.SectorSize / 0x10);

                        byte[] exefsIVWithOffset = AddToByteArray(partitionHeader.ExeFSIV, ctroffsetE);

                        exefsctrmode2C_2 = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C_2.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), exefsIVWithOffset));

                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits + 1) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits + 1) * header.SectorSize, SeekOrigin.Begin);
                        if (exefsSizeM > 0)
                        {
                            for (int i = 0; i < exefsSizeM; i++)
                            {
                                g.Write(exefsctrmode2C_2.ProcessBytes(f.ReadBytes(1024 * 1024)));
                                g.Flush();
                                Console.Write($"\rPartition {p} ExeFS: Encrypting: {i} / {exefsSizeM + 1} mb");
                            }
                        }
                        if (exefsSizeB > 0)
                        {
                            g.Write(exefsctrmode2C_2.DoFinal(f.ReadBytes(exefsSizeB)));
                            g.Flush();
                        }

                        Console.Write($"\rPartition {p} ExeFS: Encrypting: {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
                    }
                    else
                    {
                        Console.WriteLine($"Partition {p} ExeFS: No Data... Skipping...");
                    }

                    if (partitionHeader.RomFSOffsetInMediaUnits != 0)
                    {
                        int romfsBlockSize = 16; // block size in mb
                        int romfsSizeM = (int)(partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) / (romfsBlockSize * (1024 * 1024));
                        int romfsSizeB = (int)(partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) % (romfsBlockSize * (1024 * 1024));
                        int romfsSizeTotalMb = (int)((partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) / (1024 * 1024) + 1);

                        if (p > 0) // RomFS for partitions 1 and up always use Key0x2C
                        {
                            if ((backupFlags.BitMasks & BitMasks.FixedCryptoKey) != 0) // except if using zero-key
                            {
                                NormalKey = 0x00;
                            }
                            else
                            {
                                KeyX = KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                                NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                            }
                        }

                        var romfsctrmode = CipherUtilities.GetCipher("AES/CTR");
                        romfsctrmode.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey)), partitionHeader.RomFSIV));

                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        if (romfsSizeM > 0)
                        {
                            for (int i = 0; i < romfsSizeM; i++)
                            {
                                g.Write(romfsctrmode.ProcessBytes(f.ReadBytes(romfsBlockSize * 1024 * 1024)));
                                g.Flush();
                                Console.Write($"\rPartition {p} RomFS: Encrypting: {i * romfsBlockSize} / {romfsSizeTotalMb} mb");
                            }
                        }
                        if (romfsSizeB > 0)
                        {
                            g.Write(romfsctrmode.DoFinal(f.ReadBytes(romfsSizeB)));
                            g.Flush();
                        }

                        Console.Write($"\rPartition {p} RomFS: Encrypting: {romfsSizeTotalMb} / {romfsSizeTotalMb} mb... Done!\r\n");
                    }
                    else
                    {
                        Console.WriteLine($"Partition {p} RomFS: No Data... Skipping...");
                    }

                    // Write the new CryptoMethod
                    g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x18B, SeekOrigin.Begin);
                    if (p > 0)
                    {
                        g.Write((byte)CryptoMethod.Original); // For partitions 1 and up, set crypto-method to 0x00
                        g.Flush();
                    }
                    else
                    {
                        g.Write((byte)backupFlags.CryptoMethod); // If partition 0, restore crypto-method from backup flags
                        g.Flush();
                    }
                    
                    // Write the new BitMasks flag
                    g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x18F, SeekOrigin.Begin);
                    BitMasks flag = partitionHeader.Flags.BitMasks;
                    flag = (flag & ((BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF));
                    flag = (flag | (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & backupFlags.BitMasks);
                    g.Write((byte)flag);
                    g.Flush();
                }

                Console.WriteLine("Press Enter to Exit...");
                Console.Read();
            }
        }

        /// <summary>
        /// Perform a rotate left on a BigInteger
        /// </summary>
        /// <param name="val">BigInteger value to rotate</param>
        /// <param name="r_bits">Number of bits to rotate</param>
        /// <param name="max_bits">Maximum number of bits to rotate on</param>
        /// <returns>Rotated BigInteger value</returns>
        private BigInteger RotateLeft(BigInteger val, int r_bits, int max_bits)
        {
            return (val << r_bits % max_bits) & (BigInteger.Pow(2, max_bits) - 1) | ((val & (BigInteger.Pow(2, max_bits) - 1)) >> (max_bits - (r_bits % max_bits)));
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption or decryption
        /// </summary>
        /// <param name="rsaSignature">RSA-2048 signature from a partition header</param>
        /// <param name="masks">BitMasks value for a partition header or backup header</param>
        /// <param name="method">CryptoMethod used for the partition</param>
        /// <param name="partitionNumber">Partition number, only used for logging</param>
        /// <param name="KeyX">3DS KeyX value to use</param>
        /// <param name="KeyX2C">3DS KeyX2C value to use</param>
        /// <param name="KeyY">3DS KeyY value to use</param>
        /// <param name="NormalKey">3DS NormalKey value to use</param>
        /// <param name="NormalKey2C">3DS NormalKey2C value to use</param>
        private void GetEncryptionKeys(byte[] rsaSignature, BitMasks masks, CryptoMethod method, int partitionNumber,
            out BigInteger KeyX, out BigInteger KeyX2C, out BigInteger KeyY, out BigInteger NormalKey, out BigInteger NormalKey2C)
        {
            KeyX = 0;
            KeyX2C = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
            KeyY = new BigInteger(rsaSignature.Take(16).Reverse().ToArray()); // KeyY is the first 16 bytes of the partition RSA-2048 SHA-256 signature

            NormalKey = 0;
            NormalKey2C = RotateLeft((RotateLeft(KeyX2C, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);

            if ((masks & BitMasks.FixedCryptoKey) != 0)
            {
                NormalKey = 0x00;
                NormalKey2C = 0x00;
                if (partitionNumber == 0)
                    Console.WriteLine("Encryption Method: Zero Key");
            }
            else
            {
                if (method == CryptoMethod.Original)
                {
                    KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                    if (partitionNumber == 0)
                        Console.WriteLine("Encryption Method: Key 0x2C");
                }
                else if (method == CryptoMethod.Seven)
                {
                    KeyX = (development ? Constants.KeyX0x25 : Constants.KeyX0x25);
                    if (partitionNumber == 0)
                        Console.WriteLine("Encryption Method: Key 0x25");
                }
                else if (method == CryptoMethod.NineThree)
                {
                    KeyX = (development ? Constants.DevKeyX0x18 : Constants.KeyX0x18);
                    if (partitionNumber == 0)
                        Console.WriteLine("Encryption Method: Key 0x18");
                }
                else if (method == CryptoMethod.NineSix)
                {
                    KeyX = (development ? Constants.DevKeyX0x1B : Constants.KeyX0x1B);
                    if (partitionNumber == 0)
                        Console.WriteLine("Encryption Method: Key 0x1B");
                }

                NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
            }
        }

        /// <summary>
        /// Add an integer value to a number represented by a byte array
        /// </summary>
        /// <param name="input">Byte array to add to</param>
        /// <param name="add">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        private byte[] AddToByteArray(byte[] input, int add)
        {
            int len = input.Length;
            var bigint = new BigInteger(input.Reverse().ToArray());
            bigint += add;
            var arr = bigint.ToByteArray().Reverse().ToArray();

            if (arr.Length < len)
            {
                byte[] temp = new byte[len];
                for (int i = 0; i < (len - arr.Length); i++)
                    temp[i] = 0x00;

                Array.Copy(arr, 0, temp, len - arr.Length, arr.Length);
                arr = temp;
            }

            return arr;
        }

        /// <summary>
        /// Get a 16-byte array representation of a BigInteger
        /// </summary>
        /// <param name="input">BigInteger value to convert</param>
        /// <returns>16-byte array representing the BigInteger</returns>
        private byte[] TakeSixteen(BigInteger input)
        {
            var arr = input.ToByteArray().Take(16).Reverse().ToArray();

            if (arr.Length < 16)
            {
                byte[] temp = new byte[16];
                for (int i = 0; i < (16 - arr.Length); i++)
                    temp[i] = 0x00;

                Array.Copy(arr, 0, temp, 16 - arr.Length, arr.Length);
                arr = temp;
            }

            return arr;
        }
    }
}

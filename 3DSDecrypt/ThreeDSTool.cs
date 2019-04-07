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
        private readonly string filename;
        private readonly bool development;

        public ThreeDSTool(string filename, bool development)
        {
            this.filename = filename;
            this.development = development;
        }

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
                        Console.WriteLine("Partition {0} Not found... Skipping...", p);
                        continue;
                    }

                    // Seek to the beginning of the NCCH partition
                    f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize), SeekOrigin.Begin);

                    NCCHHeader partitionHeader = NCCHHeader.Read(f);
                    if (partitionHeader == null)
                    {
                        Console.WriteLine("Partition {0} Unable to read NCCH header", p);
                        continue;
                    }

                    // Check if the 'NoCrypto' bit is set
                    if ((partitionHeader.Flags.BitMasks & BitMasks.NoCrypto) != 0)
                    {
                        Console.WriteLine("Partition {0:d}: Already Decrypted?...", p);
                        continue;
                    }

                    // PartitionID is used as IV joined with the content type.
                    byte[] plainIV = partitionHeader.PartitionId.Concat(Constants.PlainCounter).ToArray(); // Get the IV for plain sector (TitleID + Plain Counter)
                    byte[] exefsIV = partitionHeader.PartitionId.Concat(Constants.ExefsCounter).ToArray(); // Get the IV for ExeFS (TitleID + ExeFS Counter)
                    byte[] romfsIV = partitionHeader.PartitionId.Concat(Constants.RomfsCounter).ToArray(); // Get the IV for RomFS (TitleID + RomFS Counter)

                    BigInteger KeyX = 0;
                    BigInteger KeyX2C = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                    BigInteger KeyY = new BigInteger(partitionHeader.RSA2048Signature.Take(16).Reverse().ToArray()); // KeyY is the first 16 bytes of the partition RSA-2048 SHA-256 signature
                   
                    BigInteger NormalKey = 0;
                    BigInteger NormalKey2C = RotateLeft((RotateLeft(KeyX2C, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);

                    // Determine the Keys to be used
                    if ((partitionHeader.Flags.BitMasks & BitMasks.FixedCryptoKey) != 0)
                    {
                        NormalKey = 0x00;
                        NormalKey2C = 0x00;
                        if (p == 0)
                            Console.WriteLine("Encryption Method: Zero Key");
                    }
                    else
                    {
                        if (partitionHeader.Flags.CryptoMethod == CryptoMethod.Original)
                        {
                            KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x2C");
                        }
                        else if (partitionHeader.Flags.CryptoMethod == CryptoMethod.Seven)
                        {
                            KeyX = (development ? Constants.KeyX0x25 : Constants.KeyX0x25);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x25");
                        }
                        else if (partitionHeader.Flags.CryptoMethod == CryptoMethod.NineThree)
                        {
                            KeyX = (development ? Constants.DevKeyX0x18 : Constants.KeyX0x18);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x18");
                        }
                        else if (partitionHeader.Flags.CryptoMethod == CryptoMethod.NineSix)
                        {
                            KeyX = (development ? Constants.DevKeyX0x1B : Constants.KeyX0x1B);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x1B");
                        }

                        NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                    }

                    // Decrypted extended header, if it exists
                    if (partitionHeader.ExtendedHeaderSizeInBytes > 0)
                    {
                        // Seek to the partition start and skip first part of the header
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);

                        var str = BitConverter.ToString(plainIV).Replace("-", "");

                        var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), plainIV));

                        Console.WriteLine("Partition {0} ExeFS: Decrypting: ExHeader", p);

                        g.Write(exefsctrmode2C.ProcessBytes(f.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                        g.Flush();
                    }

                    // Decrypt the ExeFS, if it exists
                    if (partitionHeader.ExeFSSizeInBytes > 0)
                    {
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);

                        var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), exefsIV));

                        g.Write(exefsctrmode2C.ProcessBytes(f.ReadBytes((int)header.SectorSize)));
                        g.Flush();

                        Console.WriteLine("Partition {0} ExeFS: Decrypting: ExeFS Filename Table", p);

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

                                    byte[] exefsIVWithOffsetForHeader = AddToByteArray(exefsIV, (int)ctroffset);

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
                                            Console.Write("\rPartition {0} ExeFS: Decrypting: {1}... {2} / {3} mb...", p, fileHeader.ReadableFileName, i, datalenM + 1);
                                        }
                                    }

                                    if (datalenB > 0)
                                    {
                                        g.Write(exefsctrmode2C.DoFinal(exefsctrmode.DoFinal(f.ReadBytes((int)datalenB))));
                                        g.Flush();
                                    }

                                    Console.Write("\rPartition {0} ExeFS: Decrypting: {1}... {2} / {3} mb... Done!\r\n", p, fileHeader.ReadableFileName, datalenM + 1, datalenM + 1);
                                }
                            }
                        }

                        // decrypt exefs
                        int exefsSizeM = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) / (1024 * 1024);
                        int exefsSizeB = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) % (1024 * 1024);
                        int ctroffsetE = (int)(header.SectorSize / 0x10);

                        byte[] exefsIVWithOffset = AddToByteArray(exefsIV, ctroffsetE);

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
                                Console.Write("\rPartition {0} ExeFS: Decrypting: {1} / {2} mb", p, i, exefsSizeM + 1);
                            }
                        }
                        if (exefsSizeB > 0)
                        {
                            g.Write(exefsctrmode2C.DoFinal(f.ReadBytes(exefsSizeB)));
                            g.Flush();
                        }

                        Console.Write("\rPartition {0} ExeFS: Decrypting: {1} / {2} mb... Done!\r\n", p, exefsSizeM + 1, exefsSizeM + 1);
                    }
                    else
                    {
                        Console.WriteLine("Partition {0} ExeFS: No Data... Skipping...", p);
                    }

                    if (partitionHeader.RomFSOffsetInMediaUnits != 0)
                    {
                        int romfsSizeM = (int)(partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) / (1024 * 1024);
                        int romfsSizeB = (int)(partitionHeader.RomFSSizeInMediaUnits * header.SectorSize) % (1024 * 1024);

                        var romfsctrmode = CipherUtilities.GetCipher("AES/CTR");
                        romfsctrmode.Init(false, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey)), romfsIV));

                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        if (romfsSizeM > 0)
                        {
                            for (int i = 0; i < romfsSizeM; i++)
                            {
                                g.Write(romfsctrmode.ProcessBytes(f.ReadBytes(1024 * 1024)));
                                g.Flush();
                                Console.Write("\rPartition {0} RomFS: Decrypting: {1} / {2} mb", p, i, romfsSizeM + 1);
                            }
                        }
                        if (romfsSizeB > 0)
                        {
                            g.Write(romfsctrmode.DoFinal(f.ReadBytes(romfsSizeB)));
                            g.Flush();
                        }

                        Console.Write("\rPartition {0} RomFS: Decrypting: {1} / {2} mb... Done!\r\n", p, romfsSizeM + 1, romfsSizeM + 1);
                    }
                    else
                    {
                        Console.WriteLine("Partition {0} RomFS: No Data... Skipping...", p);
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

                // Iterate over all 8 NCCH partitions
                for (int p = 0; p < 8; p++)
                {
                    if (!header.PartitionsTable[p].IsValid())
                    {
                        Console.WriteLine("Partition {0} Not found... Skipping...", p);
                        continue;
                    }

                    // Seek to the beginning of the NCCH partition
                    f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize), SeekOrigin.Begin);

                    NCCHHeader partitionHeader = NCCHHeader.Read(f);
                    if (partitionHeader == null)
                    {
                        Console.WriteLine("Partition {0} Unable to read NCCH header", p);
                        continue;
                    }

                    // Get the backup flags
                    f.BaseStream.Seek(0x1188, SeekOrigin.Begin);
                    NCCHHeaderFlags backupFlags = NCCHHeaderFlags.Read(f);

                    // Check if the 'NoCrypto' bit is not set
                    if ((partitionHeader.Flags.BitMasks & BitMasks.NoCrypto) == 0)
                    {
                        Console.WriteLine("Partition {0:d}: Already Encrypted?...", p);
                        continue;
                    }

                    // PartitionID is used as IV joined with the content type.
                    byte[] plainIV = partitionHeader.PartitionId.Concat(Constants.PlainCounter).ToArray(); // Get the IV for plain sector (TitleID + Plain Counter)
                    byte[] exefsIV = partitionHeader.PartitionId.Concat(Constants.ExefsCounter).ToArray(); // Get the IV for ExeFS (TitleID + ExeFS Counter)
                    byte[] romfsIV = partitionHeader.PartitionId.Concat(Constants.RomfsCounter).ToArray(); // Get the IV for RomFS (TitleID + RomFS Counter)

                    BigInteger KeyX = 0;
                    BigInteger KeyX2C = Constants.KeyX0x2C;
                    BigInteger KeyY = new BigInteger(partitionHeader.RSA2048Signature.Take(16).Reverse().ToArray()); // KeyY is the first 16 bytes of the partition RSA-2048 SHA-256 signature

                    BigInteger NormalKey = 0;
                    BigInteger NormalKey2C = RotateLeft((RotateLeft(KeyX2C, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);

                    // Determine the Keys to be used
                    if ((backupFlags.BitMasks & BitMasks.FixedCryptoKey) != 0)
                    {
                        NormalKey = 0x00;
                        NormalKey2C = 0x00;
                        if (p == 0)
                            Console.WriteLine("Encryption Method: Zero Key");
                    }
                    else
                    {
                        if (backupFlags.CryptoMethod == CryptoMethod.Original)
                        {
                            KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x2C");
                        }
                        else if (backupFlags.CryptoMethod == CryptoMethod.Seven)
                        {
                            KeyX = (development ? Constants.KeyX0x25 : Constants.KeyX0x25);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x25");
                        }
                        else if (backupFlags.CryptoMethod == CryptoMethod.NineThree)
                        {
                            KeyX = (development ? Constants.DevKeyX0x18 : Constants.KeyX0x18);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x18");
                        }
                        else if (backupFlags.CryptoMethod == CryptoMethod.NineSix)
                        {
                            KeyX = (development ? Constants.DevKeyX0x1B : Constants.KeyX0x1B);
                            if (p == 0)
                                Console.WriteLine("Encryption Method: Key 0x1B");
                        }

                        NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                    }

                    // Encrypt extended header, if it exists
                    if (partitionHeader.ExtendedHeaderSizeInBytes > 0)
                    {
                        // Seek to the partition start and skip first part of the header
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset * header.SectorSize) + 0x200, SeekOrigin.Begin);

                        var str = BitConverter.ToString(plainIV).Replace("-", "");

                        var exefsctrmode2C = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), plainIV));

                        Console.WriteLine("Partition {0} ExeFS: Encrypting: ExHeader", p);

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

                                    byte[] exefsIVWithOffsetForHeader = AddToByteArray(exefsIV, (int)ctroffset);

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
                                            Console.Write("\rPartition {0} ExeFS: Encrypting: {1}... {2} / {3} mb...", p, fileHeader.ReadableFileName, i, datalenM + 1);
                                        }
                                    }

                                    if (datalenB > 0)
                                    {
                                        g.Write(exefsctrmode2C.DoFinal(exefsctrmode.DoFinal(f.ReadBytes((int)datalenB))));
                                        g.Flush();
                                    }

                                    Console.Write("\rPartition {0} ExeFS: Encrypting: {1}... {2} / {3} mb... Done!\r\n", p, fileHeader.ReadableFileName, datalenM + 1, datalenM + 1);
                                }
                            }
                        }

                        // encrypt exefs filename table
                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);

                        var exefsctrmode2C_2 = CipherUtilities.GetCipher("AES/CTR");
                        exefsctrmode2C_2.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey2C)), exefsIV));

                        g.Write(exefsctrmode2C_2.ProcessBytes(f.ReadBytes((int)header.SectorSize)));
                        g.Flush();

                        Console.WriteLine("Partition {0} ExeFS: Encrypting: ExeFS Filename Table", p);

                        // encrypt exefs
                        int exefsSizeM = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) / (1024 * 1024);
                        int exefsSizeB = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.SectorSize) % (1024 * 1024);
                        int ctroffsetE = (int)(header.SectorSize / 0x10);

                        byte[] exefsIVWithOffset = AddToByteArray(exefsIV, ctroffsetE);

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
                                Console.Write("\rPartition {0} ExeFS: Encrypting: {1} / {2} mb", p, i, exefsSizeM + 1);
                            }
                        }
                        if (exefsSizeB > 0)
                        {
                            g.Write(exefsctrmode2C_2.DoFinal(f.ReadBytes(exefsSizeB)));
                            g.Flush();
                        }

                        Console.Write("\rPartition {0} ExeFS: Encrypting: {1} / {2} mb... Done!\r\n", p, exefsSizeM + 1, exefsSizeM + 1);
                    }
                    else
                    {
                        Console.WriteLine("Partition {0} ExeFS: No Data... Skipping...", p);
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
                        romfsctrmode.Init(true, new ParametersWithIV(new KeyParameter(TakeSixteen(NormalKey)), romfsIV));

                        f.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        g.BaseStream.Seek((header.PartitionsTable[p].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.SectorSize, SeekOrigin.Begin);
                        if (romfsSizeM > 0)
                        {
                            for (int i = 0; i < romfsSizeM; i++)
                            {
                                g.Write(romfsctrmode.ProcessBytes(f.ReadBytes(romfsBlockSize * 1024 * 1024)));
                                g.Flush();
                                Console.Write("\rPartition {0} RomFS: Encrypting: {1} / {2} mb", p, i * romfsBlockSize, romfsSizeTotalMb);
                            }
                        }
                        if (romfsSizeB > 0)
                        {
                            g.Write(romfsctrmode.DoFinal(f.ReadBytes(romfsSizeB)));
                            g.Flush();
                        }

                        Console.Write("\rPartition {0} RomFS: Encrypting: {1} / {2} mb... Done!\r\n", p, romfsSizeTotalMb, romfsSizeTotalMb);
                    }
                    else
                    {
                        Console.WriteLine("Partition {0} RomFS: No Data... Skipping...", p);
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

        private static BigInteger RotateLeft(BigInteger val, int r_bits, int max_bits)
        {
            return (val << r_bits % max_bits) & (BigInteger.Pow(2, max_bits) - 1) | ((val & (BigInteger.Pow(2, max_bits) - 1)) >> (max_bits - (r_bits % max_bits)));
        }

        private static string ToBytes(int num)
        {
            string numstr = string.Empty;
            while (numstr.Length < 16)
            {
                numstr += (char)(num & 0xFF);
                num >>= 8;
            }

            return numstr;
        }

        private static byte[] AddToByteArray(byte[] input, int add)
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

        private static byte[] TakeSixteen(BigInteger input)
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

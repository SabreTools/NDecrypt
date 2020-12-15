using System;
using System.IO;
using System.Linq;
using System.Numerics;
using NDecrypt.Data;

namespace NDecrypt.Headers
{
    public class NCCHHeader
    {
        private const string NCCHMagicNumber = "NCCH";

        /// <summary>
        /// Partition number for the current partition
        /// </summary>
        public int PartitionNumber { get; set; }

        /// <summary>
        /// Partition table entry for the current partition
        /// </summary>
        public PartitionTableEntry Entry { get; set; }

        /// <summary>
        /// RSA-2048 signature of the NCCH header, using SHA-256.
        /// </summary>
        public byte[] RSA2048Signature { get; private set; }

        /// <summary>
        /// Content size, in media units (1 media unit = 0x200 bytes)
        /// </summary>
        public uint ContentSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Partition ID
        /// </summary>
        public byte[] PartitionId { get; private set; }
        public byte[] PlainIV { get { return PartitionId.Concat(Constants.PlainCounter).ToArray(); } }
        public byte[] ExeFSIV { get { return PartitionId.Concat(Constants.ExefsCounter).ToArray(); } }
        public byte[] RomFSIV { get { return PartitionId.Concat(Constants.RomfsCounter).ToArray(); } }

        /// <summary>
        /// Boot rom key
        /// </summary>
        private BigInteger KeyX;

        /// <summary>
        /// NCCH boot rom key
        /// </summary>
        private BigInteger KeyX2C;

        /// <summary>
        /// Kernel9/Process9 key
        /// </summary>
        private BigInteger KeyY;

        /// <summary>
        /// Normal AES key
        /// </summary>
        private BigInteger NormalKey;

        /// <summary>
        /// NCCH AES key
        /// </summary>
        private BigInteger NormalKey2C;

        /// <summary>
        /// Maker code
        /// </summary>
        public byte[] MakerCode { get; private set; }

        /// <summary>
        /// Version
        /// </summary>
        public byte[] Version { get; private set; }

        /// <summary>
        /// When ncchflag[7] = 0x20 starting with FIRM 9.6.0-X, this is compared with the first output u32 from a
        /// SHA256 hash. The data used for that hash is 0x18-bytes: [0x10-long title-unique content lock seed]
        /// [programID from NCCH + 0x118]. This hash is only used for verification of the content lock seed, and
        /// is not the actual keyY.
        /// </summary>
        public byte[] VerificationHash { get; private set; }

        /// <summary>
        /// Program ID
        /// </summary>
        public byte[] ProgramId { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved1 { get; private set; }

        /// <summary>
        /// Logo Region SHA-256 hash. (For applications built with SDK 5+) (Supported from firmware: 5.0.0-11)
        /// </summary>
        public byte[] LogoRegionHash { get; private set; }

        /// <summary>
        /// Product code
        /// </summary>
        public byte[] ProductCode { get; private set; }

        /// <summary>
        /// Extended header SHA-256 hash (SHA256 of 2x Alignment Size, beginning at 0x0 of ExHeader)
        /// </summary>
        public byte[] ExtendedHeaderHash { get; private set; }

        /// <summary>
        /// Extended header size, in bytes
        /// </summary>
        public uint ExtendedHeaderSizeInBytes { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved2 { get; private set; }

        /// <summary>
        /// Flags
        /// </summary>
        public NCCHHeaderFlags Flags { get; private set; }

        /// <summary>
        /// Plain region offset, in media units
        /// </summary>
        public uint PlainRegionOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// Plain region size, in media units
        /// </summary>
        public uint PlainRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Logo Region offset, in media units (For applications built with SDK 5+) (Supported from firmware: 5.0.0-11)
        /// </summary>
        public uint LogoRegionOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// Logo Region size, in media units (For applications built with SDK 5+) (Supported from firmware: 5.0.0-11)
        /// </summary>
        public uint LogoRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// ExeFS offset, in media units
        /// </summary>
        public uint ExeFSOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// ExeFS size, in media units
        /// </summary>
        public uint ExeFSSizeInMediaUnits { get; private set; }

        /// <summary>
        /// ExeFS hash region size, in media units
        /// </summary>
        public uint ExeFSHashRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved3 { get; private set; }

        /// <summary>
        /// RomFS offset, in media units
        /// </summary>
        public uint RomFSOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// RomFS size, in media units
        /// </summary>
        public uint RomFSSizeInMediaUnits { get; private set; }

        /// <summary>
        /// RomFS hash region size, in media units
        /// </summary>
        public uint RomFSHashRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved4 { get; private set; }

        /// <summary>
        /// ExeFS superblock SHA-256 hash - (SHA-256 hash, starting at 0x0 of the ExeFS over the number of
        /// media units specified in the ExeFS hash region size)
        /// </summary>
        public byte[] ExeFSSuperblockHash { get; private set; }

        /// <summary>
        /// RomFS superblock SHA-256 hash - (SHA-256 hash, starting at 0x0 of the RomFS over the number
        /// of media units specified in the RomFS hash region size)
        /// </summary>
        public byte[] RomFSSuperblockHash { get; private set; }

        /// <summary>
        /// Read from a stream and get an NCCH header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="readSignature">True if the RSA signature is read, false otherwise</param>
        /// <returns>NCCH header object, null on error</returns>
        public static NCCHHeader Read(BinaryReader reader, bool readSignature)
        {
            NCCHHeader header = new NCCHHeader();

            try
            {
                if (readSignature)
                    header.RSA2048Signature = reader.ReadBytes(0x100);

                if (new string(reader.ReadChars(4)) != NCCHMagicNumber)
                    return null;

                header.ContentSizeInMediaUnits = reader.ReadUInt32();
                header.PartitionId = reader.ReadBytes(8).Reverse().ToArray();
                header.MakerCode = reader.ReadBytes(2);
                header.Version = reader.ReadBytes(2);
                header.VerificationHash = reader.ReadBytes(4);
                header.ProgramId = reader.ReadBytes(8);
                header.Reserved1 = reader.ReadBytes(0x10);
                header.LogoRegionHash = reader.ReadBytes(0x20);
                header.ProductCode = reader.ReadBytes(0x10);
                header.ExtendedHeaderHash = reader.ReadBytes(0x20);
                header.ExtendedHeaderSizeInBytes = reader.ReadUInt32();
                header.Reserved2 = reader.ReadBytes(4);
                header.Flags = NCCHHeaderFlags.Read(reader);
                header.PlainRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.PlainRegionSizeInMediaUnits = reader.ReadUInt32();
                header.LogoRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.LogoRegionSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSOffsetInMediaUnits = reader.ReadUInt32();
                header.ExeFSSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.Reserved3 = reader.ReadBytes(4);
                header.RomFSOffsetInMediaUnits = reader.ReadUInt32();
                header.RomFSSizeInMediaUnits = reader.ReadUInt32();
                header.RomFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.Reserved4 = reader.ReadBytes(4);
                header.ExeFSSuperblockHash = reader.ReadBytes(0x20);
                header.RomFSSuperblockHash = reader.ReadBytes(0x20);

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">NCSD header representing the 3DS file</param>
        /// <param name="encrypt">True if we want to encrypt the partitions, false otherwise</param>
        /// <param name="development">True if development keys should be used, false otherwise</param>
        /// <param name="force">True if we want to force the operation, false otherwise</param>
        public void ProcessPartition(BinaryReader reader, BinaryWriter writer, NCSDHeader header, bool encrypt, bool development, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {PartitionNumber} is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (Flags.PossblyDecrypted ^ encrypt)
            {
                Console.WriteLine($"Partition {PartitionNumber}: Already " + (encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // Determine the Keys to be used
            SetEncryptionKeys(header.BackupHeader.Flags, encrypt, development);

            // Process each of the pieces if they exist
            ProcessExtendedHeader(reader, writer, header.MediaUnitSize, encrypt);
            ProcessExeFS(reader, writer, header.MediaUnitSize, header.BackupHeader.Flags, encrypt);
            ProcessRomFS(reader, writer, header.MediaUnitSize, header.BackupHeader.Flags, encrypt, development);

            // Write out new CryptoMethod and BitMask flags
            UpdateCryptoAndMasks(writer, header, encrypt);
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption or decryption
        /// </summary>
        /// <param name="backupFlags">File backup flags for encryption</param>
        /// <param name="encrypt">True if we're encrypting the file, false otherwise</param>
        /// <param name="development">True if development keys should be used, false otherwise</param>
        private void SetEncryptionKeys(NCCHHeaderFlags backupFlags, bool encrypt, bool development)
        {
            KeyX = 0;
            KeyX2C = development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C;

            // Backup headers can't have a KeyY value set
            if (RSA2048Signature != null)
                KeyY = new BigInteger(RSA2048Signature.Take(16).Reverse().ToArray());
            else
                KeyY = new BigInteger(0);

            NormalKey = 0;
            NormalKey2C = Helper.RotateLeft((Helper.RotateLeft(KeyX2C, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);

            // Set the header to use based on mode
            BitMasks masks;
            CryptoMethod method;
            if (encrypt)
            {
                masks = backupFlags.BitMasks;
                method = backupFlags.CryptoMethod;
            }
            else
            {
                masks = Flags.BitMasks;
                method = Flags.CryptoMethod;
            }

            if (masks.HasFlag(BitMasks.FixedCryptoKey))
            {
                NormalKey = 0x00;
                NormalKey2C = 0x00;
                Console.WriteLine("Encryption Method: Zero Key");
            }
            else
            {
                if (method == CryptoMethod.Original)
                {
                    KeyX = development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C;
                    Console.WriteLine("Encryption Method: Key 0x2C");
                }
                else if (method == CryptoMethod.Seven)
                {
                    KeyX = development ? Constants.DevKeyX0x25 : Constants.KeyX0x25;
                    Console.WriteLine("Encryption Method: Key 0x25");
                }
                else if (method == CryptoMethod.NineThree)
                {
                    KeyX = development ? Constants.DevKeyX0x18 : Constants.KeyX0x18;
                    Console.WriteLine("Encryption Method: Key 0x18");
                }
                else if (method == CryptoMethod.NineSix)
                {
                    KeyX = development ? Constants.DevKeyX0x1B : Constants.KeyX0x1B;
                    Console.WriteLine("Encryption Method: Key 0x1B");
                }

                NormalKey = Helper.RotateLeft((Helper.RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
            }
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="mediaUnitSize">Number of bytes per media unit</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private bool ProcessExtendedHeader(BinaryReader reader, BinaryWriter writer, uint mediaUnitSize, bool encrypt)
        {
            if (ExtendedHeaderSizeInBytes > 0)
            {
                reader.BaseStream.Seek((Entry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);
                writer.BaseStream.Seek((Entry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {PartitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                var cipher = Helper.CreateAESCipher(NormalKey2C, PlainIV, encrypt);
                writer.Write(cipher.ProcessBytes(reader.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                writer.Flush();
                return true;
            }
            else
            {
                Console.WriteLine($"Partition {PartitionNumber} ExeFS: No Extended Header... Skipping...");
                return false;
            }
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="mediaUnitSize">Number of bytes per media unit</param>
        /// <param name="backupFlags">File backup flags for encryption</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private void ProcessExeFS(BinaryReader reader, BinaryWriter writer, uint mediaUnitSize, NCCHHeaderFlags backupFlags, bool encrypt)
        {
            if (ExeFSSizeInMediaUnits > 0)
            {
                // If we're decrypting, we need to decrypt the filename table first
                if (!encrypt)
                    ProcessExeFSFilenameTable(reader, writer, mediaUnitSize, encrypt);

                // For all but the original crypto method, process each of the files in the table
                if ((!encrypt && Flags.CryptoMethod != CryptoMethod.Original)
                    || (encrypt && backupFlags.CryptoMethod != CryptoMethod.Original))
                {
                    reader.BaseStream.Seek((Entry.Offset + ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
                    ExeFSHeader exefsHeader = ExeFSHeader.Read(reader);
                    if (exefsHeader != null)
                    {
                        foreach (ExeFSFileHeader fileHeader in exefsHeader.FileHeaders)
                        {
                            // Only decrypt a file if it's a code binary
                            if (!fileHeader.IsCodeBinary)
                                continue;

                            uint datalenM = ((fileHeader.FileSize) / (1024 * 1024));
                            uint datalenB = ((fileHeader.FileSize) % (1024 * 1024));
                            uint ctroffset = ((fileHeader.FileOffset + mediaUnitSize) / 0x10);

                            byte[] exefsIVWithOffsetForHeader = Helper.AddToByteArray(ExeFSIV, (int)ctroffset);

                            var firstCipher = Helper.CreateAESCipher(NormalKey, exefsIVWithOffsetForHeader, encrypt);
                            var secondCipher = Helper.CreateAESCipher(NormalKey2C, exefsIVWithOffsetForHeader, !encrypt);

                            reader.BaseStream.Seek((((Entry.Offset + ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                            writer.BaseStream.Seek((((Entry.Offset + ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                            if (datalenM > 0)
                            {
                                for (int i = 0; i < datalenM; i++)
                                {
                                    writer.Write(secondCipher.ProcessBytes(firstCipher.ProcessBytes(reader.ReadBytes(1024 * 1024))));
                                    writer.Flush();
                                    Console.Write($"\rPartition {PartitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.ReadableFileName}... {i} / {datalenM + 1} mb...");
                                }
                            }

                            if (datalenB > 0)
                            {
                                writer.Write(secondCipher.DoFinal(firstCipher.DoFinal(reader.ReadBytes((int)datalenB))));
                                writer.Flush();
                            }

                            Console.Write($"\rPartition {PartitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.ReadableFileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
                        }
                    }
                }

                // If we're encrypting, we need to encrypt the filename table now
                if (encrypt)
                    ProcessExeFSFilenameTable(reader, writer, mediaUnitSize, encrypt);

                // Process the ExeFS
                int exefsSizeM = (int)((long)((ExeFSSizeInMediaUnits - 1) * mediaUnitSize) / (1024 * 1024));
                int exefsSizeB = (int)((long)((ExeFSSizeInMediaUnits - 1) * mediaUnitSize) % (1024 * 1024));
                int ctroffsetE = (int)(mediaUnitSize / 0x10);

                byte[] exefsIVWithOffset = Helper.AddToByteArray(ExeFSIV, ctroffsetE);

                var exeFS = Helper.CreateAESCipher(NormalKey2C, exefsIVWithOffset, encrypt);

                reader.BaseStream.Seek((Entry.Offset + ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
                writer.BaseStream.Seek((Entry.Offset + ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
                if (exefsSizeM > 0)
                {
                    for (int i = 0; i < exefsSizeM; i++)
                    {
                        writer.Write(exeFS.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                        writer.Flush();
                        Console.Write($"\rPartition {PartitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                    }
                }
                if (exefsSizeB > 0)
                {
                    writer.Write(exeFS.DoFinal(reader.ReadBytes(exefsSizeB)));
                    writer.Flush();
                }

                Console.Write($"\rPartition {PartitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
            }
            else
            {
                Console.WriteLine($"Partition {PartitionNumber} ExeFS: No Data... Skipping...");
            }
        }

        /// <summary>
        /// Process the ExeFS Filename Table
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="mediaUnitSize">Number of bytes per media unit</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private void ProcessExeFSFilenameTable(BinaryReader reader, BinaryWriter writer, uint mediaUnitSize, bool encrypt)
        {
            reader.BaseStream.Seek((Entry.Offset + ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.BaseStream.Seek((Entry.Offset + ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);

            Console.WriteLine($"Partition {PartitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            var exeFSFilenameTable = Helper.CreateAESCipher(NormalKey2C, ExeFSIV, encrypt);
            writer.Write(exeFSFilenameTable.ProcessBytes(reader.ReadBytes((int)mediaUnitSize)));
            writer.Flush();
        }

        /// <summary>
        /// Process the RomFS, if it exists
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="mediaUnitSize">Number of bytes per media unit</param>
        /// <param name="backupFlags">File backup flags for encryption</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        /// <param name="development">True if development keys should be used, false otherwise</param>
        private void ProcessRomFS(BinaryReader reader, BinaryWriter writer, uint mediaUnitSize, NCCHHeaderFlags backupFlags, bool encrypt, bool development)
        {
            if (RomFSOffsetInMediaUnits != 0)
            {
                long romfsSizeM = (int)((long)(RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
                int romfsSizeB = (int)((long)(RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

                // Encrypting RomFS for partitions 1 and up always use Key0x2C
                if (encrypt && PartitionNumber > 0)
                {
                    // If the backup flags aren't provided and we're encrypting, assume defaults
                    if (backupFlags == null)
                    {
                        KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                        NormalKey = Helper.RotateLeft((Helper.RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                    }

                    if (backupFlags.BitMasks.HasFlag(BitMasks.FixedCryptoKey)) // except if using zero-key
                    {
                        NormalKey = 0x00;
                    }
                    else
                    {
                        KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                        NormalKey = Helper.RotateLeft((Helper.RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                    }
                }

                var cipher = Helper.CreateAESCipher(NormalKey, RomFSIV, encrypt);

                reader.BaseStream.Seek((Entry.Offset + RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
                writer.BaseStream.Seek((Entry.Offset + RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
                if (romfsSizeM > 0)
                {
                    for (int i = 0; i < romfsSizeM; i++)
                    {
                        writer.Write(cipher.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                        writer.Flush();
                        Console.Write($"\rPartition {PartitionNumber} RomFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {romfsSizeM + 1} mb");
                    }
                }
                if (romfsSizeB > 0)
                {
                    writer.Write(cipher.DoFinal(reader.ReadBytes(romfsSizeB)));
                    writer.Flush();
                }

                Console.Write($"\rPartition {PartitionNumber} RomFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
            }
            else
            {
                Console.WriteLine($"Partition {PartitionNumber} RomFS: No Data... Skipping...");
            }
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the partition
        /// </summary>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">NCSD header for the 3DS file</param>
        /// <param name="encrypt">True if we're writing encrypted values, false otherwise</param>
        private void UpdateCryptoAndMasks(BinaryWriter writer, NCSDHeader header, bool encrypt)
        {
            // Write the new CryptoMethod
            writer.BaseStream.Seek((Entry.Offset * header.MediaUnitSize) + 0x18B, SeekOrigin.Begin);
            if (encrypt)
            {
                // For partitions 1 and up, set crypto-method to 0x00
                if (PartitionNumber > 0)
                    writer.Write((byte)CryptoMethod.Original);

                // If partition 0, restore crypto-method from backup flags
                else
                    writer.Write((byte)header.BackupHeader.Flags.CryptoMethod);
            }
            else
            {
                writer.Write((byte)CryptoMethod.Original);
            }
            writer.Flush();

            // Write the new BitMasks flag
            writer.BaseStream.Seek((Entry.Offset * header.MediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = Flags.BitMasks;
            if (encrypt)
            {
                flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;
                flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & header.BackupHeader.Flags.BitMasks;
            }
            else
            {
                flag &= (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
                flag |= BitMasks.NoCrypto;
            }

            writer.Write((byte)flag);
            writer.Flush();
        }
    }
}

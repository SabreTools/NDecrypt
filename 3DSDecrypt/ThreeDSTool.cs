using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Org.BouncyCastle.Crypto;
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

        /// <summary>
        /// Flag to determine if encrypting or decrypting
        /// </summary>
        private readonly bool encrypt;

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

        public ThreeDSTool(string filename, bool development, bool encrypt)
        {
            this.filename = filename;
            this.development = development;
            this.encrypt = encrypt;

        }

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        public bool ProcessFile()
        {
            // Make sure we have a file to process first
            Console.WriteLine(filename);
            if (!File.Exists(filename))
                return false;

            // Open the read and write on the same file for inplace processing
            using (BinaryReader reader = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            using (BinaryWriter writer = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
            {
                NCSDHeader header = NCSDHeader.Read(reader, development);
                if (header == null)
                {
                    Console.WriteLine("Error: Not a 3DS Rom!");
                    return false;
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
                    reader.BaseStream.Seek((header.PartitionsTable[p].Offset * header.MediaUnitSize), SeekOrigin.Begin);

                    NCCHHeader partitionHeader = NCCHHeader.Read(reader, true);
                    if (partitionHeader == null)
                    {
                        Console.WriteLine($"Partition {p} Unable to read NCCH header");
                        continue;
                    }

                    // Check if the 'NoCrypto' bit is set
                    if (partitionHeader.Flags.PossblyDecrypted ^ encrypt)
                    {
                        Console.WriteLine($"Partition {p}: Already " + (encrypt ? "Encrypted" : "Decrypted") + "?...");
                        continue;
                    }

                    // Determine the Keys to be used
                    SetEncryptionKeys(header, p, partitionHeader, encrypt);

                    // Process each of the pieces if they exist
                    ProcessExtendedHeader(reader, writer, header, p, partitionHeader, encrypt);
                    ProcessExeFS(reader, writer, header, p, partitionHeader, encrypt);
                    ProcessRomFS(reader, writer, header, p, partitionHeader, encrypt);

                    // Write out new CryptoMethod and BitMask flags
                    UpdateCryptoAndMasks(reader, writer, header, p, partitionHeader, encrypt);
                }
            }

            return true;
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
        /// <param name="header">File header for backup information</param>
        /// <param name="partitionNumber">Partition number, only used for logging</param>
        /// <param name="partitionHeader">Current partition header</param>
        /// <param name="encrypt">True if we're encrypting the file, false otherwise</param>
        private void SetEncryptionKeys(NCSDHeader header, int partitionNumber, NCCHHeader partitionHeader, bool encrypt)
        {
            KeyX = 0;
            KeyX2C = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
            KeyY = new BigInteger(partitionHeader.RSA2048Signature.Take(16).Reverse().ToArray()); // KeyY is the first 16 bytes of the partition RSA-2048 SHA-256 signature

            NormalKey = 0;
            NormalKey2C = RotateLeft((RotateLeft(KeyX2C, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);

            // Set the header to use based on mode
            BitMasks masks = 0;
            CryptoMethod method = 0;
            if (encrypt)
            {
                masks = header.BackupHeader.Flags.BitMasks;
                method = header.BackupHeader.Flags.CryptoMethod;
            }
            else
            {
                masks = partitionHeader.Flags.BitMasks;
                method = partitionHeader.Flags.CryptoMethod;
            }

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
        /// Create AES cipher and intialize
        /// </summary>
        /// <param name="key">BigInteger representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <param name="encrypt">True if cipher is created for encryption, false otherwise</param>
        /// <returns>Initialized AES cipher</returns>
        private IBufferedCipher CreateAESCipher(BigInteger key, byte[] iv, bool encrypt)
        {
            var cipher = CipherUtilities.GetCipher("AES/CTR");
            cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(TakeSixteen(key)), iv));
            return cipher;
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

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">File header</param>
        /// <param name="partitionNumber">Partition number for logging</param>
        /// <param name="partitionHeader">Partition header</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private void ProcessExtendedHeader(BinaryReader reader, BinaryWriter writer, NCSDHeader header, int partitionNumber, NCCHHeader partitionHeader, bool encrypt)
        {
            if (partitionHeader.ExtendedHeaderSizeInBytes > 0)
            {
                reader.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset * header.MediaUnitSize) + 0x200, SeekOrigin.Begin);
                writer.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset * header.MediaUnitSize) + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {partitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                var cipher = CreateAESCipher(NormalKey2C, partitionHeader.PlainIV, encrypt);
                writer.Write(cipher.ProcessBytes(reader.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                writer.Flush();
            }
            else
            {
                Console.WriteLine($"Partition {partitionNumber} ExeFS: No Extended Header... Skipping...");
            }
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">File header</param>
        /// <param name="partitionNumber">Partition number for logging</param>
        /// <param name="partitionHeader">Partition header</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private void ProcessExeFS(BinaryReader reader, BinaryWriter writer, NCSDHeader header, int partitionNumber, NCCHHeader partitionHeader, bool encrypt)
        {
            if (partitionHeader.ExeFSSizeInMediaUnits > 0)
            {
                // If we're decrypting, we need to decrypt the filename table first
                if (!encrypt)
                    ProcessExeFSFilenameTable(reader, writer, header, partitionNumber, partitionHeader, encrypt);

                // For all but the original crypto method, process each of the files in the table
                if (partitionHeader.Flags.CryptoMethod != CryptoMethod.Original)
                {
                    reader.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.MediaUnitSize, SeekOrigin.Begin);
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
                            uint ctroffset = ((fileHeader.FileOffset + header.MediaUnitSize) / 0x10);

                            byte[] exefsIVWithOffsetForHeader = AddToByteArray(partitionHeader.ExeFSIV, (int)ctroffset);

                            var firstCipher = CreateAESCipher(NormalKey, exefsIVWithOffsetForHeader, encrypt);
                            var secondCipher = CreateAESCipher(NormalKey2C, exefsIVWithOffsetForHeader, !encrypt);

                            reader.BaseStream.Seek((((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits) + 1) * header.MediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                            writer.BaseStream.Seek((((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits) + 1) * header.MediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                            if (datalenM > 0)
                            {
                                for (int i = 0; i < datalenM; i++)
                                {
                                    writer.Write(secondCipher.ProcessBytes(firstCipher.ProcessBytes(reader.ReadBytes(1024 * 1024))));
                                    writer.Flush();
                                    Console.Write($"\rPartition {partitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.ReadableFileName}... {i} / {datalenM + 1} mb...");
                                }
                            }

                            if (datalenB > 0)
                            {
                                writer.Write(secondCipher.DoFinal(firstCipher.DoFinal(reader.ReadBytes((int)datalenB))));
                                writer.Flush();
                            }

                            Console.Write($"\rPartition {partitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.ReadableFileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
                        }
                    }
                }

                // If we're encrypting, we need to encrypt the filename table now
                if (encrypt)
                    ProcessExeFSFilenameTable(reader, writer, header, partitionNumber, partitionHeader, encrypt);

                // Process the ExeFS
                int exefsSizeM = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.MediaUnitSize) / (1024 * 1024);
                int exefsSizeB = (int)((partitionHeader.ExeFSSizeInMediaUnits - 1) * header.MediaUnitSize) % (1024 * 1024);
                int ctroffsetE = (int)(header.MediaUnitSize / 0x10);

                byte[] exefsIVWithOffset = AddToByteArray(partitionHeader.ExeFSIV, ctroffsetE);

                var exeFS = CreateAESCipher(NormalKey2C, exefsIVWithOffset, encrypt);

                reader.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits + 1) * header.MediaUnitSize, SeekOrigin.Begin);
                writer.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits + 1) * header.MediaUnitSize, SeekOrigin.Begin);
                if (exefsSizeM > 0)
                {
                    for (int i = 0; i < exefsSizeM; i++)
                    {
                        writer.Write(exeFS.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                        writer.Flush();
                        Console.Write($"\rPartition {partitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                    }
                }
                if (exefsSizeB > 0)
                {
                    writer.Write(exeFS.DoFinal(reader.ReadBytes(exefsSizeB)));
                    writer.Flush();
                }

                Console.Write($"\rPartition {partitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
            }
            else
            {
                Console.WriteLine($"Partition {partitionNumber} ExeFS: No Data... Skipping...");
            }
        }

        /// <summary>
        /// Process the ExeFS Filename Table
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">File header</param>
        /// <param name="partitionNumber">Partition number for logging</param>
        /// <param name="partitionHeader">Partition header</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private void ProcessExeFSFilenameTable(BinaryReader reader, BinaryWriter writer, NCSDHeader header, int partitionNumber, NCCHHeader partitionHeader, bool encrypt)
        {
            reader.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.MediaUnitSize, SeekOrigin.Begin);
            writer.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.ExeFSOffsetInMediaUnits) * header.MediaUnitSize, SeekOrigin.Begin);

            Console.WriteLine($"Partition {partitionNumber} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            var exeFSFilenameTable = CreateAESCipher(NormalKey2C, partitionHeader.ExeFSIV, encrypt);
            writer.Write(exeFSFilenameTable.ProcessBytes(reader.ReadBytes((int)header.MediaUnitSize)));
            writer.Flush();
        }

        /// <summary>
        /// Process the RomFS, if it exists
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">File header</param>
        /// <param name="partitionNumber">Partition number for logging</param>
        /// <param name="partitionHeader">Partition header</param>
        /// <param name="encrypt">True if we want to encrypt the extended header, false otherwise</param>
        private void ProcessRomFS(BinaryReader reader, BinaryWriter writer, NCSDHeader header, int partitionNumber, NCCHHeader partitionHeader, bool encrypt)
        {
            if (partitionHeader.RomFSOffsetInMediaUnits != 0)
            {
                int romfsSizeM = (int)(partitionHeader.RomFSSizeInMediaUnits * header.MediaUnitSize) / (1024 * 1024);
                int romfsSizeB = (int)(partitionHeader.RomFSSizeInMediaUnits * header.MediaUnitSize) % (1024 * 1024);

                // Encrypting RomFS for partitions 1 and up always use Key0x2C
                if (encrypt && partitionNumber > 0) 
                {
                    // If the backup flags aren't provided and we're encrypting, assume defaults
                    if (header.BackupHeader.Flags == null)
                    {
                        KeyX = KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                        NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                    }

                    if ((header.BackupHeader.Flags.BitMasks & BitMasks.FixedCryptoKey) != 0) // except if using zero-key
                    {
                        NormalKey = 0x00;
                    }
                    else
                    {
                        KeyX = KeyX = (development ? Constants.DevKeyX0x2C : Constants.KeyX0x2C);
                        NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + Constants.AESHardwareConstant, 87, 128);
                    }
                }

                var cipher = CreateAESCipher(NormalKey, partitionHeader.RomFSIV, encrypt);

                reader.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.MediaUnitSize, SeekOrigin.Begin);
                writer.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset + partitionHeader.RomFSOffsetInMediaUnits) * header.MediaUnitSize, SeekOrigin.Begin);
                if (romfsSizeM > 0)
                {
                    for (int i = 0; i < romfsSizeM; i++)
                    {
                        writer.Write(cipher.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                        writer.Flush();
                        Console.Write($"\rPartition {partitionNumber} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                    }
                }
                if (romfsSizeB > 0)
                {
                    writer.Write(cipher.DoFinal(reader.ReadBytes(romfsSizeB)));
                    writer.Flush();
                }

                Console.Write($"\rPartition {partitionNumber} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
            }
            else
            {
                Console.WriteLine($"Partition {partitionNumber} RomFS: No Data... Skipping...");
            }
        }

        /// <summary>
        /// Attempt to decrypt a 3DS file
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// <param name="header">NCSD header for the 3DS file</param>
        /// <param name="partitionNumber">Partition number for seeking in the table</param>
        /// <param name="partitionHeader">Current partition header value</param>
        /// <param name="encrypt">True if we're writing encrypted values, false otherwise</param>
        private void UpdateCryptoAndMasks(BinaryReader reader, BinaryWriter writer, NCSDHeader header, int partitionNumber, NCCHHeader partitionHeader, bool encrypt)
        {
            // Write the new CryptoMethod
            writer.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset * header.MediaUnitSize) + 0x18B, SeekOrigin.Begin);
            if (encrypt)
            {
                // For partitions 1 and up, set crypto-method to 0x00
                if (partitionNumber > 0)
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
            writer.BaseStream.Seek((header.PartitionsTable[partitionNumber].Offset * header.MediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = partitionHeader.Flags.BitMasks;
            if (encrypt)
            {
                flag = (flag & ((BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF));
                flag = (flag | (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & header.BackupHeader.Flags.BitMasks);
            }
            else
            {
                flag = flag & (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
                flag = (flag | BitMasks.NoCrypto);
            }

            writer.Write((byte)flag);
            writer.Flush();
        }
    }
}

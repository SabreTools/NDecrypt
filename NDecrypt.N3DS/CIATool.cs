using System;
using System.IO;
using System.Linq;
using System.Numerics;
using NDecrypt.Core;
using NDecrypt.N3DS.Headers;
using static NDecrypt.Core.Helper;

namespace NDecrypt.N3DS
{
    // https://www.3dbrew.org/wiki/CIA
    public class CIATool : ITool
    {
        /// <summary>
        /// Name of the input CIA file
        /// </summary>
        private readonly string filename;

        /// <summary>
        /// Decryption args to use while processing
        /// </summary>
        private readonly DecryptArgs decryptArgs;

        public CIATool(string filename, DecryptArgs decryptArgs)
        {
            this.filename = filename;
            this.decryptArgs = decryptArgs;
        }

        #region Common Methods

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        public bool ProcessFile()
        {
            // Ensure the constants are all set
            if (decryptArgs.IsReady != true)
            {
                Console.WriteLine("Could not read keys. Please make sure the file exists and try again.");
                return false;
            }

            try
            {
                // Open the read and write on the same file for inplace processing
                using (BinaryReader reader = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                using (BinaryWriter writer = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
                {
                    CIAHeader header = CIAHeader.Read(reader);
                    if (header == null)
                    {
                        Console.WriteLine("Error: Not a 3DS CIA!");
                        return false;
                    }

                    // Process all NCCH partitions
                    ProcessAllPartitions(header, reader, writer);
                }

                return false;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS CIA file and try again.");
                return false;
            }
        }

        /// <summary>
        /// Process all partitions in the content file data of a CIA header
        /// </summary>
        /// <param name="ciaHeader">CIA header representing the 3DS CIA file</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessAllPartitions(CIAHeader ciaHeader, BinaryReader reader, BinaryWriter writer)
        {
            // Iterate over all NCCH partitions
            for (int p = 0; p < ciaHeader.Partitions.Length; p++)
            {
                NCCHHeader ncchHeader = ciaHeader.Partitions[0];
                ProcessPartition(ciaHeader, ncchHeader, reader, writer);
            }
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="ciaHeader">CIA header representing the 3DS CIA file</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessPartition(CIAHeader ciaHeader, NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // If we're forcing the operation, tell the user
            if (decryptArgs.Force)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (ncchHeader.Flags.PossblyDecrypted ^ decryptArgs.Encrypt)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber}: Already " + (decryptArgs.Encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // Determine the Keys to be used
            SetEncryptionKeys(ciaHeader, ncchHeader);

            // Process the extended header
            ProcessExtendedHeader(ncchHeader, reader, writer);

            // If we're encrypting, encrypt the filesystems and update the flags
            if (decryptArgs.Encrypt)
            {
                EncryptExeFS(ncchHeader, reader, writer);
                EncryptRomFS(ncchHeader, reader, writer);
                UpdateEncryptCryptoAndMasks(ciaHeader, ncchHeader, writer);
            }

            // If we're decrypting, decrypt the filesystems and update the flags
            else
            {
                DecryptExeFS(ncchHeader, reader, writer);
                DecryptRomFS(ncchHeader, reader, writer);
                UpdateDecryptCryptoAndMasks(ncchHeader, writer);
            }
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption or decryption
        /// </summary>
        /// <param name="ciaHeader">NCSD header representing the 3DS CIA file</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        private void SetEncryptionKeys(CIAHeader ciaHeader, NCCHHeader ncchHeader)
        {
            ncchHeader.KeyX = 0;
            ncchHeader.KeyX2C = decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C;

            // Backup headers can't have a KeyY value set
            if (ncchHeader.RSA2048Signature != null)
                ncchHeader.KeyY = new BigInteger(ncchHeader.RSA2048Signature.Take(16).Reverse().ToArray());
            else
                ncchHeader.KeyY = new BigInteger(0);

            ncchHeader.NormalKey = 0;
            ncchHeader.NormalKey2C = RotateLeft((RotateLeft(ncchHeader.KeyX2C, 2, 128) ^ ncchHeader.KeyY) + decryptArgs.AESHardwareConstant, 87, 128);

            // TODO: Figure out what sane defaults for these values are
            // Set the header to use based on mode
            BitMasks masks = BitMasks.NoCrypto;
            CryptoMethod method = CryptoMethod.Original;
            if (decryptArgs.Encrypt)
            {
                // TODO: Can we actually re-encrypt a CIA?
                //masks = ciaHeader.BackupHeader.Flags.BitMasks;
                //method = ciaHeader.BackupHeader.Flags.CryptoMethod;
            }
            else
            {
                masks = ncchHeader.Flags.BitMasks;
                method = ncchHeader.Flags.CryptoMethod;
            }

            if (masks.HasFlag(BitMasks.FixedCryptoKey))
            {
                ncchHeader.NormalKey = 0x00;
                ncchHeader.NormalKey2C = 0x00;
                Console.WriteLine("Encryption Method: Zero Key");
            }
            else
            {
                if (method == CryptoMethod.Original)
                {
                    ncchHeader.KeyX = decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C;
                    Console.WriteLine("Encryption Method: Key 0x2C");
                }
                else if (method == CryptoMethod.Seven)
                {
                    ncchHeader.KeyX = decryptArgs.Development ? decryptArgs.DevKeyX0x25 : decryptArgs.KeyX0x25;
                    Console.WriteLine("Encryption Method: Key 0x25");
                }
                else if (method == CryptoMethod.NineThree)
                {
                    ncchHeader.KeyX = decryptArgs.Development ? decryptArgs.DevKeyX0x18 : decryptArgs.KeyX0x18;
                    Console.WriteLine("Encryption Method: Key 0x18");
                }
                else if (method == CryptoMethod.NineSix)
                {
                    ncchHeader.KeyX = decryptArgs.Development ? decryptArgs.DevKeyX0x1B : decryptArgs.KeyX0x1B;
                    Console.WriteLine("Encryption Method: Key 0x1B");
                }

                ncchHeader.NormalKey = RotateLeft((RotateLeft(ncchHeader.KeyX, 2, 128) ^ ncchHeader.KeyY) + decryptArgs.AESHardwareConstant, 87, 128);
            }
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private bool ProcessExtendedHeader(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            if (ncchHeader.ExtendedHeaderSizeInBytes > 0)
            {
                reader.BaseStream.Seek((ncchHeader.Entry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);
                writer.BaseStream.Seek((ncchHeader.Entry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                var cipher = CreateAESCipher(ncchHeader.NormalKey2C, ncchHeader.PlainIV, decryptArgs.Encrypt);
                writer.Write(cipher.ProcessBytes(reader.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                writer.Flush();
                return true;
            }
            else
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} ExeFS: No Extended Header... Skipping...");
                return false;
            }

            return false;
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessExeFSFileEntries(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            reader.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            ExeFSHeader exefsHeader = ExeFSHeader.Read(reader);

            // If the header failed to read, log and return
            if (exefsHeader == null)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} ExeFS header could not be read. Skipping...");
                return;
            }

            foreach (ExeFSFileHeader fileHeader in exefsHeader.FileHeaders)
            {
                // Only decrypt a file if it's a code binary
                if (!fileHeader.IsCodeBinary)
                    continue;

                uint datalenM = ((fileHeader.FileSize) / (1024 * 1024));
                uint datalenB = ((fileHeader.FileSize) % (1024 * 1024));
                uint ctroffset = ((fileHeader.FileOffset + mediaUnitSize) / 0x10);

                byte[] exefsIVWithOffsetForHeader = AddToByteArray(ncchHeader.ExeFSIV, (int)ctroffset);

                var firstCipher = CreateAESCipher(ncchHeader.NormalKey, exefsIVWithOffsetForHeader, decryptArgs.Encrypt);
                var secondCipher = CreateAESCipher(ncchHeader.NormalKey2C, exefsIVWithOffsetForHeader, !decryptArgs.Encrypt);

                reader.BaseStream.Seek((((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                writer.BaseStream.Seek((((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                if (datalenM > 0)
                {
                    for (int i = 0; i < datalenM; i++)
                    {
                        writer.Write(secondCipher.ProcessBytes(firstCipher.ProcessBytes(reader.ReadBytes(1024 * 1024))));
                        writer.Flush();
                        Console.Write($"\rPartition {ncchHeader.PartitionNumber} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.ReadableFileName}... {i} / {datalenM + 1} mb...");
                    }
                }

                if (datalenB > 0)
                {
                    writer.Write(secondCipher.DoFinal(firstCipher.DoFinal(reader.ReadBytes((int)datalenB))));
                    writer.Flush();
                }

                Console.Write($"\rPartition {ncchHeader.PartitionNumber} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.ReadableFileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
            }
        }

        /// <summary>
        /// Process the ExeFS Filename Table
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessExeFSFilenameTable(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            reader.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);

            Console.WriteLine($"Partition {ncchHeader.PartitionNumber} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            var exeFSFilenameTable = CreateAESCipher(ncchHeader.NormalKey2C, ncchHeader.ExeFSIV, decryptArgs.Encrypt);
            writer.Write(exeFSFilenameTable.ProcessBytes(reader.ReadBytes((int)mediaUnitSize)));
            writer.Flush();
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessExeFS(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            int exefsSizeM = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * mediaUnitSize) / (1024 * 1024));
            int exefsSizeB = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * mediaUnitSize) % (1024 * 1024));
            int ctroffsetE = (int)(mediaUnitSize / 0x10);

            byte[] exefsIVWithOffset = AddToByteArray(ncchHeader.ExeFSIV, ctroffsetE);

            var exeFS = CreateAESCipher(ncchHeader.NormalKey2C, exefsIVWithOffset, decryptArgs.Encrypt);

            reader.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
            writer.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
            if (exefsSizeM > 0)
            {
                for (int i = 0; i < exefsSizeM; i++)
                {
                    writer.Write(exeFS.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                    writer.Flush();
                    Console.Write($"\rPartition {ncchHeader.PartitionNumber} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                }
            }
            if (exefsSizeB > 0)
            {
                writer.Write(exeFS.DoFinal(reader.ReadBytes(exefsSizeB)));
                writer.Flush();
            }

            Console.Write($"\rPartition {ncchHeader.PartitionNumber} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void DecryptExeFS(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} ExeFS: No Data... Skipping...");
                return;
            }

            // Decrypt the filename table
            ProcessExeFSFilenameTable(ncchHeader, reader, writer);

            // For all but the original crypto method, process each of the files in the table
            if (ncchHeader.Flags.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(ncchHeader, reader, writer);

            // Decrypt the rest of the ExeFS
            ProcessExeFS(ncchHeader, reader, writer);
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// TODO: See how much can be extracted into a common method with Encrypt
        private void DecryptRomFS(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // If the RomFS offset is 0, we log and return
            if (ncchHeader.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
            int romfsSizeB = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

            var cipher = CreateAESCipher(ncchHeader.NormalKey, ncchHeader.RomFSIV, decryptArgs.Encrypt);

            reader.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    writer.Write(cipher.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                    writer.Flush();
                    Console.Write($"\rPartition {ncchHeader.PartitionNumber} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                writer.Write(cipher.DoFinal(reader.ReadBytes(romfsSizeB)));
                writer.Flush();
            }

            Console.Write($"\rPartition {ncchHeader.PartitionNumber} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void UpdateDecryptCryptoAndMasks(NCCHHeader ncchHeader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            writer.BaseStream.Seek((ncchHeader.Entry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);
            writer.Write((byte)CryptoMethod.Original);
            writer.Flush();

            // Write the new BitMasks flag
            writer.BaseStream.Seek((ncchHeader.Entry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags.BitMasks;
            flag &= (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
            flag |= BitMasks.NoCrypto;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Encrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void EncryptExeFS(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} ExeFS: No Data... Skipping...");
                return;
            }

            // TODO: Determine how to figure out the original crypto method, if possible
            // For all but the original crypto method, process each of the files in the table
            //if (ciaHeader.BackupHeader.Flags.CryptoMethod != CryptoMethod.Original)
            //    ProcessExeFSFileEntries(ncchHeader, reader, writer);

            // Encrypt the filename table
            ProcessExeFSFilenameTable(ncchHeader, reader, writer);

            // Encrypt the rest of the ExeFS
            ProcessExeFS(ncchHeader, reader, writer);
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// TODO: See how much can be extracted into a common method with Decrypt
        private void EncryptRomFS(NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // If the RomFS offset is 0, we log and return
            if (ncchHeader.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
            int romfsSizeB = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            if (ncchHeader.PartitionNumber > 0)
            {
                // TODO: Determine how to figure out the original crypto method, if possible
                //if (ciaHeader.BackupHeader.Flags?.BitMasks.HasFlag(BitMasks.FixedCryptoKey) == true) // except if using zero-key
                //{
                //    ncchHeader.NormalKey = 0x00;
                //}
                //else
                //{
                    ncchHeader.KeyX = (decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C);
                    ncchHeader.NormalKey = RotateLeft((RotateLeft(ncchHeader.KeyX, 2, 128) ^ ncchHeader.KeyY) + decryptArgs.AESHardwareConstant, 87, 128);
                //}
            }

            var cipher = CreateAESCipher(ncchHeader.NormalKey, ncchHeader.RomFSIV, decryptArgs.Encrypt);

            reader.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.BaseStream.Seek((ncchHeader.Entry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    writer.Write(cipher.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                    writer.Flush();
                    Console.Write($"\rPartition {ncchHeader.PartitionNumber} RomFS: Encrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                writer.Write(cipher.DoFinal(reader.ReadBytes(romfsSizeB)));
                writer.Flush();
            }

            Console.Write($"\rPartition {ncchHeader.PartitionNumber} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="ciaHeader">CIA header representing the 3DS CIA file</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void UpdateEncryptCryptoAndMasks(CIAHeader ciaHeader, NCCHHeader ncchHeader, BinaryWriter writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            writer.BaseStream.Seek((ncchHeader.Entry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);

            // For partitions 1 and up, set crypto-method to 0x00
            if (ncchHeader.PartitionNumber > 0)
                writer.Write((byte)CryptoMethod.Original);

            // TODO: Determine how to figure out the original crypto method, if possible
            // If partition 0, restore crypto-method from backup flags
            //else
            //    writer.Write((byte)ciaHeader.BackupHeader.Flags.CryptoMethod);

            writer.Flush();

            // Write the new BitMasks flag
            writer.BaseStream.Seek((ncchHeader.Entry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;

            // TODO: Determine how to figure out the original crypto method, if possible
            //flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & ciaHeader.BackupHeader.Flags.BitMasks;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion
    }
}
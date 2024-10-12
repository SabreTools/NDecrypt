using System;
using System.IO;
using System.Linq;
using System.Numerics;
using NDecrypt.Core;
using SabreTools.IO.Extensions;
using SabreTools.Models.N3DS;
using static NDecrypt.Core.Helper;
using CIADeserializer = SabreTools.Serialization.Deserializers.CIA;
using N3DSDeserializer = SabreTools.Serialization.Deserializers.N3DS;

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

        /// <summary>
        /// Set of all KeyX values
        /// </summary>
        private readonly BigInteger[] KeyX = new BigInteger[8];

        /// <summary>
        /// Set of all KeyX2C values
        /// </summary>
        private readonly BigInteger[] KeyX2C = new BigInteger[8];

        /// <summary>
        /// Set of all KeyY values
        /// </summary>
        private readonly BigInteger[] KeyY = new BigInteger[8];

        /// <summary>
        /// Set of all KeyY values
        /// </summary>
        private readonly BigInteger[] NormalKey = new BigInteger[8];

        /// <summary>
        /// Set of all KeyY values
        /// </summary>
        private readonly BigInteger[] NormalKey2C = new BigInteger[8];

        public CIATool(string filename, DecryptArgs decryptArgs)
        {
            this.filename = filename;
            this.decryptArgs = decryptArgs;
        }

        #region Common Methods

        /// <inheritdoc/>
        public bool EncryptFile(bool force) => ProcessFile(encrypt: true, force);

        /// <inheritdoc/>
        public bool DecryptFile(bool force) => ProcessFile(encrypt: false, force);

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        private bool ProcessFile(bool encrypt, bool force)
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
                using var reader = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the CIA information
                var cia = ReadCIA(reader);
                if (cia == null)
                {
                    Console.WriteLine("Error: Not a 3DS CIA!");
                    return false;
                }

                // Process all NCCH partitions
                ProcessAllPartitions(cia, encrypt, force, reader, writer);

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
        /// <param name="cia">CIA representing the 3DS CIA file</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessAllPartitions(CIA cia,
            bool encrypt,
            bool force,
            Stream reader,
            Stream writer)
        {
            // Iterate over all NCCH partitions
            for (int p = 0; p < cia.Partitions!.Length; p++)
            {
                var ncchHeader = cia.Partitions[0];
                if (ncchHeader == null)
                    continue;

                ProcessPartition(ncchHeader, p, encrypt, force, reader, writer);
            }
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessPartition(NCCHHeader ncchHeader,
            int partitionIndex,
            bool encrypt,
            bool force,
            Stream reader,
            Stream writer)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {partitionIndex} is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (ncchHeader.Flags!.PossblyDecrypted() ^ encrypt)
            {
                Console.WriteLine($"Partition {partitionIndex}: Already " + (encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // Get the table entry -- TODO: Fix this to get the real entry
            var tableEntry = new PartitionTableEntry();

            // Determine the Keys to be used
            SetEncryptionKeys(ncchHeader, partitionIndex, encrypt);

            // Process the extended header
            ProcessExtendedHeader(ncchHeader, partitionIndex, tableEntry, encrypt, reader, writer);

            // If we're encrypting, encrypt the filesystems and update the flags
            if (encrypt)
            {
                EncryptExeFS(ncchHeader, partitionIndex, tableEntry, reader, writer);
                EncryptRomFS(ncchHeader, partitionIndex, tableEntry, reader, writer);
                UpdateEncryptCryptoAndMasks(ncchHeader, partitionIndex, tableEntry, writer);
            }

            // If we're decrypting, decrypt the filesystems and update the flags
            else
            {
                DecryptExeFS(ncchHeader, partitionIndex, tableEntry, reader, writer);
                DecryptRomFS(ncchHeader, partitionIndex, tableEntry, reader, writer);
                UpdateDecryptCryptoAndMasks(ncchHeader, tableEntry, writer);
            }
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption or decryption
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        private void SetEncryptionKeys(NCCHHeader ncchHeader, int partitionIndex, bool encrypt)
        {
            KeyX[partitionIndex] = 0;
            KeyX2C[partitionIndex] = decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C;

            // Backup headers can't have a KeyY value set
            if (ncchHeader.RSA2048Signature != null)
                KeyY[partitionIndex] = new BigInteger(ncchHeader.RSA2048Signature.Take(16).Reverse().ToArray());
            else
                KeyY[partitionIndex] = new BigInteger(0);

            NormalKey[partitionIndex] = 0x00;
            NormalKey2C[partitionIndex] = RotateLeft((RotateLeft(KeyX2C[partitionIndex], 2, 128) ^ KeyY[partitionIndex]) + decryptArgs.AESHardwareConstant, 87, 128);

            // TODO: Figure out what sane defaults for these values are
            // Set the header to use based on mode
            BitMasks masks = BitMasks.NoCrypto;
            CryptoMethod method = CryptoMethod.Original;
            if (encrypt)
            {
                // TODO: Can we actually re-encrypt a CIA?
                //masks = ciaHeader.BackupHeader.Flags.BitMasks;
                //method = ciaHeader.BackupHeader.Flags.CryptoMethod;
            }
            else
            {
                masks = ncchHeader.Flags!.BitMasks;
                method = ncchHeader.Flags.CryptoMethod;
            }

            if (masks.HasFlag(BitMasks.FixedCryptoKey))
            {
                NormalKey[partitionIndex] = 0x00;
                NormalKey2C[partitionIndex] = 0x00;
                Console.WriteLine("Encryption Method: Zero Key");
            }
            else
            {
                if (method == CryptoMethod.Original)
                {
                    KeyX[partitionIndex] = decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C;
                    Console.WriteLine("Encryption Method: Key 0x2C");
                }
                else if (method == CryptoMethod.Seven)
                {
                    KeyX[partitionIndex] = decryptArgs.Development ? decryptArgs.DevKeyX0x25 : decryptArgs.KeyX0x25;
                    Console.WriteLine("Encryption Method: Key 0x25");
                }
                else if (method == CryptoMethod.NineThree)
                {
                    KeyX[partitionIndex] = decryptArgs.Development ? decryptArgs.DevKeyX0x18 : decryptArgs.KeyX0x18;
                    Console.WriteLine("Encryption Method: Key 0x18");
                }
                else if (method == CryptoMethod.NineSix)
                {
                    KeyX[partitionIndex] = decryptArgs.Development ? decryptArgs.DevKeyX0x1B : decryptArgs.KeyX0x1B;
                    Console.WriteLine("Encryption Method: Key 0x1B");
                }

                NormalKey[partitionIndex] = RotateLeft((RotateLeft(KeyX[partitionIndex], 2, 128) ^ KeyY[partitionIndex]) + decryptArgs.AESHardwareConstant, 87, 128);
            }
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool ProcessExtendedHeader(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            if (ncchHeader.ExtendedHeaderSizeInBytes > 0)
            {
                reader.Seek((tableEntry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);
                writer.Seek((tableEntry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                var cipher = CreateAESCipher(NormalKey2C[partitionIndex], ncchHeader.PlainIV(), encrypt);
                writer.Write(cipher.ProcessBytes(reader.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                writer.Flush();
                return true;
            }
            else
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Extended Header... Skipping...");
                return false;
            }
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessExeFSFileEntries(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            reader.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            var exefsHeader = N3DSDeserializer.ParseExeFSHeader(reader);

            // If the header failed to read, log and return
            if (exefsHeader?.FileHeaders == null)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS header could not be read. Skipping...");
                return;
            }

            foreach (var fileHeader in exefsHeader.FileHeaders)
            {
                // Only decrypt a file if it's a code binary
                if (fileHeader == null || !fileHeader.IsCodeBinary())
                    continue;

                uint datalenM = ((fileHeader.FileSize) / (1024 * 1024));
                uint datalenB = ((fileHeader.FileSize) % (1024 * 1024));
                uint ctroffset = ((fileHeader.FileOffset + mediaUnitSize) / 0x10);

                byte[] exefsIVWithOffsetForHeader = AddToByteArray(ncchHeader.ExeFSIV(), (int)ctroffset);

                var firstCipher = CreateAESCipher(NormalKey[partitionIndex], exefsIVWithOffsetForHeader, encrypt);
                var secondCipher = CreateAESCipher(NormalKey2C[partitionIndex], exefsIVWithOffsetForHeader, !encrypt);

                reader.Seek((((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                writer.Seek((((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                if (datalenM > 0)
                {
                    for (int i = 0; i < datalenM; i++)
                    {
                        writer.Write(secondCipher.ProcessBytes(firstCipher.ProcessBytes(reader.ReadBytes(1024 * 1024))));
                        writer.Flush();
                        Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {i} / {datalenM + 1} mb...");
                    }
                }

                if (datalenB > 0)
                {
                    writer.Write(secondCipher.DoFinal(firstCipher.DoFinal(reader.ReadBytes((int)datalenB))));
                    writer.Flush();
                }

                Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
            }
        }

        /// <summary>
        /// Process the ExeFS Filename Table
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessExeFSFilenameTable(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            reader.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);

            Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            var exeFSFilenameTable = CreateAESCipher(NormalKey2C[partitionIndex], ncchHeader.ExeFSIV(), encrypt);
            writer.Write(exeFSFilenameTable.ProcessBytes(reader.ReadBytes((int)mediaUnitSize)));
            writer.Flush();
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessExeFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            int exefsSizeM = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * mediaUnitSize) / (1024 * 1024));
            int exefsSizeB = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * mediaUnitSize) % (1024 * 1024));
            int ctroffsetE = (int)(mediaUnitSize / 0x10);

            byte[] exefsIVWithOffset = AddToByteArray(ncchHeader.ExeFSIV(), ctroffsetE);

            var exeFS = CreateAESCipher(NormalKey2C[partitionIndex], exefsIVWithOffset, encrypt);

            reader.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
            writer.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
            if (exefsSizeM > 0)
            {
                for (int i = 0; i < exefsSizeM; i++)
                {
                    writer.Write(exeFS.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                }
            }
            if (exefsSizeB > 0)
            {
                writer.Write(exeFS.DoFinal(reader.ReadBytes(exefsSizeB)));
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptExeFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream reader,
            Stream writer)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // Decrypt the filename table
            ProcessExeFSFilenameTable(ncchHeader, partitionIndex, tableEntry, encrypt: false, reader, writer);

            // For all but the original crypto method, process each of the files in the table
            if (ncchHeader.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(ncchHeader, partitionIndex, tableEntry, encrypt: false, reader, writer);

            // Decrypt the rest of the ExeFS
            ProcessExeFS(ncchHeader, partitionIndex, tableEntry, encrypt: false, reader, writer);
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Encrypt
        private void DecryptRomFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream reader,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // If the RomFS offset is 0, we log and return
            if (ncchHeader.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
            int romfsSizeB = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

            var cipher = CreateAESCipher(NormalKey[partitionIndex], ncchHeader.RomFSIV(), encrypt: false);

            reader.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    writer.Write(cipher.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                writer.Write(cipher.DoFinal(reader.ReadBytes(romfsSizeB)));
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="writer">Stream representing the output</param>
        private void UpdateDecryptCryptoAndMasks(NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            writer.Seek((tableEntry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);
            writer.Write((byte)CryptoMethod.Original);
            writer.Flush();

            // Write the new BitMasks flag
            writer.Seek((tableEntry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags!.BitMasks;
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
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptExeFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream reader,
            Stream writer)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // TODO: Determine how to figure out the original crypto method, if possible
            // For all but the original crypto method, process each of the files in the table
            //if (ciaHeader.BackupHeader.Flags.CryptoMethod != CryptoMethod.Original)
            //    ProcessExeFSFileEntries(ncchHeader, reader, writer);

            // Encrypt the filename table
            ProcessExeFSFilenameTable(ncchHeader, partitionIndex, tableEntry, encrypt: true, reader, writer);

            // Encrypt the rest of the ExeFS
            ProcessExeFS(ncchHeader, partitionIndex, tableEntry, encrypt: true, reader, writer);
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Decrypt
        private void EncryptRomFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream reader,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // If the RomFS offset is 0, we log and return
            if (ncchHeader.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
            int romfsSizeB = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            if (partitionIndex > 0)
            {
                // TODO: Determine how to figure out the original crypto method, if possible
                //if (ciaHeader.BackupHeader.Flags?.BitMasks.HasFlag(BitMasks.FixedCryptoKey) == true) // except if using zero-key
                //{
                //    ncchHeader.NormalKey = 0x00;
                //}
                //else
                //{
                KeyX[partitionIndex] = (decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C);
                NormalKey[partitionIndex] = RotateLeft((RotateLeft(KeyX[partitionIndex], 2, 128) ^ KeyY[partitionIndex]) + decryptArgs.AESHardwareConstant, 87, 128);
                //}
            }

            var cipher = CreateAESCipher(NormalKey[partitionIndex], ncchHeader.RomFSIV(), encrypt: true);

            reader.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            writer.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    writer.Write(cipher.ProcessBytes(reader.ReadBytes(1024 * 1024)));
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                writer.Write(cipher.DoFinal(reader.ReadBytes(romfsSizeB)));
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="writer">Stream representing the output</param>
        private void UpdateEncryptCryptoAndMasks(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream writer)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            writer.Seek((tableEntry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);

            // For partitions 1 and up, set crypto-method to 0x00
            if (partitionIndex > 0)
                writer.Write((byte)CryptoMethod.Original);

            // TODO: Determine how to figure out the original crypto method, if possible
            // If partition 0, restore crypto-method from backup flags
            //else
            //    writer.Write((byte)ciaHeader.BackupHeader.Flags.CryptoMethod);

            writer.Flush();

            // Write the new BitMasks flag
            writer.Seek((tableEntry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags!.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;

            // TODO: Determine how to figure out the original crypto method, if possible
            //flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & ciaHeader.BackupHeader.Flags.BitMasks;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion

        #region Serialization

        /// <summary>
        /// Read from a stream and get a CIA header, if possible
        /// </summary>
        /// <param name="reader">Stream representing the input</param>
        /// <returns>CIA header object, null on error</returns>
        private static CIA? ReadCIA(Stream reader)
        {
            try
            {
                return CIADeserializer.DeserializeStream(reader);
            }
            catch
            {
                return null;
            }
        }

        #endregion
    }
}
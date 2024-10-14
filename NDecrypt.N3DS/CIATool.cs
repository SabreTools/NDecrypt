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
        /// Decryption args to use while processing
        /// </summary>
        private readonly DecryptArgs _decryptArgs;

        /// <summary>
        /// Indicates if development images are expected
        /// </summary>
        private readonly bool _development;

        /// <summary>
        /// Set of all partition keys
        /// </summary>
        private readonly PartitionKeys[] KeysMap = new PartitionKeys[8];

        public CIATool(bool development, DecryptArgs decryptArgs)
        {
            _development = development;
            _decryptArgs = decryptArgs;
        }

        #region Common Methods

        /// <inheritdoc/>
        public bool EncryptFile(string filename, bool force)
            => ProcessFile(filename, encrypt: true, force);

        /// <inheritdoc/>
        public bool DecryptFile(string filename, bool force)
            => ProcessFile(filename, encrypt: false, force);

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        private bool ProcessFile(string filename, bool encrypt, bool force)
        {
            // Ensure the constants are all set
            if (_decryptArgs.IsReady != true)
            {
                Console.WriteLine("Could not read keys. Please make sure the file exists and try again.");
                return false;
            }

            try
            {
                // Open the read and write on the same file for inplace processing
                using var input = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var output = File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the CIA information
                var cia = ReadCIA(input);
                if (cia == null)
                {
                    Console.WriteLine("Error: Not a 3DS CIA!");
                    return false;
                }

                // Process all NCCH partitions
                ProcessAllPartitions(cia, encrypt, force, input, output);

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
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessAllPartitions(CIA cia,
            bool encrypt,
            bool force,
            Stream input,
            Stream output)
        {
            // Check the partitions table
            if (cia.Partitions == null)
            {
                Console.WriteLine("Invalid partitions table!");
                return;
            }

            // Iterate over all 8 NCCH partitions
            for (int p = 0; p < cia.Partitions.Length; p++)
            {
                // Check the partition exists
                var ncchHeader = cia.Partitions[0];
                if (ncchHeader == null)
                {
                    Console.WriteLine($"Partition {p} Not found... Skipping...");
                    continue;
                }

                // Process the partition, if possible
                if (ShouldProcessPartition(cia, p, encrypt, force))
                    ProcessPartition(ncchHeader, p, encrypt, input, output);
            }
        }

        /// <summary>
        /// Determine if the current partition should be processed
        /// </summary>
        private static bool ShouldProcessPartition(CIA cia, int index, bool encrypt, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (cia.Partitions![index]!.Flags!.PossblyDecrypted() ^ encrypt)
            {
                Console.WriteLine($"Partition {index}: Already " + (encrypt ? "Encrypted" : "Decrypted") + "?...");
                return false;
            }

            // By default, it passes
            return true;
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessPartition(NCCHHeader ncchHeader,
            int partitionIndex,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // Get the table entry -- TODO: Fix this to get the real entry
            var tableEntry = new PartitionTableEntry();

            // Determine the Keys to be used
            SetEncryptionKeys(ncchHeader, partitionIndex, encrypt);

            // Process the extended header
            ProcessExtendedHeader(ncchHeader, partitionIndex, tableEntry, encrypt, input, output);

            // If we're encrypting, encrypt the filesystems and update the flags
            if (encrypt)
            {
                EncryptExeFS(ncchHeader, partitionIndex, tableEntry, input, output);
                EncryptRomFS(ncchHeader, partitionIndex, tableEntry, input, output);
                UpdateEncryptCryptoAndMasks(ncchHeader, partitionIndex, tableEntry, output);
            }

            // If we're decrypting, decrypt the filesystems and update the flags
            else
            {
                DecryptExeFS(ncchHeader, partitionIndex, tableEntry, input, output);
                DecryptRomFS(ncchHeader, partitionIndex, tableEntry, input, output);
                UpdateDecryptCryptoAndMasks(ncchHeader, tableEntry, output);
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
            // Get partition-specific values
            byte[]? rsaSignature = ncchHeader.RSA2048Signature;

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

            // Get the partition keys
            KeysMap[partitionIndex] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool ProcessExtendedHeader(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            if (ncchHeader.ExtendedHeaderSizeInBytes > 0)
            {
                input.Seek((tableEntry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);
                output.Seek((tableEntry.Offset * mediaUnitSize) + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, ncchHeader.PlainIV(), encrypt);
                output.Write(cipher.ProcessBytes(input.ReadBytes(Constants.CXTExtendedDataHeaderLength)));
                output.Flush();
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
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessExeFSFileEntries(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            input.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            var exefsHeader = N3DSDeserializer.ParseExeFSHeader(input);

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

                var firstCipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey, exefsIVWithOffsetForHeader, encrypt);
                var secondCipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, exefsIVWithOffsetForHeader, !encrypt);

                input.Seek((((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);
                output.Seek((((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * mediaUnitSize) + fileHeader.FileOffset, SeekOrigin.Begin);

                if (datalenM > 0)
                {
                    for (int i = 0; i < datalenM; i++)
                    {
                        output.Write(secondCipher.ProcessBytes(firstCipher.ProcessBytes(input.ReadBytes(1024 * 1024))));
                        output.Flush();
                        Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {i} / {datalenM + 1} mb...");
                    }
                }

                if (datalenB > 0)
                {
                    output.Write(secondCipher.DoFinal(firstCipher.DoFinal(input.ReadBytes((int)datalenB))));
                    output.Flush();
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
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessExeFSFilenameTable(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            input.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            output.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);

            Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            var exeFSFilenameTable = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, ncchHeader.ExeFSIV(), encrypt);
            output.Write(exeFSFilenameTable.ProcessBytes(input.ReadBytes((int)mediaUnitSize)));
            output.Flush();
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessExeFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // mediaUnitSize;

            int exefsSizeM = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * mediaUnitSize) / (1024 * 1024));
            int exefsSizeB = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * mediaUnitSize) % (1024 * 1024));
            int ctroffsetE = (int)(mediaUnitSize / 0x10);

            byte[] exefsIVWithOffset = AddToByteArray(ncchHeader.ExeFSIV(), ctroffsetE);

            var exeFS = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, exefsIVWithOffset, encrypt);

            input.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
            output.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * mediaUnitSize, SeekOrigin.Begin);
            if (exefsSizeM > 0)
            {
                for (int i = 0; i < exefsSizeM; i++)
                {
                    output.Write(exeFS.ProcessBytes(input.ReadBytes(1024 * 1024)));
                    output.Flush();
                    Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                }
            }
            if (exefsSizeB > 0)
            {
                output.Write(exeFS.DoFinal(input.ReadBytes(exefsSizeB)));
                output.Flush();
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
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptExeFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // Decrypt the filename table
            ProcessExeFSFilenameTable(ncchHeader, partitionIndex, tableEntry, encrypt: false, input, output);

            // For all but the original crypto method, process each of the files in the table
            if (ncchHeader.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(ncchHeader, partitionIndex, tableEntry, encrypt: false, input, output);

            // Decrypt the rest of the ExeFS
            ProcessExeFS(ncchHeader, partitionIndex, tableEntry, encrypt: false, input, output);
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Encrypt
        private void DecryptRomFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
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

            var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey, ncchHeader.RomFSIV(), encrypt: false);

            input.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            output.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    output.Write(cipher.ProcessBytes(input.ReadBytes(1024 * 1024)));
                    output.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                output.Write(cipher.DoFinal(input.ReadBytes(romfsSizeB)));
                output.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="output">Stream representing the output</param>
        private void UpdateDecryptCryptoAndMasks(NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            output.Seek((tableEntry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);
            output.Write((byte)CryptoMethod.Original);
            output.Flush();

            // Write the new BitMasks flag
            output.Seek((tableEntry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags!.BitMasks;
            flag &= (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
            flag |= BitMasks.NoCrypto;
            output.Write((byte)flag);
            output.Flush();
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Encrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptExeFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
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
            ProcessExeFSFilenameTable(ncchHeader, partitionIndex, tableEntry, encrypt: true, input, output);

            // Encrypt the rest of the ExeFS
            ProcessExeFS(ncchHeader, partitionIndex, tableEntry, encrypt: true, input, output);
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Decrypt
        private void EncryptRomFS(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
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
                KeysMap[partitionIndex].KeyX = (_development ? _decryptArgs.DevKeyX0x2C : _decryptArgs.KeyX0x2C);
                KeysMap[partitionIndex].NormalKey = RotateLeft((RotateLeft(KeysMap[partitionIndex].KeyX, 2, 128) ^ KeysMap[partitionIndex].KeyY) + _decryptArgs.AESHardwareConstant, 87, 128);
                //}
            }

            var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey, ncchHeader.RomFSIV(), encrypt: true);

            input.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            output.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    output.Write(cipher.ProcessBytes(input.ReadBytes(1024 * 1024)));
                    output.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                output.Write(cipher.DoFinal(input.ReadBytes(romfsSizeB)));
                output.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="output">Stream representing the output</param>
        private void UpdateEncryptCryptoAndMasks(NCCHHeader ncchHeader,
            int partitionIndex,
            PartitionTableEntry tableEntry,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            output.Seek((tableEntry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);

            // For partitions 1 and up, set crypto-method to 0x00
            if (partitionIndex > 0)
                output.Write((byte)CryptoMethod.Original);

            // TODO: Determine how to figure out the original crypto method, if possible
            // If partition 0, restore crypto-method from backup flags
            //else
            //    writer.Write((byte)ciaHeader.BackupHeader.Flags.CryptoMethod);

            output.Flush();

            // Write the new BitMasks flag
            output.Seek((tableEntry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags!.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;

            // TODO: Determine how to figure out the original crypto method, if possible
            //flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & ciaHeader.BackupHeader.Flags.BitMasks;
            output.Write((byte)flag);
            output.Flush();
        }

        #endregion

        #region Serialization

        /// <summary>
        /// Read from a stream and get a CIA header, if possible
        /// </summary>
        /// <param name="input">Stream representing the input</param>
        /// <returns>CIA header object, null on error</returns>
        private static CIA? ReadCIA(Stream input)
        {
            try
            {
                return CIADeserializer.DeserializeStream(input);
            }
            catch
            {
                return null;
            }
        }

        #endregion
    }
}
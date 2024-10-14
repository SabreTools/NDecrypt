using System;
using System.IO;
using NDecrypt.Core;
using SabreTools.IO.Extensions;
using SabreTools.Models.N3DS;
using static NDecrypt.N3DS.CommonOperations;
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
                var header = cia.Partitions[0];
                if (header == null)
                {
                    Console.WriteLine($"Partition {p} Not found... Skipping...");
                    continue;
                }

                // Process the partition, if possible
                if (encrypt && ShouldEncryptPartition(cia, p, force))
                    EncryptPartition(header, p, input, output);
                else if (!encrypt && ShouldDecryptPartition(cia, p, force))
                    DecryptPartition(header, p, input, output);
            }
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Determine if the current partition should be decrypted
        /// </summary>
        private static bool ShouldDecryptPartition(CIA cia, int index, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (cia.Partitions![index]!.Flags!.PossblyDecrypted())
            {
                Console.WriteLine($"Partition {index}: Already Decrypted?...");
                return false;
            }

            // By default, it passes
            return true;
        }

        /// <summary>
        /// Decrypt a single partition
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptPartition(NCCHHeader header, int index, Stream input, Stream output)
        {
            // Get the table entry -- TODO: Fix this to get the real entry
            var tableEntry = new PartitionTableEntry();

            // Determine the keys needed for this partition
            SetDecryptionKeys(header, index);

            // Decrypt the parts of the partition
            DecryptExtendedHeader(header, index, tableEntry, input, output);
            DecryptExeFS(header, index, tableEntry, input, output);
            DecryptRomFS(header, index, tableEntry, input, output);

            // Update the flags
            UpdateDecryptCryptoAndMasks(header, tableEntry, output);
        }

        /// <summary>
        /// Determine the set of keys to be used for decryption
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        private void SetDecryptionKeys(NCCHHeader header, int index)
        {
            // Get partition-specific values
            byte[]? rsaSignature = header.RSA2048Signature;

            // Set the header to use based on mode
            BitMasks masks = header.Flags!.BitMasks;
            CryptoMethod method = header.Flags.CryptoMethod;

            // Get the partition keys
            KeysMap[index] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Decrypt the extended header, if it exists
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool DecryptExtendedHeader(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint mediaUnitSize = 0x200;
            uint partitionOffset = GetPartitionOffset(tableEntry, mediaUnitSize);
            if (partitionOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint extHeaderSize = GetExtendedHeaderSize(header);
            if (extHeaderSize == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Extended Header... Skipping...");
                return false;
            }

            // Seek to the extended header
            input.Seek(partitionOffset + 0x200, SeekOrigin.Begin);
            output.Seek(partitionOffset + 0x200, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index} ExeFS: Decrypting: ExHeader");

            // Create the Plain AES cipher for this partition
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, header.PlainIV());

            // Process the extended header
            PerformAESOperation(Constants.CXTExtendedDataHeaderLength, cipher, input, output, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
            return true;
        }

        /// <summary>
        /// Decrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool DecryptExeFS(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Validate the ExeFS
            uint mediaUnitSize = 0x200;
            uint exeFsOffset = GetExeFSOffset(header, tableEntry, mediaUnitSize) - mediaUnitSize;
            if (exeFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint exeFsSize = GetExeFSSize(header, mediaUnitSize);
            if (exeFsSize == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            // Decrypt the filename table
            DecryptExeFSFilenameTable(header, index, tableEntry, input, output);

            // For all but the original crypto method, process each of the files in the table
            if (header.Flags!.CryptoMethod != CryptoMethod.Original)
                DecryptExeFSFileEntries(header, index, tableEntry, input, output);

            // Seek to the ExeFS
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            // Create the ExeFS AES cipher for this partition
            int ctroffsetE = (int)(mediaUnitSize / 0x10);
            byte[] exefsIVWithOffset = AddToByteArray(header.ExeFSIV(), ctroffsetE);
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffset);

            // Setup and perform the decryption
            PerformAESOperation(exeFsSize - mediaUnitSize,
                cipher,
                input,
                output,
                (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Decrypting: {s}"));

            return true;
        }

        /// <summary>
        /// Decrypt the ExeFS Filename Table
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptExeFSFilenameTable(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Get ExeFS offset
            uint mediaUnitSize = 0x200;
            uint exeFsOffset = GetExeFSOffset(header, tableEntry, mediaUnitSize);
            if (exeFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Seek to the ExeFS header
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index} ExeFS: Decrypting: ExeFS Filename Table");

            // Create the ExeFS AES cipher for this partition
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, header.ExeFSIV());

            // Process the filename table
            PerformAESOperation(mediaUnitSize, cipher, input, output, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
        }

        /// <summary>
        /// Decrypt the ExeFS file entries
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptExeFSFileEntries(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Get ExeFS offset
            uint mediaUnitSize = 0x200;
            uint exeFsHeaderOffset = GetExeFSOffset(header, tableEntry, mediaUnitSize);
            if (exeFsHeaderOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Get to the start of the files
            uint exeFsFilesOffset = exeFsHeaderOffset + mediaUnitSize;
            input.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            var exefsHeader = N3DSDeserializer.ParseExeFSHeader(input);

            // If the header failed to read, log and return
            if (exefsHeader == null)
            {
                Console.WriteLine($"Partition {index} ExeFS header could not be read. Skipping...");
                return;
            }

            foreach (var fileHeader in exefsHeader.FileHeaders!)
            {
                // Only decrypt a file if it's a code binary
                if (fileHeader == null || !fileHeader.IsCodeBinary())
                    continue;

                // Create the ExeFS AES ciphers for this partition
                uint ctroffset = (fileHeader.FileOffset + mediaUnitSize) / 0x10;
                byte[] exefsIVWithOffsetForHeader = AddToByteArray(header.ExeFSIV(), (int)ctroffset);
                var firstCipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey, exefsIVWithOffsetForHeader);
                var secondCipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffsetForHeader);

                // Seek to the file entry
                input.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                output.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Setup and perform the encryption
                uint exeFsSize = GetExeFSSize(header, mediaUnitSize);
                PerformAESOperation(exeFsSize,
                    firstCipher,
                    secondCipher,
                    input,
                    output,
                    (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Decrypting: {fileHeader.FileName}...{s}"));
            }
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptRomFS(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // If the RomFS offset is 0, we log and return
            if (header.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(header.RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
            int romfsSizeB = (int)((long)(header.RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

            var cipher = CreateAESCipher(KeysMap[index].NormalKey, header.RomFSIV(), encrypt: false);

            input.Seek((tableEntry.Offset + header.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            output.Seek((tableEntry.Offset + header.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    output.Write(cipher.ProcessBytes(input.ReadBytes(1024 * 1024)));
                    output.Flush();
                    Console.Write($"\rPartition {index} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                output.Write(cipher.DoFinal(input.ReadBytes(romfsSizeB)));
                output.Flush();
            }

            Console.Write($"\rPartition {index} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="output">Stream representing the output</param>
        private void UpdateDecryptCryptoAndMasks(NCCHHeader header,
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
            BitMasks flag = header.Flags!.BitMasks;
            flag &= (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
            flag |= BitMasks.NoCrypto;
            output.Write((byte)flag);
            output.Flush();
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Determine if the current partition should be encrypted
        /// </summary>
        private static bool ShouldEncryptPartition(CIA cia, int index, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (!cia.Partitions![index]!.Flags!.PossblyDecrypted())
            {
                Console.WriteLine($"Partition {index}: Already Encrypted?...");
                return false;
            }

            // By default, it passes
            return true;
        }

        /// <summary>
        /// Encrypt a single partition
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptPartition(NCCHHeader header, int index, Stream input, Stream output)
        {
            // Get the table entry -- TODO: Fix this to get the real entry
            var tableEntry = new PartitionTableEntry();

            // Determine the keys needed for this partition
            SetEncryptionKeys(header, index);

            // Encrypt the parts of the partition
            EncryptExtendedHeader(header, index, tableEntry, input, output);
            EncryptExeFS(header, index, tableEntry, input, output);
            EncryptRomFS(header, index, tableEntry, input, output);

            // Update the flags
            UpdateEncryptCryptoAndMasks(header, index, tableEntry, output);
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        private void SetEncryptionKeys(NCCHHeader header, int index)
        {
            // Get partition-specific values
            byte[]? rsaSignature = header.RSA2048Signature;

            // TODO: Figure out what sane defaults for these values are
            // TODO: Can we actually re-encrypt a CIA?

            // Set the header to use based on mode
            BitMasks masks = BitMasks.NoCrypto; // ciaHeader.BackupHeader.Flags.BitMasks;
            CryptoMethod method = CryptoMethod.Original; // ciaHeader.BackupHeader.Flags.CryptoMethod;

            // Get the partition keys
            KeysMap[index] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Encrypt the extended header, if it exists
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool EncryptExtendedHeader(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint mediaUnitSize = 0x200;
            uint partitionOffset = GetPartitionOffset(tableEntry, mediaUnitSize);
            if (partitionOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint extHeaderSize = GetExtendedHeaderSize(header);
            if (extHeaderSize == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Extended Header... Skipping...");
                return false;
            }

            // Seek to the extended header
            input.Seek(partitionOffset + 0x200, SeekOrigin.Begin);
            output.Seek(partitionOffset + 0x200, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index} ExeFS: Encrypting: ExHeader");

            // Create the Plain AES cipher for this partition
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, header.PlainIV());

            // Process the extended header
            PerformAESOperation(Constants.CXTExtendedDataHeaderLength, cipher, input, output, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
            return true;
        }

        /// <summary>
        /// Encrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool EncryptExeFS(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Validate the ExeFS
            uint mediaUnitSize = 0x200;
            uint exeFsOffset = GetExeFSOffset(header, tableEntry, mediaUnitSize) - mediaUnitSize;
            if (exeFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint exeFsSize = GetExeFSSize(header, mediaUnitSize);
            if (exeFsSize == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            // TODO: Determine how to figure out the original crypto method, if possible
            // For all but the original crypto method, process each of the files in the table
            //if (ciaHeader.BackupHeader.Flags.CryptoMethod != CryptoMethod.Original)
            //    EncryptExeFSFileEntries(header, index, tableEntry, reader, writer);

            // Encrypt the filename table
            EncryptExeFSFilenameTable(header, index, tableEntry, input, output);

            // Seek to the ExeFS
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            // Create the ExeFS AES cipher for this partition
            int ctroffsetE = (int)(mediaUnitSize / 0x10);
            byte[] exefsIVWithOffset = AddToByteArray(header.ExeFSIV(), ctroffsetE);
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffset);

            // Setup and perform the decryption
            PerformAESOperation(exeFsSize - mediaUnitSize,
                cipher,
                input,
                output,
                (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Encrypting: {s}"));

            return true;
        }

        /// <summary>
        /// Encrypt the ExeFS Filename Table
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptExeFSFilenameTable(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Get ExeFS offset
            uint mediaUnitSize = 0x200;
            uint exeFsOffset = GetExeFSOffset(header, tableEntry, mediaUnitSize);
            if (exeFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Seek to the ExeFS header
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index} ExeFS: Encrypting: ExeFS Filename Table");

            // Create the ExeFS AES cipher for this partition
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, header.ExeFSIV());

            // Process the filename table
            PerformAESOperation(mediaUnitSize, cipher, input, output, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
        }

        /// <summary>
        /// Encrypt the ExeFS file entries
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptExeFSFileEntries(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // Get ExeFS offset
            uint mediaUnitSize = 0x200;
            uint exeFsHeaderOffset = GetExeFSOffset(header, tableEntry, mediaUnitSize);
            if (exeFsHeaderOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Get to the start of the files
            uint exeFsFilesOffset = exeFsHeaderOffset + mediaUnitSize;
            input.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            var exefsHeader = N3DSDeserializer.ParseExeFSHeader(input);

            // If the header failed to read, log and return
            if (exefsHeader == null)
            {
                Console.WriteLine($"Partition {index} ExeFS header could not be read. Skipping...");
                return;
            }

            foreach (var fileHeader in exefsHeader.FileHeaders!)
            {
                // Only decrypt a file if it's a code binary
                if (fileHeader == null || !fileHeader.IsCodeBinary())
                    continue;

                // Create the ExeFS AES ciphers for this partition
                uint ctroffset = (fileHeader.FileOffset + mediaUnitSize) / 0x10;
                byte[] exefsIVWithOffsetForHeader = AddToByteArray(header.ExeFSIV(), (int)ctroffset);
                var firstCipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey, exefsIVWithOffsetForHeader);
                var secondCipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffsetForHeader);

                // Seek to the file entry
                input.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                output.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Setup and perform the encryption
                uint exeFsSize = GetExeFSSize(header, mediaUnitSize);
                PerformAESOperation(exeFsSize,
                    firstCipher,
                    secondCipher,
                    input,
                    output,
                    (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Encrypting: {fileHeader.FileName}...{s}"));
            }
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptRomFS(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream input,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // If the RomFS offset is 0, we log and return
            if (header.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(header.RomFSSizeInMediaUnits * mediaUnitSize) / (1024 * 1024));
            int romfsSizeB = (int)((long)(header.RomFSSizeInMediaUnits * mediaUnitSize) % (1024 * 1024));

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            if (index > 0)
            {
                // TODO: Determine how to figure out the original crypto method, if possible
                //if (ciaHeader.BackupHeader.Flags?.BitMasks.HasFlag(BitMasks.FixedCryptoKey) == true) // except if using zero-key
                //{
                //    header.NormalKey = 0x00;
                //}
                //else
                //{
                KeysMap[index].KeyX = (_development ? _decryptArgs.DevKeyX0x2C : _decryptArgs.KeyX0x2C);
                KeysMap[index].NormalKey = RotateLeft((RotateLeft(KeysMap[index].KeyX, 2, 128) ^ KeysMap[index].KeyY) + _decryptArgs.AESHardwareConstant, 87, 128);
                //}
            }

            var cipher = CreateAESCipher(KeysMap[index].NormalKey, header.RomFSIV(), encrypt: true);

            input.Seek((tableEntry.Offset + header.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            output.Seek((tableEntry.Offset + header.RomFSOffsetInMediaUnits) * mediaUnitSize, SeekOrigin.Begin);
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    output.Write(cipher.ProcessBytes(input.ReadBytes(1024 * 1024)));
                    output.Flush();
                    Console.Write($"\rPartition {index} RomFS: Encrypting: {i} / {romfsSizeM + 1} mb");
                }
            }
            if (romfsSizeB > 0)
            {
                output.Write(cipher.DoFinal(input.ReadBytes(romfsSizeB)));
                output.Flush();
            }

            Console.Write($"\rPartition {index} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="header">NCCH header representing the partition</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="output">Stream representing the output</param>
        private void UpdateEncryptCryptoAndMasks(NCCHHeader header,
            int index,
            PartitionTableEntry tableEntry,
            Stream output)
        {
            // TODO: Determine how to figure out the MediaUnitSize without an NCSD header. Is it a default value?
            uint mediaUnitSize = 0x200; // ncsdHeader.MediaUnitSize;

            // Write the new CryptoMethod
            output.Seek((tableEntry.Offset * mediaUnitSize) + 0x18B, SeekOrigin.Begin);

            // For partitions 1 and up, set crypto-method to 0x00
            if (index > 0)
                output.Write((byte)CryptoMethod.Original);

            // TODO: Determine how to figure out the original crypto method, if possible
            // If partition 0, restore crypto-method from backup flags
            //else
            //    writer.Write((byte)ciaHeader.BackupHeader.Flags.CryptoMethod);

            output.Flush();

            // Write the new BitMasks flag
            output.Seek((tableEntry.Offset * mediaUnitSize) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = header.Flags!.BitMasks;
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
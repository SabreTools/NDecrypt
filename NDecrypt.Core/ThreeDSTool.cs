using System;
using System.IO;
using System.Text;
using SabreTools.Data.Models.N3DS;
using SabreTools.IO.Extensions;
using SabreTools.Serialization.Wrappers;
using static NDecrypt.Core.CommonOperations;
using static SabreTools.Data.Models.N3DS.Constants;

namespace NDecrypt.Core
{
    public class ThreeDSTool : ITool
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
        private readonly PartitionKeys[] _keysMap = new PartitionKeys[8];

        public ThreeDSTool(bool development, DecryptArgs decryptArgs)
        {
            _development = development;
            _decryptArgs = decryptArgs;
        }

        #region Decrypt

        /// <inheritdoc/>
        public bool DecryptFile(string input, string? output, bool force)
        {
            // Ensure the constants are all set
            if (_decryptArgs.IsReady != true)
            {
                Console.WriteLine("Could not read keys. Please make sure the file exists and try again.");
                return false;
            }

            try
            {
                // If the output is provided, copy the input file
                if (output != null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the output file for processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the cart information
                var cart = N3DS.Create(reader);
                if (cart?.Model == null)
                {
                    Console.WriteLine("Error: Not a 3DS cart image!");
                    return false;
                }

                // Decrypt all 8 NCCH partitions
                DecryptAllPartitions(cart, force, reader, writer);
                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {output} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS cart image and try again.");
                return false;
            }
        }

        /// <summary>
        /// Decrypt all partitions in the partition table of an NCSD header
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptAllPartitions(N3DS cart, bool force, Stream reader, Stream writer)
        {
            // Check the partitions table
            if (cart.PartitionsTable == null || cart.Partitions == null)
            {
                Console.WriteLine("Invalid partitions table!");
                return;
            }

            // Iterate over all 8 NCCH partitions
            for (int p = 0; p < 8; p++)
            {
                var partition = cart.Partitions[p];
                if (partition == null || partition.MagicID != NCCHMagicNumber)
                {
                    Console.WriteLine($"Partition {p} Not found... Skipping...");
                    continue;
                }

                // Check the partition has data
                var partitionEntry = cart.PartitionsTable[p];
                if (partitionEntry == null || partitionEntry.Length == 0)
                {
                    Console.WriteLine($"Partition {p} No data... Skipping...");
                    continue;
                }

                // Decrypt the partition, if possible
                if (ShouldDecryptPartition(cart, p, force))
                    DecryptPartition(cart, p, reader, writer);
            }
        }

        /// <summary>
        /// Determine if the current partition should be decrypted
        /// </summary>s
        private static bool ShouldDecryptPartition(N3DS cart, int index, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (cart.PossiblyDecrypted(index))
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptPartition(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Determine the keys needed for this partition
            SetDecryptionKeys(cart, index);

            // Decrypt the parts of the partition
            DecryptExtendedHeader(cart, index, reader, writer);
            DecryptExeFS(cart, index, reader, writer);
            DecryptRomFS(cart, index, reader, writer);

            // Update the flags
            UpdateDecryptCryptoAndMasks(cart, index, writer);
        }

        /// <summary>
        /// Determine the set of keys to be used for decryption
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        private void SetDecryptionKeys(N3DS cart, int index)
        {
            // Get the partition
            var partition = cart.Partitions?[index];
            if (partition?.Flags == null)
                return;

            // Get partition-specific values
            byte[]? rsaSignature = partition.RSA2048Signature;
            BitMasks masks = cart.GetBitMasks(index);
            CryptoMethod method = cart.GetCryptoMethod(index);

            // Get the partition keys
            _keysMap[index] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Decrypt the extended header, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool DecryptExtendedHeader(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Get required offsets
            uint partitionOffset = cart.GetPartitionOffset(index);
            if (partitionOffset == 0 || partitionOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} No Data... Skipping...");
                return false;
            }

            uint extHeaderSize = cart.GetExtendedHeaderSize(index);
            if (extHeaderSize == 0)
            {
                Console.WriteLine($"Partition {index} No Extended Header... Skipping...");
                return false;
            }

            // Seek to the extended header
            reader.Seek(partitionOffset + 0x200, SeekOrigin.Begin);
            writer.Seek(partitionOffset + 0x200, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index}: Decrypting - ExHeader");

            // Create the Plain AES cipher for this partition
            var cipher = CreateAESDecryptionCipher(_keysMap[index].NormalKey2C, cart.PlainIV(index));

            // Process the extended header
            PerformAESOperation(Constants.CXTExtendedDataHeaderLength, cipher, reader, writer, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            reader.Seek(0, SeekOrigin.Begin);
#endif
            writer.Flush();
            return true;
        }

        /// <summary>
        /// Decrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool DecryptExeFS(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Validate the ExeFS
            uint exeFsHeaderOffset = cart.GetExeFSOffset(index);
            if (exeFsHeaderOffset == 0 || exeFsHeaderOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint exeFsSize = cart.GetExeFSSize(index);
            if (exeFsSize == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            // Decrypt the filename table
            DecryptExeFSFilenameTable(cart, index, reader, writer);

            // For all but the original crypto method, process each of the files in the table
            if (cart.GetCryptoMethod(index) != CryptoMethod.Original)
                DecryptExeFSFileEntries(cart, index, reader, writer);

            // Get the ExeFS files offset
            uint exeFsFilesOffset = exeFsHeaderOffset + cart.MediaUnitSize;

            // Seek to the ExeFS
            reader.Seek(exeFsFilesOffset, SeekOrigin.Begin);
            writer.Seek(exeFsFilesOffset, SeekOrigin.Begin);

            // Create the ExeFS AES cipher for this partition
            uint ctroffsetE = cart.MediaUnitSize / 0x10;
            byte[] exefsIVWithOffset = cart.ExeFSIV(index).Add(ctroffsetE);
            var cipher = CreateAESDecryptionCipher(_keysMap[index].NormalKey2C, exefsIVWithOffset);

            // Setup and perform the decryption
            exeFsSize -= cart.MediaUnitSize;
            PerformAESOperation(exeFsSize,
                cipher,
                reader,
                writer,
                (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Decrypting - {s}"));

            return true;
        }

        /// <summary>
        /// Decrypt the ExeFS Filename Table
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptExeFSFilenameTable(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Get ExeFS offset
            uint exeFsOffset = cart.GetExeFSOffset(index);
            if (exeFsOffset == 0 || exeFsOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Seek to the ExeFS header
            reader.Seek(exeFsOffset, SeekOrigin.Begin);
            writer.Seek(exeFsOffset, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index} ExeFS: Decrypting - ExeFS Filename Table");

            // Create the ExeFS AES cipher for this partition
            var cipher = CreateAESDecryptionCipher(_keysMap[index].NormalKey2C, cart.ExeFSIV(index));

            // Process the filename table
            byte[] readBytes = reader.ReadBytes((int)cart.MediaUnitSize);
            byte[] processedBytes = cipher.ProcessBytes(readBytes);
            writer.Write(processedBytes);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            reader.Seek(0, SeekOrigin.Begin);
#endif
            writer.Flush();
        }

        /// <summary>
        /// Decrypt the ExeFS file entries
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptExeFSFileEntries(N3DS cart, int index, Stream reader, Stream writer)
        {
            if (cart.ExeFSHeaders == null || index < 0 || index > cart.ExeFSHeaders.Length)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Reread the decrypted ExeFS header
            uint exeFsHeaderOffset = cart.GetExeFSOffset(index);
            reader.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            cart.ExeFSHeaders[index] = SabreTools.Serialization.Readers.N3DS.ParseExeFSHeader(reader);

            // Get the ExeFS header
            var exeFsHeader = cart.ExeFSHeaders[index];
            if (exeFsHeader?.FileHeaders == null)
            {
                Console.WriteLine($"Partition {index} ExeFS header does not exist. Skipping...");
                return;
            }

            // Get the ExeFS files offset
            uint exeFsFilesOffset = exeFsHeaderOffset + cart.MediaUnitSize;

            // Loop through and process all headers
            for (int i = 0; i < exeFsHeader.FileHeaders.Length; i++)
            {
                // Only attempt to process code binary files
                if (!cart.IsCodeBinary(index, i))
                    continue;

                // Get the file header
                var fileHeader = exeFsHeader.FileHeaders[i];
                if (fileHeader == null)
                    continue;

                // Create the ExeFS AES ciphers for this partition
                uint ctroffset = (fileHeader.FileOffset + cart.MediaUnitSize) / 0x10;
                byte[] exefsIVWithOffsetForHeader = cart.ExeFSIV(index).Add(ctroffset);
                var firstCipher = CreateAESDecryptionCipher(_keysMap[index].NormalKey, exefsIVWithOffsetForHeader);
                var secondCipher = CreateAESEncryptionCipher(_keysMap[index].NormalKey2C, exefsIVWithOffsetForHeader);

                // Seek to the file entry
                reader.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                writer.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Setup and perform the encryption
                PerformAESOperation(fileHeader.FileSize,
                    firstCipher,
                    secondCipher,
                    reader,
                    writer,
                    (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Decrypting - {fileHeader.FileName}...{s}"));
            }
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool DecryptRomFS(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Validate the RomFS
            uint romFsOffset = cart.GetRomFSOffset(index);
            if (romFsOffset == 0 || romFsOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            uint romFsSize = cart.GetRomFSSize(index);
            if (romFsSize == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            // Seek to the RomFS
            reader.Seek(romFsOffset, SeekOrigin.Begin);
            writer.Seek(romFsOffset, SeekOrigin.Begin);

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESDecryptionCipher(_keysMap[index].NormalKey, cart.RomFSIV(index));

            // Setup and perform the decryption
            PerformAESOperation(romFsSize,
                cipher,
                reader,
                writer,
                (string s) => Console.WriteLine($"\rPartition {index} RomFS: Decrypting - {s}"));

            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="writer">Stream representing the output</param>
        private static void UpdateDecryptCryptoAndMasks(N3DS cart, int index, Stream writer)
        {
            // Get required offsets
            uint partitionOffset = cart.GetPartitionOffset(index);

            // Seek to the CryptoMethod location
            writer.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            writer.Write((byte)CryptoMethod.Original);
            writer.Flush();

            // Seek to the BitMasks location
            writer.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.GetBitMasks(index);
            flag &= (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
            flag |= BitMasks.NoCrypto;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion

        #region Encrypt

        /// <inheritdoc/>
        public bool EncryptFile(string input, string? output, bool force)
        {
            // Ensure the constants are all set
            if (_decryptArgs.IsReady != true)
            {
                Console.WriteLine("Could not read keys. Please make sure the file exists and try again.");
                return false;
            }

            try
            {
                // If the output is provided, copy the input file
                if (output != null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the output file for processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the cart information
                var cart = N3DS.Create(reader);
                if (cart?.Model == null)
                {
                    Console.WriteLine("Error: Not a 3DS cart image!");
                    return false;
                }

                // Encrypt all 8 NCCH partitions
                EncryptAllPartitions(cart, force, reader, writer);
                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {output} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS cart image and try again.");
                return false;
            }
        }

        /// <summary>
        /// Encrypt all partitions in the partition table of an NCSD header
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptAllPartitions(N3DS cart, bool force, Stream reader, Stream writer)
        {
            // Check the partitions table
            if (cart.PartitionsTable == null || cart.Partitions == null)
            {
                Console.WriteLine("Invalid partitions table!");
                return;
            }

            // Iterate over all 8 NCCH partitions
            for (int p = 0; p < 8; p++)
            {
                // Check the partition exists
                var partition = cart.Partitions[p];
                if (partition == null || partition.MagicID != NCCHMagicNumber)
                {
                    Console.WriteLine($"Partition {p} Not found... Skipping...");
                    continue;
                }

                // Check the partition has data
                var partitionEntry = cart.PartitionsTable[p];
                if (partitionEntry == null || partitionEntry.Length == 0)
                {
                    Console.WriteLine($"Partition {p} No data... Skipping...");
                    continue;
                }

                // Encrypt the partition, if possible
                if (ShouldEncryptPartition(cart, p, force))
                    EncryptPartition(cart, p, reader, writer);
            }
        }

        /// <summary>
        /// Determine if the current partition should be encrypted
        /// </summary>
        private static bool ShouldEncryptPartition(N3DS cart, int index, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (!cart.PossiblyDecrypted(index))
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptPartition(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Determine the keys needed for this partition
            SetEncryptionKeys(cart, index);

            // Encrypt the parts of the partition
            EncryptExtendedHeader(cart, index, reader, writer);
            EncryptExeFS(cart, index, reader, writer);
            EncryptRomFS(cart, index, reader, writer);

            // Update the flags
            UpdateEncryptCryptoAndMasks(cart, index, writer);
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        private void SetEncryptionKeys(N3DS cart, int index)
        {
            // Get the partition
            var partition = cart.Partitions?[index];
            if (partition == null)
                return;

            // Get the backup header
            var backupHeader = cart.BackupHeader;
            if (backupHeader?.Flags == null)
                return;

            // Get partition-specific values
            byte[]? rsaSignature = partition.RSA2048Signature;
            BitMasks masks = backupHeader.Flags.BitMasks;
            CryptoMethod method = backupHeader.Flags.CryptoMethod;

            // Get the partition keys
            _keysMap[index] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Encrypt the extended header, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool EncryptExtendedHeader(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Get required offsets
            uint partitionOffset = cart.GetPartitionOffset(index);
            if (partitionOffset == 0 || partitionOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} No Data... Skipping...");
                return false;
            }

            uint extHeaderSize = cart.GetExtendedHeaderSize(index);
            if (extHeaderSize == 0)
            {
                Console.WriteLine($"Partition {index} No Extended Header... Skipping...");
                return false;
            }

            // Seek to the extended header
            reader.Seek(partitionOffset + 0x200, SeekOrigin.Begin);
            writer.Seek(partitionOffset + 0x200, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index}: Encrypting - ExHeader");

            // Create the Plain AES cipher for this partition
            var cipher = CreateAESEncryptionCipher(_keysMap[index].NormalKey2C, cart.PlainIV(index));

            // Process the extended header
            PerformAESOperation(Constants.CXTExtendedDataHeaderLength, cipher, reader, writer, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            reader.Seek(0, SeekOrigin.Begin);
#endif
            writer.Flush();
            return true;
        }

        /// <summary>
        /// Encrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool EncryptExeFS(N3DS cart, int index, Stream reader, Stream writer)
        {
            if (cart.ExeFSHeaders == null || index < 0 || index > cart.ExeFSHeaders.Length)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            // Get the ExeFS header
            var exefsHeader = cart.ExeFSHeaders[index];
            if (exefsHeader == null)
            {
                Console.WriteLine($"Partition {index} ExeFS header does not exist. Skipping...");
                return false;
            }

            // For all but the original crypto method, process each of the files in the table
            var backupHeader = cart.BackupHeader;
            if (backupHeader!.Flags!.CryptoMethod != CryptoMethod.Original)
                EncryptExeFSFileEntries(cart, index, reader, writer);

            // Encrypt the filename table
            EncryptExeFSFilenameTable(cart, index, reader, writer);

            // Get the ExeFS files offset
            uint exeFsHeaderOffset = cart.GetExeFSOffset(index);
            uint exeFsFilesOffset = exeFsHeaderOffset + cart.MediaUnitSize;

            // Seek to the ExeFS
            reader.Seek(exeFsFilesOffset, SeekOrigin.Begin);
            writer.Seek(exeFsFilesOffset, SeekOrigin.Begin);

            // Create the ExeFS AES cipher for this partition
            uint ctroffsetE = cart.MediaUnitSize / 0x10;
            byte[] exefsIVWithOffset = cart.ExeFSIV(index).Add(ctroffsetE);
            var cipher = CreateAESEncryptionCipher(_keysMap[index].NormalKey2C, exefsIVWithOffset);

            // Setup and perform the encryption
            uint exeFsSize = cart.GetExeFSSize(index) - cart.MediaUnitSize;
            PerformAESOperation(exeFsSize,
                cipher,
                reader,
                writer,
                (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Encrypting - {s}"));

            return true;
        }

        /// <summary>
        /// Encrypt the ExeFS Filename Table
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptExeFSFilenameTable(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Get ExeFS offset
            uint exeFsOffset = cart.GetExeFSOffset(index);
            if (exeFsOffset == 0 || exeFsOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Seek to the ExeFS header
            reader.Seek(exeFsOffset, SeekOrigin.Begin);
            writer.Seek(exeFsOffset, SeekOrigin.Begin);

            Console.WriteLine($"Partition {index} ExeFS: Encrypting - ExeFS Filename Table");

            // Create the ExeFS AES cipher for this partition
            var cipher = CreateAESEncryptionCipher(_keysMap[index].NormalKey2C, cart.ExeFSIV(index));

            // Process the filename table
            byte[] readBytes = reader.ReadBytes((int)cart.MediaUnitSize);
            byte[] processedBytes = cipher.ProcessBytes(readBytes);
            writer.Write(processedBytes);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            reader.Seek(0, SeekOrigin.Begin);
#endif
            writer.Flush();
        }

        /// <summary>
        /// Encrypt the ExeFS file entries
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptExeFSFileEntries(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Get ExeFS offset
            uint exeFsHeaderOffset = cart.GetExeFSOffset(index);
            if (exeFsHeaderOffset == 0 || exeFsHeaderOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Get to the start of the files
            uint exeFsFilesOffset = exeFsHeaderOffset + cart.MediaUnitSize;

            // If the header failed to read, log and return
            var exeFsHeader = cart.ExeFSHeaders?[index];
            if (exeFsHeader?.FileHeaders == null)
            {
                Console.WriteLine($"Partition {index} ExeFS header does not exist. Skipping...");
                return;
            }

            // Loop through and process all headers
            for (int i = 0; i < exeFsHeader.FileHeaders.Length; i++)
            {
                // Only attempt to process code binary files
                if (!cart.IsCodeBinary(index, i))
                    continue;

                // Get the file header
                var fileHeader = exeFsHeader.FileHeaders[i];
                if (fileHeader == null)
                    continue;

                // Create the ExeFS AES ciphers for this partition
                uint ctroffset = (fileHeader.FileOffset + cart.MediaUnitSize) / 0x10;
                byte[] exefsIVWithOffsetForHeader = cart.ExeFSIV(index).Add(ctroffset);
                var firstCipher = CreateAESEncryptionCipher(_keysMap[index].NormalKey, exefsIVWithOffsetForHeader);
                var secondCipher = CreateAESDecryptionCipher(_keysMap[index].NormalKey2C, exefsIVWithOffsetForHeader);

                // Seek to the file entry
                reader.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                writer.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Setup and perform the encryption
                PerformAESOperation(fileHeader.FileSize,
                    firstCipher,
                    secondCipher,
                    reader,
                    writer,
                    (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Encrypting - {fileHeader.FileName}...{s}"));
            }
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool EncryptRomFS(N3DS cart, int index, Stream reader, Stream writer)
        {
            // Validate the RomFS
            uint romFsOffset = cart.GetRomFSOffset(index);
            if (romFsOffset == 0 || romFsOffset > reader.Length)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            uint romFsSize = cart.GetRomFSSize(index);
            if (romFsSize == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            // Seek to the RomFS
            reader.Seek(romFsOffset, SeekOrigin.Begin);
            writer.Seek(romFsOffset, SeekOrigin.Begin);

            // Force setting encryption keys for partitions 1 and above
            if (index > 0)
            {
                var backupHeader = cart.BackupHeader;
                _keysMap[index].SetRomFSValues(backupHeader!.Flags!.BitMasks);
            }

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESEncryptionCipher(_keysMap[index].NormalKey, cart.RomFSIV(index));

            // Setup and perform the decryption
            PerformAESOperation(romFsSize,
                cipher,
                reader,
                writer,
                (string s) => Console.WriteLine($"\rPartition {index} RomFS: Encrypting - {s}"));

            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="writer">Stream representing the output</param>
        private static void UpdateEncryptCryptoAndMasks(N3DS cart, int index, Stream writer)
        {
            // Get required offsets
            uint partitionOffset = cart.GetPartitionOffset(index);

            // Get the backup header
            var backupHeader = cart.BackupHeader;
            if (backupHeader?.Flags == null)
                return;

            // Seek to the CryptoMethod location
            writer.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            // - For partitions 1 and up, set crypto-method to 0x00
            // - If partition 0, restore crypto-method from backup flags
            byte cryptoMethod = index > 0 ? (byte)CryptoMethod.Original : (byte)backupHeader.Flags.CryptoMethod;
            writer.Write(cryptoMethod);
            writer.Flush();

            // Seek to the BitMasks location
            writer.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.GetBitMasks(index);
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;
            flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & backupHeader.Flags.BitMasks;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion

        #region Info

        /// <inheritdoc/>
        public string? GetInformation(string filename)
        {
            try
            {
                // Open the file for reading
                using var input = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                // Deserialize the cart information
                var cart = N3DS.Create(input);
                if (cart?.Model == null)
                    return "Error: Not a 3DS cart image!";

                // Get a string builder for the status
                var sb = new StringBuilder();

                // Iterate over all 8 NCCH partitions
                for (int p = 0; p < 8; p++)
                {
                    bool decrypted = cart.PossiblyDecrypted(p);
                    sb.AppendLine($"\tPartition {p}: {(decrypted ? "Decrypted" : "Encrypted")}");
                }

                // Return the status for all partitions
                return sb.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return null;
            }
        }

        #endregion
    }
}

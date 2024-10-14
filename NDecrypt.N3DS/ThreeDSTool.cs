using System;
using System.IO;
using NDecrypt.Core;
using SabreTools.IO.Extensions;
using SabreTools.Models.N3DS;
using static NDecrypt.N3DS.CommonOperations;
using N3DSDeserializer = SabreTools.Serialization.Deserializers.N3DS;

namespace NDecrypt.N3DS
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
        private readonly PartitionKeys[] KeysMap = new PartitionKeys[8];

        public ThreeDSTool(bool development, DecryptArgs decryptArgs)
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

                // Deserialize the cart information
                var cart = N3DSDeserializer.DeserializeStream(input);
                if (cart?.Header == null || cart?.CardInfoHeader?.InitialData?.BackupHeader == null)
                {
                    Console.WriteLine("Error: Not a 3DS cart image!");
                    return false;
                }

                // Process all 8 NCCH partitions
                if (encrypt) EncryptAllPartitions(cart, force, input, output);
                else         DecryptAllPartitions(cart, force, input, output);

                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS cart image and try again.");
                return false;
            }
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypt all partitions in the partition table of an NCSD header
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptAllPartitions(Cart cart, bool force, Stream input, Stream output)
        {
            // Check the partitions table
            if (cart.Header?.PartitionsTable == null || cart.Partitions == null)
            {
                Console.WriteLine("Invalid partitions table!");
                return;
            }

            // Iterate over all 8 NCCH partitions
            for (int p = 0; p < 8; p++)
            {
                // Check the partition exists
                if (cart.Partitions[p] == null)
                {
                    Console.WriteLine($"Partition {p} Not found... Skipping...");
                    continue;
                }

                // Decrypt the partition, if possible
                if (ShouldDecryptPartition(cart, p, force))
                    DecryptPartition(cart, p, input, output);
            }
        }

        /// <summary>
        /// Determine if the current partition should be decrypted
        /// </summary>s
        private static bool ShouldDecryptPartition(Cart cart, int index, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (cart.Partitions![index]!.Flags!.PossblyDecrypted())
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
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptPartition(Cart cart, int index, Stream input, Stream output)
        {
            // Determine the keys needed for this partition
            SetDecryptionKeys(cart, index);

            // Decrypt the parts of the partition
            DecryptExtendedHeader(cart, index, input, output);
            DecryptExeFS(cart, index, input, output);
            DecryptRomFS(cart, index, input, output);

            // Update the flags
            UpdateDecryptCryptoAndMasks(cart, index, output);
        }

        /// <summary>
        /// Determine the set of keys to be used for decryption
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        private void SetDecryptionKeys(Cart cart, int index)
        {
            // Get the partition
            var partition = cart.Partitions?[index];
            if (partition == null)
                return;

            // Get partition-specific values
            byte[]? rsaSignature = partition.RSA2048Signature;

            // Set the header to use based on mode
            BitMasks masks = partition.Flags!.BitMasks;
            CryptoMethod method = partition.Flags!.CryptoMethod;

            // Get the partition keys
            KeysMap[index] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Decrypt the extended header, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool DecryptExtendedHeader(Cart cart, int index, Stream input, Stream output)
        {
            // Get required offsets
            uint partitionOffset = GetPartitionOffset(cart, index);
            if (partitionOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint extHeaderSize = GetExtendedHeaderSize(cart, index);
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
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, cart.PlainIV(index));

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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool DecryptExeFS(Cart cart, int index, Stream input, Stream output)
        {
            // Validate the ExeFS
            uint exeFsOffset = GetExeFSOffset(cart, index);
            if (exeFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint exeFsSize = GetExeFSSize(cart, index);
            if (exeFsSize == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            // Decrypt the filename table
            DecryptExeFSFilenameTable(cart, index, input, output);

            // For all but the original crypto method, process each of the files in the table
            if (cart.Partitions![index]!.Flags!.CryptoMethod != CryptoMethod.Original)
                DecryptExeFSFileEntries(cart, index, input, output);

            // Seek to the ExeFS
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            // Create the ExeFS AES cipher for this partition
            int ctroffsetE = (int)(cart.MediaUnitSize() / 0x10);
            byte[] exefsIVWithOffset = AddToByteArray(cart.ExeFSIV(index), ctroffsetE);
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffset);

            // Setup and perform the decryption
            PerformAESOperation(exeFsSize,
                cipher,
                input,
                output,
                (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Decrypting: {s}"));

            return true;
        }

        /// <summary>
        /// Decrypt the ExeFS Filename Table
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptExeFSFilenameTable(Cart cart, int index, Stream input, Stream output)
        {
            // Get ExeFS offset
            uint exeFsOffset = GetExeFSOffset(cart, index);
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
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, cart.ExeFSIV(index));

            // Process the filename table
            PerformAESOperation(cart.MediaUnitSize(), cipher, input, output, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
        }

        /// <summary>
        /// Decrypt the ExeFS file entries
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptExeFSFileEntries(Cart cart, int index, Stream input, Stream output)
        {
            // Get ExeFS offset
            uint exeFsHeaderOffset = GetExeFSOffset(cart, index);
            if (exeFsHeaderOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Get to the start of the files
            uint exeFsFilesOffset = exeFsHeaderOffset + cart.MediaUnitSize();
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
                uint ctroffset = (fileHeader.FileOffset + cart.MediaUnitSize()) / 0x10;
                byte[] exefsIVWithOffsetForHeader = AddToByteArray(cart.ExeFSIV(index), (int)ctroffset);
                var firstCipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey, exefsIVWithOffsetForHeader);
                var secondCipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffsetForHeader);

                // Seek to the file entry
                input.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                output.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Setup and perform the encryption
                uint exeFsSize = GetExeFSSize(cart, index);
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool DecryptRomFS(Cart cart, int index, Stream input, Stream output)
        {
            // Validate the RomFS
            uint romFsOffset = GetRomFSOffset(cart, index);
            if (romFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            uint romFsSize = GetRomFSSize(cart, index);
            if (romFsSize == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            // Seek to the RomFS
            input.Seek(romFsOffset, SeekOrigin.Begin);
            output.Seek(romFsOffset, SeekOrigin.Begin);

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey, cart.RomFSIV(index));

            // Setup and perform the decryption
            PerformAESOperation(romFsSize,
                cipher,
                input,
                output,
                (string s) => Console.WriteLine($"\rPartition {index} RomFS: Decrypting: {s}"));

            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="output">Stream representing the output</param>
        private static void UpdateDecryptCryptoAndMasks(Cart cart, int index, Stream output)
        {
            // Get required offsets
            uint partitionOffset = GetPartitionOffset(cart, index);

            // Seek to the CryptoMethod location
            output.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            output.Write((byte)CryptoMethod.Original);
            output.Flush();

            // Seek to the BitMasks location
            output.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.Partitions![index]!.Flags!.BitMasks;
            flag &= (BitMasks)((byte)(BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) ^ 0xFF);
            flag |= BitMasks.NoCrypto;
            output.Write((byte)flag);
            output.Flush();
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Encrypt all partitions in the partition table of an NCSD header
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptAllPartitions(Cart cart, bool force, Stream input, Stream output)
        {
            // Check the partitions table
            if (cart.Header?.PartitionsTable == null || cart.Partitions == null)
            {
                Console.WriteLine("Invalid partitions table!");
                return;
            }

            // Iterate over all 8 NCCH partitions
            for (int p = 0; p < 8; p++)
            {
                // Check the partition exists
                if (cart.Partitions[p] == null)
                {
                    Console.WriteLine($"Partition {p} Not found... Skipping...");
                    continue;
                }

                // Encrypt the partition, if possible
                if (ShouldEncryptPartition(cart, p, force))
                    EncryptPartition(cart, p, input, output);
            }
        }

        /// <summary>
        /// Determine if the current partition should be encrypted
        /// </summary>
        private static bool ShouldEncryptPartition(Cart cart, int index, bool force)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {index} is not verified due to force flag being set.");
                return true;
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (!cart.Partitions![index]!.Flags!.PossblyDecrypted())
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
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptPartition(Cart cart, int index, Stream input, Stream output)
        {
            // Determine the keys needed for this partition
            SetEncryptionKeys(cart, index);

            // Encrypt the parts of the partition
            EncryptExtendedHeader(cart, index, input, output);
            EncryptExeFS(cart, index, input, output);
            EncryptRomFS(cart, index, input, output);

            // Update the flags
            UpdateEncryptCryptoAndMasks(cart, index, output);
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        private void SetEncryptionKeys(Cart cart, int index)
        {
            // Get the partition
            var partition = cart.Partitions?[index];
            if (partition == null)
                return;

            // Get partition-specific values
            byte[]? rsaSignature = partition.RSA2048Signature;

            // Set the header to use based on mode
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;
            BitMasks masks = backupHeader!.Flags!.BitMasks;
            CryptoMethod method = backupHeader.Flags.CryptoMethod;

            // Get the partition keys
            KeysMap[index] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Encrypt the extended header, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool EncryptExtendedHeader(Cart cart, int index, Stream input, Stream output)
        {
            // Get required offsets
            uint partitionOffset = GetPartitionOffset(cart, index);
            if (partitionOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint extHeaderSize = GetExtendedHeaderSize(cart, index);
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
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, cart.PlainIV(index));

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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool EncryptExeFS(Cart cart, int index, Stream input, Stream output)
        {
            // Validate the ExeFS
            uint exeFsOffset = GetExeFSOffset(cart, index);
            if (exeFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            uint exeFsSize = GetExeFSSize(cart, index);
            if (exeFsSize == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return false;
            }

            // For all but the original crypto method, process each of the files in the table
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;
            if (backupHeader!.Flags!.CryptoMethod != CryptoMethod.Original)
                EncryptExeFSFileEntries(cart, index, input, output);

            // Encrypt the filename table
            EncryptExeFSFilenameTable(cart, index, input, output);

            // Seek to the ExeFS
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            // Create the ExeFS AES cipher for this partition
            int ctroffsetE = (int)(cart.MediaUnitSize() / 0x10);
            byte[] exefsIVWithOffset = AddToByteArray(cart.ExeFSIV(index), ctroffsetE);
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffset);

            // Setup and perform the encryption
            PerformAESOperation(exeFsSize,
                cipher,
                input,
                output,
                (string s) => Console.WriteLine($"\rPartition {index} ExeFS: Encrypting: {s}"));

            return true;
        }

        /// <summary>
        /// Encrypt the ExeFS Filename Table
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptExeFSFilenameTable(Cart cart, int index, Stream input, Stream output)
        {
            // Get ExeFS offset
            uint exeFsOffset = GetExeFSOffset(cart, index);
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
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey2C, cart.ExeFSIV(index));

            // Process the filename table
            PerformAESOperation(cart.MediaUnitSize(), cipher, input, output, null);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
        }

        /// <summary>
        /// Encrypt the ExeFS file entries
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptExeFSFileEntries(Cart cart, int index, Stream input, Stream output)
        {
            // Get ExeFS offset
            uint exeFsHeaderOffset = GetExeFSOffset(cart, index);
            if (exeFsHeaderOffset == 0)
            {
                Console.WriteLine($"Partition {index} ExeFS: No Data... Skipping...");
                return;
            }

            // Get to the start of the files
            uint exeFsFilesOffset = exeFsHeaderOffset + cart.MediaUnitSize();
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
                uint ctroffset = (fileHeader.FileOffset + cart.MediaUnitSize()) / 0x10;
                byte[] exefsIVWithOffsetForHeader = AddToByteArray(cart.ExeFSIV(index), (int)ctroffset);
                var firstCipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey, exefsIVWithOffsetForHeader);
                var secondCipher = CreateAESDecryptionCipher(KeysMap[index].NormalKey2C, exefsIVWithOffsetForHeader);

                // Seek to the file entry
                input.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                output.Seek(exeFsFilesOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Setup and perform the encryption
                uint exeFsSize = GetExeFSSize(cart, index);
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool EncryptRomFS(Cart cart, int index, Stream input, Stream output)
        {
            // Validate the RomFS
            uint romFsOffset = GetRomFSOffset(cart, index);
            if (romFsOffset == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            uint romFsSize = GetRomFSSize(cart, index);
            if (romFsSize == 0)
            {
                Console.WriteLine($"Partition {index} RomFS: No Data... Skipping...");
                return false;
            }

            // Seek to the RomFS
            input.Seek(romFsOffset, SeekOrigin.Begin);
            output.Seek(romFsOffset, SeekOrigin.Begin);

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            if (index > 0)
            {
                // Except if using zero-key
                var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;
                if (backupHeader!.Flags!.BitMasks.HasFlag(BitMasks.FixedCryptoKey))
                {
                    KeysMap[index].NormalKey = 0x00;
                }
                else
                {
                    KeysMap[index].KeyX = (_development ? _decryptArgs.DevKeyX0x2C : _decryptArgs.KeyX0x2C);
                    KeysMap[index].NormalKey = RotateLeft((RotateLeft(KeysMap[index].KeyX, 2, 128) ^ KeysMap[index].KeyY) + _decryptArgs.AESHardwareConstant, 87, 128);
                }
            }

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESEncryptionCipher(KeysMap[index].NormalKey, cart.RomFSIV(index));

            // Setup and perform the decryption
            PerformAESOperation(romFsSize,
                cipher,
                input,
                output,
                (string s) => Console.WriteLine($"\rPartition {index} RomFS: Encrypting: {s}"));

            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="index">Index of the partition</param>
        /// <param name="output">Stream representing the output</param>
        private static void UpdateEncryptCryptoAndMasks(Cart cart, int index, Stream output)
        {
            // Get required offsets
            uint partitionOffset = GetPartitionOffset(cart, index);

            // Get the backup header
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;

            // Seek to the CryptoMethod location
            output.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            // - For partitions 1 and up, set crypto-method to 0x00
            // - If partition 0, restore crypto-method from backup flags
            byte cryptoMethod = index > 0 ? (byte)CryptoMethod.Original : (byte)backupHeader!.Flags!.CryptoMethod;
            output.Write(cryptoMethod);
            output.Flush();

            // Seek to the BitMasks location
            output.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.Partitions![index]!.Flags!.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;
            flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & backupHeader!.Flags!.BitMasks;
            output.Write((byte)flag);
            output.Flush();
        }

        #endregion
    }
}

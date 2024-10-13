using System;
using System.IO;
using NDecrypt.Core;
using SabreTools.IO.Extensions;
using SabreTools.Models.N3DS;
using static NDecrypt.Core.Helper;
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
                ProcessAllPartitions(cart, encrypt, force, input, output);

                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS cart image and try again.");
                return false;
            }
        }

        /// <summary>
        /// Process all partitions in the partition table of an NCSD header
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessAllPartitions(Cart cart,
            bool encrypt,
            bool force,
            Stream input,
            Stream output)
        {
            // Check the partitions table
            if (cart.Header?.PartitionsTable == null)
            {
                Console.WriteLine("Invalid partitions table!");
                return;
            }

            // Iterate over all 8 NCCH partitions
            for (int partitionIndex = 0; partitionIndex < 8; partitionIndex++)
            {
                // Check the partition exists
                if (cart.Partitions![partitionIndex] == null)
                {
                    Console.WriteLine($"Partition {partitionIndex} Not found... Skipping...");
                    continue;
                }

                ProcessPartition(cart, partitionIndex, encrypt, force, input, output);
            }
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessPartition(Cart cart,
            int partitionIndex,
            bool encrypt,
            bool force,
            Stream input,
            Stream output)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine($"Partition {partitionIndex} is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (cart.Partitions![partitionIndex]!.Flags!.PossblyDecrypted() ^ encrypt)
            {
                Console.WriteLine($"Partition {partitionIndex}: Already " + (encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // Determine the Keys to be used
            SetEncryptionKeys(cart, partitionIndex, encrypt);

            // Process the extended header
            ProcessExtendedHeader(cart, partitionIndex, encrypt, input, output);

            // If we're encrypting, encrypt the filesystems and update the flags
            if (encrypt)
            {
                EncryptExeFS(cart, partitionIndex, input, output);
                EncryptRomFS(cart, partitionIndex, input, output);
                UpdateEncryptCryptoAndMasks(cart, partitionIndex, output);
            }

            // If we're decrypting, decrypt the filesystems and update the flags
            else
            {
                DecryptExeFS(cart, partitionIndex, input, output);
                DecryptRomFS(cart, partitionIndex, input, output);
                UpdateDecryptCryptoAndMasks(cart, partitionIndex, output);
            }
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption or decryption
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        private void SetEncryptionKeys(Cart cart, int partitionIndex, bool encrypt)
        {
            // Get the partition
            var partition = cart.Partitions?[partitionIndex];
            if (partition == null)
                return;

            // Get partition-specific values
            byte[]? rsaSignature = partition.RSA2048Signature;

            // Set the header to use based on mode
            BitMasks masks;
            CryptoMethod method;
            if (encrypt)
            {
                var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;
                masks = backupHeader!.Flags!.BitMasks;
                method = backupHeader.Flags.CryptoMethod;
            }
            else
            {
                masks = partition.Flags!.BitMasks;
                method = partition.Flags!.CryptoMethod;
            }

            // Get the partition keys
            KeysMap[partitionIndex] = new PartitionKeys(_decryptArgs, rsaSignature, masks, method, _development);
        }

        /// <summary>
        /// Process the extended header, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool ProcessExtendedHeader(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint partitionOffset = partitionOffsetMU * cart.MediaUnitSize();

            if (cart.Partitions![partitionIndex]!.ExtendedHeaderSizeInBytes > 0)
            {
                // Seek to the extended header
                input.Seek(partitionOffset + 0x200, SeekOrigin.Begin);
                output.Seek(partitionOffset + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                // Create the Plain AES cipher for this partition
                var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, cart.PlainIV(partitionIndex), encrypt);

                // Process the extended header
                byte[] readBytes = input.ReadBytes(Constants.CXTExtendedDataHeaderLength);
                byte[] processedBytes = cipher.ProcessBytes(readBytes);
                output.Write(processedBytes);

#if NET6_0_OR_GREATER
                // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
                input.Seek(0, SeekOrigin.Begin);
#endif
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessExeFSFileEntries(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint exeFsOffsetMU = cart.Partitions![partitionIndex]!.ExeFSOffsetInMediaUnits;
            uint exeFsHeaderOffset = (partitionOffsetMU + exeFsOffsetMU) * cart.MediaUnitSize();
            uint exeFsOffset = (partitionOffsetMU + exeFsOffsetMU + 1) * cart.MediaUnitSize();

            input.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            var exefsHeader = N3DSDeserializer.ParseExeFSHeader(input);

            // If the header failed to read, log and return
            if (exefsHeader == null)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS header could not be read. Skipping...");
                return;
            }

            foreach (var fileHeader in exefsHeader.FileHeaders!)
            {
                // Only decrypt a file if it's a code binary
                if (fileHeader == null || !fileHeader.IsCodeBinary())
                    continue;

                // Get MiB-aligned block count and extra byte count
                uint datalenM = fileHeader.FileSize / (1024 * 1024);
                uint datalenB = fileHeader.FileSize % (1024 * 1024);
                uint ctroffset = (fileHeader.FileOffset + cart.MediaUnitSize()) / 0x10;

                // Create the ExeFS AES ciphers for this partition
                byte[] exefsIVWithOffsetForHeader = AddToByteArray(cart.ExeFSIV(partitionIndex), (int)ctroffset);
                var firstCipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey, exefsIVWithOffsetForHeader, encrypt);
                var secondCipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, exefsIVWithOffsetForHeader, !encrypt);

                // Seek to the file entry
                input.Seek(exeFsOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                output.Seek(exeFsOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Process MiB-aligned data
                if (datalenM > 0)
                {
                    for (int i = 0; i < datalenM; i++)
                    {
                        byte[] readBytes = input.ReadBytes(1024 * 1024);
                        byte[] firstProcessedBytes = firstCipher.ProcessBytes(readBytes);
                        byte[] secondProcessedBytes = secondCipher.ProcessBytes(firstProcessedBytes);
                        output.Write(secondProcessedBytes);
                        output.Flush();
                        Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {i} / {datalenM + 1} mb...");
                    }
                }

                // Process additional data
                if (datalenB > 0)
                {
                    byte[] readBytes = input.ReadBytes((int)datalenB);
                    byte[] firstFinalBytes = firstCipher.DoFinal(readBytes);
                    byte[] secondFinalBytes = secondCipher.DoFinal(firstFinalBytes);
                    output.Write(secondFinalBytes);
                    output.Flush();
                }

                Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
            }
        }

        /// <summary>
        /// Process the ExeFS Filename Table
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void ProcessExeFSFilenameTable(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint exeFsOffsetMU = cart.Partitions![partitionIndex]!.ExeFSOffsetInMediaUnits;
            uint exeFsHeaderOffset = (partitionOffsetMU + exeFsOffsetMU) * cart.MediaUnitSize();

            // Seek to the ExeFS header
            input.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            output.Seek(exeFsHeaderOffset, SeekOrigin.Begin);

            Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            // Create the ExeFS AES cipher for this partition
            var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, cart.ExeFSIV(partitionIndex), encrypt);

            // Process the filename table
            byte[] readBytes = input.ReadBytes((int)cart.MediaUnitSize());
            byte[] processedBytes = cipher.ProcessBytes(readBytes);
            output.Write(processedBytes);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            input.Seek(0, SeekOrigin.Begin);
#endif
            output.Flush();
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private bool ProcessExeFS(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint exeFsOffsetMU = cart.Partitions![partitionIndex]!.ExeFSOffsetInMediaUnits;
            uint exeFsOffset = (partitionOffsetMU + exeFsOffsetMU + 1) * cart.MediaUnitSize();

            // If the RomFS offset is 0, we log and return
            if (exeFsOffsetMU == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return false;
            }

            // Get MiB-aligned block count and extra byte count
            uint exeFsSize = (cart.Partitions![partitionIndex]!.ExeFSSizeInMediaUnits - 1) * cart.MediaUnitSize();
            int exefsSizeM = (int)((long)exeFsSize / (1024 * 1024));
            int exefsSizeB = (int)((long)exeFsSize % (1024 * 1024));
            int ctroffsetE = (int)(cart.MediaUnitSize() / 0x10);

            // Create the ExeFS AES cipher for this partition
            byte[] exefsIVWithOffset = AddToByteArray(cart.ExeFSIV(partitionIndex), ctroffsetE);
            var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey2C, exefsIVWithOffset, encrypt);

            // Seek to the ExeFS
            input.Seek(exeFsOffset, SeekOrigin.Begin);
            output.Seek(exeFsOffset, SeekOrigin.Begin);

            // Process MiB-aligned data
            if (exefsSizeM > 0)
            {
                for (int i = 0; i < exefsSizeM; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    output.Write(processedBytes);
                    output.Flush();
                    Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                }
            }

            // Process additional data
            if (exefsSizeB > 0)
            {
                byte[] readBytes = input.ReadBytes(exefsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                output.Write(finalBytes);
                output.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
            return true;
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void DecryptExeFS(Cart cart,
            int partitionIndex,
            Stream input,
            Stream output)
        {
            // If the ExeFS size is 0, we log and return
            if (cart.Partitions![partitionIndex]!.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // Decrypt the filename table
            ProcessExeFSFilenameTable(cart, partitionIndex, encrypt: false, input, output);

            // For all but the original crypto method, process each of the files in the table
            if (cart.Partitions![partitionIndex]!.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(cart, partitionIndex, encrypt: false, input, output);

            // Decrypt the rest of the ExeFS
            ProcessExeFS(cart, partitionIndex, encrypt: false, input, output);
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Encrypt
        private bool DecryptRomFS(Cart cart,
            int partitionIndex,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint romFsOffsetMU = cart.Partitions![partitionIndex]!.RomFSOffsetInMediaUnits;
            uint romFsOffset = (partitionOffsetMU + romFsOffsetMU) * cart.MediaUnitSize();

            // If the RomFS offset is 0, we log and return
            if (romFsOffsetMU == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return false;
            }

            // Get MiB-aligned block count and extra byte count
            uint romFsSize = cart.Partitions![partitionIndex]!.RomFSSizeInMediaUnits * cart.MediaUnitSize();
            long romfsSizeM = (int)((long)romFsSize / (1024 * 1024));
            int romfsSizeB = (int)((long)romFsSize % (1024 * 1024));

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey, cart.RomFSIV(partitionIndex), encrypt: false);

            // Seek to the RomFS
            input.Seek(romFsOffset, SeekOrigin.Begin);
            output.Seek(romFsOffset, SeekOrigin.Begin);

            // Process MiB-aligned data
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    output.Write(processedBytes);
                    output.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                }
            }

            // Process additional data
            if (romfsSizeB > 0)
            {
                byte[] readBytes = input.ReadBytes(romfsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                output.Write(finalBytes);
                output.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="output">Stream representing the output</param>
        private static void UpdateDecryptCryptoAndMasks(Cart cart, int partitionIndex, Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint partitionOffset = partitionOffsetMU * cart.MediaUnitSize();

            // Seek to the CryptoMethod location
            output.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            output.Write((byte)CryptoMethod.Original);
            output.Flush();

            // Seek to the BitMasks location
            output.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.Partitions![partitionIndex]!.Flags!.BitMasks;
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        private void EncryptExeFS(Cart cart,
            int partitionIndex,
            Stream input,
            Stream output)
        {
            // If the ExeFS size is 0, we log and return
            if (cart.Partitions![partitionIndex]!.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // Get the backup header
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;

            // For all but the original crypto method, process each of the files in the table
            if (backupHeader!.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(cart, partitionIndex, encrypt: true, input, output);

            // Encrypt the filename table
            ProcessExeFSFilenameTable(cart, partitionIndex, encrypt: true, input, output);

            // Encrypt the rest of the ExeFS
            ProcessExeFS(cart, partitionIndex, encrypt: true, input, output);
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="input">Stream representing the input</param>
        /// <param name="output">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Decrypt
        private bool EncryptRomFS(Cart cart,
            int partitionIndex,
            Stream input,
            Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint romFsOffsetMU = cart.Partitions![partitionIndex]!.RomFSOffsetInMediaUnits;
            uint romFsOffset = (partitionOffsetMU + romFsOffsetMU) * cart.MediaUnitSize();

            // Get the backup header
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;

            // If the RomFS offset is 0, we log and return
            if (romFsOffsetMU == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return false;
            }

            // Get MiB-aligned block count and extra byte count
            uint romFsSize = cart.Partitions![partitionIndex]!.RomFSSizeInMediaUnits * cart.MediaUnitSize();
            long romfsSizeM = (int)((long)romFsSize / (1024 * 1024));
            int romfsSizeB = (int)((long)romFsSize % (1024 * 1024));

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            if (partitionIndex > 0)
            {
                // Except if using zero-key
                if (backupHeader!.Flags!.BitMasks.HasFlag(BitMasks.FixedCryptoKey))
                {
                    KeysMap[partitionIndex].NormalKey = 0x00;
                }
                else
                {
                    KeysMap[partitionIndex].KeyX = (_development ? _decryptArgs.DevKeyX0x2C : _decryptArgs.KeyX0x2C);
                    KeysMap[partitionIndex].NormalKey = RotateLeft((RotateLeft(KeysMap[partitionIndex].KeyX, 2, 128) ^ KeysMap[partitionIndex].KeyY) + _decryptArgs.AESHardwareConstant, 87, 128);
                }
            }

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESCipher(KeysMap[partitionIndex].NormalKey, cart.RomFSIV(partitionIndex), encrypt: true);

            // Seek to the RomFS
            input.Seek(romFsOffset, SeekOrigin.Begin);
            output.Seek(romFsOffset, SeekOrigin.Begin);

            // Process MiB-aligned data
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    output.Write(processedBytes);
                    output.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {i} / {romfsSizeM + 1} mb");
                }
            }

            // Process additional data
            if (romfsSizeB > 0)
            {
                byte[] readBytes = input.ReadBytes(romfsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                output.Write(finalBytes);
                output.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="output">Stream representing the output</param>
        private static void UpdateEncryptCryptoAndMasks(Cart cart, int partitionIndex, Stream output)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint partitionOffset = partitionOffsetMU * cart.MediaUnitSize();

            // Get the backup header
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;

            // Seek to the CryptoMethod location
            output.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            // - For partitions 1 and up, set crypto-method to 0x00
            // - If partition 0, restore crypto-method from backup flags
            byte cryptoMethod = partitionIndex > 0 ? (byte)CryptoMethod.Original : (byte)backupHeader!.Flags!.CryptoMethod;
            output.Write(cryptoMethod);
            output.Flush();

            // Seek to the BitMasks location
            output.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.Partitions![partitionIndex]!.Flags!.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;
            flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & backupHeader!.Flags!.BitMasks;
            output.Write((byte)flag);
            output.Flush();
        }

        #endregion
    }
}

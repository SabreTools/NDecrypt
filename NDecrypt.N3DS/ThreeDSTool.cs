using System;
using System.IO;
using System.Linq;
using System.Numerics;
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

        public ThreeDSTool(DecryptArgs decryptArgs)
        {
            this.decryptArgs = decryptArgs;
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

                // Deserialize the cart information
                var cart = N3DSDeserializer.DeserializeStream(reader);
                if (cart?.Header == null || cart?.CardInfoHeader?.InitialData?.BackupHeader == null)
                {
                    Console.WriteLine("Error: Not a 3DS cart image!");
                    return false;
                }

                // Process all 8 NCCH partitions
                ProcessAllPartitions(cart, encrypt, force, reader, writer);

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
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessAllPartitions(Cart cart,
            bool encrypt,
            bool force,
            Stream reader,
            Stream writer)
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

                ProcessPartition(cart, partitionIndex, encrypt, force, reader, writer);
            }
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessPartition(Cart cart,
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
            else if (cart.Partitions![partitionIndex]!.Flags!.PossblyDecrypted() ^ encrypt)
            {
                Console.WriteLine($"Partition {partitionIndex}: Already " + (encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // Determine the Keys to be used
            SetEncryptionKeys(cart, partitionIndex, encrypt);

            // Process the extended header
            ProcessExtendedHeader(cart, partitionIndex, encrypt, reader, writer);

            // If we're encrypting, encrypt the filesystems and update the flags
            if (encrypt)
            {
                EncryptExeFS(cart, partitionIndex, reader, writer);
                EncryptRomFS(cart, partitionIndex, reader, writer);
                UpdateEncryptCryptoAndMasks(cart, partitionIndex, writer);
            }

            // If we're decrypting, decrypt the filesystems and update the flags
            else
            {
                DecryptExeFS(cart, partitionIndex, reader, writer);
                DecryptRomFS(cart, partitionIndex, reader, writer);
                UpdateDecryptCryptoAndMasks(cart, partitionIndex, writer);
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
            // Get the backup header
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;

            KeyX[partitionIndex] = 0;
            KeyX2C[partitionIndex] = decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C;

            // Backup headers can't have a KeyY value set
            byte[]? rsaSignature = cart.Partitions![partitionIndex]!.RSA2048Signature;
            if (rsaSignature != null)
                KeyY[partitionIndex] = new BigInteger(rsaSignature.Take(16).Reverse().ToArray());
            else
                KeyY[partitionIndex] = new BigInteger(0);

            NormalKey[partitionIndex] = 0x00;
            NormalKey2C[partitionIndex] = RotateLeft((RotateLeft(KeyX2C[partitionIndex], 2, 128) ^ KeyY[partitionIndex]) + decryptArgs.AESHardwareConstant, 87, 128);

            // Set the header to use based on mode
            BitMasks masks;
            CryptoMethod method;
            if (encrypt)
            {
                masks = backupHeader!.Flags!.BitMasks;
                method = backupHeader.Flags.CryptoMethod;
            }
            else
            {
                masks = cart.Partitions![partitionIndex]!.Flags!.BitMasks;
                method = cart.Partitions![partitionIndex]!.Flags!.CryptoMethod;
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool ProcessExtendedHeader(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint partitionOffset = partitionOffsetMU * cart.MediaUnitSize();

            if (cart.Partitions![partitionIndex]!.ExtendedHeaderSizeInBytes > 0)
            {
                // Seek to the extended header
                reader.Seek(partitionOffset + 0x200, SeekOrigin.Begin);
                writer.Seek(partitionOffset + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                // Create the Plain AES cipher for this partition
                var cipher = CreateAESCipher(NormalKey2C[partitionIndex], cart.PlainIV(partitionIndex), encrypt);

                // Process the extended header
                byte[] readBytes = reader.ReadBytes(Constants.CXTExtendedDataHeaderLength);
                byte[] processedBytes = cipher.ProcessBytes(readBytes);
                writer.Write(processedBytes);

#if NET6_0_OR_GREATER
                // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
                reader.Seek(0, SeekOrigin.Begin);
#endif
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessExeFSFileEntries(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint exeFsOffsetMU = cart.Partitions![partitionIndex]!.ExeFSOffsetInMediaUnits;
            uint exeFsHeaderOffset = (partitionOffsetMU + exeFsOffsetMU) * cart.MediaUnitSize();
            uint exeFsOffset = (partitionOffsetMU + exeFsOffsetMU + 1) * cart.MediaUnitSize();

            reader.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            var exefsHeader = N3DSDeserializer.ParseExeFSHeader(reader);

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
                var firstCipher = CreateAESCipher(NormalKey[partitionIndex], exefsIVWithOffsetForHeader, encrypt);
                var secondCipher = CreateAESCipher(NormalKey2C[partitionIndex], exefsIVWithOffsetForHeader, !encrypt);

                // Seek to the file entry
                reader.Seek(exeFsOffset + fileHeader.FileOffset, SeekOrigin.Begin);
                writer.Seek(exeFsOffset + fileHeader.FileOffset, SeekOrigin.Begin);

                // Process MiB-aligned data
                if (datalenM > 0)
                {
                    for (int i = 0; i < datalenM; i++)
                    {
                        byte[] readBytes = reader.ReadBytes(1024 * 1024);
                        byte[] firstProcessedBytes = firstCipher.ProcessBytes(readBytes);
                        byte[] secondProcessedBytes = secondCipher.ProcessBytes(firstProcessedBytes);
                        writer.Write(secondProcessedBytes);
                        writer.Flush();
                        Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {i} / {datalenM + 1} mb...");
                    }
                }

                // Process additional data
                if (datalenB > 0)
                {
                    byte[] readBytes = reader.ReadBytes((int)datalenB);
                    byte[] firstFinalBytes = firstCipher.DoFinal(readBytes);
                    byte[] secondFinalBytes = secondCipher.DoFinal(firstFinalBytes);
                    writer.Write(secondFinalBytes);
                    writer.Flush();
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
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void ProcessExeFSFilenameTable(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream reader,
            Stream writer)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint exeFsOffsetMU = cart.Partitions![partitionIndex]!.ExeFSOffsetInMediaUnits;
            uint exeFsHeaderOffset = (partitionOffsetMU + exeFsOffsetMU) * cart.MediaUnitSize();

            // Seek to the ExeFS header
            reader.Seek(exeFsHeaderOffset, SeekOrigin.Begin);
            writer.Seek(exeFsHeaderOffset, SeekOrigin.Begin);

            Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            // Create the ExeFS AES cipher for this partition
            var cipher = CreateAESCipher(NormalKey2C[partitionIndex], cart.ExeFSIV(partitionIndex), encrypt);

            // Process the filename table
            byte[] readBytes = reader.ReadBytes((int)cart.MediaUnitSize());
            byte[] processedBytes = cipher.ProcessBytes(readBytes);
            writer.Write(processedBytes);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            reader.Seek(0, SeekOrigin.Begin);
#endif
            writer.Flush();
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private bool ProcessExeFS(Cart cart,
            int partitionIndex,
            bool encrypt,
            Stream reader,
            Stream writer)
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
            var cipher = CreateAESCipher(NormalKey2C[partitionIndex], exefsIVWithOffset, encrypt);

            // Seek to the ExeFS
            reader.Seek(exeFsOffset, SeekOrigin.Begin);
            writer.Seek(exeFsOffset, SeekOrigin.Begin);

            // Process MiB-aligned data
            if (exefsSizeM > 0)
            {
                for (int i = 0; i < exefsSizeM; i++)
                {
                    byte[] readBytes = reader.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    writer.Write(processedBytes);
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} ExeFS: " + (encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                }
            }

            // Process additional data
            if (exefsSizeB > 0)
            {
                byte[] readBytes = reader.ReadBytes(exefsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                writer.Write(finalBytes);
                writer.Flush();
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
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptExeFS(Cart cart,
            int partitionIndex,
            Stream reader,
            Stream writer)
        {
            // If the ExeFS size is 0, we log and return
            if (cart.Partitions![partitionIndex]!.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // Decrypt the filename table
            ProcessExeFSFilenameTable(cart, partitionIndex, encrypt: false, reader, writer);

            // For all but the original crypto method, process each of the files in the table
            if (cart.Partitions![partitionIndex]!.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(cart, partitionIndex, encrypt: false, reader, writer);

            // Decrypt the rest of the ExeFS
            ProcessExeFS(cart, partitionIndex, encrypt: false, reader, writer);
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Encrypt
        private bool DecryptRomFS(Cart cart,
            int partitionIndex,
            Stream reader,
            Stream writer)
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
            var cipher = CreateAESCipher(NormalKey[partitionIndex], cart.RomFSIV(partitionIndex), encrypt: false);

            // Seek to the RomFS
            reader.Seek(romFsOffset, SeekOrigin.Begin);
            writer.Seek(romFsOffset, SeekOrigin.Begin);

            // Process MiB-aligned data
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    byte[] readBytes = reader.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    writer.Write(processedBytes);
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {i} / {romfsSizeM + 1} mb");
                }
            }

            // Process additional data
            if (romfsSizeB > 0)
            {
                byte[] readBytes = reader.ReadBytes(romfsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                writer.Write(finalBytes);
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="writer">Stream representing the output</param>
        private static void UpdateDecryptCryptoAndMasks(Cart cart, int partitionIndex, Stream writer)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint partitionOffset = partitionOffsetMU * cart.MediaUnitSize();

            // Seek to the CryptoMethod location
            writer.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            writer.Write((byte)CryptoMethod.Original);
            writer.Flush();

            // Seek to the BitMasks location
            writer.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.Partitions![partitionIndex]!.Flags!.BitMasks;
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
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptExeFS(Cart cart,
            int partitionIndex,
            Stream reader,
            Stream writer)
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
                ProcessExeFSFileEntries(cart, partitionIndex, encrypt: true, reader, writer);

            // Encrypt the filename table
            ProcessExeFSFilenameTable(cart, partitionIndex, encrypt: true, reader, writer);

            // Encrypt the rest of the ExeFS
            ProcessExeFS(cart, partitionIndex, encrypt: true, reader, writer);
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        /// TODO: See how much can be extracted into a common method with Decrypt
        private bool EncryptRomFS(Cart cart,
            int partitionIndex,
            Stream reader,
            Stream writer)
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
                    NormalKey[partitionIndex] = 0x00;
                }
                else
                {
                    KeyX[partitionIndex] = (decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C);
                    NormalKey[partitionIndex] = RotateLeft((RotateLeft(KeyX[partitionIndex], 2, 128) ^ KeyY[partitionIndex]) + decryptArgs.AESHardwareConstant, 87, 128);
                }
            }

            // Create the RomFS AES cipher for this partition
            var cipher = CreateAESCipher(NormalKey[partitionIndex], cart.RomFSIV(partitionIndex), encrypt: true);

            // Seek to the RomFS
            reader.Seek(romFsOffset, SeekOrigin.Begin);
            writer.Seek(romFsOffset, SeekOrigin.Begin);

            // Process MiB-aligned data
            if (romfsSizeM > 0)
            {
                for (int i = 0; i < romfsSizeM; i++)
                {
                    byte[] readBytes = reader.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    writer.Write(processedBytes);
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {i} / {romfsSizeM + 1} mb");
                }
            }

            // Process additional data
            if (romfsSizeB > 0)
            {
                byte[] readBytes = reader.ReadBytes(romfsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                writer.Write(finalBytes);
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
            return true;
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="cart">Cart representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="writer">Stream representing the output</param>
        private static void UpdateEncryptCryptoAndMasks(Cart cart, int partitionIndex, Stream writer)
        {
            // Get required offsets
            uint partitionOffsetMU = cart.Header!.PartitionsTable![partitionIndex]!.Offset;
            uint partitionOffset = partitionOffsetMU * cart.MediaUnitSize();

            // Get the backup header
            var backupHeader = cart.CardInfoHeader!.InitialData!.BackupHeader;

            // Seek to the CryptoMethod location
            writer.Seek(partitionOffset + 0x18B, SeekOrigin.Begin);

            // Write the new CryptoMethod
            // - For partitions 1 and up, set crypto-method to 0x00
            // - If partition 0, restore crypto-method from backup flags
            byte cryptoMethod = partitionIndex > 0 ? (byte)CryptoMethod.Original : (byte)backupHeader!.Flags!.CryptoMethod;
            writer.Write(cryptoMethod);
            writer.Flush();

            // Seek to the BitMasks location
            writer.Seek(partitionOffset + 0x18F, SeekOrigin.Begin);

            // Write the new BitMasks flag
            BitMasks flag = cart.Partitions![partitionIndex]!.Flags!.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;
            flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & backupHeader!.Flags!.BitMasks;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion
    }
}

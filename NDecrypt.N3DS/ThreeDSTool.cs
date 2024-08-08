using System;
using System.IO;
using System.Linq;
using System.Numerics;
using NDecrypt.Core;
using SabreTools.Models.N3DS;
using static NDecrypt.Core.Helper;

namespace NDecrypt.N3DS
{
    public class ThreeDSTool : ITool
    {
        /// <summary>
        /// Name of the input 3DS file
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

        public ThreeDSTool(string filename, DecryptArgs decryptArgs)
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
                using (var reader = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                using (var writer = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
                {
                    (var cart, var backupHeader) = Serializer.ReadCart(reader, decryptArgs.Development);
                    if (cart?.Header == null)
                    {
                        Console.WriteLine("Error: Not a 3DS cart image!");
                        return false;
                    }

                    // Process all 8 NCCH partitions
                    ProcessAllPartitions(cart.Header, backupHeader, reader, writer);
                }

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
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="backupHeader">Backup NCCH header</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessAllPartitions(NCSDHeader ncsdHeader, NCCHHeader? backupHeader, BinaryReader reader, BinaryWriter writer)
        {
            // Iterate over all 8 NCCH partitions
            for (int p = 0; p < 8; p++)
            {
                (int partitionIndex, var ncchHeader, var tableEntry) = GetPartitionHeader(ncsdHeader, reader, p);
                if (partitionIndex < 0 || ncchHeader == null || tableEntry == null)
                    continue;

                ProcessPartition(ncsdHeader, partitionIndex, ncchHeader, tableEntry, backupHeader, reader, writer);
            }
        }

        /// <summary>
        /// Get a specific partition header from the partition table
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="partitionNumber">Partition number to attempt to retrieve</param>
        /// <returns>NCCH header for the partition requested, null on error</returns>
        private static (int, NCCHHeader?, PartitionTableEntry?) GetPartitionHeader(NCSDHeader ncsdHeader, BinaryReader reader, int partitionNumber)
        {
            // Check the partitions table
            if (ncsdHeader.PartitionsTable == null)
            {
                Console.WriteLine("Invalid partitions table... Skipping...");
                return (-1, null, null);
            }

            // Check the partition is valid
            if (!ncsdHeader.PartitionsTable[partitionNumber].IsValid())
            {
                Console.WriteLine($"Partition {partitionNumber} Not found... Skipping...");
                return (-1, null, null);
            }

            // Seek to the beginning of the NCCH partition
            long offset = ncsdHeader.PartitionsTable[partitionNumber]!.Offset * ncsdHeader.ImageSizeInMediaUnits;
            reader.BaseStream.Seek(offset, SeekOrigin.Begin);

            // Read the NCCH header
            var header = Serializer.ReadNCCHHeader(reader, readSignature: true);
            if (header == null)
            {
                Console.WriteLine($"Partition {partitionNumber} Unable to read NCCH header");
                return (-1, null, null);
            }

            var entry = ncsdHeader.PartitionsTable[partitionNumber];
            return (partitionNumber, header, entry);
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="backupHeader">Backup NCCH header</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessPartition(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            NCCHHeader? backupHeader,
            BinaryReader reader,
            BinaryWriter writer)
        {
            // If we're forcing the operation, tell the user
            if (decryptArgs.Force)
            {
                Console.WriteLine($"Partition {partitionIndex} is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (ncchHeader.Flags!.PossblyDecrypted() ^ decryptArgs.Encrypt)
            {
                Console.WriteLine($"Partition {partitionIndex}: Already " + (decryptArgs.Encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // Determine the Keys to be used
            SetEncryptionKeys(partitionIndex, ncchHeader, backupHeader);

            // Process the extended header
            ProcessExtendedHeader(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);

            // If we're encrypting, encrypt the filesystems and update the flags
            if (decryptArgs.Encrypt)
            {
                EncryptExeFS(ncsdHeader, partitionIndex, ncchHeader, tableEntry, backupHeader, reader, writer);
                EncryptRomFS(ncsdHeader, partitionIndex, ncchHeader, tableEntry, backupHeader, reader, writer);
                UpdateEncryptCryptoAndMasks(ncsdHeader, partitionIndex, ncchHeader, tableEntry, backupHeader, writer);
            }

            // If we're decrypting, decrypt the filesystems and update the flags
            else
            {
                DecryptExeFS(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);
                DecryptRomFS(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);
                UpdateDecryptCryptoAndMasks(ncsdHeader, ncchHeader, tableEntry, writer);
            }
        }

        /// <summary>
        /// Determine the set of keys to be used for encryption or decryption
        /// </summary>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="backupHeader">Backup NCCH header</param>
        private void SetEncryptionKeys(int partitionIndex,
            NCCHHeader ncchHeader,
            NCCHHeader? backupHeader)
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

            // Set the header to use based on mode
            BitMasks masks;
            CryptoMethod method;
            if (decryptArgs.Encrypt)
            {
                masks = backupHeader!.Flags!.BitMasks;
                method = backupHeader.Flags.CryptoMethod;
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
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private bool ProcessExtendedHeader(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryReader reader,
            BinaryWriter writer)
        {
            if (ncchHeader.ExtendedHeaderSizeInBytes > 0)
            {
                reader.BaseStream.Seek((tableEntry.Offset * ncsdHeader.MediaUnitSize()) + 0x200, SeekOrigin.Begin);
                writer.BaseStream.Seek((tableEntry.Offset * ncsdHeader.MediaUnitSize()) + 0x200, SeekOrigin.Begin);

                Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + ": ExHeader");

                var cipher = CreateAESCipher(NormalKey2C[partitionIndex], ncchHeader.PlainIV(), decryptArgs.Encrypt);
                byte[] readBytes = reader.ReadBytes(Constants.CXTExtendedDataHeaderLength);
                byte[] processedBytes = cipher.ProcessBytes(readBytes);
                writer.Write(processedBytes);
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
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessExeFSFileEntries(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryReader reader,
            BinaryWriter writer)
        {
            reader.BaseStream.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
            var exefsHeader = Serializer.ReadExeFSHeader(reader);

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

                uint datalenM = ((fileHeader.FileSize) / (1024 * 1024));
                uint datalenB = ((fileHeader.FileSize) % (1024 * 1024));
                uint ctroffset = ((fileHeader.FileOffset + ncsdHeader.MediaUnitSize()) / 0x10);

                byte[] exefsIVWithOffsetForHeader = AddToByteArray(ncchHeader.ExeFSIV(), (int)ctroffset);

                var firstCipher = CreateAESCipher(NormalKey[partitionIndex], exefsIVWithOffsetForHeader, decryptArgs.Encrypt);
                var secondCipher = CreateAESCipher(NormalKey2C[partitionIndex], exefsIVWithOffsetForHeader, !decryptArgs.Encrypt);

                reader.BaseStream.Seek((((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * ncsdHeader.MediaUnitSize()) + fileHeader.FileOffset, SeekOrigin.Begin);
                writer.BaseStream.Seek((((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) + 1) * ncsdHeader.MediaUnitSize()) + fileHeader.FileOffset, SeekOrigin.Begin);

                if (datalenM > 0)
                {
                    for (int i = 0; i < datalenM; i++)
                    {
                        byte[] readBytes = reader.ReadBytes(1024 * 1024);
                        byte[] firstProcessedBytes = firstCipher.ProcessBytes(readBytes);
                        byte[] secondProcessedBytes = secondCipher.ProcessBytes(firstProcessedBytes);
                        writer.Write(secondProcessedBytes);
                        writer.Flush();
                        Console.Write($"\rPartition {partitionIndex} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {i} / {datalenM + 1} mb...");
                    }
                }

                if (datalenB > 0)
                {
                    byte[] readBytes = reader.ReadBytes((int)datalenB);
                    byte[] firstFinalBytes = firstCipher.DoFinal(readBytes);
                    byte[] secondFinalBytes = secondCipher.DoFinal(firstFinalBytes);
                    writer.Write(secondFinalBytes);
                    writer.Flush();
                }

                Console.Write($"\rPartition {partitionIndex} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {fileHeader.FileName}... {datalenM + 1} / {datalenM + 1} mb... Done!\r\n");
            }
        }

        /// <summary>
        /// Process the ExeFS Filename Table
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessExeFSFilenameTable(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryReader reader,
            BinaryWriter writer)
        {
            reader.BaseStream.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
            writer.BaseStream.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);

            Console.WriteLine($"Partition {partitionIndex} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": ExeFS Filename Table");

            var cipher = CreateAESCipher(NormalKey2C[partitionIndex], ncchHeader.ExeFSIV(), decryptArgs.Encrypt);
            byte[] readBytes = reader.ReadBytes((int)ncsdHeader.MediaUnitSize());
            byte[] processedBytes = cipher.ProcessBytes(readBytes);
            writer.Write(processedBytes);

#if NET6_0_OR_GREATER
            // In .NET 6.0, this operation is not picked up by the reader, so we have to force it to reload its buffer
            reader.BaseStream.Seek(0, SeekOrigin.Begin);
#endif
            writer.Flush();
        }

        /// <summary>
        /// Process the ExeFS, if it exists
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessExeFS(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryReader reader,
            BinaryWriter writer)
        {
            int exefsSizeM = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * ncsdHeader.MediaUnitSize()) / (1024 * 1024));
            int exefsSizeB = (int)((long)((ncchHeader.ExeFSSizeInMediaUnits - 1) * ncsdHeader.MediaUnitSize()) % (1024 * 1024));
            int ctroffsetE = (int)(ncsdHeader.MediaUnitSize() / 0x10);

            byte[] exefsIVWithOffset = AddToByteArray(ncchHeader.ExeFSIV(), ctroffsetE);

            var cipher = CreateAESCipher(NormalKey2C[partitionIndex], exefsIVWithOffset, decryptArgs.Encrypt);

            reader.BaseStream.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
            writer.BaseStream.Seek((tableEntry.Offset + ncchHeader.ExeFSOffsetInMediaUnits + 1) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
            if (exefsSizeM > 0)
            {
                for (int i = 0; i < exefsSizeM; i++)
                {
                    byte[] readBytes = reader.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    writer.Write(processedBytes);
                    writer.Flush();
                    Console.Write($"\rPartition {partitionIndex} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {i} / {exefsSizeM + 1} mb");
                }
            }
            if (exefsSizeB > 0)
            {
                byte[] readBytes = reader.ReadBytes(exefsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                writer.Write(finalBytes);
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} ExeFS: " + (decryptArgs.Encrypt ? "Encrypting" : "Decrypting") + $": {exefsSizeM + 1} / {exefsSizeM + 1} mb... Done!\r\n");
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypt the ExeFS, if it exists
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void DecryptExeFS(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryReader reader,
            BinaryWriter writer)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // Decrypt the filename table
            ProcessExeFSFilenameTable(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);

            // For all but the original crypto method, process each of the files in the table
            if (ncchHeader.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);

            // Decrypt the rest of the ExeFS
            ProcessExeFS(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);
        }

        /// <summary>
        /// Decrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// TODO: See how much can be extracted into a common method with Encrypt
        private void DecryptRomFS(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryReader reader,
            BinaryWriter writer)
        {
            // If the RomFS offset is 0, we log and return
            if (ncchHeader.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * ncsdHeader.MediaUnitSize()) / (1024 * 1024));
            int romfsSizeB = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * ncsdHeader.MediaUnitSize()) % (1024 * 1024));

            var cipher = CreateAESCipher(NormalKey[partitionIndex], ncchHeader.RomFSIV(), decryptArgs.Encrypt);

            reader.BaseStream.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
            writer.BaseStream.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
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
            if (romfsSizeB > 0)
            {
                byte[] readBytes = reader.ReadBytes(romfsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                writer.Write(finalBytes);
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Decrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the decrypted partition
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void UpdateDecryptCryptoAndMasks(NCSDHeader ncsdHeader,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            BinaryWriter writer)
        {
            // Write the new CryptoMethod
            writer.BaseStream.Seek((tableEntry.Offset * ncsdHeader.MediaUnitSize()) + 0x18B, SeekOrigin.Begin);
            writer.Write((byte)CryptoMethod.Original);
            writer.Flush();

            // Write the new BitMasks flag
            writer.BaseStream.Seek((tableEntry.Offset * ncsdHeader.MediaUnitSize()) + 0x18F, SeekOrigin.Begin);
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
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="backupHeader">Backup NCCH header</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void EncryptExeFS(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            NCCHHeader? backupHeader,
            BinaryReader reader,
            BinaryWriter writer)
        {
            // If the ExeFS size is 0, we log and return
            if (ncchHeader.ExeFSSizeInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} ExeFS: No Data... Skipping...");
                return;
            }

            // For all but the original crypto method, process each of the files in the table
            if (backupHeader!.Flags!.CryptoMethod != CryptoMethod.Original)
                ProcessExeFSFileEntries(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);

            // Encrypt the filename table
            ProcessExeFSFilenameTable(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);

            // Encrypt the rest of the ExeFS
            ProcessExeFS(ncsdHeader, partitionIndex, ncchHeader, tableEntry, reader, writer);
        }

        /// <summary>
        /// Encrypt the RomFS, if it exists
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="backupHeader">Backup NCCH header</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        /// TODO: See how much can be extracted into a common method with Decrypt
        private void EncryptRomFS(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            NCCHHeader? backupHeader,
            BinaryReader reader,
            BinaryWriter writer)
        {
            // If the RomFS offset is 0, we log and return
            if (ncchHeader.RomFSOffsetInMediaUnits == 0)
            {
                Console.WriteLine($"Partition {partitionIndex} RomFS: No Data... Skipping...");
                return;
            }

            long romfsSizeM = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * ncsdHeader.MediaUnitSize()) / (1024 * 1024));
            int romfsSizeB = (int)((long)(ncchHeader.RomFSSizeInMediaUnits * ncsdHeader.MediaUnitSize()) % (1024 * 1024));

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            if (partitionIndex > 0)
            {
                if (backupHeader!.Flags?.BitMasks.HasFlag(BitMasks.FixedCryptoKey) == true) // except if using zero-key
                {
                    NormalKey[partitionIndex] = 0x00;
                }
                else
                {
                    KeyX[partitionIndex] = (decryptArgs.Development ? decryptArgs.DevKeyX0x2C : decryptArgs.KeyX0x2C);
                    NormalKey[partitionIndex] = RotateLeft((RotateLeft(KeyX[partitionIndex], 2, 128) ^ KeyY[partitionIndex]) + decryptArgs.AESHardwareConstant, 87, 128);
                }
            }

            var cipher = CreateAESCipher(NormalKey[partitionIndex], ncchHeader.RomFSIV(), decryptArgs.Encrypt);

            reader.BaseStream.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
            writer.BaseStream.Seek((tableEntry.Offset + ncchHeader.RomFSOffsetInMediaUnits) * ncsdHeader.MediaUnitSize(), SeekOrigin.Begin);
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
            if (romfsSizeB > 0)
            {
                byte[] readBytes = reader.ReadBytes(romfsSizeB);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                writer.Write(finalBytes);
                writer.Flush();
            }

            Console.Write($"\rPartition {partitionIndex} RomFS: Encrypting: {romfsSizeM + 1} / {romfsSizeM + 1} mb... Done!\r\n");
        }

        /// <summary>
        /// Update the CryptoMethod and BitMasks for the encrypted partition
        /// </summary>
        /// <param name="ncsdHeader">NCSD header representing the 3DS file</param>
        /// <param name="partitionIndex">Index of the partition</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="tableEntry">PartitionTableEntry header representing the partition</param>
        /// <param name="backupHeader">Backup NCCH header</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private static void UpdateEncryptCryptoAndMasks(NCSDHeader ncsdHeader,
            int partitionIndex,
            NCCHHeader ncchHeader,
            PartitionTableEntry tableEntry,
            NCCHHeader? backupHeader,
            BinaryWriter writer)
        {
            // Write the new CryptoMethod
            writer.BaseStream.Seek((tableEntry.Offset * ncsdHeader.MediaUnitSize()) + 0x18B, SeekOrigin.Begin);
            
            // For partitions 1 and up, set crypto-method to 0x00
            if (partitionIndex > 0)
                writer.Write((byte)CryptoMethod.Original);

            // If partition 0, restore crypto-method from backup flags
            else
                writer.Write((byte)backupHeader!.Flags!.CryptoMethod);

            writer.Flush();

            // Write the new BitMasks flag
            writer.BaseStream.Seek((tableEntry.Offset * ncsdHeader.MediaUnitSize()) + 0x18F, SeekOrigin.Begin);
            BitMasks flag = ncchHeader.Flags!.BitMasks;
            flag &= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator | BitMasks.NoCrypto) ^ (BitMasks)0xFF;
            flag |= (BitMasks.FixedCryptoKey | BitMasks.NewKeyYGenerator) & backupHeader!.Flags!.BitMasks;
            writer.Write((byte)flag);
            writer.Flush();
        }

        #endregion
    }
}

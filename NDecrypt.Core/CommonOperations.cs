using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SabreTools.IO.Extensions;
using SabreTools.Models.N3DS;

namespace NDecrypt.Core
{
    internal static class CommonOperations
    {
        #region AES

        /// <summary>
        /// Create AES cipher and intialize
        /// </summary>
        /// <param name="key">BigInteger representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <param name="encrypt">True if cipher is created for encryption, false otherwise</param>
        /// <returns>Initialized AES cipher</returns>
        public static IBufferedCipher CreateAESCipher(BigInteger key, byte[] iv, bool encrypt)
        {
            return encrypt ? CreateAESEncryptionCipher(key, iv) : CreateAESDecryptionCipher(key, iv);
        }

        /// <summary>
        /// Create AES decryption cipher and intialize
        /// </summary>
        /// <param name="key">BigInteger representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <returns>Initialized AES cipher</returns>
        public static IBufferedCipher CreateAESDecryptionCipher(BigInteger key, byte[] iv)
        {
            var keyParam = new KeyParameter(TakeSixteen(key));
            var cipher = CipherUtilities.GetCipher("AES/CTR");
            cipher.Init(forEncryption: false, new ParametersWithIV(keyParam, iv));
            return cipher;
        }

        /// <summary>
        /// Create AES encryption cipher and intialize
        /// </summary>
        /// <param name="key">BigInteger representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <returns>Initialized AES cipher</returns>
        public static IBufferedCipher CreateAESEncryptionCipher(BigInteger key, byte[] iv)
        {
            var keyParam = new KeyParameter(TakeSixteen(key));
            var cipher = CipherUtilities.GetCipher("AES/CTR");
            cipher.Init(forEncryption: true, new ParametersWithIV(keyParam, iv));
            return cipher;
        }

        /// <summary>
        /// Perform an AES operation using an existing cipher
        /// </summary>
        public static void PerformAESOperation(uint size,
            IBufferedCipher cipher,
            Stream input,
            Stream output,
            Action<string>? progress)
        {
            // Get MiB-aligned block count and extra byte count
            int blockCount = (int)((long)size / (1024 * 1024));
            int extraBytes = (int)((long)size % (1024 * 1024));

            // Process MiB-aligned data
            if (blockCount > 0)
            {
                for (int i = 0; i < blockCount; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    output.Write(processedBytes);
                    output.Flush();
                    progress?.Invoke($"{i} / {blockCount + 1} MB");
                }
            }

            // Process additional data
            if (extraBytes > 0)
            {
                byte[] readBytes = input.ReadBytes(extraBytes);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                output.Write(finalBytes);
                output.Flush();
            }

            progress?.Invoke($"{blockCount + 1} / {blockCount + 1} MB... Done!\r\n");
        }

        /// <summary>
        /// Perform an AES operation using two existing ciphers
        /// </summary>
        public static void PerformAESOperation(uint size,
            IBufferedCipher firstCipher,
            IBufferedCipher secondCipher,
            Stream input,
            Stream output,
            Action<string> progress)
        {
            // Get MiB-aligned block count and extra byte count
            int blockCount = (int)((long)size / (1024 * 1024));
            int extraBytes = (int)((long)size % (1024 * 1024));

            // Process MiB-aligned data
            if (blockCount > 0)
            {
                for (int i = 0; i < blockCount; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] firstProcessedBytes = firstCipher.ProcessBytes(readBytes);
                    byte[] secondProcessedBytes = secondCipher.ProcessBytes(firstProcessedBytes);
                    output.Write(secondProcessedBytes);
                    output.Flush();
                    progress($"{i} / {blockCount + 1} MB");
                }
            }

            // Process additional data
            if (extraBytes > 0)
            {
                byte[] readBytes = input.ReadBytes(extraBytes);
                byte[] firstFinalBytes = firstCipher.DoFinal(readBytes);
                byte[] secondFinalBytes = secondCipher.DoFinal(firstFinalBytes);
                output.Write(secondFinalBytes);
                output.Flush();
            }

            progress($"{blockCount + 1} / {blockCount + 1} MB... Done!\r\n");
        }

        /// <summary>
        /// Get a 16-byte array representation of a BigInteger
        /// </summary>
        /// <param name="input">BigInteger value to convert</param>
        /// <returns>16-byte array representing the BigInteger</returns>
        private static byte[] TakeSixteen(BigInteger input)
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

        #endregion

        #region Byte Arrays

        /// <summary>
        /// Add an integer value to a number represented by a byte array
        /// </summary>
        /// <param name="input">Byte array to add to</param>
        /// <param name="add">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        public static byte[] AddToByteArray(byte[] input, int add)
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
        /// Perform a rotate left on a BigInteger
        /// </summary>
        /// <param name="val">BigInteger value to rotate</param>
        /// <param name="r_bits">Number of bits to rotate</param>
        /// <param name="max_bits">Maximum number of bits to rotate on</param>
        /// <returns>Rotated BigInteger value</returns>
        public static BigInteger RotateLeft(BigInteger val, int r_bits, int max_bits)
        {
            return (val << r_bits % max_bits) & (BigInteger.Pow(2, max_bits) - 1) | ((val & (BigInteger.Pow(2, max_bits) - 1)) >> (max_bits - (r_bits % max_bits)));
        }

        #endregion

        #region Offsets

        /// <summary>
        /// Get the offset of a partition ExeFS
        /// </summary>
        /// <returns>Offset to the ExeFS of the partition, 0 on error</returns>
        public static uint GetExeFSOffset(Cart cart, int index)
        {
            // Empty partitions table means no size is available
            var partitionsTable = cart.Header?.PartitionsTable;
            if (partitionsTable == null)
                return 0;

            // Invalid partition table entry means no size is available
            var entry = partitionsTable[index];
            if (entry == null)
                return 0;

            // Empty partitions array means no size is available
            var partitions = cart.Partitions;
            if (partitions == null)
                return 0;

            // Invalid partition means no size is available
            var header = partitions[index];
            if (header == null)
                return 0;

            // If the offset is 0, return 0
            uint exeFsOffsetMU = header.ExeFSOffsetInMediaUnits;
            if (exeFsOffsetMU == 0)
                return 0;

            // Return the adjusted offset
            uint partitionOffsetMU = entry.Offset;
            return (partitionOffsetMU + exeFsOffsetMU) * cart.MediaUnitSize();
        }

        /// <summary>
        /// Get the offset of a partition ExeFS
        /// </summary>
        /// <returns>Offset to the ExeFS of the partition, 0 on error</returns>
        public static uint GetExeFSOffset(NCCHHeader header,
            PartitionTableEntry entry,
            uint mediaUnitSize)
        {
            // If the offset is 0, return 0
            uint exeFsOffsetMU = header.ExeFSOffsetInMediaUnits;
            if (exeFsOffsetMU == 0)
                return 0;

            // Return the adjusted offset
            uint partitionOffsetMU = entry.Offset;
            return (partitionOffsetMU + exeFsOffsetMU) * mediaUnitSize;
        }

        /// <summary>
        /// Get the offset of a partition
        /// </summary>
        /// <returns>Offset to the partition, 0 on error</returns>
        public static uint GetPartitionOffset(Cart cart, int index)
        {
            // Empty partitions table means no size is available
            var partitionsTable = cart.Header?.PartitionsTable;
            if (partitionsTable == null)
                return 0;

            // Invalid partition table entry means no size is available
            var entry = partitionsTable[index];
            if (entry == null)
                return 0;

            // Return the adjusted offset
            uint partitionOffsetMU = entry.Offset;
            return partitionOffsetMU * cart.MediaUnitSize();
        }

        /// <summary>
        /// Get the offset of a partition
        /// </summary>
        /// <returns>Offset to the partition, 0 on error</returns>
        public static uint GetPartitionOffset(PartitionTableEntry entry,
            uint mediaUnitSize)
        {
            // Invalid partition table entry means no size is available
            if (entry.Offset == 0)
                return 0;

            // Return the adjusted offset
            uint partitionOffsetMU = entry.Offset;
            return partitionOffsetMU * mediaUnitSize;
        }

        /// <summary>
        /// Get the offset of a partition RomFS
        /// </summary>
        /// <returns>Offset to the RomFS of the partition, 0 on error</returns>
        public static uint GetRomFSOffset(Cart cart, int index)
        {
            // Empty partitions table means no size is available
            var partitionsTable = cart.Header?.PartitionsTable;
            if (partitionsTable == null)
                return 0;

            // Invalid partition table entry means no size is available
            var entry = partitionsTable[index];
            if (entry == null)
                return 0;

            // Empty partitions array means no size is available
            var partitions = cart.Partitions;
            if (partitions == null)
                return 0;

            // Invalid partition means no size is available
            var header = partitions[index];
            if (header == null)
                return 0;

            // If the offset is 0, return 0
            uint romFsOffsetMU = header.RomFSOffsetInMediaUnits;
            if (romFsOffsetMU == 0)
                return 0;

            // Return the adjusted offset
            uint partitionOffsetMU = entry.Offset;
            return (partitionOffsetMU + romFsOffsetMU) * cart.MediaUnitSize();
        }

        /// <summary>
        /// Get the offset of a partition RomFS
        /// </summary>
        /// <returns>Offset to the RomFS of the partition, 0 on error</returns>
        public static uint GetRomFSOffset(NCCHHeader header,
            PartitionTableEntry entry,
            uint mediaUnitSize)
        {
            // If the offset is 0, return 0
            uint romFsOffsetMU = header.RomFSOffsetInMediaUnits;
            if (romFsOffsetMU == 0)
                return 0;

            // Return the adjusted offset
            uint partitionOffsetMU = entry.Offset;
            return (partitionOffsetMU + romFsOffsetMU - 1) * mediaUnitSize;
        }

        #endregion

        #region Sizes

        /// <summary>
        /// Get the size of a partition ExeFS
        /// </summary>
        /// <returns>Size of the partition ExeFS in bytes, 0 on error</returns>
        public static uint GetExeFSSize(Cart cart, int index)
        {
            // Empty partitions array means no size is available
            var partitions = cart.Partitions;
            if (partitions == null)
                return 0;

            // Invalid partition header means no size is available
            var header = partitions[index];
            if (header == null)
                return 0;

            // Return the adjusted size
            return GetExeFSSize(header, cart.MediaUnitSize());
        }

        /// <summary>
        /// Get the size of a partition ExeFS
        /// </summary>
        /// <returns>Size of the partition ExeFS in bytes, 0 on error</returns>
        public static uint GetExeFSSize(NCCHHeader header, uint mediaUnitSize)
            => header.ExeFSSizeInMediaUnits * mediaUnitSize;

        /// <summary>
        /// Get the size of a partition extended header
        /// </summary>
        /// <returns>Size of the partition extended header in bytes, 0 on error</returns>
        public static uint GetExtendedHeaderSize(Cart cart, int index)
        {
            // Empty partitions array means no size is available
            var partitions = cart.Partitions;
            if (partitions == null)
                return 0;

            // Invalid partition header means no size is available
            var header = partitions[index];
            if (header == null)
                return 0;

            // Return the adjusted size
            return GetExtendedHeaderSize(header);
        }

        /// <summary>
        /// Get the size of a partition extended header
        /// </summary>
        /// <returns>Size of the partition extended header in bytes, 0 on error</returns>
        public static uint GetExtendedHeaderSize(NCCHHeader header)
            => header.ExtendedHeaderSizeInBytes;

        /// <summary>
        /// Get the size of a partition RomFS
        /// </summary>
        /// <returns>Size of the partition RomFS in bytes, 0 on error</returns>
        public static uint GetRomFSSize(Cart cart, int index)
        {
            // Empty partitions array means no size is available
            var partitions = cart.Partitions;
            if (partitions == null)
                return 0;

            // Invalid partition header means no size is available
            var header = partitions[index];
            if (header == null)
                return 0;

            // Return the adjusted size
            return GetRomFSSize(header, cart.MediaUnitSize());
        }

        /// <summary>
        /// Get the size of a partition RomFS
        /// </summary>
        /// <returns>Size of the partition RomFS in bytes, 0 on error</returns>
        public static uint GetRomFSSize(NCCHHeader header, uint mediaUnitSize)
            => header.RomFSSizeInMediaUnits * mediaUnitSize;

        #endregion
    }
}
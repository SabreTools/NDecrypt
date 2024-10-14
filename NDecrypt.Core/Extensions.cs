using System;
using SabreTools.Models.N3DS;

namespace NDecrypt.Core
{
    internal static class Extensions
    {
        #region Constants

        // Setup Keys and IVs
        public static byte[] PlainCounter = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        public static byte[] ExefsCounter = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        public static byte[] RomfsCounter = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        #endregion

        #region ExeFSFileHeader

        /// <summary>
        /// Determines if a file header represents a CODE block
        /// </summary>
        public static bool IsCodeBinary(this ExeFSFileHeader? header)
        {
            if (header == null)
                return false;

            return header.FileName == ".code\0\0\0";
        }

        #endregion

        #region NCCHHeader

        /// <summary>
        /// Get the initial value for the plain counter
        /// </summary>
        public static byte[] PlainIV(this Cart cart, int partitionIndex)
        {
            if (cart.Partitions == null)
                return [];
            if (partitionIndex < 0 || partitionIndex >= cart.Partitions.Length)
                return [];

            var header = cart.Partitions[partitionIndex];
            return PlainIV(header);
        }

        /// <summary>
        /// Get the initial value for the plain counter
        /// </summary>
        public static byte[] PlainIV(this NCCHHeader? header)
        {
            if (header == null)
                return [];

            byte[] partitionIdBytes = BitConverter.GetBytes(header.PartitionId);
            return [.. partitionIdBytes, .. PlainCounter];
        }

        /// <summary>
        /// Get the initial value for the ExeFS counter
        /// </summary>
        public static byte[] ExeFSIV(this Cart cart, int partitionIndex)
        {
            if (cart.Partitions == null)
                return [];
            if (partitionIndex < 0 || partitionIndex >= cart.Partitions.Length)
                return [];

            var header = cart.Partitions[partitionIndex];
            return ExeFSIV(header);
        }

        /// <summary>
        /// Get the initial value for the ExeFS counter
        /// </summary>
        public static byte[] ExeFSIV(this NCCHHeader? header)
        {
            if (header == null)
                return [];

            byte[] partitionIdBytes = BitConverter.GetBytes(header.PartitionId);
            return [.. partitionIdBytes, .. ExefsCounter];
        }

        /// <summary>
        /// Get the initial value for the RomFS counter
        /// </summary>
        public static byte[] RomFSIV(this Cart cart, int partitionIndex)
        {
            if (cart.Partitions == null)
                return [];
            if (partitionIndex < 0 || partitionIndex >= cart.Partitions.Length)
                return [];

            var header = cart.Partitions[partitionIndex];
            return RomFSIV(header);
        }

        /// <summary>
        /// Get the initial value for the RomFS counter
        /// </summary>
        public static byte[] RomFSIV(this NCCHHeader? header)
        {
            if (header == null)
                return [];

            byte[] partitionIdBytes = BitConverter.GetBytes(header.PartitionId);
            return [.. partitionIdBytes, .. RomfsCounter];
        }

        #endregion

        #region NCCHHeaderFlags

        /// <summary>
        /// Get if the NoCrypto bit is set
        /// </summary>
        public static bool PossblyDecrypted(this NCCHHeaderFlags flags)
        {
            if (flags == null)
                return false;

            return flags.BitMasks.HasFlag(BitMasks.NoCrypto);
        }

        #endregion

        #region NCSDHeader

        //// <summary>
        /// Media Unit Size i.e. u32 MediaUnitSize = 0x200*2^flags[6];
        /// </summary>
        public static uint MediaUnitSize(this Cart cart)
        {
            return cart.Header.MediaUnitSize();
        }

        /// <summary>
        /// Media Unit Size i.e. u32 MediaUnitSize = 0x200*2^flags[6];
        /// </summary>
        public static uint MediaUnitSize(this NCSDHeader? header)
        {
            if (header?.PartitionFlags == null)
                return default;

            return (uint)(0x200 * Math.Pow(2, header.PartitionFlags[(int)NCSDFlags.MediaUnitSize]));
        }

        #endregion
    }
}
using System;
using SabreTools.Models.N3DS;

namespace NDecrypt.N3DS
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

        /// <summary>
        /// Partition table entry for Executable Content (CXI)
        /// </summary>
        public static PartitionTableEntry? ExecutableContent(this NCSDHeader? header)
        {
            if (header?.PartitionsTable == null)
                return null;

            return header.PartitionsTable[0];
        }

        /// <summary>
        /// Partition table entry for E-Manual (CFA)
        /// </summary>
        public static PartitionTableEntry? EManual(this NCSDHeader? header)
        {
            if (header?.PartitionsTable == null)
                return null;

            return header.PartitionsTable[1];
        }

        /// <summary>
        /// Partition table entry for Download Play Child container (CFA)
        /// </summary>
        public static PartitionTableEntry? DownloadPlayChildContainer(this NCSDHeader? header)
        {
            if (header?.PartitionsTable == null)
                return null;

            return header.PartitionsTable[2];
        }

        /// <summary>
        /// Partition table entry for New3DS Update Data (CFA)
        /// </summary>
        public static PartitionTableEntry? New3DSUpdateData(this NCSDHeader? header)
        {
            if (header?.PartitionsTable == null)
                return null;

            return header.PartitionsTable[6];
        }

        /// <summary>
        /// Partition table entry for Update Data (CFA)
        /// </summary>
        public static PartitionTableEntry? UpdateData(this NCSDHeader? header)
        {
            if (header?.PartitionsTable == null)
                return null;

            return header.PartitionsTable[7];
        }

        /// <summary>
        /// Backup Write Wait Time (The time to wait to write save to backup after the card is recognized (0-255
        /// seconds)).NATIVE_FIRM loads this flag from the gamecard NCSD header starting with 6.0.0-11.
        /// </summary>
        public static byte BackupWriteWaitTime(this NCSDHeader? header)
        {
            if (header?.PartitionFlags == null)
                return default;

            return header.PartitionFlags[(int)NCSDFlags.BackupWriteWaitTime];
        }

        /// <summary>
        /// Media Card Device (1 = NOR Flash, 2 = None, 3 = BT) (SDK 3.X+)
        /// </summary>
        public static MediaCardDeviceType MediaCardDevice3X(this NCSDHeader? header)
        {
            if (header?.PartitionFlags == null)
                return default;

            return (MediaCardDeviceType)header.PartitionFlags[(int)NCSDFlags.MediaCardDevice3X];
        }

        /// <summary>
        /// Media Platform Index (1 = CTR)
        /// </summary>
        public static MediaPlatformIndex MediaPlatformIndex(this NCSDHeader? header)
        {
            if (header?.PartitionFlags == null)
                return default;

            return (MediaPlatformIndex)header.PartitionFlags[(int)NCSDFlags.MediaPlatformIndex];
        }

        /// <summary>
        /// Media Type Index (0 = Inner Device, 1 = Card1, 2 = Card2, 3 = Extended Device)
        /// </summary>
        public static MediaTypeIndex MediaTypeIndex(this NCSDHeader? header)
        {
            if (header?.PartitionFlags == null)
                return default;

            return (MediaTypeIndex)header.PartitionFlags[(int)NCSDFlags.MediaTypeIndex];
        }

        /// <summary>
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

        /// <summary>
        /// Media Card Device (1 = NOR Flash, 2 = None, 3 = BT) (Only SDK 2.X)
        /// </summary>
        public static MediaCardDeviceType MediaCardDevice2X(this NCSDHeader? header)
        {
            if (header?.PartitionFlags == null)
                return default;

            return (MediaCardDeviceType)header.PartitionFlags[(int)NCSDFlags.MediaCardDevice2X];
        }

        #endregion

        #region Ticket

        /// <summary>
        /// Denotes if the ticket denotes a demo or not
        /// </summary>
        public static bool IsDemo(this Ticket? ticket)
        {
            if (ticket?.Limits == null || ticket.Limits.Length == 0)
                return false;

            return ticket.Limits[0] == 0x0004;
        }

        /// <summary>
        /// Denotes if the max playcount for a demo
        /// </summary>
        public static uint PlayCount(this Ticket ticket)
        {
            if (ticket?.Limits == null || ticket.Limits.Length == 0)
                return 0;

            return ticket.Limits[1];
        }

        #endregion
    }
}
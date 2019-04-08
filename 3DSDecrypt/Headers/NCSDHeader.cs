using System;
using System.IO;
using ThreeDS.Data;

namespace ThreeDS.Headers
{
    public class NCSDHeader
    {
        private const string NCSDMagicNumber = "NCSD";

        #region Common to all NCSD files

        /// <summary>
        /// RSA-2048 SHA-256 signature of the NCSD header
        /// </summary>
        public byte[] RSA2048Signature { get; private set; }

        /// <summary>
        /// Size of the NCSD image, in media units (1 media unit = 0x200 bytes)
        /// </summary>
        public uint ImageSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Media ID
        /// </summary>
        public byte[] MediaId { get; private set; }

        /// <summary>
        /// Partitions FS type (0=None, 1=Normal, 3=FIRM, 4=AGB_FIRM save)
        /// </summary>
        public FilesystemType PartitionsFSType { get; private set; }

        /// <summary>
        /// Partitions crypt type (each byte corresponds to a partition in the partition table)
        /// </summary>
        public byte[] PartitionsCryptType { get; private set; }

        /// <summary>
        /// Offset & Length partition table, in media units
        /// </summary>
        public PartitionTableEntry[] PartitionsTable { get; private set; }

        #endregion

        #region For carts

        /// <summary>
        /// Exheader SHA-256 hash
        /// </summary>
        public byte[] ExheaderHash { get; private set; }

        /// <summary>
        /// Additional header size
        /// </summary>
        public uint AdditionalHeaderSize { get; private set; }

        /// <summary>
        /// Sector zero offset
        /// </summary>
        public uint SectorZeroOffset { get; private set; }

        /// <summary>
        /// Partition Flags
        /// </summary>
        private byte[] partitionFlags;
        public byte BackupWriteWaitTime { get { return partitionFlags[(int)NCSDFlags.BackupWriteWaitTime]; } }
        public MediaCardDeviceType MediaCardDevice3X { get { return (MediaCardDeviceType)partitionFlags[(int)NCSDFlags.MediaCardDevice3X]; } }
        public MediaPlatformIndex MediaPlatformIndex { get { return (MediaPlatformIndex)partitionFlags[(int)NCSDFlags.MediaPlatformIndex]; } }
        public MediaTypeIndex MediaTypeIndex { get { return (MediaTypeIndex)partitionFlags[(int)NCSDFlags.MediaTypeIndex]; } }
        public uint SectorSize { get { return (uint)(0x200 * Math.Pow(2, partitionFlags[(int)NCSDFlags.MediaUnitSize])); } }
        public MediaCardDeviceType MediaCardDevice2X { get { return (MediaCardDeviceType)partitionFlags[(int)NCSDFlags.MediaCardDevice2X]; } }

        /// <summary>
        /// Partition ID table
        /// </summary>
        public byte[][] PartitionIdTable { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved1 { get; private set; }

        /// <summary>
        /// Reserved?
        /// </summary>
        public byte[] Reserved2 { get; private set; }

        /// <summary>
        /// Support for this was implemented with 9.6.0-X FIRM. Bit0=1 enables using bits 1-2, it's unknown
        /// what these two bits are actually used for(the value of these two bits get compared with some other
        /// value during NCSD verification/loading). This appears to enable a new, likely hardware-based,
        /// antipiracy check on cartridges.
        /// </summary>
        public byte FirmUpdateByte1 { get; private set; }

        /// <summary>
        /// Support for this was implemented with 9.6.0-X FIRM, see below regarding save crypto.
        /// </summary>
        public byte FIrmUpdateByte2 { get; private set; }

        #endregion

        #region For NAND

        /// <summary>
        /// Unknown
        /// </summary>
        public byte[] Unknown { get; private set; }

        /// <summary>
        /// Encrypted MBR partition-table, for the TWL partitions(key-data used for this keyslot is console-unique).
        /// </summary>
        public byte[] EncryptedMBR { get; private set; }

        #endregion

        /// <summary>
        /// Read from a stream and get an NCSD header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>NCSD header object, null on error</returns>
        public static NCSDHeader Read(BinaryReader reader)
        {
            NCSDHeader header = new NCSDHeader();

            try
            {
                header.RSA2048Signature = reader.ReadBytes(0x100);

                if (new string(reader.ReadChars(4)) != NCSDMagicNumber)
                    return null;

                header.ImageSizeInMediaUnits = reader.ReadUInt32();
                header.MediaId = reader.ReadBytes(8);
                header.PartitionsFSType = (FilesystemType)reader.ReadUInt64();
                header.PartitionsCryptType = reader.ReadBytes(8);

                header.PartitionsTable = new PartitionTableEntry[8];
                for (int i = 0; i < 8; i++)
                    header.PartitionsTable[i] = PartitionTableEntry.Read(reader);

                if (header.PartitionsFSType == FilesystemType.Normal
                    || header.PartitionsFSType == FilesystemType.None)
                {
                    header.ExheaderHash = reader.ReadBytes(0x20);
                    header.AdditionalHeaderSize = reader.ReadUInt32();
                    header.SectorZeroOffset = reader.ReadUInt32();
                    header.partitionFlags = reader.ReadBytes(8);

                    header.PartitionIdTable = new byte[8][];
                    for (int i = 0; i < 8; i++)
                        header.PartitionIdTable[i] = reader.ReadBytes(8);
                    
                    header.Reserved1 = reader.ReadBytes(0x20);
                    header.Reserved2 = reader.ReadBytes(0xE);
                    header.FirmUpdateByte1 = reader.ReadByte();
                    header.FIrmUpdateByte2 = reader.ReadByte();
                }
                else if (header.PartitionsFSType == FilesystemType.FIRM)
                {
                    header.Unknown = reader.ReadBytes(0x5E);
                    header.EncryptedMBR = reader.ReadBytes(0x42);
                }

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

using System;
using System.IO;
using ThreeDS.Data;

namespace ThreeDS.Headers
{
    public class NCSDHeader
    {
        private const string NCSDMagicNumber = "NCSD";

        // Common to all NCSD files
        public byte[] RSA2048Signature = new byte[0x100];
        public uint ImageSizeInMediaUnits;
        public uint ImageSizeInBytes { get { return ImageSizeInMediaUnits * 0x200; } }
        public byte[] MediaId = new byte[8];
        public FilesystemType PartitionsFSType;
        public byte[] PartitionsCryptType = new byte[8];
        public PartitionTableEntry[] PartitionsTable = new PartitionTableEntry[8];

        // For carts
        public byte[] ExheaderHash = new byte[0x20];
        public uint AdditionalHeaderSize;
        public uint SectorZeroOffset;
        private byte[] partitionFlags = new byte[8];
        public byte BackupWriteWaitTime { get { return partitionFlags[(int)NCSDFlags.BackupWriteWaitTime]; } }
        public MediaCardDeviceType MediaCardDevice3X { get { return (MediaCardDeviceType)partitionFlags[(int)NCSDFlags.MediaCardDevice3X]; } }
        public MediaPlatformIndex MediaPlatformIndex { get { return (MediaPlatformIndex)partitionFlags[(int)NCSDFlags.MediaPlatformIndex]; } }
        public MediaTypeIndex MediaTypeIndex { get { return (MediaTypeIndex)partitionFlags[(int)NCSDFlags.MediaTypeIndex]; } }
        public uint SectorSize { get { return (uint)(0x200 * Math.Pow(2, partitionFlags[(int)NCSDFlags.MediaUnitSize])); } }
        public MediaCardDeviceType MediaCardDevice2X { get { return (MediaCardDeviceType)partitionFlags[(int)NCSDFlags.MediaCardDevice2X]; } }
        public byte[][] PartitionIdTable = new byte[8][];
        public byte[] ReservedBlock1 = new byte[0x20];
        public byte[] ReservedBlock2 = new byte[0xE];
        public byte FirmUpdateByte1;
        public byte FIrmUpdateByte2;

        // For NAND
        public byte[] Unknown = new byte[0x5E];
        public byte[] EncryptedMBR = new byte[0x42];

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

                for (int i = 0; i < 8; i++)
                    header.PartitionsTable[i] = PartitionTableEntry.Read(reader);

                if (header.PartitionsFSType == FilesystemType.Normal
                    || header.PartitionsFSType == FilesystemType.None)
                {
                    header.ExheaderHash = reader.ReadBytes(0x20);
                    header.AdditionalHeaderSize = reader.ReadUInt32();
                    header.SectorZeroOffset = reader.ReadUInt32();
                    header.partitionFlags = reader.ReadBytes(8);

                    for (int i = 0; i < 8; i++)
                        header.PartitionIdTable[i] = reader.ReadBytes(8);
                    
                    header.ReservedBlock1 = reader.ReadBytes(0x20);
                    header.ReservedBlock2 = reader.ReadBytes(0xE);
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

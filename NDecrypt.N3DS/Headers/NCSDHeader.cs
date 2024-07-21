using System;
using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class NCSDHeader
    {
        private const string NCSDMagicNumber = "NCSD";

        #region Common to all NCSD files

        /// <summary>
        /// RSA-2048 SHA-256 signature of the NCSD header
        /// </summary>
        public byte[]? RSA2048Signature { get; private set; }

        /// <summary>
        /// Size of the NCSD image, in media units (1 media unit = 0x200 bytes)
        /// </summary>
        public uint ImageSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Media ID
        /// </summary>
        public byte[]? MediaId { get; private set; }

        /// <summary>
        /// Partitions FS type (0=None, 1=Normal, 3=FIRM, 4=AGB_FIRM save)
        /// </summary>
        public FilesystemType PartitionsFSType { get; private set; }

        /// <summary>
        /// Partitions crypt type (each byte corresponds to a partition in the partition table)
        /// </summary>
        public byte[]? PartitionsCryptType { get; private set; }

        /// <summary>
        /// Offset & Length partition table, in media units
        /// </summary>
        public PartitionTableEntry[]? PartitionsTable { get; private set; }

        /// <summary>
        /// Partition table entry for Executable Content (CXI)
        /// </summary>
        public PartitionTableEntry ExecutableContent { get { return PartitionsTable![0]; } }

        /// <summary>
        /// Partition table entry for E-Manual (CFA)
        /// </summary>
        public PartitionTableEntry EManual { get { return PartitionsTable![1]; } }

        /// <summary>
        /// Partition table entry for Download Play Child container (CFA)
        /// </summary>
        public PartitionTableEntry DownloadPlayChildContainer { get { return PartitionsTable![2]; } }

        /// <summary>
        /// Partition table entry for New3DS Update Data (CFA)
        /// </summary>
        public PartitionTableEntry New3DSUpdateData { get { return PartitionsTable![6]; } }

        /// <summary>
        /// Partition table entry for Update Data (CFA)
        /// </summary>
        public PartitionTableEntry UpdateData { get { return PartitionsTable![7]; } }

        #endregion

        #region CTR Cart Image (CCI) Specific

        /// <summary>
        /// Exheader SHA-256 hash
        /// </summary>
        public byte[]? ExheaderHash { get; private set; }

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
        public byte[]? PartitionFlags { get; private set; }

        /// <summary>
        /// Backup Write Wait Time (The time to wait to write save to backup after the card is recognized (0-255
        /// seconds)).NATIVE_FIRM loads this flag from the gamecard NCSD header starting with 6.0.0-11.
        /// </summary>
        public byte BackupWriteWaitTime { get { return PartitionFlags![(int)NCSDFlags.BackupWriteWaitTime]; } }

        /// <summary>
        /// Media Card Device (1 = NOR Flash, 2 = None, 3 = BT) (SDK 3.X+)
        /// </summary>
        public MediaCardDeviceType MediaCardDevice3X { get { return (MediaCardDeviceType)PartitionFlags![(int)NCSDFlags.MediaCardDevice3X]; } }

        /// <summary>
        /// Media Platform Index (1 = CTR)
        /// </summary>
        public MediaPlatformIndex MediaPlatformIndex { get { return (MediaPlatformIndex)PartitionFlags![(int)NCSDFlags.MediaPlatformIndex]; } }

        /// <summary>
        /// Media Type Index (0 = Inner Device, 1 = Card1, 2 = Card2, 3 = Extended Device)
        /// </summary>
        public MediaTypeIndex MediaTypeIndex { get { return (MediaTypeIndex)PartitionFlags![(int)NCSDFlags.MediaTypeIndex]; } }

        /// <summary>
        /// Media Unit Size i.e. u32 MediaUnitSize = 0x200*2^flags[6];
        /// </summary>
        public uint MediaUnitSize { get { return (uint)(0x200 * Math.Pow(2, PartitionFlags![(int)NCSDFlags.MediaUnitSize])); } }

        /// <summary>
        /// Media Card Device (1 = NOR Flash, 2 = None, 3 = BT) (Only SDK 2.X)
        /// </summary>
        public MediaCardDeviceType MediaCardDevice2X { get { return (MediaCardDeviceType)PartitionFlags![(int)NCSDFlags.MediaCardDevice2X]; } }

        /// <summary>
        /// Partition ID table
        /// </summary>
        public byte[][]? PartitionIdTable { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[]? Reserved1 { get; private set; }

        /// <summary>
        /// Reserved?
        /// </summary>
        public byte[]? Reserved2 { get; private set; }

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
        public byte FirmUpdateByte2 { get; private set; }

        #endregion

        #region Raw NAND Format Specific

        /// <summary>
        /// Unknown
        /// </summary>
        public byte[]? Unknown { get; private set; }

        /// <summary>
        /// Encrypted MBR partition-table, for the TWL partitions(key-data used for this keyslot is console-unique).
        /// </summary>
        public byte[]? EncryptedMBR { get; private set; }

        #endregion

        #region Card Info Header

        /// <summary>
        /// CARD2: Writable Address In Media Units (For 'On-Chip' Savedata). CARD1: Always 0xFFFFFFFF.
        /// </summary>
        public byte[]? CARD2WritableAddressMediaUnits { get; private set; }

        /// <summary>
        /// Card Info Bitmask
        /// </summary>
        public byte[]? CardInfoBytemask { get; private set; }

        /// <summary>
        /// Reserved1
        /// </summary>
        public byte[]? Reserved3 { get; private set; }

        /// <summary>
        /// Title version
        /// </summary>
        public ushort TitleVersion { get; private set; }

        /// <summary>
        /// Card revision
        /// </summary>
        public ushort CardRevision { get; private set; }

        /// <summary>
        /// Reserved2
        /// </summary>
        public byte[]? Reserved4 { get; private set; }

        /// <summary>
        /// Card seed keyY (first u64 is Media ID (same as first NCCH partitionId))
        /// </summary>
        public byte[]? CardSeedKeyY { get; private set; }

        /// <summary>
        /// Encrypted card seed (AES-CCM, keyslot 0x3B for retail cards, see CTRCARD_SECSEED)
        /// </summary>
        public byte[]? EncryptedCardSeed { get; private set; }

        /// <summary>
        /// Card seed AES-MAC
        /// </summary>
        public byte[]? CardSeedAESMAC { get; private set; }

        /// <summary>
        /// Card seed nonce
        /// </summary>
        public byte[]? CardSeedNonce { get; private set; }

        /// <summary>
        /// Reserved3
        /// </summary>
        public byte[]? Reserved5 { get; private set; }

        /// <summary>
        /// Copy of first NCCH header (excluding RSA signature)
        /// </summary>
        public NCCHHeader? BackupHeader { get; private set; }

        #endregion

        #region Development Card Info Header Extension

        /// <summary>
        /// CardDeviceReserved1
        /// </summary>
        public byte[]? CardDeviceReserved1 { get; private set; }

        /// <summary>
        /// TitleKey
        /// </summary>
        public byte[]? TitleKey { get; private set; }

        /// <summary>
        /// CardDeviceReserved2
        /// </summary>
        public byte[]? CardDeviceReserved2 { get; private set; }

        #endregion

        /// <summary>
        /// Read from a stream and get an NCSD header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="development">True if development cart, false otherwise</param>
        /// <returns>NCSD header object, null on error</returns>
        public static NCSDHeader? Read(BinaryReader reader, bool development)
        {
            var header = new NCSDHeader();

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
                    header.PartitionsTable[i] = PartitionTableEntry.Read(reader)!;

                if (header.PartitionsFSType == FilesystemType.Normal
                    || header.PartitionsFSType == FilesystemType.None)
                {
                    header.ExheaderHash = reader.ReadBytes(0x20);
                    header.AdditionalHeaderSize = reader.ReadUInt32();
                    header.SectorZeroOffset = reader.ReadUInt32();
                    header.PartitionFlags = reader.ReadBytes(8);

                    header.PartitionIdTable = new byte[8][];
                    for (int i = 0; i < 8; i++)
                        header.PartitionIdTable[i] = reader.ReadBytes(8);
                    
                    header.Reserved1 = reader.ReadBytes(0x20);
                    header.Reserved2 = reader.ReadBytes(0xE);
                    header.FirmUpdateByte1 = reader.ReadByte();
                    header.FirmUpdateByte2 = reader.ReadByte();

                    header.CARD2WritableAddressMediaUnits = reader.ReadBytes(4);
                    header.CardInfoBytemask = reader.ReadBytes(4);
                    header.Reserved3 = reader.ReadBytes(0x108);
                    header.TitleVersion = reader.ReadUInt16();
                    header.CardRevision = reader.ReadUInt16();
                    header.Reserved4 = reader.ReadBytes(0xCEC); // Incorrectly documented as 0xCEE
                    header.CardSeedKeyY = reader.ReadBytes(0x10);
                    header.EncryptedCardSeed = reader.ReadBytes(0x10);
                    header.CardSeedAESMAC = reader.ReadBytes(0x10);
                    header.CardSeedNonce = reader.ReadBytes(0xC);
                    header.Reserved5 = reader.ReadBytes(0xC4);
                    header.BackupHeader = NCCHHeader.Read(reader, readSignature: false);

                    if (development)
                    {
                        header.CardDeviceReserved1 = reader.ReadBytes(0x200);
                        header.TitleKey = reader.ReadBytes(0x10);
                        header.CardDeviceReserved2 = reader.ReadBytes(0xF0);
                    }
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

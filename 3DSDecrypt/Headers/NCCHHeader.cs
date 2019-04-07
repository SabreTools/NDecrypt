using System.IO;
using System.Linq;
using ThreeDS.Data;

namespace ThreeDS.Headers
{
    public class NCCHHeader
    {
        private const string NCCHMagicNumber = "NCCH";

        public byte[] RSA2048Signature = new byte[0x100];
        public uint ContentSizeInMediaUnits;
        public uint ContentSizeInBytes { get { return ContentSizeInMediaUnits * 0x200; } }
        public byte[] PartitionId = new byte[8];
        public byte[] PlainIV { get { return PartitionId.Concat(Constants.PlainCounter).ToArray(); } }
        public byte[] ExeFSIV { get { return PartitionId.Concat(Constants.ExefsCounter).ToArray(); } }
        public byte[] RomFSIV { get { return PartitionId.Concat(Constants.RomfsCounter).ToArray(); } }
        public byte[] MakerCode = new byte[2];
        public byte[] Version = new byte[2];
        public byte[] VerificationHash = new byte[4];
        public byte[] ProgramId = new byte[4];
        public byte[] Reserved1 = new byte[0x10];
        public byte[] LogoRegionHash = new byte[0x20];
        public byte[] ProductCode = new byte[0x10];
        public byte[] ExtendedHeaderHash = new byte[0x20];
        public uint ExtendedHeaderSizeInBytes;
        public byte[] Reserved2 = new byte[4];
        public NCCHHeaderFlags Flags;
        public uint PlainRegionOffsetInMediaUnits;
        public uint PlainRegionOffsetInBytes { get { return PlainRegionOffsetInMediaUnits * 0x200; } }
        public uint PlainRegionSizeInMediaUnits;
        public uint PlainRegionSizeInBytes { get { return PlainRegionSizeInMediaUnits * 0x200; } }
        public uint LogoRegionOffsetInMediaUnits;
        public uint LogoRegionOffsetInBytes { get { return LogoRegionOffsetInMediaUnits * 0x200; } }
        public uint LogoRegionSizeInMediaUnits;
        public uint LogoRegionSizeInBytes { get { return LogoRegionSizeInMediaUnits * 0x200; } }
        public uint ExeFSOffsetInMediaUnits;
        public uint ExeFSOffsetInBytes { get { return ExeFSOffsetInMediaUnits * 0x200; } }
        public uint ExeFSSizeInMediaUnits;
        public uint ExeFSSizeInBytes { get { return ExeFSSizeInMediaUnits * 0x200; } }
        public uint ExeFSHashRegionOffsetInMediaUnits;
        public uint ExeFSHashRegionOffsetInBytes { get { return ExeFSHashRegionOffsetInMediaUnits * 0x200; } }
        public uint ExeFSHashRegionSizeInMediaUnits;
        public uint ExeFSHashRegionSizeInBytes { get { return ExeFSHashRegionSizeInMediaUnits * 0x200; } }
        public uint RomFSOffsetInMediaUnits;
        public uint RomFSOffsetInBytes { get { return RomFSOffsetInMediaUnits * 0x200; } }
        public uint RomFSSizeInMediaUnits;
        public uint RomFSSizeInBytes { get { return RomFSSizeInMediaUnits * 0x200; } }
        public uint RomFSHashRegionOffsetInMediaUnits;
        public uint RomFSHashRegionOffsetInBytes { get { return RomFSHashRegionOffsetInMediaUnits * 0x200; } }
        public uint RomFSHashRegionSizeInMediaUnits;
        public uint RomFSHashRegionSizeInBytes { get { return RomFSHashRegionSizeInMediaUnits * 0x200; } }
        public byte[] ExeFSSuperblockHash = new byte[0x20];
        public byte[] RomFSSuperblockHash = new byte[0x20];

        public static NCCHHeader Read(BinaryReader reader)
        {
            NCCHHeader header = new NCCHHeader();

            try
            {
                header.RSA2048Signature = reader.ReadBytes(0x100);

                if (new string(reader.ReadChars(4)) != NCCHMagicNumber)
                    return null;

                header.ContentSizeInMediaUnits = reader.ReadUInt32();
                header.PartitionId = reader.ReadBytes(8).Reverse().ToArray();
                header.MakerCode = reader.ReadBytes(2);
                header.Version = reader.ReadBytes(2);
                header.VerificationHash = reader.ReadBytes(4);
                header.ProgramId = reader.ReadBytes(8);
                header.Reserved1 = reader.ReadBytes(0x10);
                header.LogoRegionHash = reader.ReadBytes(0x20);
                header.ProductCode = reader.ReadBytes(0x10);
                header.ExtendedHeaderHash = reader.ReadBytes(0x20);
                header.ExtendedHeaderSizeInBytes = reader.ReadUInt32();
                header.Reserved2 = reader.ReadBytes(4);
                header.Flags = NCCHHeaderFlags.Read(reader);
                header.PlainRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.PlainRegionSizeInMediaUnits = reader.ReadUInt32();
                header.LogoRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.LogoRegionSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSOffsetInMediaUnits = reader.ReadUInt32();
                header.ExeFSSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSHashRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.ExeFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.RomFSOffsetInMediaUnits = reader.ReadUInt32();
                header.RomFSSizeInMediaUnits = reader.ReadUInt32();
                header.RomFSHashRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.RomFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSSuperblockHash = reader.ReadBytes(0x20);
                header.RomFSSuperblockHash = reader.ReadBytes(0x20);

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

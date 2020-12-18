using System.IO;

namespace NDecrypt.N3DS.Headers
{
    // https://www.3dbrew.org/wiki/RomFS
    internal class RomFSHeader
    {
        private const string RomFSMagicNumber = "IVFC";
        private const uint RomFSSecondMagicNumber = 0x10000;

        /// <summary>
        /// Master hash size
        /// </summary>
        public uint MasterHashSize { get; private set; }

        /// <summary>
        /// Level 1 logical offset
        /// </summary>
        public ulong Level1LogicalOffset { get; private set; }

        /// <summary>
        /// Level 1 hashdata size
        /// </summary>
        public ulong Level1HashdataSize { get; private set; }

        /// <summary>
        /// Level 1 block size, in log2
        /// </summary>
        public uint Level1BlockSizeLog2 { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved1 { get; private set; }

        /// <summary>
        /// Level 2 logical offset
        /// </summary>
        public ulong Level2LogicalOffset { get; private set; }

        /// <summary>
        /// Level 2 hashdata size
        /// </summary>
        public ulong Level2HashdataSize { get; private set; }

        /// <summary>
        /// Level 2 block size, in log2
        /// </summary>
        public uint Level2BlockSizeLog2 { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved2 { get; private set; }

        /// <summary>
        /// Level 3 logical offset
        /// </summary>
        public ulong Level3LogicalOffset { get; private set; }

        /// <summary>
        /// Level 3 hashdata size
        /// </summary>
        public ulong Level3HashdataSize { get; private set; }

        /// <summary>
        /// Level 3 block size, in log2
        /// </summary>
        public uint Level3BlockSizeLog2 { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved3 { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved4 { get; private set; }

        /// <summary>
        /// Optional info size.
        /// </summary>
        public uint OptionalInfoSize { get; private set; }

        /// <summary>
        /// Read from a stream and get a RomFS header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>RomFS header object, null on error</returns>
        public static RomFSHeader Read(BinaryReader reader)
        {
            RomFSHeader header = new RomFSHeader();

            try
            {
                if (new string(reader.ReadChars(4)) != RomFSMagicNumber)
                    return null;

                if (reader.ReadUInt32() != RomFSSecondMagicNumber)
                    return null;

                header.MasterHashSize = reader.ReadUInt32();
                header.Level1LogicalOffset = reader.ReadUInt64();
                header.Level1HashdataSize = reader.ReadUInt64();
                header.Level1BlockSizeLog2 = reader.ReadUInt32();
                header.Reserved1 = reader.ReadBytes(4);
                header.Level2LogicalOffset = reader.ReadUInt64();
                header.Level2HashdataSize = reader.ReadUInt64();
                header.Level2BlockSizeLog2 = reader.ReadUInt32();
                header.Reserved2 = reader.ReadBytes(4);
                header.Level3LogicalOffset = reader.ReadUInt64();
                header.Level3HashdataSize = reader.ReadUInt64();
                header.Level3BlockSizeLog2 = reader.ReadUInt32();
                header.Reserved3 = reader.ReadBytes(4);
                header.Reserved4 = reader.ReadBytes(4);
                header.OptionalInfoSize = reader.ReadUInt32();

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

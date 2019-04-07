using System.IO;

namespace ThreeDS.Headers
{
    public class ExeFSFileHeader
    {
        private const string codeSegment = ".code\0\0\0";

        public string FileName;
        public bool IsCodeBinary { get { return FileName == codeSegment; } }
        public uint FileOffset;
        public uint FileSize;
        public byte[] FileHash = new byte[0x20];

        public static ExeFSFileHeader Read(BinaryReader reader)
        {
            ExeFSFileHeader header = new ExeFSFileHeader();

            try
            {
                header.FileName = new string(reader.ReadChars(8));
                header.FileOffset = reader.ReadUInt32();
                header.FileSize = reader.ReadUInt32();
                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

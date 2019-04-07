using System.IO;
using System.Linq;
using System.Text;

namespace ThreeDS.Headers
{
    public class ExeFSFileHeader
    {
        private const string codeSegment = ".code\0\0\0";
        private readonly byte[] codeSegmentBytes = new byte[] { 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00 };

        public byte[] FileName = new byte[8];
        public string ReadableFileName { get { return Encoding.ASCII.GetString(FileName); } }
        public bool IsCodeBinary { get { return Enumerable.SequenceEqual(FileName, codeSegmentBytes); } }
        public uint FileOffset;
        public uint FileSize;
        public byte[] FileHash = new byte[0x20];

        public static ExeFSFileHeader Read(BinaryReader reader)
        {
            ExeFSFileHeader header = new ExeFSFileHeader();

            try
            {
                header.FileName = reader.ReadBytes(8);
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

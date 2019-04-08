using System.IO;
using System.Linq;
using System.Text;

namespace ThreeDS.Headers
{
    public class ExeFSFileHeader
    {
        private const string codeSegment = ".code\0\0\0";
        private readonly byte[] codeSegmentBytes = new byte[] { 0x2e, 0x63, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00 };

        /// <summary>
        /// File name
        /// </summary>
        public byte[] FileName { get; private set; }
        public string ReadableFileName { get { return Encoding.ASCII.GetString(FileName); } }
        public bool IsCodeBinary { get { return Enumerable.SequenceEqual(FileName, codeSegmentBytes); } }

        /// <summary>
        /// File offset
        /// </summary>
        public uint FileOffset { get; private set; }

        /// <summary>
        /// File size
        /// </summary>
        public uint FileSize { get; private set; }

        /// <summary>
        /// SHA256 hash calculated over the entire file contents
        /// </summary>
        public byte[] FileHash { get; set; }

        /// <summary>
        /// Read from a stream and get an ExeFS file header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ExeFS file header object, null on error</returns>
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

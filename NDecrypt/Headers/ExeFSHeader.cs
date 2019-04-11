using System.IO;

namespace NDecrypt.Headers
{
    public class ExeFSHeader
    {
        /// <summary>
        /// File headers (10 headers maximum, 16 bytes each)
        /// </summary>
        public ExeFSFileHeader[] FileHeaders { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved { get; private set; }

        /// <summary>
        /// Read from a stream and get an ExeFS header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ExeFS header object, null on error</returns>
        public static ExeFSHeader Read(BinaryReader reader)
        {
            ExeFSHeader header = new ExeFSHeader();

            try
            {
                header.FileHeaders = new ExeFSFileHeader[10];
                for (int i = 0; i < 10; i++)
                    header.FileHeaders[i] = ExeFSFileHeader.Read(reader);

                header.Reserved = reader.ReadBytes(0x20);

                for (int i = 0; i < 10; i++)
                    header.FileHeaders[9 - i].FileHash = reader.ReadBytes(0x20);

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

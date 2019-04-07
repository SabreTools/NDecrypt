using System.IO;

namespace ThreeDS.Headers
{
    public class ExeFSHeader
    {
        public ExeFSFileHeader[] FileHeaders = new ExeFSFileHeader[10];
        public byte[] Reserved = new byte[0x20];

        public static ExeFSHeader Read(BinaryReader reader)
        {
            ExeFSHeader header = new ExeFSHeader();

            try
            {
                for (int i = 0; i < 10; i++)
                    header.FileHeaders[i] = ExeFSFileHeader.Read(reader);

                header.Reserved = reader.ReadBytes(0x20);

                for (int i = 0; i < 10; i++)
                {
                    byte[] fileHash = reader.ReadBytes(0x20);
                    header.FileHeaders[9 - i].FileHash = fileHash;
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

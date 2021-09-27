using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class ContentInfoRecord
    {
        /// <summary>
        /// Content index offset
        /// </summary>
        public ushort ContentIndexOffset { get; private set; }

        /// <summary>
        /// Content command count [k]
        /// </summary>
        public ushort ContentCommandCount { get; private set; }

        /// <summary>
        /// SHA-256 hash of the next k content records that have not been hashed yet
        /// </summary>
        public byte[] UnhashedContentRecordsSHA256Hash { get; private set; }

        /// <summary>
        /// Read from a stream and get content info record, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Content info record object, null on error</returns>
        public static ContentInfoRecord Read(BinaryReader reader)
        {
            ContentInfoRecord cir = new ContentInfoRecord();

            try
            {
                cir.ContentIndexOffset = reader.ReadUInt16();
                cir.ContentCommandCount = reader.ReadUInt16();
                cir.UnhashedContentRecordsSHA256Hash = reader.ReadBytes(0x20);
                return cir;
            }
            catch
            {
                return null;
            }
        }
    }
}
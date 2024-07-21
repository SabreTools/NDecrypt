using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class ContentChunkRecord
    {
        /// <summary>
        /// Content id
        /// </summary>
        public uint ContentId { get; private set; }

        /// <summary>
        /// Content index
        /// </summary>
        /// <remarks>
        /// This does not apply to DLC.
        /// </remarks>
        public ContentIndex ContentIndex { get; private set; }

        /// <summary>
        /// Content type
        /// </summary>
        public TMDContentType ContentType { get; private set; }

        /// <summary>
        /// Content size
        /// </summary>
        public ulong ContentSize { get; private set; }

        /// <summary>
        /// SHA-256 hash
        /// </summary>
        public byte[]? SHA256Hash { get; private set; }

        /// <summary>
        /// Read from a stream and get content chunk record, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Content chunk record object, null on error</returns>
        public static ContentChunkRecord? Read(BinaryReader reader)
        {
            var ccr = new ContentChunkRecord();

            try
            {
                ccr.ContentId = reader.ReadUInt32();
                ccr.ContentIndex = (ContentIndex)reader.ReadUInt16();
                ccr.ContentType = (TMDContentType)reader.ReadUInt16();
                ccr.ContentSize = reader.ReadUInt64();
                ccr.SHA256Hash = reader.ReadBytes(0x20);
                return ccr;
            }
            catch
            {
                return null;
            }
        }
    }
}
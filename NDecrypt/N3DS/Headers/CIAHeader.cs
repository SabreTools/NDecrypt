using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class CIAHeader
    {
        /// <summary>
        /// Archive header size, usually 0x2020 bytes
        /// </summary>
        public uint HeaderSize { get; private set; }

        /// <summary>
        /// Type
        /// </summary>
        public ushort Type { get; private set; }

        /// <summary>
        /// Version
        /// </summary>
        public ushort Version { get; private set; }

        /// <summary>
        /// Certificate chain size
        /// </summary>
        public int CertificateChainSize { get; private set; }

        /// <summary>
        /// Ticket size
        /// </summary>
        public int TicketSize { get; private set; }

        /// <summary>
        /// TMD file size
        /// </summary>
        public int TMDFileSize { get; private set; }

        /// <summary>
        /// Meta size (0 if no Meta data is present)
        /// </summary>
        public int MetaSize { get; private set; }

        /// <summary>
        /// Content size
        /// </summary>
        public long ContentSize { get; private set; }

        /// <summary>
        /// Content Index
        /// </summary>
        public byte[] ContentIndex { get; private set; }

        /// <summary>
        /// Certificate chain
        /// </summary>
        public byte[] CertificateChain { get; set; }

        /// <summary>
        /// Ticket
        /// </summary>
        public byte[] Ticket { get; set; }

        /// <summary>
        /// TMD file data
        /// </summary>
        public byte[] TMDFileData { get; set; }

        /// <summary>
        /// Content file data
        /// </summary>
        public byte[] ContentFileData { get; set; }

        /// <summary>
        /// Meta file data (Not a necessary component)
        /// </summary>
        public MetaFile MetaFileData { get; set; }

        /// <summary>
        /// Read from a stream and get a CIA header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>CIA header object, null on error</returns>
        public static CIAHeader Read(BinaryReader reader)
        {
            CIAHeader header = new CIAHeader();

            try
            {
                header.HeaderSize = reader.ReadUInt32();
                header.Type = reader.ReadUInt16();
                header.Version = reader.ReadUInt16();
                header.CertificateChainSize = reader.ReadInt32();
                header.TicketSize = reader.ReadInt32();
                header.TMDFileSize = reader.ReadInt32();
                header.MetaSize = reader.ReadInt32();
                header.ContentSize = reader.ReadInt64();
                header.ContentIndex = reader.ReadBytes(0x2000);

                header.CertificateChain = reader.ReadBytes(header.CertificateChainSize);
                header.Ticket = reader.ReadBytes(header.TicketSize);
                header.TMDFileData = reader.ReadBytes(header.TMDFileSize);
                header.ContentFileData = reader.ReadBytes((int)header.ContentSize);
                
                if (header.MetaSize > 0)
                    header.MetaFileData = MetaFile.Read(reader);

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}
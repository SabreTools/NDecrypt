using System.Collections.Generic;
using System.IO;

namespace NDecrypt.N3DS.Headers
{
    // https://www.3dbrew.org/wiki/CIA
    internal class CIAHeader
    {
        /// <summary>
        /// Archive header size, usually 0x2020 bytes
        /// </summary>
        public int HeaderSize { get; private set; }

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
        public byte[]? ContentIndex { get; private set; }

        #region Content Index

        /// <summary>
        /// Certificate chain
        /// </summary>
        /// <remarks>
        /// https://www.3dbrew.org/wiki/CIA#Certificate_Chain
        /// </remarks>
        public Certificate[]? CertificateChain { get; set; }

        /// <summary>
        /// Ticket
        /// </summary>
        public Ticket? Ticket { get; set; }

        /// <summary>
        /// TMD file data
        /// </summary>
        public TitleMetadata? TMDFileData { get; set; }

        /// <summary>
        /// Content file data
        /// </summary>
        public NCCHHeader[]? Partitions { get; set; }

        /// <summary>
        /// Meta file data (Not a necessary component)
        /// </summary>
        public MetaFile? MetaFileData { get; set; }

        #endregion

        /// <summary>
        /// Read from a stream and get a CIA header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>CIA header object, null on error</returns>
        public static CIAHeader? Read(BinaryReader reader)
        {
            var header = new CIAHeader();

            try
            {
                header.HeaderSize = reader.ReadInt32();
                header.Type = reader.ReadUInt16();
                header.Version = reader.ReadUInt16();
                header.CertificateChainSize = reader.ReadInt32();
                header.TicketSize = reader.ReadInt32();
                header.TMDFileSize = reader.ReadInt32();
                header.MetaSize = reader.ReadInt32();
                header.ContentSize = reader.ReadInt64();
                header.ContentIndex = reader.ReadBytes(0x2000);
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                header.CertificateChain = new Certificate[3];
                header.CertificateChain[0] = Certificate.Read(reader)!; // CA
                header.CertificateChain[1] = Certificate.Read(reader)!; // Ticket
                header.CertificateChain[2] = Certificate.Read(reader)!; // TMD
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                header.Ticket = Ticket.Read(reader, header.TicketSize);
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                header.TMDFileData = TitleMetadata.Read(reader, header.TMDFileSize);
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                long startingPosition = reader.BaseStream.Position;
                List<NCCHHeader> headers = new List<NCCHHeader>();
                while (reader.BaseStream.Position < startingPosition + header.ContentSize)
                {
                    long initPosition = reader.BaseStream.Position;
                    NCCHHeader? ncchHeader = NCCHHeader.Read(reader, readSignature: true);
                    if (ncchHeader == null)
                        break;

                    headers.Add(ncchHeader);
                    reader.BaseStream.Seek(initPosition + ncchHeader.ContentSizeInMediaUnits * 0x200, SeekOrigin.Begin);
                }

                header.Partitions = headers.ToArray();
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
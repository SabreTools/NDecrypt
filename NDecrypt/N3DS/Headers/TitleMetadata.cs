using System.IO;

namespace NDecrypt.N3DS.Headers
{
    // https://www.3dbrew.org/wiki/Title_metadata
    internal class TitleMetadata
    {
        /// <summary>
        /// Signature Type
        /// </summary>
        public SignatureType SignatureType { get; private set; }

        /// <summary>
        /// Signature size
        /// </summary>
        public ushort SignatureSize { get; private set; }

        /// <summary>
        /// Padding size
        /// </summary>
        public byte PaddingSize { get; private set; }

        /// <summary>
        /// Signature
        /// </summary>
        public byte[] Signature { get; private set; }

        /// <summary>
        /// Signature Issuer
        /// </summary>
        public byte[] SignatureIssuer { get; private set; }

        /// <summary>
        /// Version
        /// </summary>
        public byte Version { get; private set; }
        
        /// <summary>
        /// CaCrlVersion
        /// </summary>
        public byte CaCrlVersion { get; private set; }

        /// <summary>
        /// SignerCrlVersion
        /// </summary>
        public byte SignerCrlVersion { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte Reserved1 { get; private set; }

        /// <summary>
        /// System Version
        /// </summary>
        public ulong SystemVersion { get; private set; }

        /// <summary>
        /// TitleID
        /// </summary>
        public ulong TitleID { get; private set; }

        /// <summary>
        /// Title Type
        /// </summary>
        public uint TitleType { get; private set; }

        /// <summary>
        /// Group ID
        /// </summary>
        public ushort GroupID { get; private set; }

        /// <summary>
        /// Save Data Size in Little Endian (Bytes) (Also SRL Public Save Data Size)
        /// </summary>
        public uint SaveDataSize { get; private set; }

        /// <summary>
        /// SRL Private Save Data Size in Little Endian (Bytes)
        /// </summary>
        public uint SRLPrivateSaveDataSize { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public uint Reserved2 { get; private set; }

        /// <summary>
        /// SRL Flag
        /// </summary>
        public byte SRLFlag { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved3 { get; private set; }

        /// <summary>
        /// Access Rights
        /// </summary>
        public uint AccessRights { get; private set; }

        /// <summary>
        /// Title Version
        /// </summary>
        public ushort TitleVersion { get; private set; }

        /// <summary>
        /// Content Count
        /// </summary>
        public ushort ContentCount { get; private set; }

        /// <summary>
        /// Boot Content
        /// </summary>
        public ushort BootContent { get; private set; }

        /// <summary>
        /// Padding
        /// </summary>
        public ushort Padding { get; private set; }

        /// <summary>
        /// SHA-256 Hash of the Content Info Records
        /// </summary>
        public byte[] SHA256HashContentInfoRecords { get; private set; }

        /// <summary>
        /// There are 64 of these records, usually only the first is used.
        /// </summary>
        public ContentInfoRecord[] ContentInfoRecords { get; private set; }

        /// <summary>
        /// There is one of these for each content contained in this title.
        /// (Determined by "Content Count" in the TMD Header).
        /// </summary>
        public ContentChunkRecord[] ContentChunkRecords { get; private set; }

        /// <summary>
        /// Read from a stream and get ticket metadata, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="metadataSize">Metadata size from the header</param>
        /// <returns>Title metadata object, null on error</returns>
        public static TitleMetadata Read(BinaryReader reader, int metadataSize)
        {
            TitleMetadata tm = new TitleMetadata();

            try
            {
                tm.SignatureType = (SignatureType)reader.ReadUInt32();
                switch (tm.SignatureType)
                {
                    case SignatureType.RSA_4096_SHA1:
                    case SignatureType.RSA_4096_SHA256:
                        tm.SignatureSize = 0x200;
                        tm.PaddingSize = 0x3C;
                        break;
                    case SignatureType.RSA_2048_SHA1:
                    case SignatureType.RSA_2048_SHA256:
                        tm.SignatureSize = 0x100;
                        tm.PaddingSize = 0x3C;
                        break;
                    case SignatureType.ECDSA_SHA1:
                    case SignatureType.ECDSA_SHA256:
                        tm.SignatureSize = 0x03C;
                        tm.PaddingSize = 0x40;
                        break;
                }

                tm.Signature = reader.ReadBytes(tm.SignatureSize);
                reader.ReadBytes(tm.PaddingSize); // Padding
                tm.SignatureIssuer = reader.ReadBytes(0x40);
                tm.Version = reader.ReadByte();
                tm.CaCrlVersion = reader.ReadByte();
                tm.SignerCrlVersion = reader.ReadByte();
                tm.Reserved1 = reader.ReadByte();
                tm.SystemVersion = reader.ReadUInt64();
                tm.TitleID = reader.ReadUInt64();
                tm.TitleType = reader.ReadUInt32();
                tm.GroupID = reader.ReadUInt16();
                tm.SaveDataSize = reader.ReadUInt32();
                tm.SRLPrivateSaveDataSize = reader.ReadUInt32();
                tm.Reserved2 = reader.ReadUInt32();
                tm.SRLFlag = reader.ReadByte();
                tm.Reserved3 = reader.ReadBytes(0x31);
                tm.AccessRights = reader.ReadUInt32();
                tm.TitleVersion = reader.ReadUInt16();
                tm.ContentCount = reader.ReadUInt16();
                tm.BootContent = reader.ReadUInt16();
                tm.Padding = reader.ReadUInt16();
                tm.SHA256HashContentInfoRecords = reader.ReadBytes(0x20);

                tm.ContentInfoRecords = new ContentInfoRecord[64];
                for (int i = 0; i < 64; i++)
                {
                    tm.ContentInfoRecords[i] = ContentInfoRecord.Read(reader);
                }

                tm.ContentChunkRecords = new ContentChunkRecord[tm.ContentCount];
                for (int i = 0; i < tm.ContentCount; i++)
                {
                    tm.ContentChunkRecords[i] = ContentChunkRecord.Read(reader);
                }

                return tm;
            }
            catch
            {
                return null;
            }
        }
    }
}
using System.IO;

namespace NDecrypt.N3DS.Headers
{
    // https://www.3dbrew.org/wiki/Ticket
    internal class Ticket
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
        /// Issuer
        /// </summary>
        public byte[] Issuer { get; private set; }

        /// <summary>
        /// ECC PublicKey
        /// </summary>
        public byte[] ECCPublicKey { get; private set; }

        /// <summary>
        /// Version (For 3DS this is always 1)
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
        /// TitleKey (normal-key encrypted using one of the common keyYs; see below)
        /// </summary>
        /// <remarks>
        /// The titlekey is decrypted by using the AES engine with the ticket common-key keyslot.
        /// The keyY is selected through an index (ticket offset 0xB1) into a plaintext array
        /// of 6 keys ("common keyYs") stored in the data section of Process9. AES-CBC mode is used
        /// where the IV is the big-endian titleID. Note that on a retail unit index0 is a retail keyY,
        /// while on a dev-unit index0 is the dev common-key which is a normal-key.
        /// (On retail for these keyYs, the hardware key-scrambler is used)
        /// 
        /// The titlekey is used to decrypt content downloaded from the CDN using 128-bit AES-CBC with
        /// the content index (as big endian u16, padded with trailing zeroes) as the IV.
        /// </remarks>
        public byte[] TitleKey { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte Reserved1 { get; private set; }

        /// <summary>
        /// TicketID
        /// </summary>
        public ulong TicketID { get; private set; }

        /// <summary>
        /// ConsoleID
        /// </summary>
        public uint ConsoleID { get; private set; }

        /// <summary>
        /// TitleID
        /// </summary>
        public ulong TitleID { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public ushort Reserved2 { get; private set; }

        /// <summary>
        /// Ticket title version
        /// </summary>
        /// <remarks>
        /// The Ticket Title Version is generally the same as the title version stored in the
        /// Title Metadata. Although it doesn't have to match the TMD version to be valid.
        /// </remarks>
        public ushort TicketTitleVersion { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public ulong Reserved3 { get; private set; }

        /// <summary>
        /// License Type
        /// </summary>
        public byte LicenseType { get; private set; }

        /// <summary>
        /// Index to the common keyY used for this ticket, usually 0x1 for retail system titles;
        /// see below.
        /// </summary>
        public byte CommonKeyYIndex { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved4 { get; private set; }

        /// <summary>
        /// eShop Account ID?
        /// </summary>
        public uint eShopAccountID { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte Reserved5 { get; private set; }

        /// <summary>
        /// Audit
        /// </summary>
        public byte Audit { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved6 { get; private set; }

        /// <summary>
        /// Limits
        /// </summary>
        /// <remarks>
        /// In demos, the first u32 in the "Limits" section is 0x4, then the second u32 is the max-playcount.
        /// </remarks>
        public byte[] Limits { get; private set; }

        /// <summary>
        /// The Content Index of a ticket has its own size defined within itself,
        /// with seemingly a minimal of 20 bytes, the second u32 in big endian defines
        /// the full value of X.
        /// </summary>
        public int ContentIndexSize { get; private set; }

        /// <summary>
        /// Content Index
        /// </summary>
        /// <remarks>
        /// The Content Index of a ticket has its own size defined within itself,
        /// with seemingly a minimal of 20 bytes, the second u32 in big endian defines
        /// the full value of X.
        /// </remarks>
        public byte[] ContentIndex { get; private set; }

        /// <summary>
        /// Certificate chain
        /// </summary>
        /// <remarks>
        /// https://www.3dbrew.org/wiki/Ticket#Certificate_Chain
        /// </remarks>
        public Certificate[] CertificateChain { get; set; }

        /// <summary>
        /// Read from a stream and get ticket, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="ticketSize">Ticket size from the header</param>
        /// <returns>Ticket object, null on error</returns>
        public static Ticket Read(BinaryReader reader, int ticketSize)
        {
            Ticket tk = new Ticket();

            try
            {
                tk.SignatureType = (SignatureType)reader.ReadUInt32();
                switch (tk.SignatureType)
                {
                    case SignatureType.RSA_4096_SHA1:
                    case SignatureType.RSA_4096_SHA256:
                        tk.SignatureSize = 0x200;
                        tk.PaddingSize = 0x3C;
                        break;
                    case SignatureType.RSA_2048_SHA1:
                    case SignatureType.RSA_2048_SHA256:
                        tk.SignatureSize = 0x100;
                        tk.PaddingSize = 0x3C;
                        break;
                    case SignatureType.ECDSA_SHA1:
                    case SignatureType.ECDSA_SHA256:
                        tk.SignatureSize = 0x03C;
                        tk.PaddingSize = 0x40;
                        break;
                }

                tk.Signature = reader.ReadBytes(tk.SignatureSize);
                reader.ReadBytes(tk.PaddingSize); // Padding
                tk.Issuer = reader.ReadBytes(0x40);
                tk.ECCPublicKey = reader.ReadBytes(0x3C);
                tk.Version = reader.ReadByte();
                tk.CaCrlVersion = reader.ReadByte();
                tk.SignerCrlVersion = reader.ReadByte();
                tk.TitleKey = reader.ReadBytes(0x10);
                tk.Reserved1 = reader.ReadByte();
                tk.TicketID = reader.ReadUInt64();
                tk.ConsoleID = reader.ReadUInt32();
                tk.TitleID = reader.ReadUInt64();
                tk.Reserved2 = reader.ReadUInt16();
                tk.TicketTitleVersion = reader.ReadUInt16();
                tk.Reserved3 = reader.ReadUInt64();
                tk.LicenseType = reader.ReadByte();
                tk.CommonKeyYIndex = reader.ReadByte();
                tk.Reserved4 = reader.ReadBytes(0x2A);
                tk.eShopAccountID = reader.ReadUInt32();
                tk.Reserved5 = reader.ReadByte();
                tk.Audit = reader.ReadByte();
                tk.Reserved6 = reader.ReadBytes(0x42);
                tk.Limits = reader.ReadBytes(0x40);
                reader.ReadBytes(4);
                tk.ContentIndexSize = reader.ReadInt32();
                reader.BaseStream.Seek(-8, SeekOrigin.Current);
                tk.ContentIndex = reader.ReadBytes(tk.ContentIndexSize);

                if (ticketSize - (0x164 + tk.ContentIndexSize) > 0)
                {
                    tk.CertificateChain = new Certificate[2];
                    tk.CertificateChain[0] = Certificate.Read(reader); // Ticket
                    tk.CertificateChain[1] = Certificate.Read(reader); // CA
                }

                return tk;
            }
            catch
            {
                return null;
            }
        }
    }
}

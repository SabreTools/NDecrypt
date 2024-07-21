using System.IO;
using System.Text;

namespace NDecrypt.N3DS.Headers
{
    // https://www.3dbrew.org/wiki/Certificates
    internal class Certificate
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
        public byte[]? Signature { get; private set; }

        /// <summary>
        /// Issuer
        /// </summary>
        public byte[]? Issuer { get; private set; }

        /// <summary>
        /// Issuer as a trimmed string
        /// </summary>
        public string? IssuerString => Issuer != null && Issuer.Length > 0
            ? Encoding.ASCII.GetString(Issuer)?.TrimEnd('\0')
            : null;

        /// <summary>
        /// Key Type
        /// </summary>
        public PublicKeyType KeyType { get; private set; }

        /// <summary>
        /// Name
        /// </summary>
        public byte[]? Name { get; private set; }

        /// <summary>
        /// Name as a trimmed string
        /// </summary>
        public string? NameString => Name != null && Name.Length > 0
            ? Encoding.ASCII.GetString(Name)?.TrimEnd('\0')
            : null;

        /// <summary>
        /// Expiration time as UNIX Timestamp, used at least for CTCert
        /// </summary>
        public uint ExpirationTime { get; private set; }

        // This contains the Public Key(i.e. Modulus & Public Exponent)
        #region RSA

        /// <summary>
        /// Modulus
        /// </summary>
        public byte[]? Modulus { get; private set; }

        /// <summary>
        /// Public Exponent
        /// </summary>
        public uint PublicExponent { get; private set; }

        #endregion

        // This contains the ECC public key, and is as follows:
        #region ECC

        /// <summary>
        /// Public Key
        /// </summary>
        public byte[]? PublicKey { get; private set; }

        #endregion

        /// <summary>
        /// Read from a stream and get certificate, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Certificate object, null on error</returns>
        public static Certificate? Read(BinaryReader reader)
        {
            var ct = new Certificate();

            try
            {
                ct.SignatureType = (SignatureType)reader.ReadUInt32();
                switch (ct.SignatureType)
                {
                    case SignatureType.RSA_4096_SHA1:
                    case SignatureType.RSA_4096_SHA256:
                        ct.SignatureSize = 0x200;
                        ct.PaddingSize = 0x3C;
                        break;
                    case SignatureType.RSA_2048_SHA1:
                    case SignatureType.RSA_2048_SHA256:
                        ct.SignatureSize = 0x100;
                        ct.PaddingSize = 0x3C;
                        break;
                    case SignatureType.ECDSA_SHA1:
                    case SignatureType.ECDSA_SHA256:
                        ct.SignatureSize = 0x03C;
                        ct.PaddingSize = 0x40;
                        break;
                    default:
                        return null;
                }

                ct.Signature = reader.ReadBytes(ct.SignatureSize);
                reader.ReadBytes(ct.PaddingSize); // Padding
                ct.Issuer = reader.ReadBytes(0x40);
                ct.KeyType = (PublicKeyType)reader.ReadUInt32();
                ct.Name = reader.ReadBytes(0x40);
                ct.ExpirationTime = reader.ReadUInt32();

                switch (ct.KeyType)
                {
                    case PublicKeyType.RSA_4096:
                        ct.Modulus = reader.ReadBytes(0x200);
                        ct.PublicExponent = reader.ReadUInt32();
                        reader.ReadBytes(0x34); // Padding
                        break;
                    case PublicKeyType.RSA_2048:
                        ct.Modulus = reader.ReadBytes(0x100);
                        ct.PublicExponent = reader.ReadUInt32();
                        reader.ReadBytes(0x34); // Padding
                        break;
                    case PublicKeyType.ECDSA:
                        ct.PublicKey = reader.ReadBytes(0x3C);
                        reader.ReadBytes(0x3C); // Padding
                        break;
                    default:
                        return null;
                }

                return ct;
            }
            catch
            {
                return null;
            }
        }
    }
}

using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class CXIExtendedHeader
    {
        /// <summary>
        /// SCI
        /// </summary>
        public SystemControlInfo? SCI { get; private set; }

        /// <summary>
        /// ACI
        /// </summary>
        public AccessControlInfo? ACI { get; private set; }

        /// <summary>
        /// AccessDesc signature (RSA-2048-SHA256)
        /// </summary>
        public byte[]? AccessDescSignature { get; private set; }

        /// <summary>
        /// NCCH HDR RSA-2048 public key
        /// </summary>
        public byte[]? NCCHHDRPublicKey { get; private set; }

        /// <summary>
        /// ACI (for limitation of first ACI)
        /// </summary>
        public AccessControlInfo? ACIForLimitations { get; private set; }

        /// <summary>
        /// Read from a stream and get a CXI extended header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>CXI extended header object, null on error</returns>
        public static CXIExtendedHeader? Read(BinaryReader reader)
        {
            var header = new CXIExtendedHeader();

            try
            {
                header.SCI = SystemControlInfo.Read(reader);
                header.ACI = AccessControlInfo.Read(reader);
                header.AccessDescSignature = reader.ReadBytes(0x100);
                header.NCCHHDRPublicKey = reader.ReadBytes(0x100);
                header.ACIForLimitations = AccessControlInfo.Read(reader);
                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

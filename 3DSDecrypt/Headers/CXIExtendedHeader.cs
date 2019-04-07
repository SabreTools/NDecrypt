using System.IO;

namespace ThreeDS.Headers
{
    public class CXIExtendedHeader
    {
        public SystemControlInfo SCI;
        public AccessControlInfo ACI;
        public byte[] AccessDescSignature = new byte[0x100];
        public byte[] NCCHHDRPublicKey = new byte[0x100];
        public AccessControlInfo ACIForLimitations;

        public static CXIExtendedHeader Read(BinaryReader reader)
        {
            CXIExtendedHeader header = new CXIExtendedHeader();

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

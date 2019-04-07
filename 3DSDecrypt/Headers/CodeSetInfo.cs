using System.IO;

namespace ThreeDS.Headers
{
    public class CodeSetInfo
    {
        public byte[] Address = new byte[0x04];
        public uint PhysicalRegionSizeInPages;
        public uint SizeInBytes;

        public static CodeSetInfo Read(BinaryReader reader)
        {
            CodeSetInfo csi = new CodeSetInfo();

            try
            {
                csi.Address = reader.ReadBytes(4);
                csi.PhysicalRegionSizeInPages = reader.ReadUInt32();
                csi.SizeInBytes = reader.ReadUInt32();
                return csi;
            }
            catch
            {
                return null;
            }
        }
    }
}

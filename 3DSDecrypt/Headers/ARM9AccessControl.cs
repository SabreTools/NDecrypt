using System.IO;

namespace ThreeDS.Headers
{
    public class ARM9AccessControl
    {
        public byte[] Descriptors = new byte[15];
        public byte DescriptorVersion;

        public static ARM9AccessControl Read(BinaryReader reader)
        {
            ARM9AccessControl ac = new ARM9AccessControl();

            try
            {
                ac.Descriptors = reader.ReadBytes(15);
                ac.DescriptorVersion = reader.ReadByte();
                return ac;
            }
            catch
            {
                return null;
            }
        }
    }
}

using System.IO;

namespace ThreeDS.Headers
{
    public class ARM11KernelCapabilities
    {
        public byte[][] Descriptors = new byte[28][];
        public byte[] Reserved = new byte[0x10];

        public static ARM11KernelCapabilities Read(BinaryReader reader)
        {
            ARM11KernelCapabilities kc = new ARM11KernelCapabilities();

            try
            {
                for (int i = 0; i < 28; i++)
                    kc.Descriptors[i] = reader.ReadBytes(4);

                kc.Reserved = reader.ReadBytes(0x10);
                return kc;
            }
            catch
            {
                return null;
            }
        }
    }
}

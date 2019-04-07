using System.IO;

namespace ThreeDS.Headers
{
    public class SystemInfo
    {
        public ulong SaveDataSize;
        public byte[] JumpID = new byte[8];
        public byte[] Reserved = new byte[0x30];

        public static SystemInfo Read(BinaryReader reader)
        {
            SystemInfo si = new SystemInfo();

            try
            {
                si.SaveDataSize = reader.ReadUInt64();
                si.JumpID = reader.ReadBytes(8);
                si.Reserved = reader.ReadBytes(0x30);
                return si;
            }
            catch
            {
                return null;
            }
        }
    }
}

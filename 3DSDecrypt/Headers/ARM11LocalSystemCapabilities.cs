using System.IO;

namespace ThreeDS.Headers
{
    public class ARM11LocalSystemCapabilities
    {
        public byte[] ProgramID = new byte[8];
        public uint CoreVersion;
        public byte Flag1;
        public byte Flag2;
        public byte Flag0;
        public byte Priority;
        public byte[][] ResourceLimitDescriptors = new byte[16][];
        public StorageInfo StorageInfo;
        public byte[][] ServiceAccessControl = new byte[32][];
        public byte[][] ExtendedServiceAccessControl = new byte[2][];
        public byte[] Reserved = new byte[0xF];
        public byte ResourceLimitCategory;

        public static ARM11LocalSystemCapabilities Read(BinaryReader reader)
        {
            ARM11LocalSystemCapabilities lsc = new ARM11LocalSystemCapabilities();

            try
            {
                lsc.ProgramID = reader.ReadBytes(8);
                lsc.CoreVersion = reader.ReadUInt32();
                lsc.Flag1 = reader.ReadByte();
                lsc.Flag2 = reader.ReadByte();
                lsc.Flag0 = reader.ReadByte();
                lsc.Priority = reader.ReadByte();

                for (int i = 0; i < 16; i++)
                    lsc.ResourceLimitDescriptors[i] = reader.ReadBytes(2);

                lsc.StorageInfo = StorageInfo.Read(reader);

                for (int i = 0; i < 32; i++)
                    lsc.ServiceAccessControl[i] = reader.ReadBytes(8);

                for (int i = 0; i < 2; i++)
                    lsc.ExtendedServiceAccessControl[i] = reader.ReadBytes(8);

                lsc.Reserved = reader.ReadBytes(0xF);
                lsc.ResourceLimitCategory = reader.ReadByte();
                return lsc;
            }
            catch
            {
                return null;
            }
        }
    }
}

using System.IO;

namespace ThreeDS.Headers
{
    public class SystemControlInfo
    {
        public char[] ApplicationTitle = new char[8];
        public byte[] Reserved1 = new byte[5];
        public byte Flag;
        public byte[] RemasterVersion = new byte[2];
        public CodeSetInfo TextCodesetInfo;
        public uint StackSize;
        public CodeSetInfo ReadOnlyCodeSetInfo;
        public byte[] Reserved2 = new byte[4];
        public CodeSetInfo DataCodeSetInfo;
        public uint BSSSize;
        public byte[][] DependencyModuleList = new byte[48][];
        public SystemInfo SystemInfo;

        public static SystemControlInfo Read(BinaryReader reader)
        {
            SystemControlInfo sci = new SystemControlInfo();

            try
            {
                sci.ApplicationTitle = reader.ReadChars(8);
                sci.Reserved1 = reader.ReadBytes(5);
                sci.Flag = reader.ReadByte();
                sci.RemasterVersion = reader.ReadBytes(2);
                sci.TextCodesetInfo = CodeSetInfo.Read(reader);
                sci.StackSize = reader.ReadUInt32();
                sci.ReadOnlyCodeSetInfo = CodeSetInfo.Read(reader);
                sci.Reserved2 = reader.ReadBytes(4);
                sci.DataCodeSetInfo = CodeSetInfo.Read(reader);
                sci.BSSSize = reader.ReadUInt32();

                for (int i = 0; i < 48; i++)
                    sci.DependencyModuleList[i] = reader.ReadBytes(8);

                sci.SystemInfo = SystemInfo.Read(reader);
                return sci;
            }
            catch
            {
                return null;
            }
        }
    }
}

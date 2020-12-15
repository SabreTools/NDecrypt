using System.IO;

namespace NDecrypt.Core.Headers
{
    public class SystemControlInfo
    {
        /// <summary>
        /// Application title (default is "CtrApp")
        /// </summary>
        public char[] ApplicationTitle { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved1 { get; private set; }

        /// <summary>
        /// Flag (bit 0: CompressExefsCode, bit 1: SDApplication)
        /// </summary>
        public byte Flag { get; private set; }

        /// <summary>
        /// Remaster version
        /// </summary>
        public byte[] RemasterVersion { get; private set; }

        /// <summary>
        /// Text code set info
        /// </summary>
        public CodeSetInfo TextCodesetInfo { get; private set; }

        /// <summary>
        /// Stack size
        /// </summary>
        public uint StackSize { get; private set; }

        /// <summary>
        /// Read-only code set info
        /// </summary>
        public CodeSetInfo ReadOnlyCodeSetInfo { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved2 { get; private set; }

        /// <summary>
        /// Data code set info
        /// </summary>
        public CodeSetInfo DataCodeSetInfo { get; private set; }

        /// <summary>
        /// BSS size
        /// </summary>
        public uint BSSSize { get; private set; }

        /// <summary>
        /// Dependency module (program ID) list
        /// </summary>
        public byte[][] DependencyModuleList { get; private set; }

        /// <summary>
        /// SystemInfo
        /// </summary>
        public SystemInfo SystemInfo { get; private set; }

        /// <summary>
        /// Read from a stream and get system control info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>System control info object, null on error</returns>
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

                sci.DependencyModuleList = new byte[48][];
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

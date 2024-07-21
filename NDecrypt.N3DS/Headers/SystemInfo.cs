using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class SystemInfo
    {
        /// <summary>
        /// SaveData Size
        /// </summary>
        public ulong SaveDataSize { get; private set; }

        /// <summary>
        /// Jump ID
        /// </summary>
        public byte[]? JumpID { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[]? Reserved { get; private set; }

        /// <summary>
        /// Read from a stream and get system info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>System info object, null on error</returns>
        public static SystemInfo? Read(BinaryReader reader)
        {
            var si = new SystemInfo();

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

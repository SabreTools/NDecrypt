using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class MetaFile
    {
        /// <summary>
        /// Title ID dependency list - Taken from the application's ExHeader
        /// </summary>
        public byte[] TitleIDDependencyList { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved1 { get; private set; }

        /// <summary>
        /// Core Version
        /// </summary>
        public uint CoreVersion { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved2 { get; private set; }

        /// <summary>
        /// Icon Data(.ICN) - Taken from the application's ExeFS
        /// </summary>
        public byte[] IconData { get; private set; }

        /// <summary>
        /// Read from a stream and get the Metafile data, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Metafile data object, null on error</returns>
        public static MetaFile Read(BinaryReader reader)
        {
            MetaFile metaFile = new MetaFile();

            try
            {
                metaFile.TitleIDDependencyList = reader.ReadBytes(0x180);
                metaFile.Reserved1 = reader.ReadBytes(0x180);
                metaFile.CoreVersion = reader.ReadUInt32();
                metaFile.Reserved2 = reader.ReadBytes(0xFC);
                metaFile.IconData = reader.ReadBytes(0x36C0);

                return metaFile;
            }
            catch
            {
                return null;
            }
        }
    }
}
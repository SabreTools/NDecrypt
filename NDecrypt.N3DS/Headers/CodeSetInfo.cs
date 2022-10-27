using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class CodeSetInfo
    {
        /// <summary>
        /// Address
        /// </summary>
        public byte[] Address { get; private set; }

        /// <summary>
        /// Physical region size (in page-multiples)
        /// </summary>
        public uint PhysicalRegionSizeInPages { get; private set; }

        /// <summary>
        /// Size (in bytes)
        /// </summary>
        public uint SizeInBytes { get; private set; }

        /// <summary>
        /// Read from a stream and get code set info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Code set info object, null on error</returns>
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

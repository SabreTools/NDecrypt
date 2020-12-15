using System.IO;
using NDecrypt.Core.Data;

namespace NDecrypt.Core.Headers
{
    public class StorageInfo
    {
        /// <summary>
        /// Extdata ID
        /// </summary>
        public byte[] ExtdataID { get; private set; }

        /// <summary>
        /// System savedata IDs
        /// </summary>
        public byte[] SystemSavedataIDs { get; private set; }

        /// <summary>
        /// Storage accessible unique IDs
        /// </summary>
        public byte[] StorageAccessibleUniqueIDs { get; private set; }

        /// <summary>
        /// Filesystem access info
        /// </summary>
        public byte[] FilesystemAccessInfo { get; private set; }

        /// <summary>
        /// Other attributes
        /// </summary>
        public StorageInfoOtherAttributes OtherAttributes { get; private set; }

        /// <summary>
        /// Read from a stream and get storage info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Storage info object, null on error</returns>
        public static StorageInfo Read(BinaryReader reader)
        {
            StorageInfo si = new StorageInfo();

            try
            {
                si.ExtdataID = reader.ReadBytes(8);
                si.SystemSavedataIDs = reader.ReadBytes(8);
                si.StorageAccessibleUniqueIDs = reader.ReadBytes(8);
                si.FilesystemAccessInfo = reader.ReadBytes(7);
                si.OtherAttributes = (StorageInfoOtherAttributes)reader.ReadByte();
                return si;
            }
            catch
            {
                return null;
            }
        }
    }
}

using System.IO;

namespace ThreeDS.Headers
{
    public class StorageInfo
    {
        public byte[] ExtdataID = new byte[8];
        public byte[] SystemSavedataIDs = new byte[8];
        public byte[] StorageAccessibleUniqueIDs = new byte[8];
        public byte[] FilesystemAccessInfo = new byte[7];
        public byte OtherAttributes;

        public static StorageInfo Read(BinaryReader reader)
        {
            StorageInfo si = new StorageInfo();

            try
            {
                si.ExtdataID = reader.ReadBytes(8);
                si.SystemSavedataIDs = reader.ReadBytes(8);
                si.StorageAccessibleUniqueIDs = reader.ReadBytes(8);
                si.FilesystemAccessInfo = reader.ReadBytes(7);
                si.OtherAttributes = reader.ReadByte();
                return si;
            }
            catch
            {
                return null;
            }
        }
    }
}

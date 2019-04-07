using System.IO;

namespace ThreeDS.Headers
{
    public class PartitionTableEntry
    {
        public uint Offset { get; set; }
        public uint Length { get; set; }

        public static PartitionTableEntry Read(BinaryReader reader)
        {
            PartitionTableEntry entry = new PartitionTableEntry();

            try
            {
                entry.Offset = reader.ReadUInt32();
                entry.Length = reader.ReadUInt32();
                return entry;
            }
            catch
            {
                return null;
            }
        }

        public bool IsValid()
        {
            return Offset != 0 && Length != 0;
        }
    }
}

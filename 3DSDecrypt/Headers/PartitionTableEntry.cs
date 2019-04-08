using System.IO;

namespace ThreeDS.Headers
{
    public class PartitionTableEntry
    {
        /// <summary>
        /// Offset
        /// </summary>
        public uint Offset { get; set; }

        /// <summary>
        /// Length
        /// </summary>
        public uint Length { get; set; }

        /// <summary>
        /// Read from a stream and get partition table entry, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Partition table entry object, null on error</returns>
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

        /// <summary>
        /// Check for a valid partition
        /// </summary>
        /// <returns>True if the offset and length are not 0, false otherwise</returns>
        public bool IsValid()
        {
            return Offset != 0 && Length != 0;
        }
    }
}

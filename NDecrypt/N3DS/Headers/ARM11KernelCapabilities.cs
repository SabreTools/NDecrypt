using System.IO;

namespace NDecrypt.N3DS.Headers
{
    public class ARM11KernelCapabilities
    {
        /// <summary>
        /// Descriptors
        /// -------------------
        /// Pattern of bits 20-31	Type	Fields
        /// 0b1110xxxxxxxx Interrupt info	
        /// 0b11110xxxxxxx System call mask    Bits 24-26: System call mask table index; Bits 0-23: mask
        /// 0b1111110xxxxx Kernel release version  Bits 8-15: Major version; Bits 0-7: Minor version
        /// 0b11111110xxxx Handle table size   Bits 0-18: size
        /// 0b111111110xxx Kernel flags
        /// 0b11111111100x Map address range   Describes a memory mapping like the 0b111111111110 descriptor, but an entire range rather than a single page is mapped.Another 0b11111111100x descriptor must follow this one to denote the(exclusive) end of the address range to map.
        /// 0b111111111110	Map memory page Bits 0-19: page index to map(virtual address >> 12; the physical address is determined per-page according to Memory layout); Bit 20: Map read-only(otherwise read-write)
        /// 
        /// ARM11 Kernel Flags
        /// -------------------
        /// Bit	Description
        /// 0	Allow debug
        /// 1	Force debug
        /// 2	Allow non-alphanum
        /// 3	Shared page writing
        /// 4	Privilege priority
        /// 5	Allow main() args
        /// 6	Shared device memory
        /// 7	Runnable on sleep
        /// 8-11	Memory type(1: application, 2: system, 3: base)
        /// 12	Special memory
        /// 13	Process has access to CPU core 2 (New3DS only)
        /// </summary>
        public byte[][] Descriptors { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved { get; private set; }

        /// <summary>
        /// Read from a stream and get ARM11 kernel capabilities, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ARM11 kernel capabilities object, null on error</returns>
        public static ARM11KernelCapabilities Read(BinaryReader reader)
        {
            ARM11KernelCapabilities kc = new ARM11KernelCapabilities();

            try
            {
                kc.Descriptors = new byte[28][];
                for (int i = 0; i < 28; i++)
                    kc.Descriptors[i] = reader.ReadBytes(4);

                kc.Reserved = reader.ReadBytes(0x10);
                return kc;
            }
            catch
            {
                return null;
            }
        }
    }
}

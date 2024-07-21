using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class ARM11LocalSystemCapabilities
    {
        /// <summary>
        /// Program ID
        /// </summary>
        public byte[]? ProgramID { get; private set; }

        /// <summary>
        /// Core version (The Title ID low of the required FIRM)
        /// </summary>
        public uint CoreVersion { get; private set; }

        /// <summary>
        /// Flag1 (implemented starting from 8.0.0-18).
        /// </summary>
        public ARM11LSCFlag1 Flag1 { get; private set; }

        /// <summary>
        /// Flag2 (implemented starting from 8.0.0-18).
        /// </summary>
        public ARM11LSCFlag2 Flag2 { get; private set; }

        /// <summary>
        /// Flag0
        /// </summary>
        public ARM11LSCFlag0 Flag0 { get; private set; }

        /// <summary>
        /// Priority
        /// </summary>
        public byte Priority { get; private set; }

        /// <summary>
        /// Resource limit descriptors. The first byte here controls the maximum allowed CpuTime.
        /// </summary>
        public byte[][]? ResourceLimitDescriptors { get; private set; }

        /// <summary>
        /// Storage info
        /// </summary>
        public StorageInfo? StorageInfo { get; private set; }

        /// <summary>
        /// Service access control
        /// </summary>
        public byte[][]? ServiceAccessControl { get; private set; }

        /// <summary>
        /// Extended service access control, support for this was implemented with 9.3.0-X.
        /// </summary>
        public byte[][]? ExtendedServiceAccessControl { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[]? Reserved { get; private set; }

        /// <summary>
        /// Resource limit category. (0 = APPLICATION, 1 = SYS_APPLET, 2 = LIB_APPLET, 3 = OTHER (sysmodules running under the BASE memregion))
        /// </summary>
        public ResourceLimitCategory ResourceLimitCategory { get; private set; }

        /// <summary>
        /// Read from a stream and get ARM11 local system capabilities, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ARM11 local system capabilities object, null on error</returns>
        public static ARM11LocalSystemCapabilities? Read(BinaryReader reader)
        {
            var lsc = new ARM11LocalSystemCapabilities();

            try
            {
                lsc.ProgramID = reader.ReadBytes(8);
                lsc.CoreVersion = reader.ReadUInt32();
                lsc.Flag1 = (ARM11LSCFlag1)reader.ReadByte();
                lsc.Flag2 = (ARM11LSCFlag2)reader.ReadByte();
                lsc.Flag0 = (ARM11LSCFlag0)reader.ReadByte();
                lsc.Priority = reader.ReadByte();

                lsc.ResourceLimitDescriptors = new byte[16][];
                for (int i = 0; i < 16; i++)
                    lsc.ResourceLimitDescriptors[i] = reader.ReadBytes(2);

                lsc.StorageInfo = StorageInfo.Read(reader);

                lsc.ServiceAccessControl = new byte[32][];
                for (int i = 0; i < 32; i++)
                    lsc.ServiceAccessControl[i] = reader.ReadBytes(8);

                lsc.ExtendedServiceAccessControl = new byte[2][];
                for (int i = 0; i < 2; i++)
                    lsc.ExtendedServiceAccessControl[i] = reader.ReadBytes(8);

                lsc.Reserved = reader.ReadBytes(0xF);
                lsc.ResourceLimitCategory = (ResourceLimitCategory)reader.ReadByte();
                return lsc;
            }
            catch
            {
                return null;
            }
        }
    }
}

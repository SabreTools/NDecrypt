using System.IO;

namespace NDecrypt.N3DS.Headers
{
    internal class AccessControlInfo
    {
        /// <summary>
        /// ARM11 local system capabilities
        /// </summary>
        public ARM11LocalSystemCapabilities ARM11LocalSystemCapabilities { get; private set; }

        /// <summary>
        /// ARM11 kernel capabilities
        /// </summary>
        public ARM11KernelCapabilities ARM11KernelCapabilities { get; private set; }

        /// <summary>
        /// ARM9 access control
        /// </summary>
        public ARM9AccessControl ARM9AccessControl { get; private set; }

        /// <summary>
        /// Read from a stream and get access control info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Access control info object, null on error</returns>
        public static AccessControlInfo Read(BinaryReader reader)
        {
            AccessControlInfo aci = new AccessControlInfo();

            try
            {
                aci.ARM11LocalSystemCapabilities = ARM11LocalSystemCapabilities.Read(reader);
                aci.ARM11KernelCapabilities = ARM11KernelCapabilities.Read(reader);
                aci.ARM9AccessControl = ARM9AccessControl.Read(reader);
                return aci;
            }
            catch
            {
                return null;
            }
        }
    }
}

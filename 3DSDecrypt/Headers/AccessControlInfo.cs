using System.IO;

namespace ThreeDS.Headers
{
    public class AccessControlInfo
    {
        public ARM11LocalSystemCapabilities ARM11LocalSystemCapabilities;
        public ARM11KernelCapabilities ARM11KernelCapabilities;
        public ARM9AccessControl ARM9AccessControl;

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

using System;

namespace NDecrypt.N3DS
{
    [Flags]
    internal enum ARM9AccessControlDescriptors : byte
    {
        MountNandRoot = 0x01,
        MountNandroWriteAccess = 0x02,
        MountTwlnRoot = 0x04,
        MountWnandRoot = 0x08,
        MountCardSPI = 0x0F,
        UseSDIF3 = 0x10,
        CreateSeed = 0x20,
        UseCardSPI = 0x40,
        SDApplication = 0x80,
        MoundSdmcWriteAccess = 0xF0,
    }
}

using System;

namespace ThreeDS.Data
{
    [Flags]
    public enum BitMasks : byte
    {
        FixedCryptoKey = 0x01,
        NoMountRomFs = 0x02,
        NoCrypto = 0x04,
        NewKeyYGenerator = 0x20,
    }

    public enum ContentPlatform : byte
    {
        CTR = 0x01,
        Snake = 0x02, // New3DS
    }

    [Flags]
    public enum ContentType : byte
    {
        Data = 0x01,
        Executable = 0x02,
        SystemUpdate = 0x04,
        Manual = 0x08,
        Child = 0x04 | 0x08,
        Trial = 0x10,
    }

    public enum CryptoMethod : byte
    {
        Original = 0x00,
        Seven = 0x01,
        NineThree = 0x0A,
        NineSix = 0x0B,
    }

    public enum FilesystemType : ulong
    {
        None = 0,
        Normal = 1,
        FIRM = 3,
        AGB_FIRMSave = 4,
    }

    public enum MediaCardDeviceType : byte
    {
        NORFlash = 0x01,
        None = 0x02,
        BT = 0x03,
    }

    public enum MediaPlatformIndex : byte
    {
        CTR = 0x01,
    }

    public enum MediaTypeIndex : byte
    {
        InnerDevice = 0x00,
        Card1 = 0x01,
        Card2 = 0x02,
        ExtendedDevice = 0x03,
    }

    public enum NCCHFlags
    {
        CryptoMethod = 0x03,
        ContentPlatform = 0x04,
        ContentTypeBitMask = 0x05,
        ContentUnitSize = 0x06,
        BitMasks = 0x07,
    }

    public enum NCSDFlags
    {
        BackupWriteWaitTime = 0x00,
        MediaCardDevice3X = 0x03,
        MediaPlatformIndex = 0x04,
        MediaTypeIndex = 0x05,
        MediaUnitSize = 0x06,
        MediaCardDevice2X = 0x07,
    }
}

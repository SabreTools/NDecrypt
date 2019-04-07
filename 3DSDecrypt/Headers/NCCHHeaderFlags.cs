using System;
using System.IO;
using ThreeDS.Data;

namespace ThreeDS.Headers
{
    public class NCCHHeaderFlags
    {
        public byte Reserved0;
        public byte Reserved1;
        public byte Reserved2;
        public CryptoMethod CryptoMethod;
        public ContentPlatform ContentPlatform;
        public ContentType MediaPlatformIndex;
        public byte ContentUnitSize;
        public uint ContentUnitSizeInBytes { get { return (uint)(0x200 * Math.Pow(2, this.ContentUnitSize)); } }
        public BitMasks BitMasks;

        public static NCCHHeaderFlags Read(BinaryReader reader)
        {
            NCCHHeaderFlags flags = new NCCHHeaderFlags();

            try
            {
                flags.Reserved0 = reader.ReadByte();
                flags.Reserved1 = reader.ReadByte();
                flags.Reserved2 = reader.ReadByte();
                flags.CryptoMethod = (CryptoMethod)reader.ReadByte();
                flags.ContentPlatform = (ContentPlatform)reader.ReadByte();
                flags.MediaPlatformIndex = (ContentType)reader.ReadByte();
                flags.ContentUnitSize = reader.ReadByte();
                flags.BitMasks = (BitMasks)reader.ReadByte();
                return flags;
            }
            catch
            {
                return null;
            }
        }

        public void Write(BinaryWriter writer)
        {
            try
            {
                writer.Write(this.Reserved0);
                writer.Write(this.Reserved1);
                writer.Write(this.Reserved2);
                writer.Write((byte)this.CryptoMethod);
                writer.Write((byte)this.ContentPlatform);
                writer.Write((byte)this.MediaPlatformIndex);
                writer.Write((byte)this.ContentUnitSize);
                writer.Write((byte)this.BitMasks);

            }
            catch { }
        }
    }
}

using System;
using System.IO;
using NDecrypt.Data;

namespace NDecrypt.Headers
{
    public class NCCHHeaderFlags
    {
        /// <summary>
        /// Reserved
        /// </summary>
        public byte Reserved0 { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte Reserved1 { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte Reserved2 { get; private set; }

        /// <summary>
        /// Crypto Method: When this is non-zero, a NCCH crypto method using two keyslots is used.
        /// </summary>
        public CryptoMethod CryptoMethod { get; private set; }

        /// <summary>
        /// Content Platform: 1 = CTR, 2 = snake (New 3DS).
        /// </summary>
        public ContentPlatform ContentPlatform { get; private set; }

        /// <summary>
        /// Content Type Bit-masks: Data = 0x1, Executable = 0x2, SystemUpdate = 0x4, Manual = 0x8,
        /// Child = (0x4|0x8), Trial = 0x10. When 'Data' is set, but not 'Executable', NCCH is a CFA.
        /// Otherwise when 'Executable' is set, NCCH is a CXI.
        /// </summary>
        public ContentType MediaPlatformIndex { get; private set; }

        /// <summary>
        /// Content Unit Size i.e. u32 ContentUnitSize = 0x200*2^flags[6];
        /// </summary>
        public byte ContentUnitSize { get; private set; }

        /// <summary>
        /// Bit-masks: FixedCryptoKey = 0x1, NoMountRomFs = 0x2, NoCrypto = 0x4, using a new keyY
        /// generator = 0x20(starting with FIRM 9.6.0-X).
        /// </summary>
        public BitMasks BitMasks { get; private set; }

        /// <summary>
        /// Get if the NoCrypto bit is set
        /// </summary>
        public bool PossblyDecrypted { get { return (BitMasks & BitMasks.NoCrypto) != 0; } }

        /// <summary>
        /// Read from a stream and get an NCCH header flags, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>NCCH header flags object, null on error</returns>
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

        /// <summary>
        /// Write NCCH header flags to stream, if possible
        /// </summary>
        /// <param name="writer">BinaryWriter representing the output stream</param>
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

using System.IO;
using System.Text;
using SabreTools.Models.Nitro;

namespace NDecrypt.Nitro
{
    internal static class Serializer
    {
        /// <summary>
        /// Read from a stream and get an NDS/NDSi Cart, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>NDS/NDSi Cart object, null on error</returns>
        public static Cart? ReadCart(BinaryReader reader)
        {
            var cart = new Cart();

            try
            {
                cart.CommonHeader = ReadCommonHeader(reader);
                if (cart.CommonHeader == null)
                    return null;

                // If we have a DSi compatible title
                if (cart.CommonHeader.UnitCode == Unitcode.NDSPlusDSi
                    || cart.CommonHeader.UnitCode == Unitcode.DSi)
                {
                    cart.ExtendedDSiHeader = ReadExtendedDSiHeader(reader);
                    if (cart.ExtendedDSiHeader == null)
                        return null;
                }

                return cart;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get a common header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Common header object, null on error</returns>
        private static CommonHeader? ReadCommonHeader(BinaryReader reader)
        {
            var header = new CommonHeader();

            try
            {
                byte[] gameTitleBytes = reader.ReadBytes(0x0C);
                header.GameTitle = Encoding.ASCII.GetString(gameTitleBytes);
                header.GameCode = reader.ReadUInt32();
                byte[] makerCodeBytes = reader.ReadBytes(2);
                header.MakerCode = Encoding.ASCII.GetString(makerCodeBytes);
                header.UnitCode = (Unitcode)reader.ReadByte();
                header.EncryptionSeedSelect = reader.ReadByte();
                header.DeviceCapacity = reader.ReadByte();
                header.Reserved1 = reader.ReadBytes(7);
                header.GameRevision = reader.ReadUInt16();
                header.RomVersion = reader.ReadByte();
                header.InternalFlags = reader.ReadByte();
                header.ARM9RomOffset = reader.ReadUInt32();
                header.ARM9EntryAddress = reader.ReadUInt32();
                header.ARM9LoadAddress = reader.ReadUInt32();
                header.ARM9Size = reader.ReadUInt32();
                header.ARM7RomOffset = reader.ReadUInt32();
                header.ARM7EntryAddress = reader.ReadUInt32();
                header.ARM7LoadAddress = reader.ReadUInt32();
                header.ARM7Size = reader.ReadUInt32();
                header.FileNameTableOffset = reader.ReadUInt32();
                header.FileNameTableLength = reader.ReadUInt32();
                header.FileAllocationTableOffset = reader.ReadUInt32();
                header.FileAllocationTableLength = reader.ReadUInt32();
                header.ARM9OverlayOffset = reader.ReadUInt32();
                header.ARM9OverlayLength = reader.ReadUInt32();
                header.ARM7OverlayOffset = reader.ReadUInt32();
                header.ARM7OverlayLength = reader.ReadUInt32();
                header.SecureDisable = reader.ReadBytes(8);
                header.NTRRegionRomSize = reader.ReadUInt32();
                header.HeaderSize = reader.ReadUInt32();
                header.Reserved2 = reader.ReadBytes(56);
                header.NintendoLogo = reader.ReadBytes(156);
                header.NintendoLogoCRC = reader.ReadUInt16();
                header.DebuggerReserved = reader.ReadBytes(0x20);

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get an extended DSi header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Extended DSi header object, null on error</returns>
        private static ExtendedDSiHeader? ReadExtendedDSiHeader(BinaryReader reader)
        {
            var header = new ExtendedDSiHeader();

            try
            {
                header.GlobalMBK15Settings = new uint[5];
                for (int i = 0; i < 5; i++)
                {
                    header.GlobalMBK15Settings[i] = reader.ReadUInt32();
                }
                header.LocalMBK68SettingsARM9 = new uint[3];
                for (int i = 0; i < 3; i++)
                {
                    header.LocalMBK68SettingsARM9[i] = reader.ReadUInt32();
                }
                header.LocalMBK68SettingsARM7 = new uint[3];
                for (int i = 0; i < 3; i++)
                {
                    header.LocalMBK68SettingsARM7[i] = reader.ReadUInt32();
                }
                header.GlobalMBK9Setting = reader.ReadUInt32();
                header.RegionFlags = reader.ReadUInt32();
                header.AccessControl = reader.ReadUInt32();
                header.ARM7SCFGEXTMask = reader.ReadUInt32();
                header.ReservedFlags = reader.ReadUInt32();
                header.ARM9iRomOffset = reader.ReadUInt32();
                header.Reserved3 = reader.ReadUInt32();
                header.ARM9iLoadAddress = reader.ReadUInt32();
                header.ARM9iSize = reader.ReadUInt32();
                header.ARM7iRomOffset = reader.ReadUInt32();
                header.Reserved4 = reader.ReadUInt32();
                header.ARM7iLoadAddress = reader.ReadUInt32();
                header.ARM7iSize = reader.ReadUInt32();
                header.DigestNTRRegionOffset = reader.ReadUInt32();
                header.DigestNTRRegionLength = reader.ReadUInt32();
                header.DigestTWLRegionOffset = reader.ReadUInt32();
                header.DigestTWLRegionLength = reader.ReadUInt32();
                header.DigestSectorHashtableRegionOffset = reader.ReadUInt32();
                header.DigestSectorHashtableRegionLength = reader.ReadUInt32();
                header.DigestBlockHashtableRegionOffset = reader.ReadUInt32();
                header.DigestBlockHashtableRegionLength = reader.ReadUInt32();
                header.DigestSectorSize = reader.ReadUInt32();
                header.DigestBlockSectorCount = reader.ReadUInt32();
                header.IconBannerSize = reader.ReadUInt32();
                header.Unknown1 = reader.ReadUInt32();
                header.ModcryptArea1Offset = reader.ReadUInt32();
                header.ModcryptArea1Size = reader.ReadUInt32();
                header.ModcryptArea2Offset = reader.ReadUInt32();
                header.ModcryptArea2Size = reader.ReadUInt32();
                header.TitleID = reader.ReadBytes(8);
                header.DSiWarePublicSavSize = reader.ReadUInt32();
                header.DSiWarePrivateSavSize = reader.ReadUInt32();
                header.ReservedZero = reader.ReadBytes(176);
                header.Unknown2 = reader.ReadBytes(0x10);
                header.ARM9WithSecureAreaSHA1HMACHash = reader.ReadBytes(20);
                header.ARM7SHA1HMACHash = reader.ReadBytes(20);
                header.DigestMasterSHA1HMACHash = reader.ReadBytes(20);
                header.BannerSHA1HMACHash = reader.ReadBytes(20);
                header.ARM9iDecryptedSHA1HMACHash = reader.ReadBytes(20);
                header.ARM7iDecryptedSHA1HMACHash = reader.ReadBytes(20);
                header.Reserved5 = reader.ReadBytes(40);
                header.ARM9NoSecureAreaSHA1HMACHash = reader.ReadBytes(20);
                header.Reserved6 = reader.ReadBytes(2636);
                header.ReservedAndUnchecked = reader.ReadBytes(0x180);
                header.RSASignature = reader.ReadBytes(0x80);

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

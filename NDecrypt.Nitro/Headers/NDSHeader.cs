using System.IO;
using System.Text;
using SabreTools.Models.Nitro;

namespace NDecrypt.Nitro.Headers
{
    internal static class NDSHeader
    {
        /// <summary>
        /// Read from a stream and get an NDS/NDSi Cart, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>NDS/NDSi Cart object, null on error</returns>
        public static Cart? Read(BinaryReader reader)
        {
            var cart = new Cart();

            try
            {
                var commonHeader = new CommonHeader();

                byte[] gameTitleBytes = reader.ReadBytes(0x0C);
                commonHeader.GameTitle = Encoding.ASCII.GetString(gameTitleBytes);
                commonHeader.GameCode = reader.ReadUInt32();
                byte[] makerCodeBytes = reader.ReadBytes(2);
                commonHeader.MakerCode = Encoding.ASCII.GetString(makerCodeBytes);
                commonHeader.UnitCode = (Unitcode)reader.ReadByte();
                commonHeader.EncryptionSeedSelect = reader.ReadByte();
                commonHeader.DeviceCapacity = reader.ReadByte();
                commonHeader.Reserved1 = reader.ReadBytes(7);
                commonHeader.GameRevision = reader.ReadUInt16();
                commonHeader.RomVersion = reader.ReadByte();
                commonHeader.InternalFlags = reader.ReadByte();
                commonHeader.ARM9RomOffset = reader.ReadUInt32();
                commonHeader.ARM9EntryAddress = reader.ReadUInt32();
                commonHeader.ARM9LoadAddress = reader.ReadUInt32();
                commonHeader.ARM9Size = reader.ReadUInt32();
                commonHeader.ARM7RomOffset = reader.ReadUInt32();
                commonHeader.ARM7EntryAddress = reader.ReadUInt32();
                commonHeader.ARM7LoadAddress = reader.ReadUInt32();
                commonHeader.ARM7Size = reader.ReadUInt32();
                commonHeader.FileNameTableOffset = reader.ReadUInt32();
                commonHeader.FileNameTableLength = reader.ReadUInt32();
                commonHeader.FileAllocationTableOffset = reader.ReadUInt32();
                commonHeader.FileAllocationTableLength = reader.ReadUInt32();
                commonHeader.ARM9OverlayOffset = reader.ReadUInt32();
                commonHeader.ARM9OverlayLength = reader.ReadUInt32();
                commonHeader.ARM7OverlayOffset = reader.ReadUInt32();
                commonHeader.ARM7OverlayLength = reader.ReadUInt32();
                commonHeader.SecureDisable = reader.ReadBytes(8);
                commonHeader.NTRRegionRomSize = reader.ReadUInt32();
                commonHeader.HeaderSize = reader.ReadUInt32();
                commonHeader.Reserved2 = reader.ReadBytes(56);
                commonHeader.NintendoLogo = reader.ReadBytes(156);
                commonHeader.NintendoLogoCRC = reader.ReadUInt16();
                commonHeader.DebuggerReserved = reader.ReadBytes(0x20);

                cart.CommonHeader = commonHeader;
            }
            catch
            {
                return null;
            }

            try
            {
                // If we have a DSi compatible title
                if (cart.CommonHeader.UnitCode == Unitcode.NDSPlusDSi
                    || cart.CommonHeader.UnitCode == Unitcode.DSi)
                {
                    var extendedDsiHeader = new ExtendedDSiHeader();

                    extendedDsiHeader.GlobalMBK15Settings = new uint[5];
                    for (int i = 0; i < 5; i++)
                    {
                        extendedDsiHeader.GlobalMBK15Settings[i] = reader.ReadUInt32();
                    }
                    extendedDsiHeader.LocalMBK68SettingsARM9 = new uint[3];
                    for (int i = 0; i < 3; i++)
                    {
                        extendedDsiHeader.LocalMBK68SettingsARM9[i] = reader.ReadUInt32();
                    }
                    extendedDsiHeader.LocalMBK68SettingsARM7 = new uint[3];
                    for (int i = 0; i < 3; i++)
                    {
                        extendedDsiHeader.LocalMBK68SettingsARM7[i] = reader.ReadUInt32();
                    }
                    extendedDsiHeader.GlobalMBK9Setting = reader.ReadUInt32();
                    extendedDsiHeader.RegionFlags = reader.ReadUInt32();
                    extendedDsiHeader.AccessControl = reader.ReadUInt32();
                    extendedDsiHeader.ARM7SCFGEXTMask = reader.ReadUInt32();
                    extendedDsiHeader.ReservedFlags = reader.ReadUInt32();
                    extendedDsiHeader.ARM9iRomOffset = reader.ReadUInt32();
                    extendedDsiHeader.Reserved3 = reader.ReadUInt32();
                    extendedDsiHeader.ARM9iLoadAddress = reader.ReadUInt32();
                    extendedDsiHeader.ARM9iSize = reader.ReadUInt32();
                    extendedDsiHeader.ARM7iRomOffset = reader.ReadUInt32();
                    extendedDsiHeader.Reserved4 = reader.ReadUInt32();
                    extendedDsiHeader.ARM7iLoadAddress = reader.ReadUInt32();
                    extendedDsiHeader.ARM7iSize = reader.ReadUInt32();
                    extendedDsiHeader.DigestNTRRegionOffset = reader.ReadUInt32();
                    extendedDsiHeader.DigestNTRRegionLength = reader.ReadUInt32();
                    extendedDsiHeader.DigestTWLRegionOffset = reader.ReadUInt32();
                    extendedDsiHeader.DigestTWLRegionLength = reader.ReadUInt32();
                    extendedDsiHeader.DigestSectorHashtableRegionOffset = reader.ReadUInt32();
                    extendedDsiHeader.DigestSectorHashtableRegionLength = reader.ReadUInt32();
                    extendedDsiHeader.DigestBlockHashtableRegionOffset = reader.ReadUInt32();
                    extendedDsiHeader.DigestBlockHashtableRegionLength = reader.ReadUInt32();
                    extendedDsiHeader.DigestSectorSize = reader.ReadUInt32();
                    extendedDsiHeader.DigestBlockSectorCount = reader.ReadUInt32();
                    extendedDsiHeader.IconBannerSize = reader.ReadUInt32();
                    extendedDsiHeader.Unknown1 = reader.ReadUInt32();
                    extendedDsiHeader.ModcryptArea1Offset = reader.ReadUInt32();
                    extendedDsiHeader.ModcryptArea1Size = reader.ReadUInt32();
                    extendedDsiHeader.ModcryptArea2Offset = reader.ReadUInt32();
                    extendedDsiHeader.ModcryptArea2Size = reader.ReadUInt32();
                    extendedDsiHeader.TitleID = reader.ReadBytes(8);
                    extendedDsiHeader.DSiWarePublicSavSize = reader.ReadUInt32();
                    extendedDsiHeader.DSiWarePrivateSavSize = reader.ReadUInt32();
                    extendedDsiHeader.ReservedZero = reader.ReadBytes(176);
                    extendedDsiHeader.Unknown2 = reader.ReadBytes(0x10);
                    extendedDsiHeader.ARM9WithSecureAreaSHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.ARM7SHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.DigestMasterSHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.BannerSHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.ARM9iDecryptedSHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.ARM7iDecryptedSHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.Reserved5 = reader.ReadBytes(40);
                    extendedDsiHeader.ARM9NoSecureAreaSHA1HMACHash = reader.ReadBytes(20);
                    extendedDsiHeader.Reserved6 = reader.ReadBytes(2636);
                    extendedDsiHeader.ReservedAndUnchecked = reader.ReadBytes(0x180);
                    extendedDsiHeader.RSASignature = reader.ReadBytes(0x80);

                    cart.ExtendedDSiHeader = extendedDsiHeader;
                }
            }
            catch
            {
                return null;
            }

            return cart;
        }
    }
}

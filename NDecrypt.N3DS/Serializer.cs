using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SabreTools.Models.N3DS;

namespace NDecrypt.N3DS
{
    internal static class Serializer
    {
        #region Constants

        private const string NCCHMagicNumber = "NCCH";
        private const string NCSDMagicNumber = "NCSD";
        private const string RomFSMagicNumber = "IVFC";
        private const uint RomFSSecondMagicNumber = 0x10000;

        #endregion

        #region Reading

        /// <summary>
        /// Read from a stream and get access control info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Access control info object, null on error</returns>
        public static AccessControlInfo? ReadAccessControlInfo(BinaryReader reader)
        {
            var aci = new AccessControlInfo();

            try
            {
                aci.ARM11LocalSystemCapabilities = ReadARM11LocalSystemCapabilities(reader);
                aci.ARM11KernelCapabilities = ReadARM11KernelCapabilities(reader);
                aci.ARM9AccessControl = ReadARM9AccessControl(reader);
                return aci;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get ARM9 access control, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ARM9 access control object, null on error</returns>
        public static ARM9AccessControl? ReadARM9AccessControl(BinaryReader reader)
        {
            var ac = new ARM9AccessControl();

            try
            {
                ac.Descriptors = new byte[15]; // TODO: Implement ARM9AccessControlDescriptors in Models
                for (int i = 0; i < 15; i++)
                {
                    ac.Descriptors[i] = reader.ReadByte();
                }

                ac.DescriptorVersion = reader.ReadByte();
                return ac;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get ARM11 kernel capabilities, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ARM11 kernel capabilities object, null on error</returns>
        public static ARM11KernelCapabilities? ReadARM11KernelCapabilities(BinaryReader reader)
        {
            var kc = new ARM11KernelCapabilities();

            try
            {
                kc.Descriptors = new uint[28];
                for (int i = 0; i < 28; i++)
                {
                    kc.Descriptors[i] = reader.ReadUInt32();
                }

                kc.Reserved = reader.ReadBytes(0x10);
                return kc;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get ARM11 local system capabilities, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ARM11 local system capabilities object, null on error</returns>
        public static ARM11LocalSystemCapabilities? ReadARM11LocalSystemCapabilities(BinaryReader reader)
        {
            var lsc = new ARM11LocalSystemCapabilities();

            try
            {
                lsc.ProgramID = reader.ReadUInt64();
                lsc.CoreVersion = reader.ReadUInt32();
                lsc.Flag1 = (ARM11LSCFlag1)reader.ReadByte();
                lsc.Flag2 = (ARM11LSCFlag2)reader.ReadByte();
                lsc.Flag0 = (ARM11LSCFlag0)reader.ReadByte();
                lsc.Priority = reader.ReadByte();

                lsc.ResourceLimitDescriptors = new ushort[16];
                for (int i = 0; i < 16; i++)
                {
                    lsc.ResourceLimitDescriptors[i] = reader.ReadUInt16();
                }

                lsc.StorageInfo = ReadStorageInfo(reader);

                lsc.ServiceAccessControl = new ulong[32];
                for (int i = 0; i < 32; i++)
                {
                    lsc.ServiceAccessControl[i] = reader.ReadUInt64();
                }

                lsc.ExtendedServiceAccessControl = new ulong[2];
                for (int i = 0; i < 2; i++)
                {
                    lsc.ExtendedServiceAccessControl[i] = reader.ReadUInt64();
                }

                lsc.Reserved = reader.ReadBytes(0xF);
                lsc.ResourceLimitCategory = (ResourceLimitCategory)reader.ReadByte();
                return lsc;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get N3DS cart image, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="development">True if development cart, false otherwise</param>
        /// <returns>N3DS cart image object, null on error</returns>
        public static (Cart?, NCCHHeader?) ReadCart(BinaryReader reader, bool development)
        {
            var cart = new Cart();
            NCCHHeader? backupHeader = null;

            try
            {
                cart.Header = ReadNCSDHeader(reader);
                if (cart.Header == null)
                    return (null, null);

                if (cart.Header.PartitionsFSType == FilesystemType.Normal
                    || cart.Header.PartitionsFSType == FilesystemType.None)
                {
                    cart.CardInfoHeader = ReadCardInfoHeader(reader);
                    if (cart.CardInfoHeader == null)
                        return (null, null);

                    // TODO: Undocumented in current model?
                    backupHeader = ReadNCCHHeader(reader, readSignature: false);

                    if (development)
                    {
                        cart.DevelopmentCardInfoHeader = ReadDevelopmentCardInfoHeader(reader);
                        if (cart.DevelopmentCardInfoHeader == null)
                            return (null, null);
                    }
                }

                return (cart, backupHeader);
            }
            catch
            {
                return (null, null); ;
            }
        }

        /// <summary>
        /// Read from a stream and get an CardInfo header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>CardInfo header object, null on error</returns>
        public static CardInfoHeader? ReadCardInfoHeader(BinaryReader reader)
        {
            var header = new CardInfoHeader();

            try
            {
                header.WritableAddressMediaUnits = reader.ReadUInt32();
                header.CardInfoBitmask = reader.ReadUInt32();
                header.Reserved3 = reader.ReadBytes(0x108);
                header.TitleVersion = reader.ReadUInt16();
                header.CardRevision = reader.ReadUInt16();
                header.Reserved4 = reader.ReadBytes(0xCEC); // Incorrectly documented as 0xCEE

                // TODO: Undocumented in current model?
                _ = reader.ReadBytes(0x10); // header.CardSeedKeyY
                _ = reader.ReadBytes(0x10); // header.EncryptedCardSeed
                _ = reader.ReadBytes(0x10); // header.CardSeedAESMAC
                _ = reader.ReadBytes(0x0C); // header.CardSeedNonce
                _ = reader.ReadBytes(0xC4); // header.Reserved5

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get certificate, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Certificate object, null on error</returns>
        public static Certificate? ReadCertificate(BinaryReader reader)
        {
            var ct = new Certificate();

            try
            {
                ct.SignatureType = (SignatureType)reader.ReadUInt32();
                switch (ct.SignatureType)
                {
                    case SignatureType.RSA_4096_SHA1:
                    case SignatureType.RSA_4096_SHA256:
                        ct.SignatureSize = 0x200;
                        ct.PaddingSize = 0x3C;
                        break;
                    case SignatureType.RSA_2048_SHA1:
                    case SignatureType.RSA_2048_SHA256:
                        ct.SignatureSize = 0x100;
                        ct.PaddingSize = 0x3C;
                        break;
                    case SignatureType.ECDSA_SHA1:
                    case SignatureType.ECDSA_SHA256:
                        ct.SignatureSize = 0x03C;
                        ct.PaddingSize = 0x40;
                        break;
                    default:
                        return null;
                }

                ct.Signature = reader.ReadBytes(ct.SignatureSize);
                reader.ReadBytes(ct.PaddingSize); // Padding
                byte[] issuerBytes = reader.ReadBytes(0x40);
                ct.Issuer = Encoding.ASCII.GetString(issuerBytes);
                ct.KeyType = (PublicKeyType)reader.ReadUInt32();
                byte[] nameBytes = reader.ReadBytes(0x40);
                ct.Name = Encoding.ASCII.GetString(nameBytes);
                ct.ExpirationTime = reader.ReadUInt32();

                switch (ct.KeyType)
                {
                    case PublicKeyType.RSA_4096:
                        ct.RSAModulus = reader.ReadBytes(0x200);
                        ct.RSAPublicExponent = reader.ReadUInt32();
                        ct.RSAPadding = reader.ReadBytes(0x34);
                        break;
                    case PublicKeyType.RSA_2048:
                        ct.RSAModulus = reader.ReadBytes(0x100);
                        ct.RSAPublicExponent = reader.ReadUInt32();
                        ct.RSAPadding = reader.ReadBytes(0x34);
                        break;
                    case PublicKeyType.EllipticCurve:
                        ct.ECCPublicKey = reader.ReadBytes(0x3C);
                        ct.ECCPadding = reader.ReadBytes(0x3C);
                        break;
                    default:
                        return null;
                }

                return ct;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get a CIA header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>CIA header object, null on error</returns>
        public static CIA? ReadCIAHeader(BinaryReader reader)
        {
            var cia = new CIA();

            try
            {
                var header = new CIAHeader();

                header.HeaderSize = reader.ReadUInt32();
                header.Type = reader.ReadUInt16();
                header.Version = reader.ReadUInt16();
                header.CertificateChainSize = reader.ReadUInt32();
                header.TicketSize = reader.ReadUInt32();
                header.TMDFileSize = reader.ReadUInt32();
                header.MetaSize = reader.ReadUInt32();
                header.ContentSize = reader.ReadUInt64();
                header.ContentIndex = reader.ReadBytes(0x2000);

                cia.Header = header;

                var certificateChain = new Certificate[3];
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                certificateChain[0] = ReadCertificate(reader)!; // CA
                certificateChain[1] = ReadCertificate(reader)!; // Ticket
                certificateChain[2] = ReadCertificate(reader)!; // TMD
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                cia.CertificateChain = certificateChain;

                cia.Ticket = ReadTicket(reader, header.TicketSize);
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                cia.TMDFileData = ReadTitleMetadata(reader, header.TMDFileSize);
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                long startingPosition = reader.BaseStream.Position;
                var headers = new List<NCCHHeader>();
                while ((ulong)reader.BaseStream.Position < (ulong)startingPosition + header.ContentSize)
                {
                    long initPosition = reader.BaseStream.Position;
                    var ncchHeader = ReadNCCHHeader(reader, readSignature: true);
                    if (ncchHeader == null)
                        break;

                    headers.Add(ncchHeader);
                    reader.BaseStream.Seek(initPosition + ncchHeader.ContentSizeInMediaUnits * 0x200, SeekOrigin.Begin);
                }

                cia.Partitions = [.. headers];
                if (header.MetaSize > 0)
                    cia.MetaData = ReadMetaData(reader);

                return cia;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get code set info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Code set info object, null on error</returns>
        public static CodeSetInfo? ReadCodeSetInfo(BinaryReader reader)
        {
            var csi = new CodeSetInfo();

            try
            {
                csi.Address = reader.ReadUInt32();
                csi.PhysicalRegionSizeInPages = reader.ReadUInt32();
                csi.SizeInBytes = reader.ReadUInt32();
                return csi;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get content chunk record, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Content chunk record object, null on error</returns>
        public static ContentChunkRecord? ReadContentChunkRecord(BinaryReader reader)
        {
            var ccr = new ContentChunkRecord();

            try
            {
                ccr.ContentId = reader.ReadUInt32();
                ccr.ContentIndex = (ContentIndex)reader.ReadUInt16();
                ccr.ContentType = (TMDContentType)reader.ReadUInt16();
                ccr.ContentSize = reader.ReadUInt64();
                ccr.SHA256Hash = reader.ReadBytes(0x20);
                return ccr;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get content info record, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Content info record object, null on error</returns>
        public static ContentInfoRecord? ReadContentInfoRecord(BinaryReader reader)
        {
            var cir = new ContentInfoRecord();

            try
            {
                cir.ContentIndexOffset = reader.ReadUInt16();
                cir.ContentCommandCount = reader.ReadUInt16();
                cir.UnhashedContentRecordsSHA256Hash = reader.ReadBytes(0x20);
                return cir;
            }
            catch
            {
                return null;
            }
        }

        // TODO: Create model for this
        /*
        /// <summary>
        /// Read from a stream and get a CXI extended header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>CXI extended header object, null on error</returns>
        public static CXIExtendedHeader? ReadCXIExtendedHeader(BinaryReader reader)
        {
            var header = new CXIExtendedHeader();

            try
            {
                header.SCI = ReadSystemControlInfo(reader);
                header.ACI = ReadAccessControlInfo(reader);
                header.AccessDescSignature = reader.ReadBytes(0x100);
                header.NCCHHDRPublicKey = reader.ReadBytes(0x100);
                header.ACIForLimitations = ReadAccessControlInfo(reader);
                return header;
            }
            catch
            {
                return null;
            }
        }
        */

        /// <summary>
        /// Read from a stream and get an DevelopmentCardInfo header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>DevelopmentCardInfo object, null on error</returns>
        public static DevelopmentCardInfoHeader? ReadDevelopmentCardInfoHeader(BinaryReader reader)
        {
            var header = new DevelopmentCardInfoHeader();

            try
            {
                header.CardDeviceReserved1 = reader.ReadBytes(0x200);
                header.TitleKey = reader.ReadBytes(0x10);
                header.CardDeviceReserved2 = reader.ReadBytes(0xF0);

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get an ExeFS file header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ExeFS file header object, null on error</returns>
        public static ExeFSFileHeader? ReadExeFSFileHeader(BinaryReader reader)
        {
            var header = new ExeFSFileHeader();

            try
            {
                byte[] fileNameBytes = reader.ReadBytes(8);
                header.FileName = Encoding.ASCII.GetString(fileNameBytes);
                header.FileOffset = reader.ReadUInt32();
                header.FileSize = reader.ReadUInt32();
                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get an ExeFS header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ExeFS header object, null on error</returns>
        public static ExeFSHeader? ReadExeFSHeader(BinaryReader reader)
        {
            var header = new ExeFSHeader();

            try
            {
                header.FileHeaders = new ExeFSFileHeader[10];
                for (int i = 0; i < 10; i++)
                {
                    header.FileHeaders[i] = ReadExeFSFileHeader(reader)!;
                }

                header.Reserved = reader.ReadBytes(0x20);

                header.FileHashes = new byte[10][];
                for (int i = 0; i < 10; i++)
                {
                    header.FileHashes[9 - i] = reader.ReadBytes(0x20);
                }

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get the Metafile data, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Metafile data object, null on error</returns>
        public static MetaData? ReadMetaData(BinaryReader reader)
        {
            var metaData = new MetaData();

            try
            {
                metaData.TitleIDDependencyList = reader.ReadBytes(0x180);
                metaData.Reserved1 = reader.ReadBytes(0x180);
                metaData.CoreVersion = reader.ReadUInt32();
                metaData.Reserved2 = reader.ReadBytes(0xFC);
                metaData.IconData = reader.ReadBytes(0x36C0);

                return metaData;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get an NCCH header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="readSignature">True if the RSA signature is read, false otherwise</param>
        /// <returns>NCCH header object, null on error</returns>
        public static NCCHHeader? ReadNCCHHeader(BinaryReader reader, bool readSignature)
        {
            var header = new NCCHHeader();

            try
            {
                if (readSignature)
                    header.RSA2048Signature = reader.ReadBytes(0x100);

                if (new string(reader.ReadChars(4)) != NCCHMagicNumber)
                    return null;

                header.ContentSizeInMediaUnits = reader.ReadUInt32();
                header.PartitionId = reader.ReadUInt64();
                header.MakerCode = reader.ReadUInt16();
                header.Version = reader.ReadUInt16();
                header.VerificationHash = reader.ReadUInt32();
                header.ProgramId = reader.ReadBytes(8);
                header.Reserved1 = reader.ReadBytes(0x10);
                header.LogoRegionHash = reader.ReadBytes(0x20);
                byte[] productCodeBytes = reader.ReadBytes(0x10);
                header.ProductCode = Encoding.ASCII.GetString(productCodeBytes);
                header.ExtendedHeaderHash = reader.ReadBytes(0x20);
                header.ExtendedHeaderSizeInBytes = reader.ReadUInt32();
                header.Reserved2 = reader.ReadUInt32();
                header.Flags = ReadNCCHHeaderFlags(reader);
                header.PlainRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.PlainRegionSizeInMediaUnits = reader.ReadUInt32();
                header.LogoRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.LogoRegionSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSOffsetInMediaUnits = reader.ReadUInt32();
                header.ExeFSSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.Reserved3 = reader.ReadUInt32();
                header.RomFSOffsetInMediaUnits = reader.ReadUInt32();
                header.RomFSSizeInMediaUnits = reader.ReadUInt32();
                header.RomFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.Reserved4 = reader.ReadUInt32();
                header.ExeFSSuperblockHash = reader.ReadBytes(0x20);
                header.RomFSSuperblockHash = reader.ReadBytes(0x20);

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get an NCCH header flags, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>NCCH header flags object, null on error</returns>
        public static NCCHHeaderFlags? ReadNCCHHeaderFlags(BinaryReader reader)
        {
            var flags = new NCCHHeaderFlags();

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
        /// Read from a stream and get an NCSD header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>NCSD header object, null on error</returns>
        public static NCSDHeader? ReadNCSDHeader(BinaryReader reader)
        {
            var header = new NCSDHeader();

            try
            {
                header.RSA2048Signature = reader.ReadBytes(0x100);

                if (new string(reader.ReadChars(4)) != NCSDMagicNumber)
                    return null;

                header.ImageSizeInMediaUnits = reader.ReadUInt32();
                header.MediaId = reader.ReadBytes(8);
                header.PartitionsFSType = (FilesystemType)reader.ReadUInt64();
                header.PartitionsCryptType = reader.ReadBytes(8);

                header.PartitionsTable = new PartitionTableEntry[8];
                for (int i = 0; i < 8; i++)
                {
                    header.PartitionsTable[i] = ReadPartitionTableEntry(reader)!;
                }

                if (header.PartitionsFSType == FilesystemType.Normal
                    || header.PartitionsFSType == FilesystemType.None)
                {
                    header.ExheaderHash = reader.ReadBytes(0x20);
                    header.AdditionalHeaderSize = reader.ReadUInt32();
                    header.SectorZeroOffset = reader.ReadUInt32();
                    header.PartitionFlags = reader.ReadBytes(8);

                    header.PartitionIdTable = new ulong[8];
                    for (int i = 0; i < 8; i++)
                    {
                        header.PartitionIdTable[i] = reader.ReadUInt64();
                    }

                    header.Reserved1 = reader.ReadBytes(0x20);
                    header.Reserved2 = reader.ReadBytes(0xE);
                    header.FirmUpdateByte1 = reader.ReadByte();
                    header.FirmUpdateByte2 = reader.ReadByte();
                }
                else if (header.PartitionsFSType == FilesystemType.FIRM)
                {
                    header.Unknown = reader.ReadBytes(0x5E);
                    header.EncryptedMBR = reader.ReadBytes(0x42);
                }

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get partition table entry, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Partition table entry object, null on error</returns>
        public static PartitionTableEntry? ReadPartitionTableEntry(BinaryReader reader)
        {
            var entry = new PartitionTableEntry();

            try
            {
                entry.Offset = reader.ReadUInt32();
                entry.Length = reader.ReadUInt32();
                return entry;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get a RomFS header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>RomFS header object, null on error</returns>
        public static RomFSHeader? ReadRomFSHeader(BinaryReader reader)
        {
            var header = new RomFSHeader();

            try
            {
                if (new string(reader.ReadChars(4)) != RomFSMagicNumber)
                    return null;

                if (reader.ReadUInt32() != RomFSSecondMagicNumber)
                    return null;

                header.MasterHashSize = reader.ReadUInt32();
                header.Level1LogicalOffset = reader.ReadUInt64();
                header.Level1HashdataSize = reader.ReadUInt64();
                header.Level1BlockSizeLog2 = reader.ReadUInt32();
                header.Reserved1 = reader.ReadUInt32();
                header.Level2LogicalOffset = reader.ReadUInt64();
                header.Level2HashdataSize = reader.ReadUInt64();
                header.Level2BlockSizeLog2 = reader.ReadUInt32();
                header.Reserved2 = reader.ReadUInt32();
                header.Level3LogicalOffset = reader.ReadUInt64();
                header.Level3HashdataSize = reader.ReadUInt64();
                header.Level3BlockSizeLog2 = reader.ReadUInt32();
                header.Reserved3 = reader.ReadUInt32();
                header.Reserved4 = reader.ReadUInt32();
                header.OptionalInfoSize = reader.ReadUInt32();

                return header;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get storage info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>Storage info object, null on error</returns>
        public static StorageInfo? ReadStorageInfo(BinaryReader reader)
        {
            var si = new StorageInfo();

            try
            {
                si.ExtdataID = reader.ReadUInt64();
                si.SystemSavedataIDs = reader.ReadBytes(8);
                si.StorageAccessibleUniqueIDs = reader.ReadBytes(8);
                si.FileSystemAccessInfo = reader.ReadBytes(7);
                si.OtherAttributes = (StorageInfoOtherAttributes)reader.ReadByte();
                return si;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get system control info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>System control info object, null on error</returns>
        public static SystemControlInfo? ReadSystemControlInfo(BinaryReader reader)
        {
            var sci = new SystemControlInfo();

            try
            {
                byte[] applicationTitleBytes = reader.ReadBytes(8);
                sci.ApplicationTitle = Encoding.ASCII.GetString(applicationTitleBytes);
                sci.Reserved1 = reader.ReadBytes(5);
                sci.Flag = reader.ReadByte();
                sci.RemasterVersion = reader.ReadUInt16();
                sci.TextCodeSetInfo = ReadCodeSetInfo(reader);
                sci.StackSize = reader.ReadUInt32();
                sci.ReadOnlyCodeSetInfo = ReadCodeSetInfo(reader);
                sci.Reserved2 = reader.ReadUInt32();
                sci.DataCodeSetInfo = ReadCodeSetInfo(reader);
                sci.BSSSize = reader.ReadUInt32();

                sci.DependencyModuleList = new ulong[48];
                for (int i = 0; i < 48; i++)
                {
                    sci.DependencyModuleList[i] = reader.ReadUInt64();
                }

                sci.SystemInfo = ReadSystemInfo(reader);
                return sci;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get system info, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>System info object, null on error</returns>
        public static SystemInfo? ReadSystemInfo(BinaryReader reader)
        {
            var si = new SystemInfo();

            try
            {
                si.SaveDataSize = reader.ReadUInt64();
                si.JumpID = reader.ReadUInt64();
                si.Reserved = reader.ReadBytes(0x30);
                return si;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get ticket, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="ticketSize">Ticket size from the header</param>
        /// <returns>Ticket object, null on error</returns>
        public static Ticket? ReadTicket(BinaryReader reader, uint ticketSize)
        {
            var tk = new Ticket();

            try
            {
                long startingPosition = reader.BaseStream.Position;

                tk.SignatureType = (SignatureType)reader.ReadUInt32();
                switch (tk.SignatureType)
                {
                    case SignatureType.RSA_4096_SHA1:
                    case SignatureType.RSA_4096_SHA256:
                        tk.SignatureSize = 0x200;
                        tk.PaddingSize = 0x3C;
                        break;
                    case SignatureType.RSA_2048_SHA1:
                    case SignatureType.RSA_2048_SHA256:
                        tk.SignatureSize = 0x100;
                        tk.PaddingSize = 0x3C;
                        break;
                    case SignatureType.ECDSA_SHA1:
                    case SignatureType.ECDSA_SHA256:
                        tk.SignatureSize = 0x03C;
                        tk.PaddingSize = 0x40;
                        break;
                    default:
                        return null;
                }

                tk.Signature = reader.ReadBytes(tk.SignatureSize);
                reader.ReadBytes(tk.PaddingSize); // Padding
                byte[] issuerBytes = reader.ReadBytes(0x40);
                tk.Issuer = Encoding.ASCII.GetString(issuerBytes);
                tk.ECCPublicKey = reader.ReadBytes(0x3C);
                tk.Version = reader.ReadByte();
                tk.CaCrlVersion = reader.ReadByte();
                tk.SignerCrlVersion = reader.ReadByte();
                tk.TitleKey = reader.ReadBytes(0x10);
                tk.Reserved1 = reader.ReadByte();
                tk.TicketID = reader.ReadUInt64();
                tk.ConsoleID = reader.ReadUInt32();
                tk.TitleID = reader.ReadUInt64();
                tk.Reserved2 = reader.ReadBytes(2);
                tk.TicketTitleVersion = reader.ReadUInt16();
                tk.Reserved3 = reader.ReadBytes(8);
                tk.LicenseType = reader.ReadByte();
                tk.CommonKeyYIndex = reader.ReadByte();
                tk.Reserved4 = reader.ReadBytes(0x2A);
                tk.eShopAccountID = reader.ReadUInt32();
                tk.Reserved5 = reader.ReadByte();
                tk.Audit = reader.ReadByte();
                tk.Reserved6 = reader.ReadBytes(0x42);

                tk.Limits = new uint[0x10];
                for (int i = 0; i < 0x10; i++)
                {
                    tk.Limits[i] = reader.ReadUInt32();
                }

                reader.ReadBytes(4); // Seek to size in Content Index
                tk.ContentIndexSize = BitConverter.ToUInt32(reader.ReadBytes(4).Reverse().ToArray(), 0);
                reader.BaseStream.Seek(-8, SeekOrigin.Current);
                tk.ContentIndex = reader.ReadBytes((int)tk.ContentIndexSize);
                if (reader.BaseStream.Position % 64 != 0)
                    reader.BaseStream.Seek(64 - (reader.BaseStream.Position % 64), SeekOrigin.Current);

                if (ticketSize > (reader.BaseStream.Position - startingPosition) + (2 * 0x200))
                {
                    tk.CertificateChain = new Certificate[2];
                    tk.CertificateChain[0] = ReadCertificate(reader)!; // Ticket
                    tk.CertificateChain[1] = ReadCertificate(reader)!; // CA
                }

                return tk;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Read from a stream and get ticket metadata, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="metadataSize">Metadata size from the header</param>
        /// <returns>Title metadata object, null on error</returns>
        public static TitleMetadata? ReadTitleMetadata(BinaryReader reader, uint metadataSize)
        {
            var tm = new TitleMetadata();

            try
            {
                long startingPosition = reader.BaseStream.Position;

                tm.SignatureType = (SignatureType)reader.ReadUInt32();
                switch (tm.SignatureType)
                {
                    case SignatureType.RSA_4096_SHA1:
                    case SignatureType.RSA_4096_SHA256:
                        tm.SignatureSize = 0x200;
                        tm.PaddingSize = 0x3C;
                        break;
                    case SignatureType.RSA_2048_SHA1:
                    case SignatureType.RSA_2048_SHA256:
                        tm.SignatureSize = 0x100;
                        tm.PaddingSize = 0x3C;
                        break;
                    case SignatureType.ECDSA_SHA1:
                    case SignatureType.ECDSA_SHA256:
                        tm.SignatureSize = 0x03C;
                        tm.PaddingSize = 0x40;
                        break;
                }

                tm.Signature = reader.ReadBytes(tm.SignatureSize);
                tm.Padding1 = reader.ReadBytes(tm.PaddingSize);
                byte[] issuerBytes = reader.ReadBytes(0x40);
                tm.Issuer = Encoding.ASCII.GetString(issuerBytes);
                tm.Version = reader.ReadByte();
                tm.CaCrlVersion = reader.ReadByte();
                tm.SignerCrlVersion = reader.ReadByte();
                tm.Reserved1 = reader.ReadByte();
                tm.SystemVersion = reader.ReadUInt64();
                tm.TitleID = reader.ReadUInt64();
                tm.TitleType = reader.ReadUInt32();
                tm.GroupID = reader.ReadUInt16();
                tm.SaveDataSize = reader.ReadUInt32();
                tm.SRLPrivateSaveDataSize = reader.ReadUInt32();
                tm.Reserved2 = reader.ReadBytes(4);
                tm.SRLFlag = reader.ReadByte();
                tm.Reserved3 = reader.ReadBytes(0x31);
                tm.AccessRights = reader.ReadUInt32();
                tm.TitleVersion = reader.ReadUInt16();
                tm.ContentCount = BitConverter.ToUInt16(reader.ReadBytes(2).Reverse().ToArray(), 0);
                tm.BootContent = reader.ReadUInt16();
                tm.Padding2 = reader.ReadBytes(2);
                tm.SHA256HashContentInfoRecords = reader.ReadBytes(0x20);

                tm.ContentInfoRecords = new ContentInfoRecord[64];
                for (int i = 0; i < 64; i++)
                {
                    tm.ContentInfoRecords[i] = ReadContentInfoRecord(reader)!;
                }

                tm.ContentChunkRecords = new ContentChunkRecord[tm.ContentCount];
                for (int i = 0; i < tm.ContentCount; i++)
                {
                    tm.ContentChunkRecords[i] = ReadContentChunkRecord(reader)!;
                }

                if (metadataSize > (reader.BaseStream.Position - startingPosition) + (2 * 0x200))
                {
                    tm.CertificateChain = new Certificate[2];
                    tm.CertificateChain[0] = ReadCertificate(reader)!; // TMD
                    tm.CertificateChain[1] = ReadCertificate(reader)!; // CA
                }

                return tm;
            }
            catch
            {
                return null;
            }
        }

        #endregion

        #region Writing

        /// <summary>
        /// Write NCCH header flags to stream, if possible
        /// </summary>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        public static void Write(NCCHHeaderFlags flags, BinaryWriter writer)
        {
            try
            {
                writer.Write(flags.Reserved0);
                writer.Write(flags.Reserved1);
                writer.Write(flags.Reserved2);
                writer.Write((byte)flags.CryptoMethod);
                writer.Write((byte)flags.ContentPlatform);
                writer.Write((byte)flags.MediaPlatformIndex);
                writer.Write(flags.ContentUnitSize);
                writer.Write((byte)flags.BitMasks);

            }
            catch { }
        }

        #endregion
    }
}
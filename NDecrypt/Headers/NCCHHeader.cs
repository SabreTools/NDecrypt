using System;
using System.IO;
using System.Linq;
using System.Numerics;
using NDecrypt.Data;

namespace NDecrypt.Headers
{
    public class NCCHHeader
    {
        private const string NCCHMagicNumber = "NCCH";

        /// <summary>
        /// Partition number for the current partition
        /// </summary>
        public int PartitionNumber { get; set; }

        /// <summary>
        /// Partition table entry for the current partition
        /// </summary>
        public PartitionTableEntry Entry { get; set; }

        /// <summary>
        /// RSA-2048 signature of the NCCH header, using SHA-256.
        /// </summary>
        public byte[] RSA2048Signature { get; private set; }

        /// <summary>
        /// Content size, in media units (1 media unit = 0x200 bytes)
        /// </summary>
        public uint ContentSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Partition ID
        /// </summary>
        public byte[] PartitionId { get; private set; }
        public byte[] PlainIV { get { return PartitionId.Concat(Constants.PlainCounter).ToArray(); } }
        public byte[] ExeFSIV { get { return PartitionId.Concat(Constants.ExefsCounter).ToArray(); } }
        public byte[] RomFSIV { get { return PartitionId.Concat(Constants.RomfsCounter).ToArray(); } }

        /// <summary>
        /// Boot rom key
        /// </summary>
        public BigInteger KeyX { get; set; }

        /// <summary>
        /// NCCH boot rom key
        /// </summary>
        public BigInteger KeyX2C { get; set; }

        /// <summary>
        /// Kernel9/Process9 key
        /// </summary>
        public BigInteger KeyY { get; set; }

        /// <summary>
        /// Normal AES key
        /// </summary>
        public BigInteger NormalKey { get; set; }

        /// <summary>
        /// NCCH AES key
        /// </summary>
        public BigInteger NormalKey2C { get; set; }

        /// <summary>
        /// Maker code
        /// </summary>
        public byte[] MakerCode { get; private set; }

        /// <summary>
        /// Version
        /// </summary>
        public byte[] Version { get; private set; }

        /// <summary>
        /// When ncchflag[7] = 0x20 starting with FIRM 9.6.0-X, this is compared with the first output u32 from a
        /// SHA256 hash. The data used for that hash is 0x18-bytes: [0x10-long title-unique content lock seed]
        /// [programID from NCCH + 0x118]. This hash is only used for verification of the content lock seed, and
        /// is not the actual keyY.
        /// </summary>
        public byte[] VerificationHash { get; private set; }

        /// <summary>
        /// Program ID
        /// </summary>
        public byte[] ProgramId { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved1 { get; private set; }

        /// <summary>
        /// Logo Region SHA-256 hash. (For applications built with SDK 5+) (Supported from firmware: 5.0.0-11)
        /// </summary>
        public byte[] LogoRegionHash { get; private set; }

        /// <summary>
        /// Product code
        /// </summary>
        public byte[] ProductCode { get; private set; }

        /// <summary>
        /// Extended header SHA-256 hash (SHA256 of 2x Alignment Size, beginning at 0x0 of ExHeader)
        /// </summary>
        public byte[] ExtendedHeaderHash { get; private set; }

        /// <summary>
        /// Extended header size, in bytes
        /// </summary>
        public uint ExtendedHeaderSizeInBytes { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved2 { get; private set; }

        /// <summary>
        /// Flags
        /// </summary>
        public NCCHHeaderFlags Flags { get; private set; }

        /// <summary>
        /// Plain region offset, in media units
        /// </summary>
        public uint PlainRegionOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// Plain region size, in media units
        /// </summary>
        public uint PlainRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Logo Region offset, in media units (For applications built with SDK 5+) (Supported from firmware: 5.0.0-11)
        /// </summary>
        public uint LogoRegionOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// Logo Region size, in media units (For applications built with SDK 5+) (Supported from firmware: 5.0.0-11)
        /// </summary>
        public uint LogoRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// ExeFS offset, in media units
        /// </summary>
        public uint ExeFSOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// ExeFS size, in media units
        /// </summary>
        public uint ExeFSSizeInMediaUnits { get; private set; }

        /// <summary>
        /// ExeFS hash region size, in media units
        /// </summary>
        public uint ExeFSHashRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved3 { get; private set; }

        /// <summary>
        /// RomFS offset, in media units
        /// </summary>
        public uint RomFSOffsetInMediaUnits { get; private set; }

        /// <summary>
        /// RomFS size, in media units
        /// </summary>
        public uint RomFSSizeInMediaUnits { get; private set; }

        /// <summary>
        /// RomFS hash region size, in media units
        /// </summary>
        public uint RomFSHashRegionSizeInMediaUnits { get; private set; }

        /// <summary>
        /// Reserved
        /// </summary>
        public byte[] Reserved4 { get; private set; }

        /// <summary>
        /// ExeFS superblock SHA-256 hash - (SHA-256 hash, starting at 0x0 of the ExeFS over the number of
        /// media units specified in the ExeFS hash region size)
        /// </summary>
        public byte[] ExeFSSuperblockHash { get; private set; }

        /// <summary>
        /// RomFS superblock SHA-256 hash - (SHA-256 hash, starting at 0x0 of the RomFS over the number
        /// of media units specified in the RomFS hash region size)
        /// </summary>
        public byte[] RomFSSuperblockHash { get; private set; }

        /// <summary>
        /// Read from a stream and get an NCCH header, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="readSignature">True if the RSA signature is read, false otherwise</param>
        /// <returns>NCCH header object, null on error</returns>
        public static NCCHHeader Read(BinaryReader reader, bool readSignature)
        {
            NCCHHeader header = new NCCHHeader();

            try
            {
                if (readSignature)
                    header.RSA2048Signature = reader.ReadBytes(0x100);

                if (new string(reader.ReadChars(4)) != NCCHMagicNumber)
                    return null;

                header.ContentSizeInMediaUnits = reader.ReadUInt32();
                header.PartitionId = reader.ReadBytes(8).Reverse().ToArray();
                header.MakerCode = reader.ReadBytes(2);
                header.Version = reader.ReadBytes(2);
                header.VerificationHash = reader.ReadBytes(4);
                header.ProgramId = reader.ReadBytes(8);
                header.Reserved1 = reader.ReadBytes(0x10);
                header.LogoRegionHash = reader.ReadBytes(0x20);
                header.ProductCode = reader.ReadBytes(0x10);
                header.ExtendedHeaderHash = reader.ReadBytes(0x20);
                header.ExtendedHeaderSizeInBytes = reader.ReadUInt32();
                header.Reserved2 = reader.ReadBytes(4);
                header.Flags = NCCHHeaderFlags.Read(reader);
                header.PlainRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.PlainRegionSizeInMediaUnits = reader.ReadUInt32();
                header.LogoRegionOffsetInMediaUnits = reader.ReadUInt32();
                header.LogoRegionSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSOffsetInMediaUnits = reader.ReadUInt32();
                header.ExeFSSizeInMediaUnits = reader.ReadUInt32();
                header.ExeFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.Reserved3 = reader.ReadBytes(4);
                header.RomFSOffsetInMediaUnits = reader.ReadUInt32();
                header.RomFSSizeInMediaUnits = reader.ReadUInt32();
                header.RomFSHashRegionSizeInMediaUnits = reader.ReadUInt32();
                header.Reserved4 = reader.ReadBytes(4);
                header.ExeFSSuperblockHash = reader.ReadBytes(0x20);
                header.RomFSSuperblockHash = reader.ReadBytes(0x20);

                return header;
            }
            catch
            {
                return null;
            }
        }
    }
}

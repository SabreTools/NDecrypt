using System;
using System.IO;
using System.Linq;
using NDecrypt.NDS;
using NDecrypt.NDS.Headers;

namespace NDecrypt
{
    public class DSTool : ITool
    {
        /// <summary>
        /// Name of the input DS/DSi file
        /// </summary>
        private readonly string filename;

        /// <summary>
        /// Flag to determine if encrypting or decrypting
        /// </summary>
        private readonly bool encrypt;

        /// <summary>
        /// Flag to determine if forcing operations
        /// </summary>
        private readonly bool force;

        #region Encryption process variables

        private uint[] cardHash = new uint[0x412];
        private uint[] arg2 = new uint[3];

        #endregion

        public DSTool(string filename, bool encrypt, bool force)
        {
            this.filename = filename;
            this.encrypt = encrypt;
            this.force = force;
        }

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        public bool ProcessFile()
        {
            // Make sure we have a file to process first
            Console.WriteLine(filename);
            if (!File.Exists(filename))
                return false;

            // Open the read and write on the same file for inplace processing
            using (BinaryReader reader = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
            using (BinaryWriter writer = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
            {
                NDSHeader header = NDSHeader.Read(reader);
                if (header == null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Process the secure area
                ProcessSecureArea(header, reader, writer);
            }

            return true;
        }

        /// <summary>
        /// Process secure area in the DS/DSi file
        /// </summary>
        /// <param name="ndsHeader">NDS header representing the DS file</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessSecureArea(NDSHeader ndsHeader, BinaryReader reader, BinaryWriter writer)
        {
            // If we're forcing the operation, tell the user
            if (force)
            {
                Console.WriteLine("File is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check to see if we should be proceeding
            else
            {
                bool? isDecrypted = CheckIfDecrypted(reader);
                if (isDecrypted == null)
                {
                    Console.WriteLine("File has an empty secure area, cannot proceed");
                    return;
                }
                else if (encrypt ^ isDecrypted.Value)
                {
                    Console.WriteLine("File is already " + (encrypt ? "encrypted" : "decrypted"));
                    return;
                }
            }

            ProcessARM9(ndsHeader, reader, writer);

            Console.WriteLine("File has been " + (encrypt ? "encrypted" : "decrypted"));
        }

        /// <summary>
        /// Determine if the current file is already decrypted or not (or has an empty secure area)
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>True if the file has known values for a decrypted file, null if it's empty, false otherwise</returns>
        private bool? CheckIfDecrypted(BinaryReader reader)
        {
            reader.BaseStream.Seek(0x4000, SeekOrigin.Begin);
            uint firstValue = reader.ReadUInt32();
            uint secondValue = reader.ReadUInt32();

            // Empty secure area standard
            if (firstValue == 0x00000000 && secondValue == 0x00000000)
            {
                Console.WriteLine("Empty secure area found. Cannot be encrypted or decrypted.");
                return null;
            }

            // Improperly decrypted empty secure area (decrypt empty with woodsec)
            else if ((firstValue == 0xE386C397 && secondValue == 0x82775B7E)
                || (firstValue == 0xF98415B8 && secondValue == 0x698068FC))
            {
                Console.WriteLine("Improperly decrypted empty secure area found. Should be encrypted to get proper value.");
                return true;
            }

            // Improperly encrypted empty secure area (encrypt empty with woodsec)
            else if ((firstValue == 0x4BCE88BE && secondValue == 0xD3662DD1)
                || (firstValue == 0x2543C534 && secondValue == 0xCC4BE38E))
            {
                Console.WriteLine("Improperly encrypted empty secure area found. Should be decrypted to get proper value.");
                return false;
            }

            // Properly decrypted nonstandard value (mastering issue)
            else if ((firstValue == 0xD0D48B67 && secondValue == 0x39392F23) // Dragon Quest 5 (EU)
                || (firstValue == 0x014A191A && secondValue == 0xA5C470B9)   // Dragon Quest 5 (USA)
                || (firstValue == 0x7829BC8D && secondValue == 0x9968EF44))  // Dragon Quest 5 (JP)
            {
                Console.WriteLine("Decrypted secure area for known, nonstandard value found.");
                return true;
            }

            // Properly decrypted prototype value
            else if (firstValue == 0xBA35F813 && secondValue == 0xB691AAE8)
            {
                Console.WriteLine("Decrypted secure area for prototype found.");
                return true;
            }

            // Properly encrypted prototype value
            else if (firstValue == 0xA71329EE && secondValue == 0x2A1D4C38)
            {
                Console.WriteLine("Encrypted secure area for prototype found.");
                return false;
            }

            // Standard decryption values
            return firstValue == 0xE7FFDEFF && secondValue == 0xE7FFDEFF;
        }

        /// <summary>
        /// Process the secure ARM9 region of the file, if possible
        /// </summary>
        /// <param name="ndsHeader">NDS header representing the DS file</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessARM9(NDSHeader ndsHeader, BinaryReader reader, BinaryWriter writer)
        {
            // Seek to the beginning of the secure area
            reader.BaseStream.Seek(0x4000, SeekOrigin.Begin);
            writer.BaseStream.Seek(0x4000, SeekOrigin.Begin);

            // Grab the first two blocks
            uint p0 = reader.ReadUInt32();
            uint p1 = reader.ReadUInt32();

            // Perform the initialization steps
            Init1(ndsHeader);
            if (!encrypt) Decrypt(ref p1, ref p0);
            arg2[1] <<= 1;
            arg2[2] >>= 1;
            Init2();

            // If we're decrypting, set the proper flags
            if (!encrypt)
            {
                Decrypt(ref p1, ref p0);
                if (p0 == Constants.MAGIC30 && p1 == Constants.MAGIC34)
                {
                    p0 = 0xE7FFDEFF;
                    p1 = 0xE7FFDEFF;
                }

                writer.Write(p0);
                writer.Write(p1);
            }

            // Ensure alignment
            reader.BaseStream.Seek(0x4008, SeekOrigin.Begin);
            writer.BaseStream.Seek(0x4008, SeekOrigin.Begin);

            // Loop throgh the main encryption step
            uint size = 0x800 - 8;
            while (size > 0)
            {
                p0 = reader.ReadUInt32();
                p1 = reader.ReadUInt32();

                if (encrypt)
                    Encrypt(ref p1, ref p0);
                else
                    Decrypt(ref p1, ref p0);

                writer.Write(p0);
                writer.Write(p1);

                size -= 8;
            }

            // Replace the header explicitly if we're encrypting
            if (encrypt)
            {
                reader.BaseStream.Seek(0x4000, SeekOrigin.Begin);
                writer.BaseStream.Seek(0x4000, SeekOrigin.Begin);

                p0 = reader.ReadUInt32();
                p1 = reader.ReadUInt32();

                if (p0 == 0xE7FFDEFF && p1 == 0xE7FFDEFF)
                {
                    p0 = Constants.MAGIC30;
                    p1 = Constants.MAGIC34;
                }

                Encrypt(ref p1, ref p0);
                Init1(ndsHeader);
                Encrypt(ref p1, ref p0);

                writer.Write(p0);
                writer.Write(p1);
            }
        }

        /// <summary>
        /// First common initialization step
        /// </summary>
        /// <param name="ndsHeader">NDS header representing the DS file</param>
        private void Init1(NDSHeader ndsHeader)
        {
            Buffer.BlockCopy(Constants.NDSEncryptionData, 0, cardHash, 0, 4 * (1024 + 18));
            arg2 = new uint[] { ndsHeader.Gamecode, ndsHeader.Gamecode >> 1, ndsHeader.Gamecode << 1 };
            Init2();
            Init2();
        }

        /// <summary>
        /// Second common initialization step
        /// </summary>
        private void Init2()
        {
            Encrypt(ref arg2[2], ref arg2[1]);
            Encrypt(ref arg2[1], ref arg2[0]);

            byte[] allBytes = BitConverter.GetBytes(arg2[0])
                .Concat(BitConverter.GetBytes(arg2[1]))
                .Concat(BitConverter.GetBytes(arg2[2]))
                .ToArray();

            UpdateHashtable(allBytes);
        }

        /// <summary>
        /// Perform a decryption step
        /// </summary>
        /// <param name="arg1">First unsigned value to use in decryption</param>
        /// <param name="arg2">Second unsigned value to use in decryption</param>
        private void Decrypt(ref uint arg1, ref uint arg2)
        {
            uint a = arg1;
            uint b = arg2;
            for (int i = 17; i > 1; i--)
            {
                uint c = cardHash[i] ^ a;
                a = b ^ Lookup(c);
                b = c;
            }

            arg1 = b ^ cardHash[0];
            arg2 = a ^ cardHash[1];
        }

        /// <summary>
        /// Perform an encryption step
        /// </summary>
        /// <param name="arg1">First unsigned value to use in encryption</param>
        /// <param name="arg2">Second unsigned value to use in encryption</param>
        private void Encrypt(ref uint arg1, ref uint arg2)
        {
            uint a = arg1;
            uint b = arg2;
            for (int i = 0; i < 16; i++)
            {
                uint c = cardHash[i] ^ a;
                a = b ^ Lookup(c);
                b = c;
            }

            arg2 = a ^ cardHash[16];
            arg1 = b ^ cardHash[17];
        }

        /// <summary>
        /// Lookup the value from the hashtable
        /// </summary>
        /// <param name="v">Value to lookup in the hashtable</param>
        /// <returns>Processed value through the hashtable</returns>
        private uint Lookup(uint v)
        {
            uint a = (v >> 24) & 0xFF;
            uint b = (v >> 16) & 0xFF;
            uint c = (v >> 8) & 0xFF;
            uint d = (v >> 0) & 0xFF;

            a = cardHash[a + 18 + 0];
            b = cardHash[b + 18 + 256];
            c = cardHash[c + 18 + 512];
            d = cardHash[d + 18 + 768];

            return d + (c ^ (b + a));
        }

        /// <summary>
        /// Update the hashtable
        /// </summary>
        /// <param name="arg1">Value to update the hashtable with</param>
        private void UpdateHashtable(byte[] arg1)
        {
            for (int j = 0; j < 18; j++)
            {
                uint r3 = 0;
                for (int i = 0; i < 4; i++)
                {
                    r3 <<= 8;
                    r3 |= arg1[(j * 4 + i) & 7];
                }

                cardHash[j] ^= r3;
            }

            uint tmp1 = 0;
            uint tmp2 = 0;
            for (int i = 0; i < 18; i += 2)
            {
                Encrypt(ref tmp1, ref tmp2);
                cardHash[i + 0] = tmp1;
                cardHash[i + 1] = tmp2;
            }
            for (int i = 0; i < 0x400; i += 2)
            {
                Encrypt(ref tmp1, ref tmp2);
                cardHash[i + 18 + 0] = tmp1;
                cardHash[i + 18 + 1] = tmp2;
            }
        }
    }
}

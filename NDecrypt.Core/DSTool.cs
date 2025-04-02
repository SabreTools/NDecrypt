﻿using System;
using System.IO;
using System.Text;
using SabreTools.IO.Extensions;
using SabreTools.Models.Nitro;
using SabreTools.Serialization.Deserializers;

namespace NDecrypt.Core
{
    public class DSTool : ITool
    {
        #region Encryption process variables

        private uint[] _cardHash = new uint[0x412];
        private uint[] _arg2 = new uint[3];

        #endregion

        /// <summary>
        /// Decryption args to use while processing
        /// </summary>
        private readonly DecryptArgs _decryptArgs;

        public DSTool(DecryptArgs decryptArgs)
        {
            _decryptArgs = decryptArgs;
        }

        #region Encrypt

        /// <inheritdoc/>
        public bool EncryptFile(string filename, bool force)
        {
            try
            {
                // Open the read and write on the same file for inplace processing
                using var reader = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the cart information
                var commonHeader = Nitro.ParseCommonHeader(reader);
                if (commonHeader == null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Reset state variables
                _cardHash = new uint[0x412];
                _arg2 = new uint[3];

                // Encrypt the secure area
                EncryptSecureArea(commonHeader, force, reader, writer);
                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid DS or DSi file and try again.");
                return false;
            }
        }

        /// <summary>
        /// Encrypt secure area in the DS/DSi file
        /// </summary>s
        /// <param name="commonHeader">CommonHeader representing the DS file header</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptSecureArea(CommonHeader commonHeader, bool force, Stream reader, Stream writer)
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
                else if (!isDecrypted.Value)
                {
                    Console.WriteLine("File is already encrypted");
                    return;
                }
            }

            EncryptARM9(commonHeader, reader, writer);
            Console.WriteLine("File has been encrypted");
        }

        /// <summary>
        /// Encrypt the secure ARM9 region of the file, if possible
        /// </summary>
        /// <param name="commonHeader">CommonHeader representing the DS header</param>
        /// <param name="encrypt">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void EncryptARM9(CommonHeader commonHeader, Stream reader, Stream writer)
        {
            // Seek to the beginning of the secure area
            reader.Seek(0x4000, SeekOrigin.Begin);
            writer.Seek(0x4000, SeekOrigin.Begin);

            // Grab the first two blocks
            uint p0 = reader.ReadUInt32();
            uint p1 = reader.ReadUInt32();

            // Perform the initialization steps
            Init1(commonHeader);
            _arg2[1] <<= 1;
            _arg2[2] >>= 1;
            Init2();

            // Ensure alignment
            reader.Seek(0x4008, SeekOrigin.Begin);
            writer.Seek(0x4008, SeekOrigin.Begin);

            // Loop throgh the main encryption step
            uint size = 0x800 - 8;
            while (size > 0)
            {
                p0 = reader.ReadUInt32();
                p1 = reader.ReadUInt32();

                Encrypt(ref p1, ref p0);

                writer.Write(p0);
                writer.Write(p1);

                size -= 8;
            }

            // Replace the header explicitly
            reader.Seek(0x4000, SeekOrigin.Begin);
            writer.Seek(0x4000, SeekOrigin.Begin);

            p0 = reader.ReadUInt32();
            p1 = reader.ReadUInt32();

            if (p0 == 0xE7FFDEFF && p1 == 0xE7FFDEFF)
            {
                p0 = Constants.MAGIC30;
                p1 = Constants.MAGIC34;
            }

            Encrypt(ref p1, ref p0);
            Init1(commonHeader);
            Encrypt(ref p1, ref p0);

            writer.Write(p0);
            writer.Write(p1);
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
                uint c = _cardHash[i] ^ a;
                a = b ^ Lookup(c);
                b = c;
            }

            arg2 = a ^ _cardHash[16];
            arg1 = b ^ _cardHash[17];
        }

        #endregion

        #region Decrypt

        /// <inheritdoc/>
        public bool DecryptFile(string filename, bool force)
        {
            try
            {
                // Open the read and write on the same file for inplace processing
                using var reader = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the cart information
                var commonHeader = Nitro.ParseCommonHeader(reader);
                if (commonHeader == null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Reset state variables
                _cardHash = new uint[0x412];
                _arg2 = new uint[3];

                // Decrypt the secure area
                DecryptSecureArea(commonHeader, force, reader, writer);

                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid DS or DSi file and try again.");
                return false;
            }
        }

        /// <summary>
        /// Decrypt secure area in the DS/DSi file
        /// </summary>s
        /// <param name="commonHeader">CommonHeader representing the DS file header</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptSecureArea(CommonHeader commonHeader, bool force, Stream reader, Stream writer)
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
                else if (isDecrypted.Value)
                {
                    Console.WriteLine("File is already decrypted");
                    return;
                }
            }

            DecryptARM9(commonHeader, reader, writer);
            Console.WriteLine("File has been decrypted");
        }

        /// <summary>
        /// Decrypt the secure ARM9 region of the file, if possible
        /// </summary>
        /// <param name="commonHeader">CommonHeader representing the DS header</param>
        /// <param name="">Indicates if the file should be encrypted or decrypted</param>
        /// <param name="reader">Stream representing the input</param>
        /// <param name="writer">Stream representing the output</param>
        private void DecryptARM9(CommonHeader commonHeader, Stream reader, Stream writer)
        {
            // Seek to the beginning of the secure area
            reader.Seek(0x4000, SeekOrigin.Begin);
            writer.Seek(0x4000, SeekOrigin.Begin);

            // Grab the first two blocks
            uint p0 = reader.ReadUInt32();
            uint p1 = reader.ReadUInt32();

            // Perform the initialization steps
            Init1(commonHeader);
            Decrypt(ref p1, ref p0);
            _arg2[1] <<= 1;
            _arg2[2] >>= 1;
            Init2();

            // Set the proper flags
            Decrypt(ref p1, ref p0);
            if (p0 == Constants.MAGIC30 && p1 == Constants.MAGIC34)
            {
                p0 = 0xE7FFDEFF;
                p1 = 0xE7FFDEFF;
            }

            writer.Write(p0);
            writer.Write(p1);

            // Ensure alignment
            reader.Seek(0x4008, SeekOrigin.Begin);
            writer.Seek(0x4008, SeekOrigin.Begin);

            // Loop throgh the main encryption step
            uint size = 0x800 - 8;
            while (size > 0)
            {
                p0 = reader.ReadUInt32();
                p1 = reader.ReadUInt32();

                Decrypt(ref p1, ref p0);

                writer.Write(p0);
                writer.Write(p1);

                size -= 8;
            }
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
                uint c = _cardHash[i] ^ a;
                a = b ^ Lookup(c);
                b = c;
            }

            arg1 = b ^ _cardHash[0];
            arg2 = a ^ _cardHash[1];
        }

        #endregion

        #region Info

        /// <inheritdoc/>
        public string? GetInformation(string filename)
        {
            try
            {
                // Open the file for reading
                using var input = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                // Get a string builder for the status
                var sb = new StringBuilder();
                sb.Append("\tSecure Area: ");

                // Get the encryption status
                bool? decrypted = CheckIfDecrypted(input);
                if (decrypted == null)
                    sb.Append("Empty");
                else if (decrypted == true)
                    sb.Append("Decrypted");
                else
                    sb.Append("Encrypted");

                // Return the status for the secure area
                sb.Append(Environment.NewLine);
                return sb.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return null;
            }
        }

        #endregion

        #region Common

        /// <summary>
        /// Determine if the current file is already decrypted or not (or has an empty secure area)
        /// </summary>
        /// <param name="reader">Stream representing the input</param>
        /// <returns>True if the file has known values for a decrypted file, null if it's empty, false otherwise</returns>
        private static bool? CheckIfDecrypted(Stream reader)
        {
            reader.Seek(0x4000, SeekOrigin.Begin);
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
                || (firstValue == 0xF98415B8 && secondValue == 0x698068FC)
                || (firstValue == 0xA71329EE && secondValue == 0x2A1D4C38)
                || (firstValue == 0xC44DCC48 && secondValue == 0x38B6F8CB)
                || (firstValue == 0x3A9323B5 && secondValue == 0xC0387241))
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
                || (firstValue == 0x7829BC8D && secondValue == 0x9968EF44)   // Dragon Quest 5 (JP)
                || (firstValue == 0xC4A15AB8 && secondValue == 0xD2E667C8)   // Prince of Persia (EU)
                || (firstValue == 0xD5E97D20 && secondValue == 0x21B2A159))  // Prince of Persia (USA)
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

            // Strange, unlicenced values that can't determine decryption state
            else if ((firstValue == 0xE1D830D8 && secondValue == 0xE3530000) // Aquela Ball (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xDC002A02 && secondValue == 0x2900E612)   // Bahlz (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE1A03BA3 && secondValue == 0xE2011CFF)   // Battle Ship (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE3A01001 && secondValue == 0xE1A02001)   // Breakout!! DS (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE793200C && secondValue == 0xE4812004)   // Bubble Fusion (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE583C0DC && secondValue == 0x0A00000B)   // Carre Rouge (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0x0202453C && secondValue == 0x02060164)   // ChainReaction (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xEBFFF218 && secondValue == 0xE31000FF)   // Collection (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0x4A6CD003 && secondValue == 0x425B2301)   // DiggerDS (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE3A00001 && secondValue == 0xEBFFFF8C)   // Double Skill (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0x21043701 && secondValue == 0x45BA448C)   // DSChess (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE59D0010 && secondValue == 0xE0833000)   // Hexa-Virus (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE5C3A006 && secondValue == 0xE5C39007)   // Invasion (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE1D920F4 && secondValue == 0xE06A3000)   // JoggleDS (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE59F32EC && secondValue == 0xE5DD7011)   // London Underground (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE08A3503 && secondValue == 0xE1D3C4B8)   // NumberMinds (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE1A0C001 && secondValue == 0xE0031001)   // Paddle Battle (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE1A03005 && secondValue == 0xE88D0180)   // Pop the Balls (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE8BD4030 && secondValue == 0xE12FFF1E)   // Solitaire DS (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE0A88006 && secondValue == 0xE1A00003)   // Squash DS (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE51F3478 && secondValue == 0xEB004A02)   // Super Snake DS (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0x1C200052 && secondValue == 0xFD12F013)   // Tales of Dagur (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0x601F491E && secondValue == 0x041B880B)   // Tetris & Touch (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE1A03843 && secondValue == 0xE0000293)   // Tic Tac Toe (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0xE3530000 && secondValue == 0x13A03003)   // Warrior Training (World) (Unl) (Datel Games n' Music)
                || (firstValue == 0x02054A80 && secondValue == 0x02054B80))  // Zi (World) (Unl) (Datel Games n' Music)
            {
                Console.WriteLine("Unlicensed invalid value found. Unknown if encrypted or decrypted.");
                return null;
            }

            // Standard decryption values
            return firstValue == 0xE7FFDEFF && secondValue == 0xE7FFDEFF;
        }

        /// <summary>
        /// First common initialization step
        /// </summary>
        /// <param name="commonHeader">CommonHeader representing the DS file</param>
        private void Init1(CommonHeader commonHeader)
        {
            Buffer.BlockCopy(_decryptArgs.NitroEncryptionData, 0, _cardHash, 0, 4 * (1024 + 18));
            _arg2 = [commonHeader.GameCode, commonHeader.GameCode >> 1, commonHeader.GameCode << 1];
            Init2();
            Init2();
        }

        /// <summary>
        /// Second common initialization step
        /// </summary>
        private void Init2()
        {
            Encrypt(ref _arg2[2], ref _arg2[1]);
            Encrypt(ref _arg2[1], ref _arg2[0]);

            byte[] allBytes =[.. BitConverter.GetBytes(_arg2[0]),
                .. BitConverter.GetBytes(_arg2[1]),
                .. BitConverter.GetBytes(_arg2[2])];

            UpdateHashtable(allBytes);
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

            a = _cardHash[a + 18 + 0];
            b = _cardHash[b + 18 + 256];
            c = _cardHash[c + 18 + 512];
            d = _cardHash[d + 18 + 768];

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

                _cardHash[j] ^= r3;
            }

            uint tmp1 = 0;
            uint tmp2 = 0;
            for (int i = 0; i < 18; i += 2)
            {
                Encrypt(ref tmp1, ref tmp2);
                _cardHash[i + 0] = tmp1;
                _cardHash[i + 1] = tmp2;
            }
            for (int i = 0; i < 0x400; i += 2)
            {
                Encrypt(ref tmp1, ref tmp2);
                _cardHash[i + 18 + 0] = tmp1;
                _cardHash[i + 18 + 1] = tmp2;
            }
        }

        #endregion
    }
}

using System;
using System.IO;
using System.Text;
using SabreTools.IO.Extensions;
using SabreTools.Serialization.Wrappers;

namespace NDecrypt.Core
{
    public class DSTool : ITool
    {
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
        public bool EncryptFile(string input, string? output, bool force)
        {
            try
            {
                // If the output is provided, copy the input file
                if (output != null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the output file for processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                // Deserialize the cart information
                var nitro = Nitro.Create(reader);
                if (nitro == null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Ensure the secure area was read
                if (nitro.SecureArea == null)
                {
                    Console.WriteLine("Error: Invalid secure area!");
                    return false;
                }

                // Encrypt the secure area
                nitro.EncryptSecureArea(_decryptArgs.NitroEncryptionData, force);

                // Write the encrypted secure area
                using var writer = File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                writer.Seek(0x4000, SeekOrigin.Begin);
                writer.Write(nitro.SecureArea);
                writer.Flush();

                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {output} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid DS or DSi file and try again.");
                return false;
            }
        }

        #endregion

        #region Decrypt

        /// <inheritdoc/>
        public bool DecryptFile(string input, string? output, bool force)
        {
            try
            {
                // If the output is provided, copy the input file
                if (output != null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the read and write on the same file for inplace processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                // Deserialize the cart information
                var nitro = Nitro.Create(reader);
                if (nitro == null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Ensure the secure area was read
                if (nitro.SecureArea == null)
                {
                    Console.WriteLine("Error: Invalid secure area!");
                    return false;
                }

                // Decrypt the secure area
                nitro.DecryptSecureArea(_decryptArgs.NitroEncryptionData, force);

                // Write the decrypted secure area
                using var writer = File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                writer.Seek(0x4000, SeekOrigin.Begin);
                writer.Write(nitro.SecureArea);
                writer.Flush();

                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {output} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid DS or DSi file and try again.");
                return false;
            }
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

        #endregion
    }
}

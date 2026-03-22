using System;
using System.IO;
using System.Text;
using SabreTools.Hashing;
using SabreTools.IO.Extensions;
using SabreTools.Serialization.Wrappers;

namespace NDecrypt.Core
{
    public class DSTool : ITool
    {
        #region Properties

        /// <summary>
        /// Blowfish Table
        /// </summary>
        public byte[] BlowfishTable
        {
            get;
            set
            {
                // Ignore missing encryption data
                if (value.Length == 0)
                    return;

                // Validate the blowfish table data
                byte[]? actual = HashTool.GetByteArrayHashArray(value, HashType.SHA512);
                if (actual is null || !actual.EqualsExactly(ExpectedNitroSha512Hash))
                    return;

                // Assign the validated value
                field = value;
            }
        } = [];

        #endregion

        #region Internal Test Values

        /// <summary>
        /// Expected hash for NitroEncryptionData
        /// </summary>
        private static readonly byte[] ExpectedNitroSha512Hash =
        [
            0x1A, 0xD6, 0x40, 0x21, 0xFC, 0x3D, 0x1A, 0x9A,
            0x9B, 0xC0, 0x88, 0x8E, 0x2E, 0x68, 0xDE, 0x4E,
            0x8A, 0x60, 0x6B, 0x86, 0x63, 0x22, 0xD2, 0xC7,
            0xC6, 0xD7, 0xD6, 0xCE, 0x65, 0xF5, 0xBA, 0xA7,
            0xEA, 0x69, 0x63, 0x7E, 0xC9, 0xE4, 0x57, 0x7B,
            0x01, 0xFD, 0xCE, 0xC2, 0x26, 0x3B, 0xD9, 0x0D,
            0x84, 0x57, 0xC2, 0x00, 0xB8, 0x56, 0x9F, 0xE5,
            0x56, 0xDA, 0x8D, 0xDE, 0x84, 0xB8, 0x8E, 0xE4,
        ];

        #endregion

        #region Encrypt

        /// <inheritdoc/>
        public bool EncryptFile(string input, string? output, bool force)
        {
            // If the blowfish table is not set, do not process
            if (BlowfishTable.Length == 0)
            {
                Console.WriteLine("Error: Nitro encryption data not provided!");
                return false;
            }

            try
            {
                // If the output is provided, copy the input file
                if (output is not null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the output file for processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                // Deserialize the cart information
                var nitro = Nitro.Create(reader);
                if (nitro is null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Ensure the secure area was read
                if (nitro.SecureArea is null)
                {
                    Console.WriteLine("Error: Invalid secure area!");
                    return false;
                }

                // Encrypt the secure area
                nitro.EncryptSecureArea(BlowfishTable, force);

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
            // If the blowfish table is not set, do not process
            if (BlowfishTable.Length == 0)
            {
                Console.WriteLine("Error: Nitro encryption data not provided!");
                return false;
            }

            try
            {
                // If the output is provided, copy the input file
                if (output is not null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the read and write on the same file for inplace processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                // Deserialize the cart information
                var nitro = Nitro.Create(reader);
                if (nitro is null)
                {
                    Console.WriteLine("Error: Not a DS or DSi Rom!");
                    return false;
                }

                // Ensure the secure area was read
                if (nitro.SecureArea is null)
                {
                    Console.WriteLine("Error: Invalid secure area!");
                    return false;
                }

                // Decrypt the secure area
                nitro.DecryptSecureArea(BlowfishTable, force);

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

                // Deserialize the cart information
                var cart = Nitro.Create(input);
                if (cart?.Model is null)
                    return "Error: Not a DS/DSi cart image!";

                // Get a string builder for the status
                var sb = new StringBuilder();
                sb.Append("\tSecure Area: ");

                // Get the encryption status
                bool? decrypted = cart.CheckIfDecrypted(out _);
                if (decrypted is null)
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
    }
}

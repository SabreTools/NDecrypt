using System;
using System.IO;
using System.Text;
#if NETFRAMEWORK || NETSTANDARD2_0_OR_GREATER
using SabreTools.IO.Extensions;
#endif
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

                // Deserialize the cart information
                var cart = Nitro.Create(input);
                if (cart?.Model == null)
                    return "Error: Not a DS/DSi cart image!";

                // Get a string builder for the status
                var sb = new StringBuilder();
                sb.Append("\tSecure Area: ");

                // Get the encryption status
                bool? decrypted = cart.CheckIfDecrypted(out _);
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
    }
}

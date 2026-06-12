using System;
using System.IO;
using System.Text;
using SabreTools.Security.Cryptography;
using SabreTools.Wrappers;

namespace NDecrypt.Core
{
    public class ThreeDSProcessor : ICartProcessor
    {
        /// <summary>
        /// Encryption settings for processing
        /// </summary>
        private readonly N3DSEncryptionSettings _settings;

        public ThreeDSProcessor(N3DSEncryptionSettings settings)
        {
            _settings = settings;
        }

        #region Decrypt

        /// <inheritdoc/>
        public bool DecryptFile(string input, string? output, bool force)
        {
            try
            {
                // If the output is provided, copy the input file
                if (output is not null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the output file for processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the cart information
                var cart = N3DS.Create(reader);
                if (cart?.Model is null)
                {
                    Console.WriteLine("Error: Not a 3DS cart image!");
                    return false;
                }

                // Decrypt all 8 NCCH partitions
                cart.DecryptAllPartitions(force,
                    reader,
                    writer,
                    _settings.Development,
                    _settings.AESHardwareConstant,
                    _settings.KeyX0x18,
                    _settings.DevKeyX0x18,
                    _settings.KeyX0x1B,
                    _settings.DevKeyX0x1B,
                    _settings.KeyX0x25,
                    _settings.DevKeyX0x25,
                    _settings.KeyX0x2C,
                    _settings.DevKeyX0x2C);
                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {output} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS cart image and try again.");
                return false;
            }
        }

        #endregion

        #region Encrypt

        /// <inheritdoc/>
        public bool EncryptFile(string input, string? output, bool force)
        {
            try
            {
                // If the output is provided, copy the input file
                if (output is not null)
                    File.Copy(input, output, overwrite: true);
                else
                    output = input;

                // Open the output file for processing
                using var reader = File.Open(output, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var writer = File.Open(output, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);

                // Deserialize the cart information
                var cart = N3DS.Create(reader);
                if (cart?.Model is null)
                {
                    Console.WriteLine("Error: Not a 3DS cart image!");
                    return false;
                }

                // Encrypt all 8 NCCH partitions
                cart.EncryptAllPartitions(force,
                    reader,
                    writer,
                    _settings.Development,
                    _settings.AESHardwareConstant,
                    _settings.KeyX0x18,
                    _settings.DevKeyX0x18,
                    _settings.KeyX0x1B,
                    _settings.DevKeyX0x1B,
                    _settings.KeyX0x25,
                    _settings.DevKeyX0x25,
                    _settings.KeyX0x2C,
                    _settings.DevKeyX0x2C);
                return true;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {output} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS cart image and try again.");
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
                var cart = N3DS.Create(input);
                if (cart?.Model is null)
                    return "Error: Not a 3DS cart image!";

                // Get a string builder for the status
                var sb = new StringBuilder();

                // Iterate over all 8 NCCH partitions
                for (int p = 0; p < 8; p++)
                {
                    bool decrypted = cart.PossiblyDecrypted(p);
                    sb.AppendLine($"\tPartition {p}: {(decrypted ? "Decrypted" : "Encrypted")}");
                }

                // Return the status for all partitions
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

using System;
using System.IO;
using NDecrypt.N3DS.Headers;

namespace NDecrypt.N3DS
{
    // https://www.3dbrew.org/wiki/CIA
    internal class CIATool : ITool
    {
        /// <summary>
        /// Name of the input CIA file
        /// </summary>
        private readonly string filename;

        /// <summary>
        /// Decryption args to use while processing
        /// </summary>
        private readonly DecryptArgs decryptArgs;

        public CIATool(string filename, DecryptArgs decryptArgs)
        {
            this.filename = filename;
            this.decryptArgs = decryptArgs;
        }

        #region Common Methods

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        public bool ProcessFile()
        {
            // Ensure the constants are all set
            if (decryptArgs.IsReady != true)
            {
                Console.WriteLine("Could not read keys. Please make sure the file exists and try again.");
                return false;
            }

            try
            {
                // Open the read and write on the same file for inplace processing
                using (BinaryReader reader = new BinaryReader(File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                using (BinaryWriter writer = new BinaryWriter(File.Open(filename, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite)))
                {
                    CIAHeader header = CIAHeader.Read(reader);
                    if (header == null)
                    {
                        Console.WriteLine("Error: Not a 3DS CIA!");
                        return false;
                    }

                    // TODO: Implement CIA encrypt/decrypt
                    return false;
                }
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS CIA file and try again.");
                return false;
            }
        }

        #endregion
    }
}
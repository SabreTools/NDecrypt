using System;
using System.IO;
using System.Reflection;
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
        /// Flag to detrmine if keys.bin (false) or aes_keys.txt (true) should be used
        /// </summary>
        private readonly bool useCitraKeyFile;

        /// <summary>
        /// Flag to detrmine if development keys should be used
        /// </summary>
        private readonly bool development;

        /// <summary>
        /// Flag to determine if encrypting or decrypting
        /// </summary>
        private readonly bool encrypt;

        /// <summary>
        /// Flag to determine if forcing operations
        /// </summary>
        private readonly bool force;

        public CIATool(string filename, bool useCitraKeyFile, bool development, bool encrypt, bool force)
        {
            this.filename = filename;
            this.useCitraKeyFile = useCitraKeyFile;
            this.development = development;
            this.encrypt = encrypt;
            this.force = force;
        }

        #region Common Methods

        /// <summary>
        /// Process an input file given the input values
        /// </summary>
        public bool ProcessFile()
        {
            // Ensure the constants are all set
            string keyfile;
            if (this.useCitraKeyFile)
                keyfile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "aes_keys.txt");
            else
                keyfile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "keys.bin");

            Constants.Init(keyfile, useCitraKeyFile);
            if (Constants.IsReady != true)
            {
                Console.WriteLine("Could not read keys from keys.bin. Please make sure the file exists and try again.");
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
                        Console.WriteLine("Error: Not a 3DS Rom!");
                        return false;
                    }

                    // TODO: Implement CIA encrypt/decrypt
                    return false;
                }
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS or New 3DS file and try again.");
                return false;
            }
        }

        #endregion
    }
}
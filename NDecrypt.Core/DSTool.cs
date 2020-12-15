using System;
using System.IO;
using NDecrypt.Core.Headers;

namespace NDecrypt.Core
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
                header.ProcessSecureArea(reader, writer, encrypt, force);
            }

            return true;
        }
    }
}

using System;
using System.IO;
using NDecrypt.Headers;

namespace NDecrypt
{
    public class ThreeDSTool : ITool
    {
        /// <summary>
        /// Name of the input 3DS file
        /// </summary>
        private readonly string filename;

        /// <summary>
        /// Flag to detrmine if development keys should be used
        /// </summary>
        private readonly bool development;

        /// <summary>
        /// Flag to determine if encrypting or decrypting
        /// </summary>
        private readonly bool encrypt;

        public ThreeDSTool(string filename, bool development, bool encrypt)
        {
            this.filename = filename;
            this.development = development;
            this.encrypt = encrypt;
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
                NCSDHeader header = NCSDHeader.Read(reader, development);
                if (header == null)
                {
                    Console.WriteLine("Error: Not a 3DS Rom!");
                    return false;
                }

                // Process all 8 NCCH partitions
                header.ProcessAllPartitions(reader, writer, encrypt, development);
            }

            return true;
        }        
    }
}

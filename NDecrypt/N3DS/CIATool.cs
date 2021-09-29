using System;
using System.IO;
using NDecrypt.N3DS.Headers;

namespace NDecrypt.N3DS
{
    // https://www.3dbrew.org/wiki/CIA
    public class CIATool : ITool
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

                    // Process all NCCH partitions
                    ProcessAllPartitions(header, reader, writer);
                }

                return false;
            }
            catch
            {
                Console.WriteLine($"An error has occurred. {filename} may be corrupted if it was partially processed.");
                Console.WriteLine("Please check that the file was a valid 3DS CIA file and try again.");
                return false;
            }
        }

        /// <summary>
        /// Process all partitions in the content file data of a CIA header
        /// </summary>
        /// <param name="ciaHeader">CIA header representing the 3DS CIA file</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessAllPartitions(CIAHeader ciaHeader, BinaryReader reader, BinaryWriter writer)
        {
            // Iterate over all NCCH partitions
            for (int p = 0; p < ciaHeader.Partitions.Length; p++)
            {
                NCCHHeader ncchHeader = ciaHeader.Partitions[0];
                ProcessPartition(ciaHeader, ncchHeader, reader, writer);
            }
        }

        /// <summary>
        /// Process a single partition
        /// </summary>
        /// <param name="ciaHeader">CIA header representing the 3DS CIA file</param>
        /// <param name="ncchHeader">NCCH header representing the partition</param>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <param name="writer">BinaryWriter representing the output stream</param>
        private void ProcessPartition(CIAHeader ciaHeader, NCCHHeader ncchHeader, BinaryReader reader, BinaryWriter writer)
        {
            // If we're forcing the operation, tell the user
            if (decryptArgs.Force)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber} is not verified due to force flag being set.");
            }
            // If we're not forcing the operation, check if the 'NoCrypto' bit is set
            else if (ncchHeader.Flags.PossblyDecrypted ^ decryptArgs.Encrypt)
            {
                Console.WriteLine($"Partition {ncchHeader.PartitionNumber}: Already " + (decryptArgs.Encrypt ? "Encrypted" : "Decrypted") + "?...");
                return;
            }

            // TODO: Determine what steps need to be done here to set encryption keys and process encrypt/decrypt
            // TODO: Below code is copied directly from ThreeDSTool.cs and may not be accurate

            //// Determine the Keys to be used
            //SetEncryptionKeys(ciaHeader, ncchHeader);

            //// Process the extended header
            //ProcessExtendedHeader(ciaHeader, ncchHeader, reader, writer);

            //// If we're encrypting, encrypt the filesystems and update the flags
            //if (decryptArgs.Encrypt)
            //{
            //    EncryptExeFS(ciaHeader, ncchHeader, reader, writer);
            //    EncryptRomFS(ciaHeader, ncchHeader, reader, writer);
            //    UpdateEncryptCryptoAndMasks(ciaHeader, ncchHeader, writer);
            //}

            //// If we're decrypting, decrypt the filesystems and update the flags
            //else
            //{
            //    DecryptExeFS(ciaHeader, ncchHeader, reader, writer);
            //    DecryptRomFS(ciaHeader, ncchHeader, reader, writer);
            //    UpdateDecryptCryptoAndMasks(ciaHeader, ncchHeader, writer);
            //}
        }

        #endregion
    }
}
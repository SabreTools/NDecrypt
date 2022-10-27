using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NDecrypt.Core.Tools;

namespace NDecrypt
{
    internal static class HashingHelper
    {
        /// <summary>
        /// Retrieve file information for a single file
        /// </summary>
        /// <param name="input">Filename to get information from</param>
        /// <returns>Formatted string representing the hashes, null on error</returns>
        public static string GetInfo(string input)
        {
            // If the file doesn't exist, return null
            if (!File.Exists(input))
                return null;
            
            // Get the file length
            long size = new FileInfo(input).Length;

            // Open the file
            Stream inputStream = File.OpenRead(input);

            try
            {
                // Get a list of hashers to run over the buffer
                List<Hasher> hashers = new List<Hasher>
                {
                    new Hasher(Hash.CRC),
                    new Hasher(Hash.MD5),
                    new Hasher(Hash.SHA1),
                    new Hasher(Hash.SHA256),
                };

                // Initialize the hashing helpers
                int buffersize = 3 * 1024 * 1024;
                byte[] buffer = new byte[buffersize];

                /*
                Please note that some of the following code is adapted from
                RomVault. This is a modified version of how RomVault does
                threaded hashing. As such, some of the terminology and code
                is the same, though variable names and comments may have
                been tweaked to better fit this code base.
                */

                // Pre load the buffer
                int next = buffersize > size ? (int)size : buffersize;
                int current = inputStream.Read(buffer, 0, next);
                long refsize = size;
                
                while (refsize > 0)
                {
                    // Run hashes in parallel
                    if (current > 0)
                        Parallel.ForEach(hashers, h => h.Process(buffer, current));

                    // Load the next buffer
                    refsize -= current;
                    next = buffersize > refsize ? (int)refsize : buffersize;

                    if (next > 0)
                        current = inputStream.Read(buffer, 0, next);
                }
            
                // Finalize all hashing helpers
                Parallel.ForEach(hashers, h => h.Terminate());

                // Get the results
                string result = $"Size: {size}\n"
                    + $"CRC32: {ByteArrayToString(hashers.First(h => h.HashType == Hash.CRC).GetHash()) ?? ""}\n"
                    + $"MD5: {ByteArrayToString(hashers.First(h => h.HashType == Hash.MD5).GetHash()) ?? ""}\n"
                    + $"SHA1: {ByteArrayToString(hashers.First(h => h.HashType == Hash.SHA1).GetHash()) ?? ""}\n"
                    + $"SHA256: {ByteArrayToString(hashers.First(h => h.HashType == Hash.SHA256).GetHash()) ?? ""}\n";

                // Dispose of the hashers
                hashers.ForEach(h => h.Dispose());

                return result;
            }
            catch
            {
                return null;
            }
            finally
            {
                inputStream.Dispose();
            }
        }

        /// <summary>
        /// Convert a byte array to a hex string
        /// </summary>
        /// <param name="bytes">Byte array to convert</param>
        /// <returns>Hex string representing the byte array</returns>
        /// <link>http://stackoverflow.com/questions/311165/how-do-you-convert-byte-array-to-hexadecimal-string-and-vice-versa</link>
        private static string ByteArrayToString(byte[] bytes)
        {
            // If we get null in, we send null out
            if (bytes == null)
                return null;

            try
            {
                string hex = BitConverter.ToString(bytes);
                return hex.Replace("-", string.Empty).ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }
    }
}

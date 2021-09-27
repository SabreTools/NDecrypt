using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Compress.ThreadReaders;
using NDecrypt.Tools;

namespace NDecrypt.CMD
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
                var loadBuffer = new ThreadLoadBuffer(inputStream);
                int buffersize = 3 * 1024 * 1024;
                byte[] buffer0 = new byte[buffersize];
                byte[] buffer1 = new byte[buffersize];

                /*
                Please note that some of the following code is adapted from
                RomVault. This is a modified version of how RomVault does
                threaded hashing. As such, some of the terminology and code
                is the same, though variable names and comments may have
                been tweaked to better fit this code base.
                */

                // Pre load the first buffer
                long refsize = size;
                int next = refsize > buffersize ? buffersize : (int)refsize;
                inputStream.Read(buffer0, 0, next);
                int current = next;
                refsize -= next;
                bool bufferSelect = true;

                while (current > 0)
                {
                    // Trigger the buffer load on the second buffer
                    next = refsize > buffersize ? buffersize : (int)refsize;
                    if (next > 0)
                        loadBuffer.Trigger(bufferSelect ? buffer1 : buffer0, next);

                    byte[] buffer = bufferSelect ? buffer0 : buffer1;

                    // Run hashes in parallel
                    Parallel.ForEach(hashers, h => h.Process(buffer, current));

                    // Wait for the load buffer worker, if needed
                    if (next > 0)
                        loadBuffer.Wait();

                    // Setup for the next hashing step
                    current = next;
                    refsize -= next;
                    bufferSelect = !bufferSelect;
                }

                // Finalize all hashing helpers
                loadBuffer.Finish();
                Parallel.ForEach(hashers, h => h.Terminate());

                // Get the results
                string result = $"Size: {size}\n"
                    + $"CRC32: {ByteArrayToString(hashers.First(h => h.HashType == Hash.CRC).GetHash()) ?? ""}\n"
                    + $"MD5: {ByteArrayToString(hashers.First(h => h.HashType == Hash.MD5).GetHash()) ?? ""}\n"
                    + $"SHA1: {ByteArrayToString(hashers.First(h => h.HashType == Hash.SHA1).GetHash()) ?? ""}\n"
                    + $"SHA256: {ByteArrayToString(hashers.First(h => h.HashType == Hash.SHA256).GetHash()) ?? ""}\n";

                // Dispose of the hashers
                loadBuffer.Dispose();
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

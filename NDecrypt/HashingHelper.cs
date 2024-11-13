using System.IO;
using SabreTools.Hashing;

namespace NDecrypt
{
    internal static class HashingHelper
    {
        /// <summary>
        /// Retrieve file information for a single file
        /// </summary>
        /// <param name="input">Filename to get information from</param>
        /// <returns>Formatted string representing the hashes, null on error</returns>
        public static string? GetInfo(string input)
        {
            // If the file doesn't exist, return null
            if (!File.Exists(input))
                return null;

            // Get the file information, if possible
            HashType[] hashTypes = [HashType.CRC32, HashType.MD5, HashType.SHA1, HashType.SHA256];
            var hashDict = HashTool.GetFileHashesAndSize(input, hashTypes, out long size);
            if (hashDict == null)
                return null;

            // Get the results
            return $"Size: {size}\n"
                + $"CRC-32: {(hashDict.ContainsKey(HashType.CRC32) ? hashDict[HashType.CRC32] : string.Empty)}\n"
                + $"MD5: {(hashDict.ContainsKey(HashType.MD5) ? hashDict[HashType.MD5] : string.Empty)}\n"
                + $"SHA-1: {(hashDict.ContainsKey(HashType.SHA1) ? hashDict[HashType.SHA1] : string.Empty)}\n"
                + $"CSHA-256: {(hashDict.ContainsKey(HashType.SHA256) ? hashDict[HashType.SHA256] : string.Empty)}\n";
        }
    }
}

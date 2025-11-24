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
                + $"CRC-32: {(hashDict.TryGetValue(HashType.CRC32, out string? value) ? value : string.Empty)}\n"
                + $"MD5: {(hashDict.TryGetValue(HashType.MD5, out string? value1) ? value1 : string.Empty)}\n"
                + $"SHA-1: {(hashDict.TryGetValue(HashType.SHA1, out string? value2) ? value2 : string.Empty)}\n"
                + $"SHA-256: {(hashDict.TryGetValue(HashType.SHA256, out string? value3) ? value3 : string.Empty)}\n";
        }
    }
}

using System.IO;
using System.Linq;
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
                + $"CRC32: {hashDict.First(h => h.Key == HashType.CRC32).Value ?? string.Empty}\n"
                + $"MD5: {hashDict.First(h => h.Key == HashType.MD5).Value ?? string.Empty}\n"
                + $"SHA1: {hashDict.First(h => h.Key == HashType.SHA1).Value ?? string.Empty}\n"
                + $"SHA256: {hashDict.First(h => h.Key == HashType.SHA256).Value ?? string.Empty}\n";
        }
    }
}

using System;

namespace NDecrypt.Tools
{
    /// <summary>
    /// Available hashing types
    /// </summary>
    [Flags]
    public enum Hash
    {
        CRC = 1 << 0,
        MD5 = 1 << 1,
        SHA1 = 1 << 2,
        SHA256 = 1 << 3,
        SHA384 = 1 << 4,
        SHA512 = 1 << 5,

        // Special combinations
        Standard = CRC | MD5 | SHA1,
        DeepHashes = SHA256 | SHA384 | SHA512,
        SecureHashes = MD5 | SHA1 | SHA256 | SHA384 | SHA512,
        All =  CRC | MD5 | SHA1 | SHA256 | SHA384 | SHA512,
    }
}
using System;
using SabreTools.Data.Models.N3DS;
using SabreTools.IO.Extensions;

namespace NDecrypt.Core
{
    /// <summary>
    /// Set of all keys associated with a partition
    /// </summary>
    internal class PartitionKeys
    {
        /// <summary>
        /// Primary AES-CTR encryption key
        /// </summary>
        /// <remarks>Used for both EXE-FS and ROM-FS</remarks>
        public byte[] NormalKey { get; private set; }

        /// <summary>
        /// Secondary AES-CTR encryption key
        /// </summary>
        /// <remarks>Used for only EXE-FS</remarks>
        public byte[] NormalKey2C { get; }

        /// <summary>
        /// First 16 bytes of the RSA-2048 signature
        /// </summary>
        /// <remarks>Used as an XOR value during key generation</remarks>
        private readonly byte[] KeyY;

        /// <summary>
        /// Create a new set of keys for a given partition
        /// </summary>
        /// <param name="signature">RSA-2048 signature from the partition</param>
        /// <param name="masks">BitMasks from the partition or backup header</param>
        /// <param name="hardwareConstant">AES hardware constant to use</param>
        /// <param name="keyX">KeyX value to assign based on crypto method and development status</param>
        /// <param name="keyX0x2C">KeyX2C value to assign based on development status</param>
        public PartitionKeys(byte[]? signature, BitMasks masks, byte[] hardwareConstant, byte[] keyX, byte[] keyX0x2C)
        {
            // Validate inputs
            if (signature is not null && signature.Length < 16)
                throw new ArgumentOutOfRangeException(nameof(signature), $"{nameof(signature)} must be at least 16 bytes");

            // Backup headers can't have a KeyY value set
            KeyY = new byte[16];
            if (signature is not null)
                Array.Copy(signature, KeyY, 16);

            // Special case for zero-key
#if NET20 || NET35
            if ((masks & BitMasks.FixedCryptoKey) > 0)
#else
            if (masks.HasFlag(BitMasks.FixedCryptoKey))
#endif
            {
                Console.WriteLine("Encryption Method: Zero Key");
                NormalKey = new byte[16];
                NormalKey2C = new byte[16];
                return;
            }

            // Set the standard normal key values
            NormalKey = ProcessKey(keyX, KeyY, hardwareConstant);
            NormalKey2C = ProcessKey(keyX0x2C, KeyY, hardwareConstant);
        }

        /// <summary>
        /// Set RomFS values based on the bit masks
        /// </summary>
        /// <param name="masks">BitMasks from the partition or backup header</param>
        /// <param name="hardwareConstant">AES hardware constant to use</param>
        /// <param name="keyX0x2C">KeyX2C value to assign based on development status</param>
        public void SetRomFSValues(BitMasks masks, byte[] hardwareConstant, byte[] keyX0x2C)
        {
            // NormalKey has a constant value for zero-key
#if NET20 || NET35
            if ((masks & BitMasks.FixedCryptoKey) > 0)
#else
            if (masks.HasFlag(BitMasks.FixedCryptoKey))
#endif
            {
                NormalKey = new byte[16];
                return;
            }

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            NormalKey = ProcessKey(keyX0x2C, KeyY, hardwareConstant);
        }

        /// <summary>
        /// Process a key with the standard processing steps
        /// </summary>
        private static byte[] ProcessKey(byte[] keyBase, byte[] keyY, byte[] hardwareConstant)
        {
            byte[] processed = keyBase.RotateLeft(2);
            processed = processed.Xor(keyY);
            processed = processed.Add(hardwareConstant);
            return processed.RotateLeft(87);
        }
    }
}

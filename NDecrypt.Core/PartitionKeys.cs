using System;
using SabreTools.Data.Models.N3DS;
using SabreTools.IO.Extensions;

namespace NDecrypt.Core
{
    /// <summary>
    /// Set of all keys associated with a partition
    /// </summary>
    public class PartitionKeys
    {
        public byte[] NormalKey { get; private set; }

        public byte[] NormalKey2C { get; }

        private readonly byte[] KeyY;

        /// <summary>
        /// Create a new set of keys for a given partition
        /// </summary>
        /// <param name="signature">RSA-2048 signature from the partition</param>
        /// <param name="masks">BitMasks from the partition or backup header</param>
        /// <param name="hardwareConstant">AES hardware constant to use</param>
        /// <param name="keyX">KeyX value to assign based on crypto method and development status</param>
        /// <param name="KeyX2C">KeyX value to assign based on development status</param>
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
            NormalKey = keyX.RotateLeft(2);
            NormalKey = NormalKey.Xor(KeyY);
            NormalKey = NormalKey.Add(hardwareConstant);
            NormalKey = NormalKey.RotateLeft(87);

            NormalKey2C = keyX0x2C.RotateLeft(2);
            NormalKey2C = NormalKey2C.Xor(KeyY);
            NormalKey2C = NormalKey2C.Add(hardwareConstant);
            NormalKey2C = NormalKey2C.RotateLeft(87);
        }

        /// <summary>
        /// Set RomFS values based on the bit masks
        /// </summary>
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
            NormalKey = keyX0x2C.RotateLeft(2);
            NormalKey = NormalKey.Xor(KeyY);
            NormalKey = NormalKey.Add(hardwareConstant);
            NormalKey = NormalKey.RotateLeft(87);
        }
    }
}

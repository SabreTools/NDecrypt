using System;
using System.Linq;
using System.Numerics;
using Org.BouncyCastle.Crypto;
using SabreTools.Models.N3DS;
using static NDecrypt.Core.CommonOperations;

namespace NDecrypt.Core
{
    /// <summary>
    /// Set of all keys associated with a partition
    /// </summary>
    public class PartitionKeys
    {
        public BigInteger KeyX { get; private set; }

        public BigInteger KeyX2C { get; private set; }

        public BigInteger KeyY { get; private set; }

        public BigInteger NormalKey { get; private set; }

        public BigInteger NormalKey2C { get; private set; }

        /// <summary>
        /// Decryption args to use while processing
        /// </summary>
        private readonly DecryptArgs _decryptArgs;

        /// <summary>
        /// Indicates if development images are expected
        /// </summary>
        private readonly bool _development;

        /// <summary>
        /// Create a new set of keys for a given partition
        /// </summary>
        /// <param name="args">Decryption args representing available keys</param>
        /// <param name="signature">RSA-2048 signature from the partition</param>
        /// <param name="masks">BitMasks from the partition or backup header</param>
        /// <param name="method">CryptoMethod from the partition or backup header</param>
        /// <param name="development">Determine if development keys are used</param>
        public PartitionKeys(DecryptArgs args, byte[]? signature, BitMasks masks, CryptoMethod method, bool development)
        {
            // Validate inputs
            if (args.IsReady != true)
                throw new InvalidOperationException($"{nameof(args)} must be initialized before use");
            if (signature != null && signature.Length < 16)
                throw new DataLengthException($"{nameof(signature)} must be at least 16 bytes");

            // Set fields for future use
            _decryptArgs = args;
            _development = development;

            // Set the standard KeyX values
            KeyX = 0;
            KeyX2C = development ? args.DevKeyX0x2C : args.KeyX0x2C;

            // Backup headers can't have a KeyY value set
            if (signature != null)
                KeyY = new BigInteger(signature.Take(16).Reverse().ToArray());
            else
                KeyY = new BigInteger(0);

            // Set the standard normal key values
            NormalKey = 0x00;
            NormalKey2C = RotateLeft((RotateLeft(KeyX2C, 2, 128) ^ KeyY) + args.AESHardwareConstant, 87, 128);

            // Special case for zero-key
            if (masks.HasFlag(BitMasks.FixedCryptoKey))
            {
                Console.WriteLine("Encryption Method: Zero Key");
                NormalKey = 0x00;
                NormalKey2C = 0x00;
                return;
            }

            // Set KeyX values based on crypto method
            switch (method)
            {
                case CryptoMethod.Original:
                    Console.WriteLine("Encryption Method: Key 0x2C");
                    KeyX = development ? args.DevKeyX0x2C : args.KeyX0x2C;
                    break;

                case CryptoMethod.Seven:
                    Console.WriteLine("Encryption Method: Key 0x25");
                    KeyX = development ? args.DevKeyX0x25 : args.KeyX0x25;
                    break;

                case CryptoMethod.NineThree:
                    Console.WriteLine("Encryption Method: Key 0x18");
                    KeyX = development ? args.DevKeyX0x18 : args.KeyX0x18;
                    break;

                case CryptoMethod.NineSix:
                    Console.WriteLine("Encryption Method: Key 0x1B");
                    KeyX = development ? args.DevKeyX0x1B : args.KeyX0x1B;
                    break;
            }

            // Set the normal key based on the new KeyX value
            NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + args.AESHardwareConstant, 87, 128);
        }

        /// <summary>
        /// Set RomFS values based on the bit masks
        /// </summary>
        public void SetRomFSValues(BitMasks masks)
        {
            // NormalKey has a constant value for zero-key
            if (masks.HasFlag(BitMasks.FixedCryptoKey))
            {
                NormalKey = 0x00;
                return;
            }

            // Encrypting RomFS for partitions 1 and up always use Key0x2C
            KeyX = _development ? _decryptArgs.DevKeyX0x2C : _decryptArgs.KeyX0x2C;
            NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + _decryptArgs.AESHardwareConstant, 87, 128);
        }
    }
}
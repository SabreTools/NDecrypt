using System;
using System.Linq;
using System.Numerics;
using NDecrypt.Core;
using SabreTools.Models.N3DS;
using static NDecrypt.N3DS.CommonOperations;

namespace NDecrypt.N3DS
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
            // Set fields for future use
            _decryptArgs = args;
            _development = development;

            KeyX = 0;
            KeyX2C = development ? args.DevKeyX0x2C : args.KeyX0x2C;

            // Backup headers can't have a KeyY value set
            if (signature != null)
                KeyY = new BigInteger(signature.Take(16).Reverse().ToArray());
            else
                KeyY = new BigInteger(0);

            NormalKey = 0x00;
            NormalKey2C = RotateLeft((RotateLeft(KeyX2C, 2, 128) ^ KeyY) + args.AESHardwareConstant, 87, 128);

            if (masks.HasFlag(BitMasks.FixedCryptoKey))
            {
                NormalKey = 0x00;
                NormalKey2C = 0x00;
                Console.WriteLine("Encryption Method: Zero Key");
            }
            else
            {
                if (method == CryptoMethod.Original)
                {
                    KeyX = development ? args.DevKeyX0x2C : args.KeyX0x2C;
                    Console.WriteLine("Encryption Method: Key 0x2C");
                }
                else if (method == CryptoMethod.Seven)
                {
                    KeyX = development ? args.DevKeyX0x25 : args.KeyX0x25;
                    Console.WriteLine("Encryption Method: Key 0x25");
                }
                else if (method == CryptoMethod.NineThree)
                {
                    KeyX = development ? args.DevKeyX0x18 : args.KeyX0x18;
                    Console.WriteLine("Encryption Method: Key 0x18");
                }
                else if (method == CryptoMethod.NineSix)
                {
                    KeyX = development ? args.DevKeyX0x1B : args.KeyX0x1B;
                    Console.WriteLine("Encryption Method: Key 0x1B");
                }

                NormalKey = RotateLeft((RotateLeft(KeyX, 2, 128) ^ KeyY) + args.AESHardwareConstant, 87, 128);
            }
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
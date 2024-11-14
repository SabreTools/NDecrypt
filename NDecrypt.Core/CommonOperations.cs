using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SabreTools.IO.Extensions;

namespace NDecrypt.Core
{
    public static class CommonOperations
    {
        #region AES

        /// <summary>
        /// Create AES decryption cipher and intialize
        /// </summary>
        /// <param name="key">Byte array representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <returns>Initialized AES cipher</returns>
        public static IBufferedCipher CreateAESDecryptionCipher(byte[] key, byte[] iv)
        {
            if (key.Length != 16)
                throw new ArgumentOutOfRangeException(nameof(key));

            var keyParam = new KeyParameter(key);
            var cipher = CipherUtilities.GetCipher("AES/CTR");
            cipher.Init(forEncryption: false, new ParametersWithIV(keyParam, iv));
            return cipher;
        }

        /// <summary>
        /// Create AES encryption cipher and intialize
        /// </summary>
        /// <param name="key">Byte array representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <returns>Initialized AES cipher</returns>
        public static IBufferedCipher CreateAESEncryptionCipher(byte[] key, byte[] iv)
        {
            if (key.Length != 16)
                throw new ArgumentOutOfRangeException(nameof(key));

            var keyParam = new KeyParameter(key);
            var cipher = CipherUtilities.GetCipher("AES/CTR");
            cipher.Init(forEncryption: true, new ParametersWithIV(keyParam, iv));
            return cipher;
        }

        /// <summary>
        /// Perform an AES operation using an existing cipher
        /// </summary>
        public static void PerformAESOperation(uint size,
            IBufferedCipher cipher,
            Stream input,
            Stream output,
            Action<string>? progress)
        {
            // Get MiB-aligned block count and extra byte count
            int blockCount = (int)((long)size / (1024 * 1024));
            int extraBytes = (int)((long)size % (1024 * 1024));

            // Process MiB-aligned data
            if (blockCount > 0)
            {
                for (int i = 0; i < blockCount; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] processedBytes = cipher.ProcessBytes(readBytes);
                    output.Write(processedBytes);
                    output.Flush();
                    progress?.Invoke($"{i} / {blockCount + 1} MB");
                }
            }

            // Process additional data
            if (extraBytes > 0)
            {
                byte[] readBytes = input.ReadBytes(extraBytes);
                byte[] finalBytes = cipher.DoFinal(readBytes);
                output.Write(finalBytes);
                output.Flush();
            }

            progress?.Invoke($"{blockCount + 1} / {blockCount + 1} MB... Done!\r\n");
        }

        /// <summary>
        /// Perform an AES operation using two existing ciphers
        /// </summary>
        public static void PerformAESOperation(uint size,
            IBufferedCipher firstCipher,
            IBufferedCipher secondCipher,
            Stream input,
            Stream output,
            Action<string> progress)
        {
            // Get MiB-aligned block count and extra byte count
            int blockCount = (int)((long)size / (1024 * 1024));
            int extraBytes = (int)((long)size % (1024 * 1024));

            // Process MiB-aligned data
            if (blockCount > 0)
            {
                for (int i = 0; i < blockCount; i++)
                {
                    byte[] readBytes = input.ReadBytes(1024 * 1024);
                    byte[] firstProcessedBytes = firstCipher.ProcessBytes(readBytes);
                    byte[] secondProcessedBytes = secondCipher.ProcessBytes(firstProcessedBytes);
                    output.Write(secondProcessedBytes);
                    output.Flush();
                    progress($"{i} / {blockCount + 1} MB");
                }
            }

            // Process additional data
            if (extraBytes > 0)
            {
                byte[] readBytes = input.ReadBytes(extraBytes);
                byte[] firstFinalBytes = firstCipher.DoFinal(readBytes);
                byte[] secondFinalBytes = secondCipher.DoFinal(firstFinalBytes);
                output.Write(secondFinalBytes);
                output.Flush();
            }

            progress($"{blockCount + 1} / {blockCount + 1} MB... Done!\r\n");
        }

        #endregion

        #region Byte Arrays

        /// <summary>
        /// Add an integer value to a number represented by a byte array
        /// </summary>
        /// <param name="input">Byte array to add to</param>
        /// <param name="add">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        public static byte[] Add(byte[] input, uint add)
        {
            byte[] addBytes = BitConverter.GetBytes(add);
            Array.Reverse(addBytes);
            byte[] paddedBytes = new byte[16];
            Array.Copy(addBytes, 0, paddedBytes, 12, 4);
            return Add(input, paddedBytes);
        }

        /// <summary>
        /// Add two numbers represented by byte arrays
        /// </summary>
        /// <param name="left">Byte array to add to</param>
        /// <param name="right">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        public static byte[] Add(byte[] left, byte[] right)
        {
            int addBytes = Math.Min(left.Length, right.Length);
            int outLength = Math.Max(left.Length, right.Length);

            byte[] output = new byte[outLength];

            uint carry = 0;
            for (int i = addBytes - 1; i >= 0; i--)
            {
                uint addValue = (uint)(left[i] + right[i]) + carry;
                output[i] = (byte)addValue;
                carry = addValue >> 8;
            }

            if (outLength != addBytes && left.Length == outLength)
                Array.Copy(left, addBytes, output, addBytes, outLength - addBytes);
            else if (outLength != addBytes && right.Length == outLength)
                Array.Copy(right, addBytes, output, addBytes, outLength - addBytes);

            return output;
        }

        /// <summary>
        /// Perform a rotate left on a byte array
        /// </summary>
        /// <param name="val">Byte array value to rotate</param>
        /// <param name="r_bits">Number of bits to rotate</param>
        /// <returns>Rotated byte array value</returns>
        public static byte[] RotateLeft(byte[] val, int r_bits)
        {
            byte[] output = new byte[val.Length];
            Array.Copy(val, output, output.Length);

            // Shift by bytes
            while (r_bits >= 8)
            {
                byte temp = output[0];
                for (int i = 0; i < output.Length - 1; i++)
                {
                    output[i] = output[i + 1];
                }

                output[output.Length - 1] = temp;
                r_bits -= 8;
            }

            // Shift by bits
            if (r_bits > 0)
            {
                byte bitMask = (byte)(8 - r_bits), carry, wrap = 0;
                for (int i = 0; i < output.Length; i++)
                {
                    carry = (byte)((255 << bitMask & output[i]) >> bitMask);

                    // Make sure the first byte carries to the end
                    if (i == 0)
                        wrap = carry;

                    // Otherwise, move to the last byte
                    else
                        output[i - 1] |= carry;

                    // Shift the current bits
                    output[i] <<= r_bits;
                }

                // Make sure the wrap happens
                output[output.Length - 1] |= wrap;
            }

            return output;
        }

        /// <summary>
        /// XOR two numbers represented by byte arrays
        /// </summary>
        /// <param name="left">Byte array to XOR to</param>
        /// <param name="right">Amount to XOR</param>
        /// <returns>Byte array representing the new value</returns>
        public static byte[] Xor(byte[] left, byte[] right)
        {
            int xorBytes = Math.Min(left.Length, right.Length);
            int outLength = Math.Max(left.Length, right.Length);

            byte[] output = new byte[outLength];
            for (int i = 0; i < xorBytes; i++)
            {
                output[i] = (byte)(left[i] ^ right[i]);
            }

            if (outLength != xorBytes && left.Length == outLength)
                Array.Copy(left, xorBytes, output, xorBytes, outLength - xorBytes);
            else if (outLength != xorBytes && right.Length == outLength)
                Array.Copy(right, xorBytes, output, xorBytes, outLength - xorBytes);

            return output;
        }

        #endregion
    }
}
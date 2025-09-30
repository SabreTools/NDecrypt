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

        // TODO: Remove when IO updated
        #region Byte Arrays

        /// <summary>
        /// Add an integer value to a number represented by a byte array
        /// </summary>
        /// <param name="self">Byte array to add to</param>
        /// <param name="add">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        /// <remarks>Assumes array values are in big-endian format</remarks>
        public static byte[] Add(this byte[] self, uint add)
        {
            // If nothing is being added, just return
            if (add == 0)
                return self;

            // Get the big-endian representation of the value
            byte[] addBytes = BitConverter.GetBytes(add);
            Array.Reverse(addBytes);

            // Pad the array out to 16 bytes
            byte[] paddedBytes = new byte[16];
            Array.Copy(addBytes, 0, paddedBytes, 12, 4);

            // If the input is empty, just return the added value
            if (self.Length == 0)
                return paddedBytes;

            return self.Add(paddedBytes);
        }

        /// <summary>
        /// Add two numbers represented by byte arrays
        /// </summary>
        /// <param name="self">Byte array to add to</param>
        /// <param name="add">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        /// <remarks>Assumes array values are in big-endian format</remarks>
        public static byte[] Add(this byte[] self, byte[] add)
        {
            // If either input is empty
            if (self.Length == 0 && add.Length == 0)
                return [];
            else if (self.Length > 0 && add.Length == 0)
                return self;
            else if (self.Length == 0 && add.Length > 0)
                return add;

            // Setup the output array
            int outLength = Math.Max(self.Length, add.Length);
            byte[] output = new byte[outLength];

            // Loop adding with carry
            uint carry = 0;
            for (int i = 0; i < outLength; i++)
            {
                int selfIndex = self.Length - i - 1;
                uint selfValue = selfIndex >= 0 ? self[selfIndex] : 0u;

                int addIndex = add.Length - i - 1;
                uint addValue = addIndex >= 0 ? add[addIndex] : 0u;

                uint next = selfValue + addValue + carry;
                carry = next >> 8;

                int outputIndex = output.Length - i - 1;
                output[outputIndex] = (byte)(next & 0xFF);
            }

            return output;
        }

        /// <summary>
        /// Perform a rotate left on a byte array
        /// </summary>
        /// <param name="self">Byte array value to rotate</param>
        /// <param name="numBits">Number of bits to rotate</param>
        /// <returns>Rotated byte array value</returns>
        /// <remarks>Assumes array values are in big-endian format</remarks>
        public static byte[] RotateLeft(this byte[] self, int numBits)
        {
            // If either input is empty
            if (self.Length == 0)
                return [];
            else if (numBits == 0)
                return self;

            byte[] output = new byte[self.Length];
            Array.Copy(self, output, output.Length);

            // Shift by bytes
            while (numBits >= 8)
            {
                byte temp = output[0];
                for (int i = 0; i < output.Length - 1; i++)
                {
                    output[i] = output[i + 1];
                }

                output[output.Length - 1] = temp;
                numBits -= 8;
            }

            // Shift by bits
            if (numBits > 0)
            {
                byte bitMask = (byte)(8 - numBits), carry, wrap = 0;
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
                    output[i] <<= numBits;
                }

                // Make sure the wrap happens
                output[output.Length - 1] |= wrap;
            }

            return output;
        }

        /// <summary>
        /// XOR two numbers represented by byte arrays
        /// </summary>
        /// <param name="self">Byte array to XOR to</param>
        /// <param name="xor">Amount to XOR</param>
        /// <returns>Byte array representing the new value</returns>
        /// <remarks>Assumes array values are in big-endian format</remarks>
        public static byte[] Xor(this byte[] self, byte[] xor)
        {
            // If either input is empty
            if (self.Length == 0 && xor.Length == 0)
                return [];
            else if (self.Length > 0 && xor.Length == 0)
                return self;
            else if (self.Length == 0 && xor.Length > 0)
                return xor;

            // Setup the output array
            int outLength = Math.Max(self.Length, xor.Length);
            byte[] output = new byte[outLength];

            // Loop XOR
            for (int i = 0; i < outLength; i++)
            {
                int selfIndex = self.Length - i - 1;
                uint selfValue = selfIndex >= 0 ? self[selfIndex] : 0u;

                int xorIndex = xor.Length - i - 1;
                uint xorValue = xorIndex >= 0 ? xor[xorIndex] : 0u;

                uint next = selfValue ^ xorValue;

                int outputIndex = output.Length - i - 1;
                output[outputIndex] = (byte)(next & 0xFF);
            }

            return output;
        }

        #endregion
    }
}
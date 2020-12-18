using System;
using System.Linq;
using System.Numerics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace NDecrypt
{
    internal static class Helper
    {
        /// <summary>
        /// Add an integer value to a number represented by a byte array
        /// </summary>
        /// <param name="input">Byte array to add to</param>
        /// <param name="add">Amount to add</param>
        /// <returns>Byte array representing the new value</returns>
        public static byte[] AddToByteArray(byte[] input, int add)
        {
            int len = input.Length;
            var bigint = new BigInteger(input.Reverse().ToArray());
            bigint += add;
            var arr = bigint.ToByteArray().Reverse().ToArray();

            if (arr.Length < len)
            {
                byte[] temp = new byte[len];
                for (int i = 0; i < (len - arr.Length); i++)
                    temp[i] = 0x00;

                Array.Copy(arr, 0, temp, len - arr.Length, arr.Length);
                arr = temp;
            }

            return arr;
        }

        /// <summary>
        /// Create AES cipher and intialize
        /// </summary>
        /// <param name="key">BigInteger representation of 128-bit encryption key</param>
        /// <param name="iv">AES initial value for counter</param>
        /// <param name="encrypt">True if cipher is created for encryption, false otherwise</param>
        /// <returns>Initialized AES cipher</returns>
        public static IBufferedCipher CreateAESCipher(BigInteger key, byte[] iv, bool encrypt)
        {
            var cipher = CipherUtilities.GetCipher("AES/CTR");
            cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(TakeSixteen(key)), iv));
            return cipher;
        }

        /// <summary>
        /// Perform a rotate left on a BigInteger
        /// </summary>
        /// <param name="val">BigInteger value to rotate</param>
        /// <param name="r_bits">Number of bits to rotate</param>
        /// <param name="max_bits">Maximum number of bits to rotate on</param>
        /// <returns>Rotated BigInteger value</returns>
        public static BigInteger RotateLeft(BigInteger val, int r_bits, int max_bits)
        {
            return (val << r_bits % max_bits) & (BigInteger.Pow(2, max_bits) - 1) | ((val & (BigInteger.Pow(2, max_bits) - 1)) >> (max_bits - (r_bits % max_bits)));
        }

        /// <summary>
        /// Get a 16-byte array representation of a BigInteger
        /// </summary>
        /// <param name="input">BigInteger value to convert</param>
        /// <returns>16-byte array representing the BigInteger</returns>
        private static byte[] TakeSixteen(BigInteger input)
        {
            var arr = input.ToByteArray().Take(16).Reverse().ToArray();

            if (arr.Length < 16)
            {
                byte[] temp = new byte[16];
                for (int i = 0; i < (16 - arr.Length); i++)
                    temp[i] = 0x00;

                Array.Copy(arr, 0, temp, 16 - arr.Length, arr.Length);
                arr = temp;
            }

            return arr;
        }
    }
}

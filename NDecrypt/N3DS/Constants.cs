using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;

namespace NDecrypt.N3DS
{
    public class Constants
    {
        // Setup Keys and IVs
        public static byte[] PlainCounter = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public static byte[] ExefsCounter = new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public static byte[] RomfsCounter = new byte[] { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        public static BigInteger AESHardwareConstant { get; private set; }

        #region Retail 3DS keys

        // KeyX 0x18 (New 3DS 9.3)
        public static BigInteger KeyX0x18 { get; private set; }

        // KeyX 0x1B (New 3DS 9.6)
        public static BigInteger KeyX0x1B { get; private set; }

        // KeyX 0x25 (> 7.x)
        public static BigInteger KeyX0x25 { get; private set; }

        // KeyX 0x2C (< 6.x)
        public static BigInteger KeyX0x2C { get; private set; }

        #endregion

        #region Dev 3DS Keys

        // Dev KeyX 0x18 (New 3DS 9.3)
        public static BigInteger DevKeyX0x18 { get; private set; }

        // Dev KeyX 0x1B New 3DS 9.6)
        public static BigInteger DevKeyX0x1B { get; private set; }

        // Dev KeyX 0x25 (> 7.x)
        public static BigInteger DevKeyX0x25 { get; private set; }

        // Dev KeyX 0x2C (< 6.x)
        public static BigInteger DevKeyX0x2C { get; private set; }

        #endregion

        public const int CXTExtendedDataHeaderLength = 0x800;

        /// <summary>
        /// Represents if all of the keys have been initialized properly
        /// </summary>
        public static bool? IsReady { get; private set; }

        /// <summary>
        /// Setup all of the necessary constants
        /// </summary>
        /// <remarks>keys.bin should be in little endian format</remarks>
        public static void Init()
        {
            // If we're already attempted to set the constants, don't try to again
            if (IsReady != null)
                return;

            string keyfile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "keys.bin");
            if (!File.Exists(keyfile))
            {
                IsReady = false;
                return;
            }

            try
            {
                using (BinaryReader reader = new BinaryReader(File.Open(keyfile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                {
                    // This is required to preserve sign for BigInteger
                    byte[] signByte = new byte[] { 0x00 };

                    // Hardware constant
                    AESHardwareConstant = new BigInteger(reader.ReadBytes(16));

                    // Retail keys
                    KeyX0x18 = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                    KeyX0x1B = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                    KeyX0x25 = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                    KeyX0x2C = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());

                    // Development keys
                    DevKeyX0x18 = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                    DevKeyX0x1B = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                    DevKeyX0x25 = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                    DevKeyX0x2C = new BigInteger(reader.ReadBytes(16).Concat(signByte).ToArray());
                }
            }
            catch
            {
                IsReady = false;
                return;
            }

            IsReady = true;
        }
    }
}

using System.IO;
using Newtonsoft.Json;

namespace NDecrypt.Core
{
    internal class Configuration
    {
        #region DS-Specific Fields

        /// <summary>
        /// Encryption data taken from woodsec
        /// </summary>
        public string? NitroEncryptionData { get; set; }

        #endregion

        #region 3DS-Specific Fields

        /// <summary>
        /// AES Hardware Constant
        /// </summary>
        /// <remarks>generator</remarks>
        public string? AESHardwareConstant { get; set; }

        /// <summary>
        /// KeyX 0x18 (New 3DS 9.3)
        /// </summary>
        /// <remarks>slot0x18KeyX</remarks>
        public string? KeyX0x18 { get; set; }

        /// <summary>
        /// Dev KeyX 0x18 (New 3DS 9.3)
        /// </summary>
        public string? DevKeyX0x18 { get; set; }

        /// <summary>
        /// KeyX 0x1B (New 3DS 9.6)
        /// </summary>
        /// <remarks>slot0x1BKeyX</remarks>
        public string? KeyX0x1B { get; set; }

        /// <summary>
        /// Dev KeyX 0x1B New 3DS 9.6)
        /// </summary>
        public string? DevKeyX0x1B { get; set; }

        /// <summary>
        /// KeyX 0x25 (> 7.x)
        /// </summary>
        /// <remarks>slot0x25KeyX</remarks>
        public string? KeyX0x25 { get; set; }

        /// <summary>
        /// Dev KeyX 0x25 (> 7.x)
        /// </summary>
        public string? DevKeyX0x25 { get; set; }

        /// <summary>
        /// KeyX 0x2C (< 6.x)
        /// </summary>
        /// <remarks>slot0x2CKeyX</remarks>
        public string? KeyX0x2C { get; set; }

        /// <summary>
        /// Dev KeyX 0x2C (< 6.x)
        /// </summary>
        public string? DevKeyX0x2C { get; set; }

        #endregion

        public static Configuration? Create(string path)
        {
            // Ensure the file exists
            if (!File.Exists(path))
                return null;

            // Parse the configuration directly
            try
            {
                string contents = File.ReadAllText(path);
                return JsonConvert.DeserializeObject<Configuration?>(contents);
            }
            catch
            {
                return null;
            }
        }
    }
}

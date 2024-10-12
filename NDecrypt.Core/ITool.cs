namespace NDecrypt.Core
{
    public interface ITool
    {
        /// <summary>
        /// Attempts to encrypt an input file
        /// </summary>
        /// <returns>True if the file could be encrypted, false otherwise</returns>
        bool EncryptFile();

        /// <summary>
        /// Attempts to decrypt an input file
        /// </summary>
        /// <returns>True if the file could be decrypted, false otherwise</returns>
        bool DecryptFile();
    }
}

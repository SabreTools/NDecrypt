namespace NDecrypt.Core
{
    public interface ITool
    {
        /// <summary>
        /// Attempts to encrypt an input file
        /// </summary>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <returns>True if the file could be encrypted, false otherwise</returns>
        bool EncryptFile(bool force);

        /// <summary>
        /// Attempts to decrypt an input file
        /// </summary>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <returns>True if the file could be decrypted, false otherwise</returns>
        bool DecryptFile(bool force);
    }
}

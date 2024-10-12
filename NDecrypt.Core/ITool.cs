namespace NDecrypt.Core
{
    public interface ITool
    {
        /// <summary>
        /// Attempts to encrypt an input file
        /// </summary>
        /// <param name="filename">Name of the file to encrypt</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <returns>True if the file could be encrypted, false otherwise</returns>
        bool EncryptFile(string filename, bool force);

        /// <summary>
        /// Attempts to decrypt an input file
        /// </summary>
        /// <param name="filename">Name of the file to decrypt</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <returns>True if the file could be decrypted, false otherwise</returns>
        bool DecryptFile(string filename, bool force);
    }
}

namespace NDecrypt.Core
{
    public interface ITool
    {
        /// <summary>
        /// Attempts to encrypt an input file
        /// </summary>
        /// <param name="input">Name of the file to encrypt</param>
        /// <param name="output">Optional name of the file to write to</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <returns>True if the file could be encrypted, false otherwise</returns>
        /// <remarks>If an output filename is not provided, the input file will be overwritten</remarks>
        bool EncryptFile(string input, string? output, bool force);

        /// <summary>
        /// Attempts to decrypt an input file
        /// </summary>
        /// <param name="input">Name of the file to decrypt</param>
        /// <param name="output">Optional name of the file to write to</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <returns>True if the file could be decrypted, false otherwise</returns>
        /// <remarks>If an output filename is not provided, the input file will be overwritten</remarks>
        bool DecryptFile(string input, string? output, bool force);

        /// <summary>
        /// Attempts to get information on an input file
        /// </summary>
        /// <param name="filename">Name of the file get information on</param>
        /// <returns>String representing the info, null on error</returns>
        string? GetInformation(string filename);
    }
}

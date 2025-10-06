namespace NDecrypt
{
    /// <summary>
    /// Functionality to use from the program
    /// </summary>
    internal enum FeatureFlag
    {
        NULL,
        Decrypt,
        Encrypt,
        Info,
    }

    /// <summary>
    /// Type of the detected file
    /// </summary>
    internal enum FileType
    {
        NULL,
        NDS,
        NDSi,
        iQueDS,
        N3DS,
        iQue3DS,
    }
}
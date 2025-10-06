using System;

namespace NDecrypt.Features
{
    internal sealed class EncryptFeature : BaseFeature
    {
        #region Feature Definition

        public const string DisplayName = "encrypt";

        private static readonly string[] _flags = ["e", "encrypt"];

        private const string _description = "Encrypt the input files";

        #endregion

        public EncryptFeature()
            : base(DisplayName, _flags, _description)
        {
            RequiresInputs = true;

            Add(ConfigString);
            Add(DevelopmentFlag);
            Add(ForceFlag);
            Add(HashFlag);

            // TODO: Include this when enabled
            // Add(OverwriteFlag);
        }

        /// <inheritdoc/>
        protected override void ProcessFile(string input)
        {
            // Attempt to derive the tool for the path
            var tool = DeriveTool(input);
            if (tool == null)
                return;

            // Derive the output filename, if required
            string? output = null;
            if (!GetBoolean(OverwriteName))
                output = GetOutputFile(input, ".enc");

            Console.WriteLine($"Processing {input}");

            if (!tool.EncryptFile(input, output, GetBoolean(ForceName)))
            {
                Console.WriteLine("Encryption failed!");
                return;
            }

            // Output the file hashes, if expected
            if (GetBoolean(HashName))
                WriteHashes(input);
        }
    }
}

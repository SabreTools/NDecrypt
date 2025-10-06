using System;

namespace NDecrypt.Features
{
    internal sealed class DecryptFeature : BaseFeature
    {
        #region Feature Definition

        public const string DisplayName = "decrypt";

        private static readonly string[] _flags = ["d", "decrypt"];

        private const string _description = "Decrypt the input files";

        #endregion

        public DecryptFeature()
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
                output = GetOutputFile(input, ".dec");

            Console.WriteLine($"Processing {input}");

            if (!tool.DecryptFile(input, output, GetBoolean(ForceName)))
            {
                Console.WriteLine("Decryption failed!");
                return;
            }

            // Output the file hashes, if expected
            if (GetBoolean(HashName))
                WriteHashes(input);
        }
    }
}

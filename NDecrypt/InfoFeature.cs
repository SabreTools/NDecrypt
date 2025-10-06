using System;

namespace NDecrypt
{
    internal sealed class InfoFeature : BaseFeature
    {
        #region Feature Definition

        public const string DisplayName = "info";

        private static readonly string[] _flags = ["i", "info"];

        private const string _description = "Output file information";

        #endregion

        public InfoFeature()
            : base(DisplayName, _flags, _description)
        {
            RequiresInputs = true;

            Add(HashFlag);
        }

        /// <inheritdoc/>
        protected override void ProcessFile(string input)
        {
            // Attempt to derive the tool for the path
            var tool = DeriveTool(input);
            if (tool == null)
                return;

            Console.WriteLine($"Processing {input}");

            string? infoString = tool.GetInformation(input);
            infoString ??= "There was a problem getting file information!";

            Console.WriteLine(infoString);

            // Output the file hashes, if expected
            if (GetBoolean(HashName))
                WriteHashes(input);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using NDecrypt.Core;
using SabreTools.CommandLine;
using SabreTools.CommandLine.Inputs;

namespace NDecrypt.Features
{
    internal abstract class BaseFeature : Feature
    {
        #region Common Inputs

        protected const string ConfigName = "config";
        protected readonly StringInput ConfigString = new(ConfigName, ["-c", "--config"], "Path to config.json");

        protected const string DevelopmentName = "development";
        protected readonly FlagInput DevelopmentFlag = new(DevelopmentName, ["-d", "--development"], "Enable using development keys, if available");

        protected const string ForceName = "force";
        protected readonly FlagInput ForceFlag = new(ForceName, ["-f", "--force"], "Force operation by avoiding sanity checks");

        protected const string HashName = "hash";
        protected readonly FlagInput HashFlag = new(HashName, "--hash", "Output size and hashes to a companion file");

        protected const string OverwriteName = "overwrite";
        protected readonly FlagInput OverwriteFlag = new(OverwriteName, ["-o", "--overwrite"], "Overwrite input files instead of creating new ones");

        #endregion

        /// <summary>
        /// Mapping of reusable tools
        /// </summary>
        private readonly Dictionary<FileType, ITool> _tools = [];

        protected BaseFeature(string name, string[] flags, string description, string? detailed = null)
            : base(name, flags, description, detailed)
        {
        }

        /// <inheritdoc/>
        public override bool Execute()
        {
            // Initialize required pieces
            InitializeTools();

            for (int i = 0; i < Inputs.Count; i++)
            {
                if (File.Exists(Inputs[i]))
                {
                    ProcessFile(Inputs[i]);
                }
                else if (Directory.Exists(Inputs[i]))
                {
                    foreach (string file in Directory.GetFiles(Inputs[i], "*", SearchOption.AllDirectories))
                    {
                        ProcessFile(file);
                    }
                }
                else
                {
                    Console.WriteLine($"{Inputs[i]} is not a file or folder. Please check your spelling and formatting and try again.");
                }
            }

            return true;
        }

        /// <inheritdoc/>
        public override bool VerifyInputs() => Inputs.Count > 0;

        /// <summary>
        /// Process a single file path
        /// </summary>
        /// <param name="input">File path to process</param>
        protected abstract void ProcessFile(string input);

        /// <summary>
        /// Initialize the tools to be used by the feature
        /// </summary>
        private void InitializeTools()
        {

            var decryptArgs = new DecryptArgs(GetString(ConfigName));
            _tools[FileType.NDS] = new DSTool(decryptArgs);
            _tools[FileType.N3DS] = new ThreeDSTool(GetBoolean(DevelopmentName), decryptArgs);
        }

        /// <summary>
        /// Derive the encryption tool to be used for the given file
        /// </summary>
        /// <param name="filename">Filename to derive the tool from</param>
        protected ITool? DeriveTool(string filename)
        {
            if (!File.Exists(filename))
            {
                Console.WriteLine($"{filename} does not exist! Skipping...");
                return null;
            }

            FileType type = DetermineFileType(filename);
            return type switch
            {
                FileType.NDS => _tools[FileType.NDS],
                FileType.NDSi => _tools[FileType.NDS],
                FileType.iQueDS => _tools[FileType.NDS],
                FileType.N3DS => _tools[FileType.N3DS],
                _ => null,
            };
        }

        /// <summary>
        /// Derive an output filename from the input, if possible
        /// </summary>
        /// <param name="filename">Name of the input file to derive from</param>
        /// <param name="extension">Preferred extension set by the feature implementation</param>
        /// <returns>Output filename based on the input</returns>
        protected static string GetOutputFile(string filename, string extension)
        {
            // Empty filenames are passed back
            if (filename.Length == 0)
                return filename;

            // TODO: Replace the suffix instead of just appending
            // TODO: Ensure that the input and output aren't the same

            // If the extension does not include a leading period
#if NETCOREAPP || NETSTANDARD2_0_OR_GREATER
            if (!extension.StartsWith('.'))
#else
            if (!extension.StartsWith("."))
#endif
                extension = $".{extension}";

            // Append the extension and return
            return $"{filename}{extension}";
        }

        /// <summary>
        /// Write out the hashes of a file to a named file
        /// </summary>
        /// <param name="filename">Filename to get hashes for/param>
        protected static void WriteHashes(string filename)
        {
            // If the file doesn't exist, don't try anything
            if (!File.Exists(filename))
                return;

            // Get the hash string from the file
            string? hashString = HashingHelper.GetInfo(filename);
            if (hashString == null)
                return;

            // Open the output file and write the hashes
            using var fs = File.Open(Path.GetFullPath(filename) + ".hash", FileMode.Create, FileAccess.Write, FileShare.None);
            using var sw = new StreamWriter(fs);
            sw.Write(hashString);
        }

        /// <summary>
        /// Determine the file type from the filename extension
        /// </summary>
        /// <param name="filename">Filename to derive the type from</param>
        /// <returns>FileType value, if possible</returns>
        private static FileType DetermineFileType(string filename)
        {
            if (filename.EndsWith(".nds", StringComparison.OrdinalIgnoreCase)        // Standard carts
                || filename.EndsWith(".nds.dec", StringComparison.OrdinalIgnoreCase) // Carts/images with secure area decrypted
                || filename.EndsWith(".nds.enc", StringComparison.OrdinalIgnoreCase) // Carts/images with secure area encrypted
                || filename.EndsWith(".srl", StringComparison.OrdinalIgnoreCase))    // Development carts/images
            {
                Console.WriteLine("File recognized as Nintendo DS");
                return FileType.NDS;
            }
            else if (filename.EndsWith(".dsi", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("File recognized as Nintendo DSi");
                return FileType.NDSi;
            }
            else if (filename.EndsWith(".ids", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("File recognized as iQue DS");
                return FileType.iQueDS;
            }
            else if (filename.EndsWith(".3ds", StringComparison.OrdinalIgnoreCase)    // Standard carts
                || filename.EndsWith(".3ds.dec", StringComparison.OrdinalIgnoreCase)  // Decrypted carts/images
                || filename.EndsWith(".3ds.enc", StringComparison.OrdinalIgnoreCase)  // Encrypted carts/images
                || filename.EndsWith(".cci", StringComparison.OrdinalIgnoreCase))     // Development carts/images
            {
                Console.WriteLine("File recognized as Nintendo 3DS");
                return FileType.N3DS;
            }

            Console.WriteLine($"Unrecognized file format for {filename}. Expected *.nds, *.srl, *.dsi, *.3ds, *.cci");
            return FileType.NULL;
        }
    }
}

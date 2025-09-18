using System;
using System.Collections.Generic;
using System.IO;
using NDecrypt.Core;

namespace NDecrypt
{
    class Program
    {
        /// <summary>
        /// Mapping of reusable tools
        /// </summary>
        private static readonly Dictionary<FileType, ITool> _tools = [];

        public static void Main(string[] args)
        {
            // Get the options from the arguments
            var options = Options.ParseOptions(args);

            // If we have an invalid state
            if (options == null)
            {
                Options.DisplayHelp();
                return;
            }

            // Initialize the decrypt args, if possible
            var decryptArgs = new DecryptArgs(options.ConfigPath); ;

            // Create reusable tools
            _tools[FileType.NDS] = new DSTool(decryptArgs);
            _tools[FileType.N3DS] = new ThreeDSTool(options.Development, decryptArgs);

            for (int i = 0; i < options.InputPaths.Count; i++)
            {
                if (File.Exists(options.InputPaths[i]))
                {
                    ProcessFile(options.InputPaths[i], options);
                }
                else if (Directory.Exists(options.InputPaths[i]))
                {
                    foreach (string file in Directory.GetFiles(options.InputPaths[i], "*", SearchOption.AllDirectories))
                    {
                        ProcessFile(file, options);
                    }
                }
                else
                {
                    Console.WriteLine($"{args[i]} is not a file or folder. Please check your spelling and formatting and try again.");
                }
            }
        }

        /// <summary>
        /// Process a single file path
        /// </summary>
        /// <param name="input">File path to process</param>
        /// <param name="options">Options indicating how to process the file</param>
        private static void ProcessFile(string input, Options options)
        {
            // Attempt to derive the tool for the path
            var tool = DeriveTool(input);
            if (tool == null)
                return;

            Console.WriteLine($"Processing {input}");

            // Derive the output filename, if required
            string? output = null;
            if (!options.Overwrite)
                output = GetOutputFile(input, options);

            // Encrypt or decrypt the file as requested
            if (options.Feature == Feature.Encrypt && !tool.EncryptFile(input, output, options.Force))
            {
                Console.WriteLine("Encryption failed!");
                return;
            }
            else if (options.Feature == Feature.Decrypt && !tool.DecryptFile(input, output, options.Force))
            {
                Console.WriteLine("Decryption failed!");
                return;
            }
            else if (options.Feature == Feature.Info)
            {
                string? infoString = tool.GetInformation(input);
                infoString ??= "There was a problem getting file information!";

                Console.WriteLine(infoString);
            }

            // Output the file hashes, if expected
            if (options.OutputHashes)
                WriteHashes(input);
        }

        /// <summary>
        /// Derive the encryption tool to be used for the given file
        /// </summary>
        /// <param name="filename">Filename to derive the tool from</param>
        private static ITool? DeriveTool(string filename)
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

        /// <summary>
        /// Derive an output filename from the input, if possible
        /// </summary>
        /// <param name="filename">Name of the input file to derive from</param>
        /// <param name="options">Options indicating how to process the file</param>
        /// <returns>Output filename based on the input</returns>
        private static string GetOutputFile(string filename, Options options)
        {
            // Empty filenames are passed back
            if (filename.Length == 0)
                return filename;

            // TODO: Replace the suffix instead of just appending
            // TODO: Ensure that the input and output aren't the same

            // Append '.enc' or '.dec' based on the feature
            if (options.Feature == Feature.Decrypt)
                filename += ".dec";
            else if (options.Feature == Feature.Encrypt)
                filename += ".enc";

            // Return the reformatted name
            return filename;
        }

        /// <summary>
        /// Write out the hashes of a file to a named file
        /// </summary>
        /// <param name="filename">Filename to get hashes for/param>
        private static void WriteHashes(string filename)
        {
            // If the file doesn't exist, don't try anything
            if (!File.Exists(filename))
                return;

            // Get the hash string from the file
            string? hashString = HashingHelper.GetInfo(filename);
            if (hashString == null)
                return;

            // Open the output file and write the hashes
            using var fs = File.Create(Path.GetFullPath(filename) + ".hash");
            using var sw = new StreamWriter(fs);
            sw.WriteLine(hashString);
        }
    }
}

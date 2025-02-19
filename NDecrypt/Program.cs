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
            if (args.Length < 2)
            {
                DisplayHelp("Not enough arguments");
                return;
            }

            Feature feature;
            if (args[0] == "decrypt" || args[0] == "d")
            {
                feature = Feature.Decrypt;
            }
            else if (args[0] == "encrypt" || args[0] == "e")
            {
                feature = Feature.Encrypt;
            }
            else if (args[0] == "info" || args[0] == "i")
            {
                feature = Feature.Info;
            }
            else
            {
                DisplayHelp($"Invalid operation: {args[0]}");
                return;
            }

            bool development = false,
                force = false,
                outputHashes = false,
                useAesKeysTxt = false;
            string? keyfile = null;
            int start = 1;
            for (; start < args.Length; start++)
            {
                if (args[start] == "-a" || args[start] == "--aes-keys"
                    || args[start] == "-c" || args[start] == "--citra")
                {
                    useAesKeysTxt = true;
                }
                else if (args[start] == "-dev" || args[start] == "--development")
                {
                    development = true;
                }
                else if (args[start] == "-f" || args[start] == "--force")
                {
                    force = true;
                }
                else if (args[start] == "-h" || args[start] == "--hash")
                {
                    outputHashes = true;
                }
                else if (args[start] == "-k" || args[start] == "--keyfile")
                {
                    if (start == args.Length - 1)
                        Console.WriteLine("Invalid keyfile path: no additional arguments found!");

                    start++;
                    string tempPath = args[start];
                    if (string.IsNullOrEmpty(tempPath))
                        Console.WriteLine($"Invalid keyfile path: null or empty path found!");

                    tempPath = Path.GetFullPath(tempPath);
                    if (!File.Exists(tempPath))
                        Console.WriteLine($"Invalid keyfile path: file {tempPath} not found!");
                    else
                        keyfile = tempPath;
                }
                else
                {
                    break;
                }
            }

            // Derive the keyfile path based on the runtime folder if not already set
            keyfile = DeriveKeyFile(keyfile, useAesKeysTxt);

            // If we are using a Citra keyfile, there are no development keys
            if (development && useAesKeysTxt)
            {
                Console.WriteLine("AES keyfiles don't contain development keys; disabling the option...");
                development = false;
            }

            // Initialize the decrypt args, if possible
            var decryptArgs = new DecryptArgs(keyfile, useAesKeysTxt);

            // Create reusable tools
            _tools[FileType.NDS] = new DSTool();
            _tools[FileType.N3DS] = new ThreeDSTool(development, decryptArgs);

            for (int i = start; i < args.Length; i++)
            {
                if (File.Exists(args[i]))
                {
                    ProcessPath(args[i], feature, force, outputHashes);
                }
                else if (Directory.Exists(args[i]))
                {
                    foreach (string file in Directory.GetFiles(args[i], "*", SearchOption.AllDirectories))
                    {
                        ProcessPath(file, feature, force, outputHashes);
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
        /// <param name="path">File path to process</param>
        /// <param name="feature">Indicates what should be done to the file</param>
        /// <param name="force">Indicates if the operation should be forced</param>
        /// <param name="outputHashes">Indicates if hashes should be output after a successful operation</param>
        private static void ProcessPath(string path, Feature feature, bool force, bool outputHashes)
        {
            // Attempt to derive the tool for the path
            var tool = DeriveTool(path);
            if (tool == null)
                return;

            Console.WriteLine($"Processing {path}");

            // Encrypt or decrypt the file as requested
            if (feature == Feature.Encrypt && !tool.EncryptFile(path, force))
            {
                Console.WriteLine("Encryption failed!");
                return;
            }
            else if (feature == Feature.Decrypt && !tool.DecryptFile(path, force))
            {
                Console.WriteLine("Decryption failed!");
                return;
            }
            else if (feature == Feature.Info)
            {
                string? infoString = tool.GetInformation(path);
                infoString ??= "There was a problem getting file information!";

                Console.WriteLine(infoString);
                return;
            }

            // Output the file hashes, if expected
            if (outputHashes)
                WriteHashes(path);
        }

        /// <summary>
        /// Display a basic help text
        /// </summary>
        /// <param name="err">Additional error text to display, can be null to ignore</param>
        private static void DisplayHelp(string? err = null)
        {
            if (!string.IsNullOrEmpty(err))
                Console.WriteLine($"Error: {err}");

            Console.WriteLine(@"Usage: NDecrypt <operation> [flags] <path> ...

Possible values for <operation>:
e, encrypt - Encrypt the input files
d, decrypt - Decrypt the input files
i, info    - Output file information

Possible values for [flags] (one or more can be used):
-a, --aes-keys        Enable using aes_keys.txt instead of keys.bin
-dev, --development   Enable using development keys, if available
-f, --force           Force operation by avoiding sanity checks
-h, --hash            Output size and hashes to a companion file
-k, --keyfile <path>  Path to keys.bin or aes_keys.txt

<path> can be any file or folder that contains uncompressed items.
More than one path can be specified at a time.");
        }

        /// <summary>
        /// Derive the full path to the keyfile, if possible
        /// </summary>
        private static string? DeriveKeyFile(string? keyfile, bool useAesKeysTxt)
        {
            // If a path is passed in
            if (!string.IsNullOrEmpty(keyfile))
            {
                keyfile = Path.GetFullPath(keyfile);
                if (File.Exists(keyfile))
                    return keyfile;
            }

            // Derive the keyfile path based on the runtime folder if not already set
            using var processModule = System.Diagnostics.Process.GetCurrentProcess().MainModule;
            string applicationDirectory = Path.GetDirectoryName(processModule?.FileName) ?? string.Empty;

            // Use the proper default name for the type
            if (useAesKeysTxt)
                keyfile = Path.Combine(applicationDirectory, "aes_keys.txt");
            else
                keyfile = Path.Combine(applicationDirectory, "keys.bin");

            // Only return the path if the file exists
            return File.Exists(keyfile) ? keyfile : null;
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
            using (var fs = File.Create(Path.GetFullPath(filename) + ".hash"))
            using (var sw = new StreamWriter(fs))
            {
                sw.WriteLine(hashString);
            }
        }
    }
}

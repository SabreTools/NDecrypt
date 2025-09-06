using System;
using System.Collections.Generic;
using System.IO;
#if NET20 || NET35 || NET40 || NET452
using System.Reflection;
#endif

namespace NDecrypt
{
    /// <summary>
    /// Set of options for the test executable
    /// </summary>
    internal sealed class Options
    {
        #region Properties

        /// <summary>
        /// Feature to process input files with
        /// </summary>
        public Feature Feature { get; private set; }

        /// <summary>
        /// Path to config.json
        /// </summary>
        public string? ConfigPath { get; private set; }

        /// <summary>
        /// Enable using development keys, if available
        /// </summary>
        public bool Development { get; private set; } = false;

        /// <summary>
        /// Force operation by avoiding sanity checks
        /// </summary>
        public bool Force { get; private set; } = false;

        /// <summary>
        /// Set of input paths to use for operations
        /// </summary>
        public List<string> InputPaths { get; private set; } = [];

        /// <summary>
        /// Output size and hashes to a companion file
        /// </summary>
        public bool OutputHashes { get; private set; } = false;

        /// <summary>
        /// Enable overwriting of the original file
        /// </summary>
        /// TODO: Change this to default false when hooked up
        public bool Overwrite { get; private set; } = true;

        #endregion

        /// <summary>
        /// Parse commandline arguments into an Options object
        /// </summary>
        public static Options? ParseOptions(string[] args)
        {
            // If we have invalid arguments
            if (args == null || args.Length < 2)
            {
                Console.WriteLine("Not enough arguments");
                return null;
            }

            // Create an Options object
            var options = new Options();

            // Derive the feature
            switch (args[0])
            {
                case "-?":
                case "-h":
                case "--help":
                    return null;

                case "d":
                case "decrypt":
                    options.Feature = Feature.Decrypt;
                    break;

                case "e":
                case "encrypt":
                    options.Feature = Feature.Encrypt;
                    break;

                case "i":
                case "info":
                    options.Feature = Feature.Info;
                    break;

                default:
                    Console.WriteLine($"Invalid operation: {args[0]}");
                    return null;
            }

            // Parse the options and paths
            for (int index = 1; index < args.Length; index++)
            {
                string arg = args[index];
                switch (arg)
                {
                    case "-?":
                    case "-h":
                    case "--help":
                        return null;

                    case "-c":
                    case "--config":
                        if (index == args.Length - 1)
                        {
                            Console.WriteLine("Invalid config path: no additional arguments found!");
                            continue;
                        }

                        index++;
                        options.ConfigPath = args[index];
                        if (string.IsNullOrEmpty(options.ConfigPath))
                            Console.WriteLine($"Invalid config path: null or empty path found!");

                        options.ConfigPath = Path.GetFullPath(options.ConfigPath);
                        if (!File.Exists(options.ConfigPath))
                        {
                            Console.WriteLine($"Invalid config path: file {options.ConfigPath} not found!");
                            options.ConfigPath = null;
                        }

                        break;

                    case "-d":
                    case "--development":
                        options.Development = true;
                        break;

                    case "-f":
                    case "--force":
                        options.Force = true;
                        break;

                    case "--hash":
                        options.Force = true;
                        break;

                    case "-o":
                    case "--overwrite":
                        options.Overwrite = true;
                        break;

                    default:
                        options.InputPaths.Add(arg);
                        break;
                }
            }

            // Validate we have any input paths to work on
            if (options.InputPaths.Count == 0)
            {
                Console.WriteLine("At least one path is required!");
                return null;
            }

            // Derive the config path based on the runtime folder if not already set
            options.ConfigPath = DeriveConfigFile(options.ConfigPath);

            return options;
        }

        /// <summary>
        /// Display help text
        /// </summary>
        /// <param name="err">Additional error text to display, can be null to ignore</param>
        public static void DisplayHelp(string? err = null)
        {
            if (!string.IsNullOrEmpty(err))
                Console.WriteLine($"Error: {err}");

            Console.WriteLine("Cart Image Encrypt/Decrypt Tool");
            Console.WriteLine();
            Console.WriteLine("NDecrypt <operation> [options] <path> ...");
            Console.WriteLine();
            Console.WriteLine("Operations:");
            Console.WriteLine("e, encrypt               Encrypt the input files");
            Console.WriteLine("d, decrypt               Decrypt the input files");
            Console.WriteLine("i, info                  Output file information");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("-?, -h, --help           Display this help text and quit");
            Console.WriteLine("-c, --config <path>      Path to config.json");
            Console.WriteLine("-d, --development        Enable using development keys, if available");
            Console.WriteLine("-f, --force              Force operation by avoiding sanity checks");
            Console.WriteLine("--hash                   Output size and hashes to a companion file");
            // Console.WriteLine("-o, --overwrite          Overwrite input files instead of creating new ones"); // TODO: Print this when enabled
            Console.WriteLine();
            Console.WriteLine("<path> can be any file or folder that contains uncompressed items.");
            Console.WriteLine("More than one path can be specified at a time.");
        }

        #region Helpers

        /// <summary>
        /// Derive the full path to the config file, if possible
        /// </summary>
        private static string? DeriveConfigFile(string? config)
        {
            // If a path is passed in
            if (!string.IsNullOrEmpty(config))
            {
                config = Path.GetFullPath(config);
                if (File.Exists(config))
                    return config;
            }

            // Derive the keyfile path, if possible
            return GetFileLocation("config.json");
        }

        /// <summary>
        /// Search for a file in local and config directories
        /// </summary>
        /// <param name="filename">Filename to check in local and config directories</param>
        /// <returns>The full path to the file if found, null otherwise</returns>
        /// <remarks>
        /// This method looks in the following locations:
        /// - %HOME%/.config/ndecrypt
        /// - Assembly location directory
        /// - Process runtime directory
        /// </remarks>
        private static string? GetFileLocation(string filename)
        {
            // User home directory
#if NET20 || NET35
            string homeDir = Environment.ExpandEnvironmentVariables("%HOMEDRIVE%%HOMEPATH%");
            homeDir = Path.Combine(Path.Combine(homeDir, ".config"), "ndecrypt");
#else
            string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            homeDir = Path.Combine(homeDir, ".config", "ndecrypt");
#endif
            if (File.Exists(Path.Combine(homeDir, filename)))
                return Path.Combine(homeDir, filename);

            // Local directory
#if NET20 || NET35 || NET40 || NET452
            string runtimeDir =  Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
#else
            string runtimeDir = AppContext.BaseDirectory;
#endif
            if (File.Exists(Path.Combine(runtimeDir, filename)))
                return Path.Combine(runtimeDir, filename);

            // Process directory
            using var processModule = System.Diagnostics.Process.GetCurrentProcess().MainModule;
            string applicationDirectory = Path.GetDirectoryName(processModule?.FileName) ?? string.Empty;
            if (File.Exists(Path.Combine(applicationDirectory, filename)))
                return Path.Combine(applicationDirectory, filename);

            // No file was found
            return null;
        }

        #endregion
    }
}
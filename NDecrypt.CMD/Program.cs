using System;
using System.IO;
using System.Reflection;
using NDecrypt.N3DS;
using NDecrypt.NDS;

namespace NDecrypt.CMD
{
    class Program
    {
        /// <summary>
        /// Type of the detected file
        /// </summary>
        private enum FileType
        {
            NULL,
            NDS,
            NDSi,
            iQueDS,
            N3DS,
            iQue3DS,
            N3DSCIA,
        }

        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                DisplayHelp("Not enough arguments");
                return;
            }

            var decryptArgs = new DecryptArgs(); 
            if (args[0] == "decrypt" || args[0] == "d")
            {
                decryptArgs.Encrypt = false;
            }
            else if (args[0] == "encrypt" || args[0] == "e")
            {
                decryptArgs.Encrypt = true;
            }
            else
            {
                DisplayHelp($"Invalid operation: {args[0]}");
                return;
            }

            bool outputHashes = false;
            int start = 1;
            for ( ; start < args.Length; start++)
            {
                if (args[start] == "-c" || args[start] == "--citra")
                    decryptArgs.UseCitraKeyFile = true;

                else if (args[start] == "-dev" || args[start] == "--development")
                    decryptArgs.Development = true;

                else if (args[start] == "-f" || args[start] == "--force")
                    decryptArgs.Force = true;

                else if (args[start] == "-h" || args[start] == "--hash")
                    outputHashes = true;

                else
                    break;
            }

            // If we are using a Citra keyfile, there are no development keys
            if (decryptArgs.Development && decryptArgs.UseCitraKeyFile)
            {
                Console.WriteLine("Citra keyfiles don't contain development keys; disabling the option...");
                decryptArgs.Development = false;
            }

            // Derive the keyfile path based on the runtime folder -- TODO: Make the keyfile path configurable
            if (decryptArgs.UseCitraKeyFile)
                decryptArgs.KeyFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "aes_keys.txt");
            else
                decryptArgs.KeyFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "keys.bin");
            
            // Initialize the constants, if possible
            decryptArgs.Initialize();

            for (int i = start; i < args.Length; i++)
            {
                if (File.Exists(args[i]))
                {
                    Console.WriteLine(args[i]);
                    ITool tool = DeriveTool(args[i], decryptArgs);
                    if (tool?.ProcessFile() != true)
                        Console.WriteLine("Processing failed!");
                    else if (outputHashes)
                        WriteHashes(args[i]);
                }
                else if (Directory.Exists(args[i]))
                {
                    foreach (string file in Directory.EnumerateFiles(args[i], "*", SearchOption.AllDirectories))
                    {
                        Console.WriteLine(file);
                        ITool tool = DeriveTool(file, decryptArgs);
                        if (tool?.ProcessFile() != true)
                            Console.WriteLine("Processing failed!");
                        else if (outputHashes)
                            WriteHashes(file);
                    }
                }
                else
                {
                    Console.WriteLine($"{args[i]} is not a file or folder. Please check your spelling and formatting and try again.");
                }
            }
        }

        /// <summary>
        /// Display a basic help text
        /// </summary>
        /// <param name="err">Additional error text to display, can be null to ignore</param>
        private static void DisplayHelp(string err = null)
        {
            if (!string.IsNullOrWhiteSpace(err))
                Console.WriteLine($"Error: {err}");

            Console.WriteLine(@"Usage: NDecrypt.exe <opeation> [flags] <path> ...

Possible values for <operation>:
e, encrypt - Encrypt the input files
d, decrypt - Decrypt the input files

Possible values for [flags] (one or more can be used):
-c, --citra         - Enable using aes_keys.txt instead of keys.bin
-dev, --development - Enable using development keys, if available
-f, --force         - Force operation by avoiding sanity checks
-h, --hash          - Output size and hashes to a companion file

<path> can be any file or folder that contains uncompressed items.
More than one path can be specified at a time.");
        }

        /// <summary>
        /// Derive the encryption tool to be used for the given file
        /// </summary>
        /// <param name="filename">Filename to derive the tool from</param>
        /// <param name="decryptArgs">Arguments to pass to the tools on creation</param>
        /// <returns></returns>
        private static ITool DeriveTool(string filename, DecryptArgs decryptArgs)
        {
            FileType type = DetermineFileType(filename);
            switch(type)
            {
                case FileType.NDS:
                    Console.WriteLine("File recognized as Nintendo DS");
                    return new DSTool(filename, decryptArgs);
                case FileType.NDSi:
                    Console.WriteLine("File recognized as Nintendo DS");
                    return new DSTool(filename, decryptArgs);
                case FileType.iQueDS:
                    Console.WriteLine("File recognized as iQue DS");
                    return new DSTool(filename, decryptArgs);
                case FileType.N3DS:
                    Console.WriteLine("File recognized as Nintendo 3DS");
                    return new ThreeDSTool(filename, decryptArgs);
                // case FileType.N3DSCIA:
                //     Console.WriteLine("File recognized as Nintendo 3DS");
                //     return new CIATool(filename, decryptArgs);
                case FileType.NULL:
                default:
                    Console.WriteLine($"Unrecognized file format for {filename}. Expected *.nds, *.srl, *.dsi, *.3ds");
                    return null;
            }
        }

        /// <summary>
        /// Determine the file type from the filename extension
        /// </summary>
        /// <param name="filename">Filename to derive the type from</param>
        /// <returns>FileType value, if possible</returns>
        private static FileType DetermineFileType(string filename)
        {
            if (filename.EndsWith(".nds", StringComparison.OrdinalIgnoreCase)     // Standard carts
                || filename.EndsWith(".srl", StringComparison.OrdinalIgnoreCase)) // Development carts/images
                return FileType.NDS;

            else if (filename.EndsWith(".dsi", StringComparison.OrdinalIgnoreCase))
                return FileType.NDSi;

            else if (filename.EndsWith(".ids", StringComparison.OrdinalIgnoreCase))
                return FileType.iQueDS;

            else if (filename.EndsWith(".3ds", StringComparison.OrdinalIgnoreCase))
                return FileType.N3DS;
            
            else if (filename.EndsWith(".cia", StringComparison.OrdinalIgnoreCase))
                return FileType.N3DSCIA;

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
            string hashString = HashingHelper.GetInfo(filename);
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

using System;
using System.IO;
using NDecrypt.Core.Data;

namespace NDecrypt.Core
{
    class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                DisplayHelp("Not enough arguments");
                return;
            }

            bool? encrypt;
            if (args[0] == "decrypt" || args[0] == "d")
            {
                encrypt = false;
            }
            else if (args[0] == "encrypt" || args[0] == "e")
            {
                encrypt = true;
            }
            else
            {
                DisplayHelp($"Invalid operation: {args[0]}");
                return;
            }

            bool development = false, force = false;
            int start = 1;
            for ( ; start < args.Length; start++)
            {
                if (args[start] == "-dev" || args[start] == "--development")
                    development = true;

                else if (args[start] == "-f" || args[start] == "--force")
                    force = true;

                else
                    break;
            }

            // Ensure the constants are all set
            new Constants();
            if (!Constants.IsReady)
            {
                Console.WriteLine("Could not read keys from keys.bin. Please make sure the file exists and try again");
                return;
            }

            for (int i = start; i < args.Length; i++)
            {
                if (File.Exists(args[i]))
                {
                    ITool tool = DeriveTool(args[i], encrypt.Value, development, force);
                    if (tool?.ProcessFile() != true)
                        Console.WriteLine("Processing failed!");
                }
                else if (Directory.Exists(args[i]))
                {
                    foreach (string file in Directory.EnumerateFiles(args[i], "*", SearchOption.AllDirectories))
                    {
                        ITool tool = DeriveTool(file, encrypt.Value, development, force);
                        if (tool?.ProcessFile() != true)
                            Console.WriteLine("Processing failed!");
                    }
                }
            }

            Console.WriteLine("Press Enter to Exit...");
            Console.Read();
        }

        /// <summary>
        /// Display a basic help text
        /// </summary>
        /// <param name="err">Additional error text to display, can be null to ignore</param>
        private static void DisplayHelp(string err = null)
        {
            if (!string.IsNullOrWhiteSpace(err))
                Console.WriteLine($"Error: {err}");

            Console.WriteLine("Usage: NDecrypt.exe (decrypt|encrypt) [-dev] [-f] <file|dir> ...");
        }

        private enum RomType
        {
            NULL,
            NDS,
            NDSi,
            N3DS,
        }

        /// <summary>
        /// Derive the encryption tool to be used for the given file
        /// </summary>
        /// <param name="filename">Filename to derive the tool from</param>
        /// <param name="encrypt">True if we are encrypting the file, false otherwise</param>
        /// <param name="development">True if we are using development keys, false otherwise</param>
        /// <param name="force">True if operations should be forced, false otherwise</param>
        /// <returns></returns>
        private static ITool DeriveTool(string filename, bool encrypt, bool development, bool force)
        {
            RomType type = DetermineRomType(filename);
            switch(type)
            {
                case RomType.NDS:
                case RomType.NDSi:
                    return new DSTool(filename, encrypt, force);
                case RomType.N3DS:
                    return new ThreeDSTool(filename, development, encrypt, force);
                case RomType.NULL:
                default:
                    Console.WriteLine($"Unrecognized file format for {filename}. Expected *.nds, *.srl, *.dsi, *.3ds");
                    return null;
            }
        }

        /// <summary>
        /// Determine the rom type from the filename extension
        /// </summary>
        /// <param name="filename">Filename to derive the type from</param>
        /// <returns>RomType value, if possible</returns>
        private static RomType DetermineRomType(string filename)
        {
            if (filename.EndsWith(".nds", StringComparison.OrdinalIgnoreCase)
                || filename.EndsWith(".srl", StringComparison.OrdinalIgnoreCase))
                return RomType.NDS;

            else if (filename.EndsWith(".dsi", StringComparison.OrdinalIgnoreCase))
                return RomType.NDSi;

            else if (filename.EndsWith(".3ds", StringComparison.OrdinalIgnoreCase))
                return RomType.N3DS;

            return RomType.NULL;
        }
    }
}

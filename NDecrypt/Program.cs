using System;
using System.IO;

namespace NDecrypt
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

            bool? encrypt = null;
            if (args[0] == "decrypt")
            {
                encrypt = false;
            }
            else if (args[0] == "encrypt")
            {
                encrypt = true;
            }
            else
            {
                DisplayHelp($"Invalid operation: {args[0]}");
                return;
            }

            bool development = false;
            int start = 1;
            if (args[1] == "-dev")
            {
                development = true;
                start = 2;
            }

            for (int i = start; i < args.Length; i++)
            {
                if (File.Exists(args[i]))
                {
                    ITool tool = DeriveTool(args[i], encrypt.Value, development);
                    if (tool?.ProcessFile() != true)
                        Console.WriteLine("Processing failed!");
                }
                else if (Directory.Exists(args[i]))
                {
                    foreach (string file in Directory.EnumerateFiles(args[i], "*", SearchOption.AllDirectories))
                    {
                        ITool tool = DeriveTool(file, encrypt.Value, development);
                        if (tool?.ProcessFile() != true)
                            Console.WriteLine("Processing failed!");
                    }
                }
            }

            Console.WriteLine("Press Enter to Exit...");
            Console.Read();
        }

        private static void DisplayHelp(string err = null)
        {
            if (!string.IsNullOrWhiteSpace(err))
                Console.WriteLine($"Error: {err}");

            Console.WriteLine("Usage: NDecrypt.exe (decrypt|encrypt) [-dev] <file|dir> ...");
        }

        private enum RomType
        {
            NULL,
            NDS,
            NDSi,
            N3DS,
        }

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

        private static ITool DeriveTool(string filename, bool encrypt, bool development)
        {
            RomType type = DetermineRomType(filename);
            switch(type)
            {
                case RomType.NDS:
                case RomType.NDSi:
                    return new DSTool(filename, encrypt);
                case RomType.N3DS:
                    return new ThreeDSTool(filename, development, encrypt);
                case RomType.NULL:
                default:
                    Console.WriteLine($"Unrecognized file format for {filename}. Expected *.nds, *.dsi, *.3ds");
                    return null;
            }
        }
    }
}

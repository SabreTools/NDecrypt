using System;
using System.IO;

namespace ThreeDS
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
                    ThreeDSTool tool = new ThreeDSTool(args[i], development, encrypt.Value);
                    if (!tool.ProcessFile())
                        Console.WriteLine("Processing failed!");
                }
                else if (Directory.Exists(args[i]))
                {
                    foreach (string file in Directory.EnumerateFiles(args[i], "*", SearchOption.AllDirectories))
                    {
                        ThreeDSTool tool = new ThreeDSTool(file, development, encrypt.Value);
                        if (!tool.ProcessFile())
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

            Console.WriteLine("Usage: 3dsdecrypt.exe (decrypt|encrypt) [-dev] <file|dir> ...");
        }
    }
}

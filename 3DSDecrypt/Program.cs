using System;
using System.IO;

namespace ThreeDS
{
    class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 2 || (args[0] != "encrypt" && args[0] != "decrypt"))
            {
                Console.WriteLine("Usage: 3dsdecrypt.exe (decrypt|encrypt) [-dev] <file|dir> ...");
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
                    ThreeDSTool tool = new ThreeDSTool(args[i], development);
                    if (args[0] == "decrypt")
                        tool.Decrypt();
                    else if (args[0] == "encrypt")
                        tool.Encrypt();
                }
                else if (Directory.Exists(args[i]))
                {
                    foreach (string file in Directory.EnumerateFiles(args[i], "*", SearchOption.AllDirectories))
                    {
                        ThreeDSTool tool = new ThreeDSTool(file, development);
                        if (args[0] == "decrypt")
                            tool.Decrypt();
                        else if (args[0] == "encrypt")
                            tool.Encrypt();

                    }
                }
            }
        }
    }
}

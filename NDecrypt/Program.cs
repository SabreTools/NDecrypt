using System;
using System.Collections.Generic;
using NDecrypt.Features;
using SabreTools.CommandLine;
using SabreTools.CommandLine.Features;

namespace NDecrypt
{
    class Program
    {
        public static void Main(string[] args)
        {
            // Create the command set
            var commandSet = CreateCommands();

            // If we have no args, show the help and quit
            if (args == null || args.Length == 0)
            {
                commandSet.OutputAllHelp();
                return;
            }

            // Get the first argument as a feature flag
            string featureName = args[0];

            // Get the associated feature
            var topLevel = commandSet.GetTopLevel(featureName);
            if (topLevel == null || topLevel is not Feature feature)
            {
                Console.WriteLine($"'{featureName}' is not valid feature flag");
                commandSet.OutputFeatureHelp(featureName);
                return;
            }

            // Handle default help functionality
            if (topLevel is Help helpFeature)
            {
                helpFeature.ProcessArgs(args, 0, commandSet);
                return;
            }

            // Now verify that all other flags are valid
            if (!feature.ProcessArgs(args, 1))
                return;

            // If inputs are required
            if (feature.RequiresInputs && !feature.VerifyInputs())
            {
                commandSet.OutputFeatureHelp(topLevel.Name);
                Environment.Exit(0);
            }

            // Now execute the current feature
            if (!feature.Execute())
            {
                Console.Error.WriteLine("An error occurred during processing!");
                commandSet.OutputFeatureHelp(topLevel.Name);
            }
        }

        /// <summary>
        /// Create the command set for the program
        /// </summary>
        private static CommandSet CreateCommands()
        {
            List<string> header = [
                "Cart Image Encrypt/Decrypt Tool",
                string.Empty,
                "NDecrypt <operation> [options] <path> ...",
                string.Empty,
            ];

            List<string> footer = [
                string.Empty,
                "<path> can be any file or folder that contains uncompressed items.",
                "More than one path can be specified at a time.",
            ];

            var commandSet = new CommandSet(header, footer);

            commandSet.Add(new Help());
            commandSet.Add(new EncryptFeature());
            commandSet.Add(new DecryptFeature());
            commandSet.Add(new InfoFeature());

            return commandSet;
        }
    }
}

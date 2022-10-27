using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NDecrypt.Core.Tools
{
    public class IniReader : IDisposable
    {
        /// <summary>
        /// Internal stream reader for inputting
        /// </summary>
        private readonly StreamReader sr;

        /// <summary>
        /// Get if at end of stream
        /// </summary>
        public bool EndOfStream
        {
            get
            {
                return sr?.EndOfStream ?? true;
            }
        }

        /// <summary>
        /// Contents of the currently read line as a key value pair
        /// </summary>
        public KeyValuePair<string, string>? KeyValuePair { get; private set; } = null;

        /// <summary>
        /// Contents of the current line, unprocessed
        /// </summary>
        public string CurrentLine { get; private set; } = string.Empty;

        /// <summary>
        /// Get the current line number
        /// </summary>
        public long LineNumber { get; private set; } = 0;

        /// <summary>
        /// Current row type
        /// </summary>
        public IniRowType RowType { get; private set; } = IniRowType.None;

        /// <summary>
        /// Current section being read
        /// </summary>
        public string Section { get; private set; } = string.Empty;

        /// <summary>
        /// Validate that rows are in key=value format
        /// </summary>
        public bool ValidateRows { get; set; } = true;

        /// <summary>
        /// Constructor for reading from a file
        /// </summary>
        public IniReader(string filename)
        {
            sr = new StreamReader(filename);
        }

        /// <summary>
        /// Constructor for reading from a stream
        /// </summary>
        public IniReader(Stream stream, Encoding encoding)
        {
            sr = new StreamReader(stream, encoding);
        }

        /// <summary>
        /// Read the next line in the INI file
        /// </summary>
        public bool ReadNextLine()
        {
            if (!(sr.BaseStream?.CanRead ?? false) || sr.EndOfStream)
                return false;

            CurrentLine = sr.ReadLine().Trim();
            LineNumber++;
            ProcessLine();
            return true;
        }

        /// <summary>
        /// Process the current line and extract out values
        /// </summary>
        private void ProcessLine()
        {
            // Comment
            if (CurrentLine.StartsWith(";"))
            {
                KeyValuePair = null;
                RowType = IniRowType.Comment;
            }

            // Section
            else if (CurrentLine.StartsWith("[") && CurrentLine.EndsWith("]"))
            {
                KeyValuePair = null;
                RowType = IniRowType.SectionHeader;
                Section = CurrentLine.TrimStart('[').TrimEnd(']');
            }

            // KeyValuePair
            else if (CurrentLine.Contains("="))
            {
                // Split the line by '=' for key-value pairs
                string[] data = CurrentLine.Split('=');

                // If the value field contains an '=', we need to put them back in
                string key = data[0].Trim();
                string value = string.Join("=", data.Skip(1)).Trim();

                KeyValuePair = new KeyValuePair<string, string>(key, value);
                RowType = IniRowType.KeyValue;
            }

            // Empty
            else if (string.IsNullOrEmpty(CurrentLine))
            {
                KeyValuePair = null;
                CurrentLine = string.Empty;
                RowType = IniRowType.None;
            }

            // Invalid
            else
            {
                KeyValuePair = null;
                RowType = IniRowType.Invalid;

                if (ValidateRows)
                    throw new InvalidDataException($"Invalid INI row found, cannot continue: {CurrentLine}");
            }
        }

        /// <summary>
        /// Dispose of the underlying reader
        /// </summary>
        public void Dispose()
        {
            sr.Dispose();
        }
    }
}

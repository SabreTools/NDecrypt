using System.IO;

namespace NDecrypt.N3DS.Headers
{
    public class ARM9AccessControl
    {
        /// <summary>
        /// Descriptors
        /// </summary>
        public ARM9AccessControlDescriptors[] Descriptors { get; private set; }

        /// <summary>
        /// ARM9 Descriptor Version. Originally this value had to be ≥ 2. Starting with 9.3.0-X this value has to be either value 2 or value 3.
        /// </summary>
        public byte DescriptorVersion { get; private set; }

        /// <summary>
        /// Read from a stream and get ARM9 access control, if possible
        /// </summary>
        /// <param name="reader">BinaryReader representing the input stream</param>
        /// <returns>ARM9 access control object, null on error</returns>
        public static ARM9AccessControl Read(BinaryReader reader)
        {
            ARM9AccessControl ac = new ARM9AccessControl();

            try
            {
                ac.Descriptors = new ARM9AccessControlDescriptors[15];
                for (int i = 0; i < 15; i++)
                    ac.Descriptors[i] = (ARM9AccessControlDescriptors)reader.ReadByte();
                ac.DescriptorVersion = reader.ReadByte();
                return ac;
            }
            catch
            {
                return null;
            }
        }
    }
}

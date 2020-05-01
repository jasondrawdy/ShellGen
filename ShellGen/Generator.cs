/*
==============================================================================
Copyright © Jason Drawdy 

All rights reserved.

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Except as contained in this notice, the name of the above copyright holder
shall not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization.
==============================================================================
*/

#region Imports

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using SecurityDriven.Inferno;

#endregion
namespace ShellGen
{
    /// <summary>
    /// The style of formatting applied to the generated shellcode.
    /// </summary>
    public enum FormatType { Plain, Hex, Shellcode }

    /// <summary>
    /// An encrypted shellcode generator meant to accelerate development of security tools.
    /// </summary>
    public static class ShellGenerator
    {
        #region Methods

        /// <summary>
        /// Generate a shell object containing encrypted shellcode from a file path.
        /// </summary>
        /// <param name="filepath">Location of a file to transform into encrypted shellcode.</param>
        /// <returns>A shell object containing encrypted shellcode from a file path.</returns>
        public static Shell GenerateShell(string filepath, FormatType type, string password = null)
        {
            // Generate an empty shell to fill.
            Shell s = new Shell();

            // Try and generate data to fill the shell with.
            try
            {
                Random r = new Random();
                byte[] filebytes = filepath.Read();
                byte[] encrypted = (password == null) ? filebytes : filebytes.Encrypt(password);
                string encoded = encrypted.Encode();
                string formatted = encoded.Format(type);
                string id = GenerateID(r.Next(5, 25));
                s = new Shell(id, formatted, null);
            }
            catch (Exception e) { s = new Shell(null, null, e); }

            // Return our shell.
            return s;
        }

        /// <summary>
        /// Generate a shell object containing encrypted shellcode from a byte array.
        /// </summary>
        /// <param name="filebytes">Bytes of a file to transform into encrypted shellcode.</param>
        /// <returns>A shell object containing encrypted shellcode from a byte array.</returns>
        public static Shell GenerateShell(byte[] filebytes, FormatType type, string password = null)
        {
            // Generate an empty shell to fill.
            Shell s = new Shell();

            // Try and generate data to fill the shell with.
            try
            {
                Random r = new Random();
                byte[] encrypted = (password == null) ? filebytes : filebytes.Encrypt(password);
                string encoded = encrypted.Encode();
                string formatted = encoded.Format(type);
                string id = GenerateID(r.Next(5, 25));
                s = new Shell(id, formatted, null);
            }
            catch (Exception e) { s = new Shell(null, null, e); }

            // Return our shell.
            return s;
        }

        /// <summary>
        /// Read the bytes of a file.
        /// </summary>
        /// <param name="file">The location of a file to read the bytes of.</param>
        /// <returns>A byte array containing the bytes of a file.</returns>
        private static byte[] Read(this string file)
        {
            // Read the bytes of a file.
            byte[] filebytes = File.ReadAllBytes(file);
            return filebytes;
        }

        /// <summary>
        /// Encrypted a byte array.
        /// </summary>
        /// <param name="plainbytes">A byte array containing the bytes of a file.</param>
        /// <returns>A byte array containing the encrypted bytes of a file.</returns>
        private static byte[] Encrypt(this byte[] plainbytes, string key)
        {
            // Encrypt our filebytes.
            byte[] pass = Encoding.ASCII.GetBytes(key);
            byte[] cipherbytes = null;
            MemoryStream s = new MemoryStream();
            using (var bytes = new MemoryStream(plainbytes))
            using (var transform = new EtM_EncryptTransform(key: pass))
            using (var crypto = new CryptoStream(s, transform, CryptoStreamMode.Write))
            {
                bytes.CopyTo(crypto);
            }
            cipherbytes = s.ToArray();
            return cipherbytes;
        }

        /// <summary>
        /// Encode a byte array into Base64.
        /// </summary>
        /// <param name="cipherbytes"></param>
        /// <returns>A byte array containing the encrypted bytes of a file.</returns>
        public static string Encode(this byte[] cipherbytes)
        {
            // Encode our encrypted filebytes.
            string encoded = Convert.ToBase64String(cipherbytes);
            return encoded;
        }

        /// <summary>
        /// Format a string using a custom algorithm.
        /// </summary>
        /// <param name="encoded">A base64 encoded string.</param>
        /// <returns>A custom formatted string.</returns>
        private static string Format(this string encoded, FormatType type)
        {
            // Format our encrypted code however we wish.
            StringBuilder sb = new StringBuilder();
            byte[] encodedbytes = Encoding.ASCII.GetBytes(encoded);
            switch (type)
            {
                case FormatType.Plain:
                    return Encoding.ASCII.GetString(encodedbytes);
                case FormatType.Hex:
                    int z = 0;
                    for (int i = 0; i < encodedbytes.Length; i++)
                    {
                        if (z == 12) { z = 0; sb.Append("\n\t"); }
                        sb.Append(encodedbytes[i].ToString("x2"));
                    }
                    break;
                case FormatType.Shellcode:
                    sb.Append("unsigned char shellcode[] = {\n\t");
                    int x = 0, c = 0;
                    for (int i = 0; i < encodedbytes.Length; i++)
                    {
                        if (c == 12) { c = 0; sb.Append("\n\t"); }
                        sb.Append("0x" + encodedbytes[i].ToString("X2") + ",");
                        x++;
                        c++;
                    }
                    sb.Remove(sb.ToString().Length - 1, 1);
                    sb.Append("\n\t};\n");
                    sb.Append("unsigned int size = " + x.ToString());
                    break;
            }
            return sb.ToString();
        }

        /// <summary>
        /// Generate a random string to use as an identifier.
        /// </summary>
        /// <param name="length">The length of the identifier.</param>
        /// <returns>A randomly generated string of alphanumeric characters.</returns>
        public static string GenerateID(int length)
        {
            // Generate a random ID.
            string id = null;
            Random r = new Random();
            string[] pool = { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
                              "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
                              "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d",
                              "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
                              "o", "p", "q", "r", "s", "t", "u", "v", "w", "x",
                              "y", "z", "0", "1", "2", "3", "4", "5", "6", "7",
                              "8", "9"};

            // Build our ID.
            for (int i = 0; i < length; i++){
                id += pool[r.Next(0, pool.Length)];
            }

            // Return our random ID.
            return id;
        }

        #endregion
    }

    /// <summary>
    /// An object representing a file in an encrypted shellcode form.
    /// </summary>
    [Serializable]
    public class Shell
    {
        #region Variables

        /// <summary>
        /// An alphanumeric value assigned to the generated shell for easy maintainability.
        /// </summary>
        public string ID { get; private set; }
        /// <summary>
        /// The actual encrypted byte code of a specified file.
        /// </summary>
        public string Code { get; private set; }
        /// <summary>
        /// Caught exception if anything goes wrong during generation.
        /// </summary>
        public Exception Error { get; private set; }

        #endregion
        #region Initialization

        /// <summary>
        /// The default constructor for the shell object.
        /// </summary>
        public Shell() { }
        /// <summary>
        /// Constuct a shell object providing the ID, Code, and Description of a specified file.
        /// </summary>
        /// <param name="id">An alphanumeric value assigned to the generated shell for easy maintainability.</param>
        /// <param name="code">The actual encrypted byte code of a specified file.</param>
        public Shell(string id, string code, Exception error)
        {
            ID = id;
            Code = code;
            Error = error;
        }

        #endregion
    }
}

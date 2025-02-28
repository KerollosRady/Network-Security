using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            return Decrypt(cipherText, plainText);
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
                plainText += (char)('A' + (cipherText[i] - key[i % key.Length] + 26) % 26);
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
                cipherText += (char)('A' + (key[i % key.Length] + plainText[i] - 2 * 'A') % 26);
            return cipherText;
        }
    }
}
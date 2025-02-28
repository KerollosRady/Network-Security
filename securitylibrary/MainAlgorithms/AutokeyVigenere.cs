using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            int i = 0;
            int n = Math.Min(key.Length, cipherText.Length);
            for (; i < n; i++)
                plainText += (char)('A' + (cipherText[i] - key[i] + 26) % 26);
            for (int j = 0; i < cipherText.Length; i++, j++)
                plainText += (char)('A' + (cipherText[i] - plainText[j] + 26) % 26);
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            int n = Math.Min(key.Length, plainText.Length);
            string cipherText = "";
            int i = 0;
            for (; i < n; i++)
                cipherText += (char)('A' + (key[i] + plainText[i] - 2 * 'A') % 26);
            for (int j = 0; i < plainText.Length; i++, j++)
                cipherText += (char)('A' + (plainText[j] + plainText[i] - 2 * 'A') % 26);
            return cipherText;
        }
    }
}

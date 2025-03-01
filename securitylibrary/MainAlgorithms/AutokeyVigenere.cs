using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string smallest_key(string plainText,string s)
        {
            plainText = plainText.ToUpper();
            int st = plainText.Length;
            s = plainText + s;
            int n = s.Length;
            List<int> z = new List<int>(new int[n]);
            int l = 0, r = 0;
            for (int i = 1; i < n; i++)
            {
                if (i < r)
                {
                    z[i] = Math.Min(r - i, z[i - l]);
                }
                while (i + z[i] < n && s[z[i]] == s[i + z[i]])
                {
                    z[i]++;
                }
                if (i + z[i] > r)
                {
                    l = i;
                    r = i + z[i];
                }
            }
            for(int i = st; i < n; i++)
            {
                if (z[i] == n-i)
                    return s.Substring(st,i-st);
            }
            return "";
        }
        public string Analyse(string plainText, string cipherText)
        {
            return smallest_key(plainText,Decrypt(cipherText, plainText));
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

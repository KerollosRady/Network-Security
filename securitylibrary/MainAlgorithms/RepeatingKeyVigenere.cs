using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string smallest_key(string s)
        {
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
            z[0] = n;
            for (int sz = 1; sz <= n; sz++)
            {
                bool ok = true;
                int en = n - sz;
                for (int j = 0; j < en; j += sz)
                {
                    if (z[j] < sz)
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok && (en < n || en + z[en] == n))
                    return s.Substring(0, sz);
            }
            return "";
        }
        public string Analyse(string plainText, string cipherText)
        {
            return smallest_key(Decrypt(cipherText, plainText));
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
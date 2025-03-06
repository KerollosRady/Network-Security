using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[] key = new char[26];
            bool[] taken = new bool[26];
            // clean
            for (int i = 0; i < 26; i++)
            {
                key[i] = '-';
                taken[i] = false;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                key[plainText[i] - 'a'] = cipherText[i];
                taken[cipherText[i] - 'a'] = true;
            }
            List<char> rem = new List<char>();
            for (int i = 0; i < 26; i++)
                if (!taken[i])
                    rem.Add((char)('a' + i));
            int curr = 0;
            string res = "";
            foreach (char c in key)
            {
                if (c == '-')
                    res += rem[curr++];
                else
                    res += c;
            }
            return res;
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string plainText = "";
            char[] key2 = new char[26];
            for (int i = 0; i < key.Length; i++)
                key2[key[i] - 'A'] = (char)('A' + i);
            foreach (char c in cipherText)
                plainText += key2[c - 'A'];
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            string cipherText = "";
            foreach (char c in plainText)
                cipherText += key[c - 'A'];
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        char[] plainOrder = new char[] { 'E', 'T', 'A', 'O', 'I', 'N', 'S', 'R', 'H', 'L', 'D', 'C', 'U', 'M', 'F', 'P', 'G', 'W', 'Y', 'B', 'V', 'K', 'X', 'J', 'Q', 'Z' };
        int[] cipherOrder = new int[26];
        int[] frequency = new int[26];
        public string AnalyseUsingCharFrequency(string cipher)
        {
            // clean
            for (int i = 0; i < 26; i++)
            {
                cipherOrder[i] = i;
                frequency[i] = 0;
            }
            cipher = cipher.ToUpper();
            // count frequency of each character
            foreach (char c in cipher)
                frequency[c - 'A']++;
            // sort characters by frequency
            for (int i = 1; i < 26; i++)
            {
                int j = i;
                while (j > 0 && frequency[cipherOrder[j - 1]] < frequency[cipherOrder[j]])
                {
                    int tmpc = cipherOrder[j];
                    cipherOrder[j] = cipherOrder[j - 1];
                    cipherOrder[j - 1] = tmpc;
                    j--;
                }
            }
            char[] keyList = new char[26];
            // build key
            for (int i = 0; i < 26; i++)
                keyList[plainOrder[i] - 'A'] = (char)('A' + cipherOrder[i]);
            string key = "";
            foreach (char c in keyList)
                key += c;
            // get plain text 
            return Decrypt(cipher, key).ToLower();
        }
    }
}


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
                return -1;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int n = plainText.Length;
            for (int key = 1; key <= n; key++)
            {
                int startRow = 0, j = 0;
                bool valid = true;
                for (int i = 0; i < n; i++)
                {
                    if (!cipherText[i].Equals(plainText[j]))
                    {
                        valid = false;
                        break;
                    }
                    j += key;
                    if (j >= n)
                    {
                        startRow++;
                        j = startRow;
                    }
                }
                if (valid)
                {
                    Console.WriteLine(key);
                    return key;
                }
            }
            throw new InvalidAnlysisException();
            // throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            int w = (cipherText.Length + key - 1) / key;
            string plainText = "";
            for (int i = 0; i < w; i++)
            {
                for (int j = i; j < cipherText.Length; j+=w)
                {
                    plainText += cipherText[j];
                }
            }
            return plainText; //.ToLower();
            // throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key)
                    cipherText += plainText[j];
            }
            return cipherText; //.ToUpper();
            // throw new NotImplementedException();
        }
    }
}
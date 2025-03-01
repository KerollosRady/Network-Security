using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            Console.WriteLine(plainText + " " + cipherText);
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            if (plainText.Length != cipherText.Length)
                throw new InvalidAnlysisException();

            int n = plainText.Length;
            for (int key = 1; key <= n; key++)
            {
                if (n % key != 0) continue;
                int rows = n / key;
                Dictionary<string, List<int>> idxs = new Dictionary<string, List<int>>(); // colString, col
                for (int col = 0; col < key; col++)
                {
                    string sub = "";
                    for (int j = col; j < n; j+=key) sub += plainText[j];
                    if (!idxs.ContainsKey(sub)) idxs[sub] = new List<int>();
                    idxs[sub].Add(col);
                }
                
                List<int> res = new List<int>();
                bool valid = true;
                for (int i = 0; i < n; i+=rows)
                {
                    string sub = cipherText.Substring(i, rows);
                    if (!idxs.ContainsKey(sub))
                    {
                        valid = false;
                        break;
                    }
                    List<int> lst = idxs[sub];
                    if (lst.Count == 0)
                    {
                        valid = false;
                        break;
                    }
                    res.Add(lst.Last()+1);
                    lst.RemoveAt(lst.Count - 1);
                }
                if (valid)
                {
                    foreach(int x in res)
                    {
                        Console.Write(x + " ");
                    }
                    Console.WriteLine();
                    return res;
                }
            }
            return Enumerable.Range(1, n).ToList(); // invalid
            // throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, List<int> key)
        {

            int n = cipherText.Length;
            int elementsInCol = n / key.Count;
            int rem = n % key.Count;
            List<char> plainText = new List<char>(new char[n]);

            int total = 0;
            for (int i = 0; i < key.Count; i++) {
                int elements = elementsInCol + (key[i] <= rem ? 1 : 0);
                for (int j = key[i]-1; total < n && j < n && elements > 0; j+=key.Count, elements--)
                {
                    plainText[j] = cipherText[total++];
                }
            }
            string res = "";
            foreach (char c in plainText) res += c;
            Console.WriteLine(cipherText + " " + res);
            foreach (int x in key)
            {
                Console.Write(x + " ");
            }
            return res;
            // throw new NotImplementedException();
        }
        public string Encrypt(string plainText, List<int> key)
        {
            // while (plainText.Length % key.Count != 0) plainText += '#';
            string cipherText = "";
            foreach (int col in key)
                for (int i = col-1; i < plainText.Length; i += key.Count)
                    cipherText += plainText[i];
            Console.WriteLine(cipherText);
            return cipherText;
            // throw new NotImplementedException();
        }
    }
}

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
        public List<int> ConvertKey(List<int> key)
        {
            int n = key.Count;
            List<int> pos = new List<int>(new int[n]);
            for (int i = 0; i < n; i++) pos[key[i] - 1] = i + 1;
            return pos;
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
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
                    res.Add(lst.Last()+1);
                    lst.RemoveAt(lst.Count - 1);
                    if (lst.Count == 0) idxs.Remove(sub);
                }
                if (valid)
                {
                    return ConvertKey(res);
                }
            }
            return Enumerable.Range(1, n).ToList(); // invalid
        }
        public string Decrypt(string cipherText, List<int> key)
        {
            List<int> pos = ConvertKey(key);
            int n = cipherText.Length;
            int elementsInCol = n / pos.Count;
            int rem = n % pos.Count;
            List<char> plainText = new List<char>(new char[n]);

            int total = 0;
            for (int i = 0; i < pos.Count; i++) {
                int elements = elementsInCol + (pos[i] <= rem ? 1 : 0);
                for (int j = pos[i]-1; elements > 0; j+= pos.Count, elements--)
                {
                    plainText[j] = cipherText[total++];
                }
            }
            string plain = "";
            foreach (char c in plainText) plain += c;
            return plain;
        }
        public string Encrypt(string plainText, List<int> key)
        {
            List<int> pos = ConvertKey(key);
            while (plainText.Length % pos.Count != 0) plainText += 'x';
            string cipherText = "";
            foreach (int col in pos)
                for (int i = col-1; i < plainText.Length; i += pos.Count)
                    cipherText += plainText[i];
            return cipherText;
        }
    }
}

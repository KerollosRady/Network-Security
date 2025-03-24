using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            String P = des.Decrypt(cipherText, key[0]);
            P = des.Encrypt(P, key[1]);
            P = des.Decrypt(P, key[0]);
            return P;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            String C = des.Encrypt(plainText, key[0]);
            C = des.Decrypt(C, key[1]);
            C = des.Encrypt(C, key[0]);
            return C;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}

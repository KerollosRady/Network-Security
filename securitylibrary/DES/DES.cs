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

    // constants:

    // IP, IP-1
    // 8 s-Boxes each 4*15
    // Straight Permutation (P)
    // PC - 1, PC - 2

    // Hexa2bin (String) -> long
    // bin2Hexa (long) -> String
    // Permute
    // Expand
    // F
    // Execute
    // RevertExpansion
    // GenerateKeys

    public class DES : CryptographicTechnique
    {
        long[] keys = new long[16];
        long Hexa2bin(String hexa)
        {
            long res = 0;
            return res;
        }
        String bin2Hexa(long bin)
        {
            String res = "";
            return res;
        }
        long Permute(long bits, ref List<int> p)
        {
            long res = 0;
            return res;
        }
        long Expand(long bits)
        {
            long res = 0;
            return res;
        }
        long RevertExpansion(long bits)
        {
            long res = 0;
            return res;
        }
        long F(long bits, long ki)
        {
            long res = 0;
            return res;
        }
        void GenerateKeys(long k)
        {

        }
        long Execute(long bits, long k)
        {
            GenerateKeys(k);
            long res = 0;
            return res;
        }
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
    }
}

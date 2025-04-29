using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            return PowMod(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = new ExtendedEuclid().GetMultiplicativeInverse(e, phi);
            return PowMod(C, d, n);
        }

        private int PowMod(long a, long exp, int mod)
        {
            long result = 1;
            a %= mod;

            while (exp > 0)
            {
                if ((exp & 1) == 1) result = (result * a) % mod;
                a = (a * a) % mod;
                exp >>= 1;
            }

            return (int)result;
        }
    }
}

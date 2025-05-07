using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.RSA;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long c1 = RSA.RSA.PowMod(alpha, k, q);
            long c2 = ((long) m * RSA.RSA.PowMod(y, k, q)) % q;
            return new List<long> { c1, c2 };
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int s = RSA.RSA.PowMod(c1, x, q);
            long sInverse = new ExtendedEuclid().GetMultiplicativeInverse(s, q);
            int m = (int) (c2 * sInverse % q);
            return m;
        }
    }
}

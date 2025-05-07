using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.RSA;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            // public keys
            int ya = RSA.RSA.PowMod(alpha, xa, q);
            int yb = RSA.RSA.PowMod(alpha, xb, q);

            // secret keys
            int keyA = RSA.RSA.PowMod(yb, xa, q); // A computes
            int keyB = RSA.RSA.PowMod(ya, xb, q); // B computes

            Debug.Assert(keyA == keyB);
            return new List<int> { keyA, keyB };
        }
    }
}

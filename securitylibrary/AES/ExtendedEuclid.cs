using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        private int ExtendedGCD(int a, int b, out int x, out int y)
        {
            if (b == 0)
            {
                x = 1;
                y = 0;
                return a;
            }
            int gcd = ExtendedGCD(b, a % b, out int x1, out int y1);
            x = y1;
            y = x1 - (a / b) * y1;
            return gcd;
        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int x, y;
            int gcd = ExtendedGCD(number, baseN, out x, out y);

            if (gcd != 1)
                return -1;
            return (x % baseN + baseN) % baseN;
        }

    }
}

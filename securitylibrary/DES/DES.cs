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
        #region constants
        readonly int[] IP = {
            57, 49, 41, 33, 25, 17,  9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16,  8, 0,
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6
        };
        readonly int[] IP_1 = {
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25,
            32,  0, 40,  8, 48, 16, 56, 24
        };
        readonly int[] P = {
            15, 6, 19, 20, 28, 11, 27, 16,
            0, 14, 22, 25, 4, 17, 30, 9,
            1, 7, 23, 13, 31, 26, 2, 8,
            18, 12, 29, 5, 21, 10, 3, 24
        };
        readonly int[] PC1 = {
            56, 48, 40, 32, 24, 16,  8,
            0, 57, 49, 41, 33, 25, 17,
            9,  1, 58, 50, 42, 34, 26,
            18, 10,  2, 59, 51, 43, 35,
            62, 54, 46, 38, 30, 22, 14,
            6, 61, 53, 45, 37, 29, 21,
            13,  5, 60, 52, 44, 36, 28,
            20, 12,  4, 27, 19, 11,  3
        };
        readonly int[] PC2 =
        {
            13, 16, 10, 23, 0, 4, 2, 27,
            14, 5, 20, 9, 22, 11, 3,
            25, 7, 15, 6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54, 29, 39,
            50, 44, 32, 47, 43, 48, 38, 55,
            33, 52, 45, 41, 42, 28, 35, 31
        };
        readonly int[,,] SBox =
    {
        {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };
        const string hexChars = "0123456789ABCDEF";
        #endregion
        long[] keys = new long[16];
        long Hexa2Bin(string hexa)
        {
            // Skip "0x" prefix if present
            int startIndex = 2;
            long result = 0;
            for (int i = startIndex; i < hexa.Length; i++)
            {
                char c = hexa[i];
                uint digit;

                if (c >= '0' && c <= '9')
                {
                    digit = (uint)(c - '0');
                }
                else if (c >= 'A' && c <= 'F')
                {
                    digit = (uint)(c - 'A' + 10);
                }
                else if (c >= 'a' && c <= 'f')
                {
                    digit = (uint)(c - 'a' + 10);
                }
                else
                {
                    throw new ArgumentException("Invalid hex character: " + c);
                }

                result = (result << 4) | digit;
            }

            return result;
        }
        string Bin2Hexa(long bin)
        {
            char[] buffer = new char[18]; // 0x + 16 digits
            // Add prefix
            buffer[0] = '0';
            buffer[1] = 'x';
            // Process each nibble (4 bits) from most significant to least
            for (int i = 0 , stb = 60; i < 16; i++,stb-=4)
            {
                // Get the current nibble (0-15)
                int nibble = (int)((bin >> stb) & 0xF);
                buffer[i + 2] = hexChars[nibble];
            }
            return new string(buffer);
        }
        long Permute(long bits, int[] p)
        {
            long res = 0;
            int n= p.Length;
            for (int i = 0; i < n; i++)
            {
                res <<= 1;
                res |= (bits >> p[i]) & 1;
            }
            return res;
        }
        long Expand(long bits)
        {
            long res = 0;
            // 31-0
            // add 0-bit to end 
            bits |= (bits & 1) << 32;
            // add 31-bit to first
            bits = (bits>>31)&1|(bits << 1);
            const int needBits = (1 << 6) - 1;
            //   1111 0000   1010 1010 1111 0000 1010 1010
            // 0 1111 [0]000 [1]010 1010 1111 0000 1010 1010 1
            //        [28]   [24] .. 
            for (int startBit = 28; startBit>=0; startBit -= 4)
            {
                res <<= 6;
                res|= (bits >> startBit)&needBits;
            }
            return res;
        }
        long RevertExpansion(long bits)
        {
            long res = 0;
            const int needBits = (1 << 4) - 1;
            for (int i=42,idx = 0;i >= 0; i -= 6,idx++)
            {
                int val = (int)(bits >>i);
                int row = val & 1;
                val >>= 1;
                int col = val & needBits;
                val >>= 3;
                row |= val & 2;
                res <<= 4;
                res = SBox[idx, row, col];
            }
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

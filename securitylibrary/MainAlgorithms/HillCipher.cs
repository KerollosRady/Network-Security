using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class HillCipher
    {
        static int ModInverse(int a, int mod)
        {
            for (int x = 1; x < mod; x++)
                if ((a * x) % mod == 1)
                    return x;
            return -1;
        }

        static int[,] MultiplyMatrix(int[,] A, int[,] B, int mod)
        {
            int m = A.GetLength(0), n = B.GetLength(1), p = A.GetLength(1);
            int[,] result = new int[m, n];
            for (int i = 0; i < m; i++)
                for (int k = 0; k < p; k++)
                    for (int j = 0; j < n; j++)
                        result[i, j] = (result[i, j] + A[i, k] * B[k, j]) % mod;

            return result;
        }
        static int[,] InverseMatrix(int[,] A, int mod)
        {
            int n = A.GetLength(0);
            int det = Determinant(A, mod);
            if (det == 0)
                return null;
            int detInv = ModInverse(det, mod);
            if (detInv == -1)
                return null;
            int[,] inv = new int[n, n];
            Adjugate(A, inv, mod);
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    inv[i, j] = (inv[i, j] * detInv) % mod;
            return inv;
        }
        static int Determinant(int[,] A, int mod)
        {
            int n = A.GetLength(0);
            if (n == 2)
                return ((A[0, 0] * A[1, 1] - A[0, 1] * A[1, 0]) % mod + mod) % mod;

            return ((A[0, 0] * (A[1, 1] * A[2, 2] - A[1, 2] * A[2, 1])
                   - A[0, 1] * (A[1, 0] * A[2, 2] - A[1, 2] * A[2, 0])
                   + A[0, 2] * (A[1, 0] * A[2, 1] - A[1, 1] * A[2, 0])) % mod + mod) % mod;
        }

        static void Adjugate(int[,] A, int[,] adj, int mod)
        {
            int n = A.GetLength(0);
            if (n == 2)
            {
                adj[0, 0] = A[1, 1];
                adj[0, 1] = -A[0, 1];
                adj[1, 0] = -A[1, 0];
                adj[1, 1] = A[0, 0];
            }
            else
            {
                adj[0, 0] = (A[1, 1] * A[2, 2] - A[1, 2] * A[2, 1]) % mod;
                adj[0, 1] = (-1 * (A[0, 1] * A[2, 2] - A[0, 2] * A[2, 1])) % mod;
                adj[0, 2] = (A[0, 1] * A[1, 2] - A[0, 2] * A[1, 1]) % mod;
                adj[1, 0] = (-1 * (A[1, 0] * A[2, 2] - A[1, 2] * A[2, 0])) % mod;
                adj[1, 1] = (A[0, 0] * A[2, 2] - A[0, 2] * A[2, 0]) % mod;
                adj[1, 2] = (-1 * (A[0, 0] * A[1, 2] - A[0, 2] * A[1, 0])) % mod;
                adj[2, 0] = (A[1, 0] * A[2, 1] - A[1, 1] * A[2, 0]) % mod;
                adj[2, 1] = (-1 * (A[0, 0] * A[2, 1] - A[0, 1] * A[2, 0])) % mod;
                adj[2, 2] = (A[0, 0] * A[1, 1] - A[0, 1] * A[1, 0]) % mod;
            }

            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    adj[i, j] = (adj[i, j] % mod + mod) % mod;
        }
        static int[,] TransposeMatrix(int[,] A)
        {
            int rows = A.GetLength(0);
            int cols = A.GetLength(1);
            int[,] transpose = new int[cols, rows];

            for (int i = 0; i < rows; i++)
                for (int j = 0; j < cols; j++)
                    transpose[j, i] = A[i, j];

            return transpose;
        }
        /// <summary>
        /// The List<int> is row based. Which means that the key is given in row based manner.
        /// </summary>
        static int[,] list2mat(List<int> list, int rows)
        {
            Debug.Assert(list.Count % rows == 0);
            int cols = list.Count / rows;
            int[,] mat = new int[rows, cols];
            int idx = 0;
            for (int j = 0; j < cols; j++)
                for (int i = 0; i < rows; i++)
                    mat[i, j] = list[idx++];
            return mat;
        }
        static List<int> mat2list(int[,] mat, int size)
        {
            int rows = mat.GetLength(0);
            int cols = mat.GetLength(1);
            List<int> list = new List<int>();
            for (int j = 0; j < cols; j++)
                for (int i = 0; i < rows; i++)
                {
                    list.Add(mat[i, j]);
                    if (list.Count == size)
                        return list;
                }
            return list;
        }
        int getDimOfKey(List<int> key)
        {
            if (key.Count == 4)
                return 2;
            if (key.Count == 9)
                return 3;
            throw new Exception("Key should only be 3x3 or 2x2");
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = getDimOfKey(key);
            int[,] matC = list2mat(cipherText, m), matk = TransposeMatrix(list2mat(key, m));
            int[,] invMatk = InverseMatrix(matk, 26);
            int[,] matPt = MultiplyMatrix(invMatk, matC, 26);
            return mat2list(matPt, cipherText.Count);
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = getDimOfKey(key);
            int[,] matPt = list2mat(plainText, m), matk = TransposeMatrix(list2mat(key, m));
            int[,] matC = MultiplyMatrix(matk, matPt, 26);
            return mat2list(matC, plainText.Count);
        }
        int[,] matp, matc, submatp, submatc;
        int m , n ;
        List<int> solve(int taken , int col)
        {
            if (taken == m)
            {
                int[,] InvOfsubmatp = InverseMatrix(submatp, 26);
                if (InvOfsubmatp == null)
                    return null;
                int[,] matk = MultiplyMatrix(submatc, InvOfsubmatp, 26);
                int[,] kp = MultiplyMatrix(matk, matp, 26);
                bool ok = true;
                for (int i = 0; i < m && ok; i++)
                    for (int j = 0; j < n; j++)
                        if (kp[i, j] != matc[i, j])
                        {
                            ok = false;
                            break;
                        }
                if (!ok)
                    return null;
                matk = TransposeMatrix(matk);
                return mat2list(matk, m*m);
            }
            while(col<n)
            {
                for(int row = 0; row < m; row++)
                {
                    submatp[row, taken] = matp[row, col];
                    submatc[row, taken] = matc[row, col];
                }
                List<int> res = solve(taken + 1, col+1);
                if (res != null)
                    return res;
                col++;
            }
            return null;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText, int m = 2)
        {
            this.m = m;
            Debug.Assert(plainText.Count % m == 0);
            n = plainText.Count / m;
            matp = list2mat(plainText, m);
            matc = list2mat(cipherText, m);
            int[,] invPt = InverseMatrix(matp, 26);
            if (invPt != null)
            {
                int[,] matk = MultiplyMatrix(matc, invPt, 26);
                matk = TransposeMatrix(matk);
                return mat2list(matk, m * m);
            }
            submatp = new int[m, m];
            submatc = new int[m, m];
            List<int> res = solve(0, 0);
            if(res == null)
                throw new InvalidAnlysisException();
            return res;
        }

        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            return Analyse(plainText, cipherText, 3);
        }
    }
}

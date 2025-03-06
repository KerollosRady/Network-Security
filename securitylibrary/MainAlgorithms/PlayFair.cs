using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            char[,] key_matrix = Generate_matrix(key);
            StringBuilder plainText = new StringBuilder();

            int size = cipherText.Length;

            for (int i = 0; i < size; i += 2)
            {
                char first = cipherText[i];
                char second = cipherText[i + 1];

                int[] Position1 = FindPosition(key_matrix, first);
                int[] position2 = FindPosition(key_matrix, second);

                int row1 = Position1[0], col1 = Position1[1];
                int row2 = position2[0], col2 = position2[1];

                if (row1 == row2)
                {
                    plainText.Append(key_matrix[row1, (col1 - 1 + 5) % 5]);
                    plainText.Append(key_matrix[row2, (col2 - 1 + 5) % 5]);
                }
                else if (col1 == col2)
                {
                    plainText.Append(key_matrix[(row1 - 1 + 5) % 5, col1]);
                    plainText.Append(key_matrix[(row2 - 1 + 5) % 5, col2]);
                }
                else
                {
                    plainText.Append(key_matrix[row1, col2]);
                    plainText.Append(key_matrix[row2, col1]);
                }
            }


            if (size > 0 && plainText[size - 1] == 'X')
            {
               size--;
            }


            StringBuilder finalPlainText = new StringBuilder();
            finalPlainText.Append(plainText[0]);

            for (int i = 1; i <= size-1; i++)
            {
                if (!(plainText[i] == 'X' && plainText[i - 1] == plainText[i + 1] && i%2!=0 ))
                {
                    finalPlainText.Append(plainText[i]);
                }
                
            }
            


            return finalPlainText.ToString();

        }

    
    

        public string Encrypt(string plainText, string key)
        {

            char[,] key_matrix = Generate_matrix(key);
            string preparedText = Prepare_Plain_Text(plainText);
            StringBuilder cipherText = new StringBuilder();

            for (int i = 0; i < preparedText.Length; i += 2)
            {
                char first = preparedText[i];
                char second = preparedText[i + 1];

                int[] position1 = FindPosition(key_matrix, first);
                int[] position2 = FindPosition(key_matrix, second);

                int row1 = position1[0], col1 = position1[1];
                int row2 = position2[0], col2 = position2[1];

                if (row1 == row2)
                {
                    cipherText.Append(key_matrix[row1, (col1 + 1) % 5]);
                    cipherText.Append(key_matrix[row2, (col2 + 1) % 5]);
                }
                else if (col1 == col2)
                {
                    cipherText.Append(key_matrix[(row1 + 1) % 5, col1]);
                    cipherText.Append(key_matrix[(row2 + 1) % 5, col2]);
                }
                else
                {
                    cipherText.Append(key_matrix[row1, col2]);
                    cipherText.Append(key_matrix[row2, col1]);
                }
            }

            return cipherText.ToString();


        }
        public char[,] Generate_matrix(string key)
        {
            char[,] key_matrix = new char[5, 5];
            string keyString = key.ToUpper().Replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string uniqueChars = new string(keyString.Distinct().ToArray());
            int index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    key_matrix[i, j] = uniqueChars[index];
                    index++;
                }
            }
            return key_matrix;
        }
        public string Prepare_Plain_Text(string plainText)
        {
            int size = plainText.Length;
            plainText = plainText.Replace(" ", "").ToUpper();

            plainText = plainText.Replace("J", "I");

             StringBuilder preparedText = new StringBuilder();
            for (int i = 0; i < size; i += 2)
            {
                if (i + 1 < size)
                {
                    if (plainText[i] == plainText[i + 1])
                    {
                        preparedText.Append(plainText[i]);
                        preparedText.Append('X');
                        i--;
                    }
                    else
                    {
                        preparedText.Append(plainText[i]);
                        preparedText.Append(plainText[i + 1]);
                    }
                }
                else
                {
                    preparedText.Append(plainText[i]);
                    preparedText.Append('X');
                }
            }

            return preparedText.ToString();
        }
        public int[] FindPosition(char[,] key_matrix, char letter)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (key_matrix[i, j] == letter)
                    {
                        return new int[] { i, j };
                    }
                }
            }

            return new int[] { -1, -1 }; 
        }




    }
}

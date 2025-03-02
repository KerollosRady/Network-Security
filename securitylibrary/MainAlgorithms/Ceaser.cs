using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            // Ensure the key is within the range of 0-25
            key = key % 26;
            char[] result = new char[plainText.Length];

            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsLetter(plainText[i]))
                {
                    char offset = char.IsUpper(plainText[i]) ? 'A' : 'a';
                    result[i] = (char)(((plainText[i] + key - offset + 26) % 26) + offset);
                }
                else
                {
                    result[i] = plainText[i]; // Non-alphabetic characters remain unchanged
                }
            }

            return new string(result).ToUpper(); // Ensure the result is in uppercase
        }

        public string Decrypt(string cipherText, int key)
        {
            // Decryption is just encryption with a negative key
            return Encrypt(cipherText, -key).ToLower(); // Ensure the result is in lowercase
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
            {
                throw new ArgumentException("Plain text and cipher text must be of the same length.");
            }

            // Calculate the key based on the first letter (assuming both texts are in the same case)
            int key = (cipherText.ToUpper()[0] - plainText.ToUpper()[0] + 26) % 26;
            return key;
        }
    }
}





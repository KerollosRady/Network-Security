# 🔐 Security Algorithms Package

This repository provides hands-on implementations of various **classical** and **modern** encryption/decryption algorithms, along with **analysis tools** to break certain ciphers using known plaintext-ciphertext pairs.

---

## Features

* Implementations of **symmetric** and **asymmetric** cryptographic algorithms
* **Key analysis modules** for classical ciphers using **known-plaintext attacks**
* Includes **test cases** for validating encryption, decryption, and key recovery logic
* Developed entirely in **C#**

---

## Implemented Algorithms

### 🔑 Classical Ciphers (with Key Analysis)

* `Caesar.cs` – Caesar Cipher

* `PlayFair.cs` – Playfair Cipher

* `AutokeyVigenere.cs` – Autokey Vigenère Cipher

* `RepeatingKeyVigenere.cs` – Repeating-Key Vigenère Cipher

* `HillCipher.cs` – Hill Cipher (supports 2×2 and 3×3 key matrices)

* `Monoalphabetic.cs` – Monoalphabetic Substitution Cipher

* `RailFence.cs` – Rail Fence Transposition Cipher

* `Columnar.cs` – Columnar Transposition Cipher


### 🔒 Modern Ciphers

* `DES.cs` – **Data Encryption Standard**
* `TripleDES.cs` – **Triple DES** (Encrypt-Decrypt-Encrypt variant)
* `AES.cs` – **Advanced Encryption Standard**
* `RSA.cs` – **RSA** public-key cryptosystem
* `DiffieHellman.cs` – **Diffie-Hellman** key exchange protocol
* `ElGamal.cs` – **ElGamal** probabilistic public-key encryption


### ⚙️ Supporting Algorithms

* `ExtendedEuclid.cs` – Computes **modular inverses** used in:

  * `RSA.cs`
  * `DiffieHellman.cs`

---

## 🧪 Testing

Each cipher includes **unit tests** to:

* Verify correctness of encryption and decryption
* Confirm successful key recovery (for classical ciphers)
* Provide usage examples for learning and experimentation

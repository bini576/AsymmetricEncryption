<div align="center">

# ðŸ”‘ RSA Asymmetric File Encryption
### Public-Key Cryptosystem for Secure File Encryption, Decryption & Key Management in Java

[![Java Version](https://img.shields.io/badge/Java-11%20%7C%2017%20%7C%2021-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Algorithm: RSA](https://img.shields.io/badge/Algorithm-RSA%202048%2F4096-00C7B7?style=for-the-badge&logo=shield)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
[![Security](https://img.shields.io/badge/Security-OAEP%20Padding-blue?style=for-the-badge)](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

---

## ðŸ“Œ Project Overview

**RSA Asymmetric File Encryption** is an enterprise-ready Java implementation of public-key cryptography. It provides a robust, standalone cryptographic engine capable of generating cryptographically sound asymmetric keypairs (2048-bit / 4096-bit), exporting keys in standardized formats, encrypting sensitive files with public keys, and securely decrypting ciphertext with private keys.

Developed by **Biniyam Ademasu Afework**, this project demonstrates both the theoretical mathematical mechanics of the RSA cryptosystem and practical implementation considerations such as OAEP padding, safe key serialization, and chunked file stream processing.

---

## âœ¨ Key Features

- **Configurable Asymmetric Key Generation:** Generate 2048-bit (standard) or 4096-bit (high security) RSA keypairs backed by Java's `SecureRandom` CSPRNG.
- **Standards-Compliant Key Export:** Exports Public keys using `X.509` encoding and Private keys using `PKCS#8` encoding.
- **CCA2-Secure Padding:** Employs **RSA/ECB/OAEPWithSHA-256AndMGF1Padding** to eliminate vulnerabilities associated with textbook RSA and PKCS#1 v1.5 padding oracle attacks.
- **Hybrid Streaming Architecture Support:** Processes files in cryptographic blocks to handle arbitrarily sized payloads safely without memory exhaustion.
- **Interactive Command-Line Interface:** Intuitive CLI options for key generation, file encryption, and file decryption.
- **Zero Third-Party Dependency:** Built purely using the standard Java Cryptography Architecture (`java.security` & `javax.crypto`).

---

## ðŸ“ Mathematical Foundations of RSA

```
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚    Generate Primes     â”‚
                    â”‚       p  and  q        â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                â”‚
                                â–¼
                       Compute Modulus:
                         n = p Ã— q
                     Totient: Ï†(n) = (p-1)(q-1)
                                â”‚
                                â–¼
                        Select Exponent e:
                    gcd(e, Ï†(n)) = 1,  1 < e < Ï†(n)
                                â”‚
                                â–¼
                    Compute Modular Inverse d:
                      e Ã— d â‰¡ 1 (mod Ï†(n))
                                â”‚
         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
         â–¼                                             â–¼
  [ Public Key: (e, n) ]                     [ Private Key: (d, n) ]
  Encryption: C â‰¡ M^e (mod n)               Decryption: M â‰¡ C^d (mod n)
```

1. **Trapdoor One-Way Function:** RSA security relies on the computational difficulty of the **Integer Factorization Problem**. Multiplying two large prime numbers $p$ and $q$ to produce $n$ is computationally trivial, but deducing $p$ and $q$ from $n$ alone is computationally intractable for sufficiently large keys (e.g., 2048+ bits).
2. **Padding Necessity:** Pure "textbook" RSA is deterministic ($M_1 = M_2 \implies C_1 = C_2$) and malleable ($E(M_1) \cdot E(M_2) = E(M_1 \cdot M_2)$). OAEP introduces randomized asymmetric padding to render ciphertext indistinguishable under chosen-ciphertext attack (IND-CCA2).

---

## ðŸš€ Installation & Compilation

### Prerequisites
- Java Development Kit (JDK) 11, 17, or 21+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/bini576/AsymmetricEncryption.git
cd AsymmetricEncryption
```

### 2. Compile the Source Code
```bash
# Compile with standard javac
javac -d bin src/*.java

# (Optional) Package into executable JAR:
jar cfe bin/rsa-tool.jar Main -C bin .
```

---

## ðŸ’» Usage Examples

### 1. Generate a New RSA Key Pair
```bash
java -cp bin Main --generate-keys --keysize 2048
```
*Output files generated:*
- `publicKey.pem` (Public key â€” share freely with senders)
- `privateKey.pem` (Private key â€” keep secret and secure)

### 2. Encrypt a File
```bash
java -cp bin Main --encrypt --input confidential.pdf --output confidential.pdf.enc --key publicKey.pem
```
*Result:* Creates `confidential.pdf.enc` which cannot be decrypted without the private key.

### 3. Decrypt the Encrypted File
```bash
java -cp bin Main --decrypt --input confidential.pdf.enc --output recovered.pdf --key privateKey.pem
```
*Result:* Reconstitutes the original `confidential.pdf` file with perfect integrity.

---

## ðŸ”’ Security Notes & Best Practices

| Concern | Assessment & Mitigation |
|:---|:---|
| **Key Size** | 2048-bit keys provide 112 bits of security (NIST approved through 2030). For extended security margins, 4096-bit keys are supported. |
| **Why not raw RSA?** | "Textbook RSA" ($C = M^e \pmod n$) is vulnerable to co-prime factoring, small exponent attacks, and homomorphic manipulation. Always use OAEP padding. |
| **File Size Constraints** | RSA is computationally expensive and mathematically limited to encrypting data smaller than key modulus size minus padding overhead. For gigabyte-scale datasets, use a **Hybrid Cryptosystem** (RSA encrypts a single random AES-256 session key; AES encrypts the bulk file data). |
| **Private Key Custody** | Private keys must be protected with filesystem access controls (`chmod 600`) or stored in encrypted keystores (PKCS#12). |

---

## ðŸ“„ License & Author

Distributed under the **MIT License**.

- **Author:** [Biniyam Ademasu Afework](https://github.com/bini576)
- **Degree:** B.Sc. Cyber Security, Bahir Dar University
- **GitHub:** [@bini576](https://github.com/bini576)
- **LinkedIn:** [linkedin.com/in/biniyam-ademasu](https://linkedin.com/in/biniyam-ademasu)
- **Email:** [admasubiniyam96@gmail.com](mailto:admasubiniyam96@gmail.com)

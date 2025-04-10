# DA352-Privacy-and-Info-Security-Course-Project

This project implements the **Diffie-Hellman key exchange** protocol using the [GMP (GNU Multi‑Precision)](https://gmplib.org/) library in C, along with **HKDF** for key derivation. It uses GMP and OpenSSL libraries in C/C++ on Windows under MSYS2.

## 📁 File Structure

| File                         | Description |
|------------------------------|-------------|
| `diffie-hellman.h`           | Header file containing declarations, macros, and global variables for key exchange. |
| `diffie-hellman.c`           | Implementation of the Diffie-Hellman protocol and key derivation logic. |
| `diffie-hellman-example.c`   | Example usage: generates key pairs, exchanges keys, and prints derived key. |
| `Makefile`                   | Build script for Windows (MinGW or compatible GCC) with `make`. |

---

## 🧠 Mathematical Background

The **Diffie-Hellman (DH)** key exchange is a cryptographic protocol that allows two parties (e.g., Alice and Bob) to establish a **shared secret** over a public channel, without ever transmitting the secret directly.

### 📌 Parameters

Let the following be public:

- **p**: a large prime such that `p = 2q + 1`, where `q` is also a prime.
- **q**: a large prime factor of `p − 1`, typically 256 bits.
- **g**: a generator of the cyclic subgroup of order `q` in `ℤ_p*`.

These values are either:
- Loaded from a file using `init("dhparams.txt")`, or
- Generated from scratch using `initFromScratch(qBits, pBits)` (slow, used once).

### 🔐 Key Generation

Each party generates:
- A private key `a ∈ [1, q−1]` (chosen randomly)
- A public key `A = g^a mod p`

In code (for Alice):
```c
dhGen(a, A);  // Generates private key a and public key A = g^a mod p
```

### 🔁 Shared Secret Computation

After public keys are exchanged:
- Alice computes `S = B^a mod p`
- Bob computes `S = A^b mod p`

Since:
```
A = g^a mod p
B = g^b mod p
```
Both compute:
```
S = g^(ab) mod p
```

So the shared secret `S` is identical for both.

### 🔑 Key Derivation using HKDF

The raw shared secret `S` is not used directly as a key. Instead, it's processed using **HKDF** (HMAC-based Key Derivation Function) with **HMAC-SHA256** to produce a cryptographically strong, fixed-length key suitable for symmetric encryption.

In code:
```c
dhFinal(a, A, B, kA, klen);  // Alice's derived key
dhFinal(b, B, A, kB, klen);  // Bob's derived key
```

This ensures the derived key has high entropy and is secure for further cryptographic use.


---
## ⚙️ How to Build and Run (on Windows using MSYS2)

### 🧰 Step 1: Install MSYS2

Download and install MSYS2 from: https://www.msys2.org/

### 🧪 Step 2: Open MSYS2 terminal (MinGW 64-bit)

Launch **`MSYS2 MinGW 64-bit`** from the Start menu. This is important to get access to the correct compiler and libraries.

### 🔄 Step 3: Update MSYS2 and package database

```bash
pacman -Syu
```

> 🔁 If prompted to restart the terminal after core update, do so.

Then complete the update:

```bash
pacman -Su
```

### 📦 Step 4: Install required libraries and build tools

```bash
pacman -S \
  mingw-w64-x86_64-toolchain \
  mingw-w64-x86_64-gmp \
  mingw-w64-x86_64-openssl
```

This installs:
- GCC toolchain (`gcc`, `make`)
- GMP library (`-lgmp`)
- OpenSSL (`-lssl`, `-lcrypto`, `-lbcrypt`)

### 📥 Step 5: Clone the repository

```bash
git clone https://github.com/<your-username>/DA352-Privacy-and-Info-Security-Course-Project.git
cd DA352-Privacy-and-Info-Security-Course-Project
```

### 📂 Step 6: Navigate to your project directory

```bash
cd /c/Users/<your-username>/path/to/DA352-Privacy-and-Info-Security-Course-Project
```

### 🛠️ Step 7: Build the project

```bash
make
```

### 🚀 Step 8: Run the program

```bash
./diffie-hellman.exe
```

### 🧹 Step 9: Clean the build (optional)

```bash
make clean
```

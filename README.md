


# DA352 Privacy and Information Security Course Project

A secure, cross-platform chat application demonstrating **Diffie-Hellman key exchange** and **HKDF-based symmetric key derivation** using C/C++ (GMP and OpenSSL). This project is designed for educational purposes, showcasing how two parties can establish a shared secret and communicate securely over an insecure network.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Mathematical Foundations](#mathematical-foundations)
- [Features](#features)
- [File Structure](#file-structure)
- [Build Instructions](#build-instructions)
- [Command-Line Usage](#command-line-usage)
- [Usage Examples](#usage-examples)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [References](#references)

---

## Project Overview

This project implements a secure chat system using the Diffie-Hellman (DH) key exchange protocol for establishing a shared secret, and HKDF (HMAC-based Key Derivation Function) for deriving a strong symmetric key. The derived key is then used to encrypt and decrypt chat messages between a server and a client.

---

## Mathematical Foundations

# 🔐 Diffie-Hellman Key Exchange with HKDF

This project demonstrates a basic implementation of the **Diffie-Hellman Key Exchange** protocol, combined with **HKDF** (HMAC-based Key Derivation Function) using HMAC-SHA256 to derive a strong symmetric key from the shared secret.

---

## 📘 1. Diffie-Hellman Key Exchange

# 🔐 Diffie-Hellman Key Exchange with HKDF

This project demonstrates a basic implementation of the **Diffie-Hellman Key Exchange** protocol, combined with **HKDF** (HMAC-based Key Derivation Function) using HMAC-SHA256 to derive a strong symmetric key from the shared secret.

---

## 📘 1. Diffie-Hellman Key Exchange

The DH protocol allows two parties to securely agree on a shared secret over an insecure channel. Its security relies on the hardness of the **Discrete Logarithm Problem**.

### 🔧 Parameters

- **Safe prime `p`**: A large prime number (usually ≥ 2048 bits)
- **Prime `q`**: Such that `p = 2q + 1`
- **Generator `g`**: Generator of a subgroup of order `q` in `Z_p*`

### 🔐 Key Generation

Each party:

- Chooses a private key `a` (or `b`), where `1 ≤ a < q`
- Computes the public key:

  ```
  A = g^a mod p
  B = g^b mod p
  ```

### 🔁 Shared Secret

After exchanging public keys:

- Both compute the same shared secret:

  ```
  S = B^a mod p = A^b mod p = g^(ab) mod p
  ```

---

## 🔑 2. HKDF (HMAC-based Key Derivation Function)

The raw shared secret `S` is passed through HKDF using `HMAC-SHA256` to derive a cryptographically strong symmetric key.

### ✂️ Extract

```
PRK = HMAC(salt, S)
```

### ➕ Expand

```
OKM = HMAC(PRK, info || counter)
```





## Features

- **Secure Key Exchange:** Uses DH with safe primes and secure random number generation.
- **Key Derivation:** HKDF with HMAC-SHA256 for strong symmetric keys.
- **Encrypted Chat:** All messages are encrypted using the derived key.
- **Cross-Platform:** Designed for Windows (MSYS2/MinGW), easily portable to Linux.
- **Simple CLI:** Start as server or client with easy command-line options.

---

## File Structure

| File | Description |
| :-- | :-- |
| `diffie-hellman.h` | DH and HKDF function declarations |
| `diffie-hellman.c` | DH and HKDF implementation |
| `diffie-hellman-example.c` | Example/test for DH key exchange |
| `chat.c` / `chat.cpp` | Main chat application (server/client) |
| `Makefile` | Build script for MSYS2/MinGW |

---

## Build Instructions

### Prerequisites

- **MSYS2/MinGW (Windows):** [Install MSYS2](https://www.msys2.org/)
- **GMP and OpenSSL:** Install via MSYS2 terminal:

```bash
pacman -S mingw-w64-x86_64-gmp mingw-w64-x86_64-openssl
```


### Build Steps

```bash
# Clone the repository
git clone https://github.com/raunitpatel/DA352-Privacy-and-Info-Security-Course-Project.git
cd DA352-Privacy-and-Info-Security-Course-Project

# Build the project
make
```

This will produce `chat.exe` and `diffie-hellman.exe` in the project directory.

---

## Command-Line Usage

The application supports the following arguments:


| Long Option | Short Flag | Argument | Description |
| :-- | :-- | :-- | :-- |
| `--connect` | `-c` | `&lt;SERVER_IP&gt;` | Connect as client to the specified IP |
| `--listen` | `-l` | None | Start in server/listen mode |
| `--port` | `-p` | `&lt;PORT&gt;` | Port number (required for both modes) |
| `--help` | `-h` | None | Show help message |

### Usage Patterns

```bash
# Start the server (listening mode)
./chat.exe --listen --port &lt;PORT&gt;
# or using short flags
./chat.exe -l -p &lt;PORT&gt;

# Start the client (connect to server)
./chat.exe --connect &lt;SERVER_IP&gt; --port &lt;PORT&gt;
# or using short flags
./chat.exe -c &lt;SERVER_IP&gt; -p &lt;PORT&gt;

# Display help
./chat.exe --help
# or
./chat.exe -h
```

---

## Usage Examples

### 1. Start a Server on Port 1337

```bash
./chat.exe -l -p 1337
```

**Output:**

```
[SERVER] Listening on 0.0.0.0:1337
[DH] Parameters initialized. Waiting for client...
```


### 2. Connect as a Client to `192.168.1.100:1337`

```bash
./chat.exe -c 192.168.1.100 -p 1337
```

**Output:**

```
[CLIENT] Connecting to 192.168.1.100:1337...
[DH] Shared secret derived. Secure channel ready.
&gt; 
```


### 3. Show Help

```bash
./chat.exe -h
```

**Output:**

```
Usage: chat.exe [OPTIONS]
Options:
  -c, --connect &lt;IP&gt;  Connect to server at specified IP
  -l, --listen        Start in server mode
  -p, --port &lt;PORT&gt;   Port number (required)
  -h, --help          Show this help
```


### 4. Chatting

- After connection, both sides perform DH key exchange and derive a shared AES-256 key.
- All messages are encrypted and decrypted automatically.
- Type messages and press Enter to send.
- Use `/exit` to leave the chat.

---

## Security Notes

- **Private keys** are never transmitted; only public keys are exchanged.
- **Ephemeral keys**: Each session uses fresh keys for forward secrecy.
- **HKDF** ensures the derived key is suitable for symmetric encryption.
- **No authentication**: This demo does not prevent man-in-the-middle attacks. For real-world use, add authentication (e.g., digital signatures or certificates).

---

## Troubleshooting

- **Port already in use:** Use a different port or close other applications using the port.
- **Firewall issues:** Allow `chat.exe` through your firewall.
- **OpenSSL errors:** Ensure `libcrypto-3-x64.dll` is in your PATH (Windows).
- **GMP errors:** Ensure `libgmp-10.dll` is in your PATH (Windows).
- **Missing arguments:** Run `./chat.exe -h` for usage instructions.

---

## References

- [Diffie-Hellman Key Exchange (Wikipedia)](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [GMP Library](https://gmplib.org/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [MSYS2 Project](https://www.msys2.org/)



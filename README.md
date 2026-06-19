# 🔐 Cryptography Algorithms Implementation

**Project 6 — Cybersecurity Internship | Codec Technologies**

A hands-on implementation of the three pillars of modern cryptography: **AES**, **RSA**, and **SHA**, built entirely in Python with detailed explanations of every algorithm.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Algorithms Implemented](#algorithms-implemented)
  - [AES — Symmetric Encryption](#1-aes--advanced-encryption-standard)
  - [RSA — Asymmetric Encryption](#2-rsa--rivesthameradleman)
  - [SHA — Secure Hashing](#3-sha--secure-hash-algorithms)
- [Installation](#installation)
- [Running the Demo](#running-the-demo)
- [Running Tests](#running-tests)
- [Step-by-Step Explanation](#step-by-step-explanation)
- [Real-World Use Cases](#real-world-use-cases)
- [Security Best Practices](#security-best-practices)
- [Skills Learned](#skills-learned)

---

## Overview

This project implements and demonstrates the three most important cryptographic primitives used in modern security:

| Algorithm | Type | Purpose | Key Size |
|-----------|------|---------|----------|
| AES-256 | Symmetric | Encrypt/decrypt bulk data | 256 bits |
| RSA-2048 | Asymmetric | Key exchange, digital signatures | 2048 bits |
| SHA-256/512 | Hash Function | Integrity verification, password storage | N/A (output only) |

Each algorithm is implemented from the cryptographic library level (not from scratch, which would be insecure) and demonstrated with clear educational output showing exactly what each step does.

---

## Project Structure

```
crypto_project/
├── src/
│   ├── aes_cipher.py     # AES-CBC and AES-GCM encryption
│   ├── rsa_cipher.py     # RSA encryption, decryption, digital signatures
│   ├── sha_hash.py       # SHA-256/512/SHA-3, HMAC, PBKDF2 password hashing
│   └── main.py           # Interactive demo of all algorithms
├── tests/
│   └── test_crypto.py    # 26 unit tests covering all modules
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

---

## Algorithms Implemented

### 1. AES — Advanced Encryption Standard

**File:** `src/aes_cipher.py`

AES is a **symmetric block cipher** — the same key is used for both encryption and decryption. It operates on 128-bit blocks and supports key sizes of 128, 192, or 256 bits.

#### How AES Works (Simplified)

```
Plaintext Block (128 bits)
         │
    ┌────▼────┐
    │ AddKey  │  ← XOR with round key
    └────┬────┘
         │  ×10 rounds (for AES-256: ×14)
    ┌────▼─────────────────────┐
    │  SubBytes → ShiftRows   │
    │  MixColumns → AddKey    │
    └────┬─────────────────────┘
         │
    Ciphertext Block (128 bits)
```

#### Modes Implemented

**AES-CBC (Cipher Block Chaining)**
```
IV ──→ XOR ──→ AES_Encrypt ──→ Ciphertext Block 1
               ↑                       │
          Plaintext 1                  ▼
                              XOR ──→ AES_Encrypt ──→ Ciphertext Block 2
                              ↑
                         Plaintext 2
```
- Each block is XORed with the previous ciphertext block before encryption
- Requires a random **IV** (Initialization Vector) — never reuse it!
- Same plaintext → different ciphertext every time (due to random IV)

**AES-GCM (Galois/Counter Mode)**
- Provides **Authenticated Encryption** — combines encryption WITH integrity check
- Produces a 16-byte **authentication tag** alongside the ciphertext
- Any tampering with the ciphertext is detected immediately
- Supports **Additional Authenticated Data (AAD)** — metadata that's authenticated but not encrypted

#### Usage Example

```python
from src.aes_cipher import AESCipher

# Create cipher with 256-bit key
aes = AESCipher(key_size=256)

# CBC mode
result = aes.encrypt_cbc("Hello, World!")
plaintext = aes.decrypt_cbc(result["iv"], result["ciphertext"])

# GCM mode (with authentication)
result = aes.encrypt_gcm("Secret data", aad=b"user_id=42")
plaintext = aes.decrypt_gcm(result["nonce"], result["ciphertext"],
                             result["tag"], aad=b"user_id=42")
```

---

### 2. RSA — Rivest–Shamir–Adleman

**File:** `src/rsa_cipher.py`

RSA is an **asymmetric encryption algorithm** — uses two mathematically linked keys:
- **Public Key**: Share with anyone → used to ENCRYPT
- **Private Key**: Keep secret → used to DECRYPT

#### How RSA Works (Mathematical Foundation)

```
Key Generation:
  1. Choose two large primes: p, q
  2. n = p × q  (modulus — public)
  3. φ(n) = (p-1)(q-1)
  4. Choose e such that gcd(e, φ(n)) = 1  (public exponent)
  5. d = e⁻¹ mod φ(n)  (private exponent)

Encryption:  C = M^e mod n
Decryption:  M = C^d mod n
```

Security relies on the **integer factorization problem**: given `n`, it's computationally infeasible to find `p` and `q` for large enough `n`.

#### Features Implemented

| Feature | How it works |
|---------|-------------|
| **Encryption** | PKCS1-OAEP padding + public key |
| **Decryption** | Private key |
| **Digital Signatures** | SHA-256 hash signed with private key, verified with public key |
| **Hybrid Encryption** | RSA encrypts AES key → AES encrypts data |
| **Key Export/Import** | PEM format (industry standard) |

#### Why Hybrid Encryption?

RSA can only encrypt data smaller than its key size (~190 bytes for 2048-bit).  
For larger data, we use **Hybrid Encryption**:

```
Large File
    │
    ▼
AES-GCM Encrypt ──── random AES key ──→ RSA Encrypt ──→ Encrypted AES Key
    │
    ▼
Encrypted File

= Send both Encrypted File + Encrypted AES Key
```

#### Usage Example

```python
from src.rsa_cipher import RSACipher

rsa = RSACipher(key_size=2048)

# Encrypt / Decrypt
ciphertext = rsa.encrypt("Secret message")
plaintext = rsa.decrypt(ciphertext)

# Digital Signature
signature = rsa.sign("Document text")
is_valid = rsa.verify("Document text", signature)  # True
is_valid = rsa.verify("Tampered text", signature)  # False

# Hybrid encryption for large data
package = rsa.hybrid_encrypt("Very long text..." * 100)
recovered = rsa.hybrid_decrypt(package)
```

---

### 3. SHA — Secure Hash Algorithms

**File:** `src/sha_hash.py`

A **hash function** converts any input into a fixed-size fingerprint. It is **one-way** — you cannot reverse a hash to get the original input.

#### Hash Algorithm Comparison

| Algorithm | Output Size | Status | Notes |
|-----------|------------|--------|-------|
| SHA-1 | 160 bits | ⚠️ DEPRECATED | Collision attacks found (2017) |
| SHA-256 | 256 bits | ✅ Secure | Most widely used, part of SHA-2 family |
| SHA-512 | 512 bits | ✅ Secure | Better for 64-bit systems |
| SHA3-256 | 256 bits | ✅ Secure | Keccak algorithm, different structure from SHA-2 |
| SHA3-512 | 512 bits | ✅ Secure | Most secure, resists length-extension attacks |

#### Avalanche Effect

Change just ONE character → completely different hash:

```
SHA-256("Hello") = 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
SHA-256("Hellp") = 2113cd4a7aebc3a400a234c3de8a5c0c4d9fa8c6ca370d030aac9ab51e8c4476
                   ^^^^ completely different — ~49.6% of bits changed
```

#### HMAC — Keyed Hashing

Regular hashing proves integrity but not **authenticity** — anyone can compute a hash.  
HMAC adds a **secret key**:

```
HMAC(message, secret_key) = Hash(key ⊕ opad || Hash(key ⊕ ipad || message))
```

Used in: JWT tokens, webhook signatures, API authentication.

#### PBKDF2 — Secure Password Hashing

**Why not just SHA-256 for passwords?**
- Attackers precompute millions of hashes (rainbow tables)
- Passwords are short → small search space

**PBKDF2 solution:**
```
PBKDF2(password, salt, iterations) → stored_hash

Where:
  salt      = 256 random bits (unique per password)
  iterations = 100,000+ (makes brute force ~100,000× slower)
```

#### Usage Example

```python
from src.sha_hash import SHAHasher

# Basic hashing
digest = SHAHasher.hash_sha256("Hello, World!")

# Compare all algorithms
results = SHAHasher.compare_all("my data")

# HMAC
mac = SHAHasher.hmac_sha256("message", "secret_key")
is_valid = SHAHasher.verify_hmac("message", "secret_key", mac)

# Password hashing
stored = SHAHasher.hash_password("MyPassword123!")
# Later, verify:
ok = SHAHasher.verify_password("MyPassword123!", stored["salt"],
                                stored["hash"], stored["iterations"])

# File integrity
file_hash = SHAHasher.hash_file("/path/to/file.zip")
```

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/cryptography-implementation.git
cd cryptography-implementation

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pycryptodome` | ≥3.20 | AES, RSA, SHA, HMAC, PBKDF2 implementation |
| `pytest` | ≥7.0 | Unit testing framework |

---

## Running the Demo

```bash
cd src
python main.py
```

**Expected output sections:**
1. **AES Demo** — Encrypts/decrypts a message in CBC and GCM modes, demonstrates tamper detection
2. **RSA Demo** — Key generation, encrypt/decrypt, digital signatures, hybrid encryption
3. **SHA Demo** — All hash algorithms compared, avalanche effect, HMAC, password hashing

---

## Running Tests

```bash
# Run all 26 tests
python -m pytest tests/ -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/ --cov=src --cov-report=term-missing
```

### Test Coverage

| Module | Tests | What's Tested |
|--------|-------|--------------|
| `aes_cipher.py` | 8 | CBC encrypt/decrypt, GCM encrypt/decrypt, tamper detection, unicode, empty string |
| `rsa_cipher.py` | 6 | Encrypt/decrypt, signatures, tamper rejection, hybrid encryption, key export/import |
| `sha_hash.py` | 12 | All hash functions, determinism, avalanche, HMAC, password hash/verify, unique salts |

---

## Step-by-Step Explanation

### Step 1: Setting Up the Environment
Install `pycryptodome` — a self-contained cryptographic library that provides hardware-accelerated implementations of AES, RSA, and SHA algorithms.

### Step 2: AES Implementation (`aes_cipher.py`)
1. Generate a cryptographically random 256-bit key using `get_random_bytes(32)`
2. For **CBC mode**: generate random 16-byte IV, apply PKCS7 padding, encrypt
3. For **GCM mode**: generate random 12-byte nonce, encrypt, produce 16-byte auth tag
4. Decryption reverses the process; GCM also verifies the tag before decrypting

### Step 3: RSA Implementation (`rsa_cipher.py`)
1. Generate a 2048-bit RSA key pair using `RSA.generate(2048)` (uses OS entropy)
2. **Encryption**: wrap plaintext with OAEP padding, encrypt with public key
3. **Decryption**: decrypt with private key, strip padding
4. **Signing**: hash message with SHA-256, sign hash with private key using PSS padding
5. **Verification**: re-hash message, verify signature matches using public key
6. **Hybrid encryption**: generate AES key → encrypt data with AES → encrypt AES key with RSA

### Step 4: SHA Implementation (`sha_hash.py`)
1. **Basic hashing**: feed data into SHA object, call `.hexdigest()` for hex output
2. **HMAC**: uses HMAC construction `H(key ⊕ opad || H(key ⊕ ipad || message))`
3. **PBKDF2**: applies HMAC-SHA256 repeatedly (100k iterations) with a random 256-bit salt
4. **Constant-time comparison**: use `hmac.compare_digest()` to prevent timing attacks

### Step 5: Testing
Each function is unit-tested for:
- Correct encryption/decryption roundtrip
- Randomness (same input → different output due to IV/nonce/salt)
- Error cases (tampered ciphertext, wrong passwords, wrong keys)
- Edge cases (empty string, unicode, very long messages)

---

## Real-World Use Cases

| What you built | Where it's used in production |
|---------------|------------------------------|
| AES-GCM | HTTPS (TLS 1.3), file encryption, Signal messenger |
| RSA encryption | SSH key exchange, S/MIME email encryption |
| RSA signatures | Code signing, SSL certificates, JWT (RS256) |
| SHA-256 | Bitcoin mining, Git commit hashes, file checksums |
| HMAC | JWT tokens (HS256), webhook security, API signing |
| PBKDF2 | Django's default password hasher, WPA2 Wi-Fi passwords |
| Hybrid RSA+AES | PGP email encryption, TLS handshake |

---

## Security Best Practices

This project follows industry-standard security practices:

- ✅ **Never use ECB mode** — blocks encrypt independently, reveals patterns
- ✅ **Random IV/nonce every time** — prevents ciphertext analysis
- ✅ **OAEP padding for RSA** — prevents chosen-ciphertext attacks  
- ✅ **PSS padding for RSA signatures** — more secure than PKCS1v15
- ✅ **Authenticated encryption (GCM)** — detects tampering
- ✅ **Salt passwords** — defeats rainbow table attacks
- ✅ **Key stretching (PBKDF2)** — slows brute-force attacks
- ✅ **Constant-time comparison** — prevents timing side-channel attacks
- ✅ **Never implement crypto from scratch** — use audited libraries

---

## Skills Learned

- **Cryptography Fundamentals**: symmetric vs asymmetric encryption, block ciphers, stream ciphers
- **AES**: CBC/GCM modes, padding schemes, IV/nonce management, authenticated encryption
- **RSA**: key generation, OAEP encryption, PSS signatures, hybrid encryption
- **Hashing**: SHA-2 vs SHA-3 families, avalanche effect, collision resistance
- **HMAC**: message authentication codes, key stretching
- **Secure Coding**: constant-time comparison, proper randomness, error handling
- **Python**: `pycryptodome` library, `base64` encoding, `pytest` testing

---

## Author

**Cybersecurity Internship Project**  
Codec technologies
made by milan nai

---

## License

This project is for educational purposes as part of a cybersecurity internship program.

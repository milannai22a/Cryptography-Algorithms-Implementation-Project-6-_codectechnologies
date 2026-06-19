"""
SHA (Secure Hash Algorithm) Implementation
==========================================
SHA produces a fixed-size "digest" (fingerprint) of any input.

Properties of a good hash function:
  - Deterministic: same input → same output always
  - One-way: cannot reverse the hash to get original input
  - Avalanche effect: small change in input → completely different hash
  - Collision resistant: near impossible to find two inputs with same hash

Algorithms implemented:
  - SHA-1   (160-bit) — DEPRECATED, shown for educational purposes only
  - SHA-256 (256-bit) — Standard, widely used
  - SHA-512 (512-bit) — High security
  - SHA-3   (256/512-bit) — Newest standard (Keccak algorithm)

Also includes:
  - HMAC (Hash-based Message Authentication Code)
  - Password hashing with PBKDF2 (salted, iterated)
"""

import os
import hmac
import hashlib
import base64
import secrets
from Crypto.Hash import SHA256, SHA512, SHA3_256, SHA3_512, HMAC as CryptoHMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


class SHAHasher:
    """Collection of SHA hashing utilities."""

    # ── Basic Hashing ─────────────────────────────────────────────────────────

    @staticmethod
    def hash_sha1(data: str) -> str:
        """
        SHA-1 hash (DEPRECATED — for educational comparison only).
        Produces 160-bit (40 hex chars) digest. NOT for security use.
        """
        return hashlib.sha1(data.encode()).hexdigest()

    @staticmethod
    def hash_sha256(data: str) -> str:
        """
        SHA-256 hash — most common secure hash.
        Produces 256-bit (64 hex chars) digest.
        """
        h = SHA256.new()
        h.update(data.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def hash_sha512(data: str) -> str:
        """
        SHA-512 hash — higher security.
        Produces 512-bit (128 hex chars) digest.
        """
        h = SHA512.new()
        h.update(data.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def hash_sha3_256(data: str) -> str:
        """
        SHA-3 (256-bit) — Next-generation hash (Keccak).
        Structurally different from SHA-2, resistant to length extension attacks.
        """
        h = SHA3_256.new()
        h.update(data.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def hash_sha3_512(data: str) -> str:
        """SHA-3 (512-bit) variant."""
        h = SHA3_512.new()
        h.update(data.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def compare_all(data: str) -> dict:
        """
        Run all hash algorithms on the same input and compare.
        Shows the avalanche effect and output length differences.
        """
        return {
            "input": data,
            "SHA-1 (DEPRECATED)": {
                "digest": SHAHasher.hash_sha1(data),
                "bits": 160,
                "secure": False,
            },
            "SHA-256": {
                "digest": SHAHasher.hash_sha256(data),
                "bits": 256,
                "secure": True,
            },
            "SHA-512": {
                "digest": SHAHasher.hash_sha512(data),
                "bits": 512,
                "secure": True,
            },
            "SHA3-256": {
                "digest": SHAHasher.hash_sha3_256(data),
                "bits": 256,
                "secure": True,
            },
            "SHA3-512": {
                "digest": SHAHasher.hash_sha3_512(data),
                "bits": 512,
                "secure": True,
            },
        }

    # ── HMAC ──────────────────────────────────────────────────────────────────

    @staticmethod
    def hmac_sha256(message: str, secret_key: str) -> str:
        """
        HMAC-SHA256 — Keyed hash for message authentication.

        Unlike a plain hash, HMAC requires a secret key. It proves both:
          1. Data integrity (not tampered)
          2. Authenticity (came from key holder)

        Used in: JWT tokens, API request signing, webhook verification.

        Returns:
            Hex-encoded HMAC digest
        """
        h = CryptoHMAC.new(secret_key.encode('utf-8'), digestmod=SHA256)
        h.update(message.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def verify_hmac(message: str, secret_key: str, expected_hmac: str) -> bool:
        """Verify an HMAC in constant time (prevents timing attacks)."""
        computed = SHAHasher.hmac_sha256(message, secret_key)
        return hmac.compare_digest(computed, expected_hmac)

    # ── Password Hashing ──────────────────────────────────────────────────────

    @staticmethod
    def hash_password(password: str, iterations: int = 200_000) -> dict:
        """
        Securely hash a password using PBKDF2-HMAC-SHA256.

        Why not plain SHA-256 for passwords?
          - Passwords are short and predictable → attackers use rainbow tables
          - PBKDF2 adds: (1) random SALT, (2) many iterations → slows brute force

        Args:
            password: The user's password
            iterations: Number of hash iterations (higher = slower = more secure)

        Returns:
            dict with salt and hash (store BOTH in database)
        """
        salt = get_random_bytes(32)  # 256-bit random salt
        dk = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=32,
            count=iterations,
            prf=lambda p, s: CryptoHMAC.new(p, s, SHA256).digest()
        )
        return {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode(),
            "hash": base64.b64encode(dk).decode(),
        }

    @staticmethod
    def verify_password(password: str, stored_salt_b64: str,
                        stored_hash_b64: str, iterations: int = 200_000) -> bool:
        """
        Verify a password against a stored PBKDF2 hash.

        Args:
            password: Password to check
            stored_salt_b64: Salt from hash_password()
            stored_hash_b64: Hash from hash_password()
            iterations: Must match what was used to create the hash

        Returns:
            True if password matches
        """
        salt = base64.b64decode(stored_salt_b64)
        stored_hash = base64.b64decode(stored_hash_b64)
        dk = PBKDF2(
            password.encode('utf-8'),
            salt,
            dkLen=32,
            count=iterations,
            prf=lambda p, s: CryptoHMAC.new(p, s, SHA256).digest()
        )
        return hmac.compare_digest(dk, stored_hash)

    # ── File Integrity ────────────────────────────────────────────────────────

    @staticmethod
    def hash_file(filepath: str, algorithm: str = "sha256") -> str:
        """
        Compute hash of a file for integrity verification.

        Used to verify downloads, detect file tampering, malware analysis.

        Args:
            filepath: Path to the file
            algorithm: 'sha256', 'sha512', or 'sha3_256'

        Returns:
            Hex digest of file contents
        """
        h = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def demonstrate_avalanche(base_text: str) -> dict:
        """
        Demonstrate the avalanche effect: changing 1 character → totally different hash.

        This shows SHA-256's sensitivity to input changes.
        """
        text1 = base_text
        text2 = base_text[:-1] + chr(ord(base_text[-1]) + 1) if base_text else "B"

        hash1 = SHAHasher.hash_sha256(text1)
        hash2 = SHAHasher.hash_sha256(text2)

        # Count differing bits
        int1 = int(hash1, 16)
        int2 = int(hash2, 16)
        diff_bits = bin(int1 ^ int2).count('1')

        return {
            "input_1": text1,
            "input_2": text2,
            "hash_1": hash1,
            "hash_2": hash2,
            "bits_different": diff_bits,
            "total_bits": 256,
            "percent_changed": f"{diff_bits/256*100:.1f}%",
        }

"""
AES (Advanced Encryption Standard) Implementation
=================================================
AES is a symmetric block cipher that encrypts data in 128-bit blocks
using keys of 128, 192, or 256 bits.

Modes implemented:
- AES-CBC (Cipher Block Chaining) — most common secure mode
- AES-GCM (Galois/Counter Mode) — authenticated encryption
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class AESCipher:
    """
    AES Symmetric Encryption/Decryption

    Supports:
      - CBC mode (with PKCS7 padding)
      - GCM mode (with authentication tag — detects tampering)
    """

    def __init__(self, key_size: int = 256):
        """
        Initialize AES cipher with a random key.

        Args:
            key_size: Key length in bits. Must be 128, 192, or 256.
        """
        if key_size not in (128, 192, 256):
            raise ValueError("AES key size must be 128, 192, or 256 bits.")
        self.key_size = key_size
        self.key = get_random_bytes(key_size // 8)
        print(f"[AES] Generated {key_size}-bit key: {self.key.hex()}")

    def set_key(self, key_hex: str):
        """Load an existing key from hex string."""
        self.key = bytes.fromhex(key_hex)
        self.key_size = len(self.key) * 8

    # ── CBC Mode ──────────────────────────────────────────────────────────────

    def encrypt_cbc(self, plaintext: str) -> dict:
        """
        Encrypt plaintext using AES-CBC.

        CBC XORs each plaintext block with the previous ciphertext block
        before encryption, making identical blocks produce different output.

        Returns:
            dict with 'iv' and 'ciphertext' (both base64-encoded)
        """
        iv = get_random_bytes(AES.block_size)          # 16-byte random IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded)

        return {
            "mode": "AES-CBC",
            "key_size": self.key_size,
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

    def decrypt_cbc(self, iv_b64: str, ciphertext_b64: str) -> str:
        """
        Decrypt AES-CBC ciphertext.

        Args:
            iv_b64: Base64-encoded IV (must match what was used to encrypt)
            ciphertext_b64: Base64-encoded ciphertext

        Returns:
            Decrypted plaintext string
        """
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        return unpad(padded, AES.block_size).decode('utf-8')

    # ── GCM Mode ──────────────────────────────────────────────────────────────

    def encrypt_gcm(self, plaintext: str, aad: bytes = b"") -> dict:
        """
        Encrypt using AES-GCM (authenticated encryption).

        GCM provides both confidentiality AND integrity — it produces a
        16-byte authentication tag that verifies the ciphertext wasn't
        tampered with during transit.

        Args:
            plaintext: Text to encrypt
            aad: Additional Authenticated Data (not encrypted, but authenticated)

        Returns:
            dict with nonce, ciphertext, and tag (all base64-encoded)
        """
        cipher = AES.new(self.key, AES.MODE_GCM)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        return {
            "mode": "AES-GCM",
            "key_size": self.key_size,
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
            "aad": aad.decode() if aad else None,
        }

    def decrypt_gcm(self, nonce_b64: str, ciphertext_b64: str,
                    tag_b64: str, aad: bytes = b"") -> str:
        """
        Decrypt AES-GCM ciphertext and verify authentication tag.

        Raises ValueError if the tag doesn't match (data tampered).
        """
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except ValueError:
            raise ValueError("[AES-GCM] Authentication FAILED — data may have been tampered!")

"""
RSA (Rivest–Shamir–Adleman) Implementation
==========================================
RSA is an asymmetric encryption algorithm that uses a PUBLIC key for
encryption and a PRIVATE key for decryption.

It is based on the mathematical difficulty of factoring the product of
two large prime numbers.

Key sizes: 1024 (legacy), 2048 (standard), 4096 (high security)

Use cases:
  - Encrypting small amounts of data (e.g., symmetric keys)
  - Digital signatures (sign with private key, verify with public key)
  - Key exchange protocols
"""

import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


class RSACipher:
    """
    RSA Asymmetric Encryption, Decryption, and Digital Signatures

    Key pair is generated on instantiation. You can also load existing keys.
    """

    def __init__(self, key_size: int = 2048):
        """
        Generate a new RSA key pair.

        Args:
            key_size: Bit length of the RSA key (2048 recommended minimum).
        """
        if key_size < 1024:
            raise ValueError("RSA key size should be at least 1024 bits (2048 recommended).")
        print(f"[RSA] Generating {key_size}-bit key pair... (this may take a moment)")
        self.private_key = RSA.generate(key_size)
        self.public_key = self.private_key.publickey()
        print(f"[RSA] Key pair generated. Key size: {key_size} bits")

    # ── Key Export / Import ───────────────────────────────────────────────────

    def export_keys(self) -> dict:
        """Export keys in PEM format (industry standard)."""
        return {
            "private_key_pem": self.private_key.export_key().decode(),
            "public_key_pem": self.public_key.export_key().decode(),
        }

    def load_private_key(self, pem: str):
        """Load private key from PEM string."""
        self.private_key = RSA.import_key(pem)
        self.public_key = self.private_key.publickey()

    def load_public_key(self, pem: str):
        """Load public key from PEM string (for encryption only)."""
        self.public_key = RSA.import_key(pem)

    # ── Encryption / Decryption ───────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext with the RSA PUBLIC key (OAEP padding).

        PKCS1-OAEP (Optimal Asymmetric Encryption Padding) adds randomness
        to prevent deterministic encryption attacks.

        Note: RSA can only encrypt data smaller than the key size minus padding
        overhead (~190 bytes for 2048-bit key). For larger data, use RSA to
        encrypt an AES key, then AES to encrypt the data (hybrid encryption).

        Returns:
            Base64-encoded ciphertext
        """
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        """
        Decrypt ciphertext with the RSA PRIVATE key.

        Args:
            ciphertext_b64: Base64-encoded ciphertext from encrypt()

        Returns:
            Original plaintext string
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(ciphertext).decode('utf-8')

    # ── Digital Signatures ────────────────────────────────────────────────────

    def sign(self, message: str) -> str:
        """
        Create a digital signature using the PRIVATE key.

        The message is hashed with SHA-256, then the hash is signed.
        This proves:
          1. The message came from the holder of the private key
          2. The message was not altered after signing

        Returns:
            Base64-encoded signature
        """
        h = SHA256.new(message.encode('utf-8'))
        signature = pss.new(self.private_key).sign(h)
        return base64.b64encode(signature).decode()

    def verify(self, message: str, signature_b64: str) -> bool:
        """
        Verify a digital signature using the PUBLIC key.

        Args:
            message: Original message that was signed
            signature_b64: Base64-encoded signature from sign()

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            h = SHA256.new(message.encode('utf-8'))
            pss.new(self.public_key).verify(h, base64.b64decode(signature_b64))
            return True
        except (ValueError, TypeError):
            return False

    # ── Hybrid Encryption (RSA + AES) ─────────────────────────────────────────

    def hybrid_encrypt(self, plaintext: str) -> dict:
        """
        Encrypt arbitrary-length data using Hybrid Encryption.

        How it works:
          1. Generate a random 256-bit AES session key
          2. Encrypt the plaintext with AES-GCM (fast, secure)
          3. Encrypt the AES key with RSA public key
          4. Bundle everything together

        This combines RSA's key exchange strength with AES's speed.
        """
        from Crypto.Cipher import AES as _AES

        # Step 1: Random AES session key
        aes_key = get_random_bytes(32)  # 256-bit

        # Step 2: Encrypt data with AES-GCM
        aes_cipher = _AES.new(aes_key, _AES.MODE_GCM)
        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        # Step 3: Encrypt AES key with RSA
        rsa_cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)

        return {
            "mode": "RSA+AES Hybrid",
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
            "nonce": base64.b64encode(aes_cipher.nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
        }

    def hybrid_decrypt(self, package: dict) -> str:
        """Decrypt a hybrid-encrypted package."""
        from Crypto.Cipher import AES as _AES

        # Recover AES key with RSA private key
        rsa_cipher = PKCS1_OAEP.new(self.private_key)
        aes_key = rsa_cipher.decrypt(base64.b64decode(package["encrypted_key"]))

        # Decrypt data with AES
        aes_cipher = _AES.new(aes_key, _AES.MODE_GCM,
                               nonce=base64.b64decode(package["nonce"]))
        plaintext = aes_cipher.decrypt_and_verify(
            base64.b64decode(package["ciphertext"]),
            base64.b64decode(package["tag"])
        )
        return plaintext.decode('utf-8')

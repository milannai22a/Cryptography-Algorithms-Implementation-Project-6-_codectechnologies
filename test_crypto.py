"""
Unit Tests — Cryptography Algorithms Implementation
===================================================
Run: python -m pytest tests/ -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aes_cipher import AESCipher
from rsa_cipher import RSACipher
from sha_hash import SHAHasher


# ── AES Tests ─────────────────────────────────────────────────────────────────

class TestAESCipher:

    def setup_method(self):
        self.aes = AESCipher(256)
        self.message = "Test message for AES encryption!"

    def test_cbc_encrypt_decrypt(self):
        result = self.aes.encrypt_cbc(self.message)
        assert "iv" in result
        assert "ciphertext" in result
        decrypted = self.aes.decrypt_cbc(result["iv"], result["ciphertext"])
        assert decrypted == self.message

    def test_cbc_different_iv_each_time(self):
        r1 = self.aes.encrypt_cbc(self.message)
        r2 = self.aes.encrypt_cbc(self.message)
        assert r1["iv"] != r2["iv"]           # Different IV each time
        assert r1["ciphertext"] != r2["ciphertext"]  # Different ciphertext

    def test_gcm_encrypt_decrypt(self):
        result = self.aes.encrypt_gcm(self.message)
        decrypted = self.aes.decrypt_gcm(
            result["nonce"], result["ciphertext"], result["tag"])
        assert decrypted == self.message

    def test_gcm_aad(self):
        result = self.aes.encrypt_gcm(self.message, aad=b"header=1")
        decrypted = self.aes.decrypt_gcm(
            result["nonce"], result["ciphertext"], result["tag"], aad=b"header=1")
        assert decrypted == self.message

    def test_gcm_tamper_detection(self):
        result = self.aes.encrypt_gcm(self.message)
        tampered = result["ciphertext"][:-2] + "XX"
        with pytest.raises(ValueError):
            self.aes.decrypt_gcm(result["nonce"], tampered, result["tag"])

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            AESCipher(512)

    def test_empty_string(self):
        result = self.aes.encrypt_cbc("")
        decrypted = self.aes.decrypt_cbc(result["iv"], result["ciphertext"])
        assert decrypted == ""

    def test_unicode_message(self):
        msg = "こんにちは世界 🔐 नमस्ते"
        result = self.aes.encrypt_cbc(msg)
        assert self.aes.decrypt_cbc(result["iv"], result["ciphertext"]) == msg


# ── RSA Tests ─────────────────────────────────────────────────────────────────

class TestRSACipher:

    @pytest.fixture(scope="class")
    def rsa(self):
        return RSACipher(2048)

    def test_encrypt_decrypt(self, rsa):
        message = "Hello RSA!"
        ct = rsa.encrypt(message)
        assert rsa.decrypt(ct) == message

    def test_different_ciphertext_same_plaintext(self, rsa):
        msg = "same message"
        ct1 = rsa.encrypt(msg)
        ct2 = rsa.encrypt(msg)
        assert ct1 != ct2  # OAEP adds randomness

    def test_sign_verify_valid(self, rsa):
        msg = "Document to sign"
        sig = rsa.sign(msg)
        assert rsa.verify(msg, sig) is True

    def test_sign_verify_tampered(self, rsa):
        msg = "Original document"
        sig = rsa.sign(msg)
        assert rsa.verify("Tampered document", sig) is False

    def test_hybrid_encrypt_decrypt(self, rsa):
        long_msg = "A" * 1000  # 1000 chars — too long for plain RSA
        pkg = rsa.hybrid_encrypt(long_msg)
        assert rsa.hybrid_decrypt(pkg) == long_msg

    def test_key_export_import(self):
        rsa1 = RSACipher(2048)
        keys = rsa1.export_keys()

        rsa2 = RSACipher.__new__(RSACipher)
        rsa2.load_private_key(keys["private_key_pem"])

        msg = "Key exchange test"
        ct = rsa1.encrypt(msg)
        assert rsa2.decrypt(ct) == msg


# ── SHA Tests ─────────────────────────────────────────────────────────────────

class TestSHAHasher:

    def test_sha256_known_value(self):
        # Known SHA-256 of "abc"
        expected = "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f490f4170c36f4e7c" \
                   "bef0469f490f4170c36f4e7c"
        result = SHAHasher.hash_sha256("abc")
        assert len(result) == 64  # 256 bits = 64 hex chars

    def test_sha512_length(self):
        result = SHAHasher.hash_sha512("test")
        assert len(result) == 128  # 512 bits = 128 hex chars

    def test_sha3_256_length(self):
        result = SHAHasher.hash_sha3_256("test")
        assert len(result) == 64

    def test_deterministic(self):
        assert SHAHasher.hash_sha256("hello") == SHAHasher.hash_sha256("hello")

    def test_avalanche_effect(self):
        h1 = SHAHasher.hash_sha256("Hello")
        h2 = SHAHasher.hash_sha256("Iello")
        assert h1 != h2
        int1, int2 = int(h1, 16), int(h2, 16)
        diff = bin(int1 ^ int2).count('1')
        assert diff > 50  # Should differ in many bits

    def test_hmac_valid(self):
        mac = SHAHasher.hmac_sha256("message", "key")
        assert SHAHasher.verify_hmac("message", "key", mac) is True

    def test_hmac_wrong_key(self):
        mac = SHAHasher.hmac_sha256("message", "key")
        assert SHAHasher.verify_hmac("message", "wrong_key", mac) is False

    def test_hmac_tampered_message(self):
        mac = SHAHasher.hmac_sha256("original", "key")
        assert SHAHasher.verify_hmac("tampered", "key", mac) is False

    def test_password_hash_and_verify(self):
        pwd = "SecurePassword!123"
        hashed = SHAHasher.hash_password(pwd, iterations=10_000)
        assert SHAHasher.verify_password(
            pwd, hashed["salt"], hashed["hash"], hashed["iterations"]) is True

    def test_wrong_password_rejected(self):
        hashed = SHAHasher.hash_password("correct", iterations=10_000)
        assert SHAHasher.verify_password(
            "wrong", hashed["salt"], hashed["hash"], hashed["iterations"]) is False

    def test_unique_salts(self):
        h1 = SHAHasher.hash_password("password", 10_000)
        h2 = SHAHasher.hash_password("password", 10_000)
        assert h1["salt"] != h2["salt"]     # Different salts
        assert h1["hash"] != h2["hash"]     # Different hashes (same password!)

    def test_compare_all_returns_all_algos(self):
        result = SHAHasher.compare_all("test")
        assert "SHA-256" in result
        assert "SHA-512" in result
        assert "SHA3-256" in result

"""
Cryptography Algorithms Implementation — Interactive CLI
========================================================
User-driven menu to explore AES, RSA, SHA, HMAC, and PBKDF2.
Run: python main.py
"""

import os
import sys
from aes_cipher import AESCipher
from rsa_cipher import RSACipher
from sha_hash import SHAHasher

# ── Globals (session state) ────────────────────────────────────────────────
aes_instance = None
rsa_instance = None
current_aes_result = None
current_rsa_signature = None
current_rsa_doc = None
current_pwd_hash = None

SEP  = "=" * 60
SEP2 = "-" * 60

# ── Helpers ────────────────────────────────────────────────────────────────

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input("\n  Press Enter to continue...")

def header(title):
    print(f"\n{SEP}")
    print(f"  🔐 {title}")
    print(SEP)

def success(msg): print(f"\n  ✅ {msg}")
def error(msg):   print(f"\n  ❌ {msg}")
def info(msg):    print(f"\n  ℹ️  {msg}")
def result(label, val): print(f"\n  {label}:\n  {val}")

def get_input(prompt, allow_empty=False):
    while True:
        val = input(f"\n  {prompt}: ").strip()
        if val or allow_empty:
            return val
        print("  ⚠️  Input cannot be empty. Please try again.")

def print_menu(title, options):
    print(f"\n{SEP2}")
    print(f"  {title}")
    print(SEP2)
    for key, label in options:
        print(f"  [{key}] {label}")
    print(SEP2)

# ══════════════════════════════════════════════════════════════════════════
# AES MENU
# ══════════════════════════════════════════════════════════════════════════

def aes_menu():
    global aes_instance, current_aes_result

    while True:
        header("AES — Advanced Encryption Standard")
        print("""
  AES is a SYMMETRIC cipher — same key encrypts and decrypts.
  Used in: HTTPS, file encryption, VPNs, WhatsApp, Wi-Fi WPA2.
        """)

        status = "⚡ No key yet" if not aes_instance else f"✅ Key loaded ({aes_instance.key_size}-bit)"
        print(f"  Current Key Status: {status}")

        print_menu("AES Options", [
            ("1", "Generate new AES key"),
            ("2", "Encrypt a message  (AES-CBC)"),
            ("3", "Decrypt last ciphertext"),
            ("4", "Encrypt with authentication  (AES-GCM)"),
            ("5", "Simulate tampering / tamper detection"),
            ("6", "Load existing key (hex)"),
            ("7", "Show current key"),
            ("0", "Back to main menu"),
        ])

        choice = get_input("Choose option")

        if choice == "1":
            aes_generate_key()
        elif choice == "2":
            aes_encrypt_cbc()
        elif choice == "3":
            aes_decrypt_cbc()
        elif choice == "4":
            aes_encrypt_gcm()
        elif choice == "5":
            aes_tamper_demo()
        elif choice == "6":
            aes_load_key()
        elif choice == "7":
            aes_show_key()
        elif choice == "0":
            break
        else:
            error("Invalid option. Try again.")

        pause()


def aes_generate_key():
    global aes_instance
    print_menu("Key Size", [("1","128-bit"),("2","192-bit"),("3","256-bit (recommended)")])
    sizes = {"1": 128, "2": 192, "3": 256}
    c = get_input("Choose key size")
    size = sizes.get(c, 256)
    aes_instance = AESCipher(key_size=size)
    success(f"AES-{size} key generated!")
    result("Key (hex)", aes_instance.key.hex())


def aes_encrypt_cbc():
    global aes_instance, current_aes_result
    if not aes_instance:
        error("No key! Generate a key first (option 1).")
        return
    msg = get_input("Enter message to encrypt")
    current_aes_result = aes_instance.encrypt_cbc(msg)
    current_aes_result["_mode_used"] = "cbc"
    current_aes_result["_original"] = msg
    success("Message encrypted with AES-CBC!")
    result("IV", current_aes_result["iv"])
    result("Ciphertext (base64)", current_aes_result["ciphertext"])
    info("The IV + Ciphertext are needed to decrypt. Stored in session.")


def aes_decrypt_cbc():
    global aes_instance, current_aes_result
    if not aes_instance:
        error("No key loaded.")
        return

    print_menu("Decrypt Source", [("1","Use last encrypted result"),("2","Enter manually")])
    c = get_input("Choose")

    if c == "1":
        if not current_aes_result or current_aes_result.get("_mode_used") != "cbc":
            error("No CBC result in session. Encrypt something first.")
            return
        iv = current_aes_result["iv"]
        ct = current_aes_result["ciphertext"]
    else:
        iv = get_input("Enter IV (base64)")
        ct = get_input("Enter Ciphertext (base64)")

    try:
        plaintext = aes_instance.decrypt_cbc(iv, ct)
        success("Decryption successful!")
        result("Decrypted Message", plaintext)
    except Exception as e:
        error(f"Decryption failed: {e}")


def aes_encrypt_gcm():
    global aes_instance, current_aes_result
    if not aes_instance:
        error("No key! Generate a key first (option 1).")
        return
    msg = get_input("Enter message to encrypt")
    aad = get_input("Enter Additional Auth Data (or press Enter to skip)", allow_empty=True)
    aad_bytes = aad.encode() if aad else b""
    current_aes_result = aes_instance.encrypt_gcm(msg, aad=aad_bytes)
    current_aes_result["_mode_used"] = "gcm"
    current_aes_result["_original"] = msg
    current_aes_result["_aad"] = aad
    success("Message encrypted with AES-GCM (authenticated)!")
    result("Nonce", current_aes_result["nonce"])
    result("Ciphertext (base64)", current_aes_result["ciphertext"])
    result("Auth Tag", current_aes_result["tag"])
    info("Auth tag ensures no one tampered with the ciphertext.")


def aes_tamper_demo():
    global aes_instance, current_aes_result
    if not current_aes_result or current_aes_result.get("_mode_used") != "gcm":
        error("Encrypt something with AES-GCM first (option 4).")
        return
    print("\n  Simulating an attacker modifying the ciphertext...")
    tampered = current_aes_result["ciphertext"][:-2] + "XX"
    aad = current_aes_result.get("_aad", "")
    try:
        aes_instance.decrypt_gcm(
            current_aes_result["nonce"], tampered,
            current_aes_result["tag"], aad=aad.encode() if aad else b""
        )
        error("Tamper NOT detected (should not happen!)")
    except ValueError as e:
        success("Tamper DETECTED by AES-GCM authentication tag!")
        info(str(e))


def aes_load_key():
    global aes_instance
    key_hex = get_input("Enter AES key in hex")
    try:
        aes_instance = AESCipher.__new__(AESCipher)
        aes_instance.set_key(key_hex)
        success(f"AES-{aes_instance.key_size} key loaded!")
    except Exception as e:
        error(f"Invalid key: {e}")


def aes_show_key():
    if not aes_instance:
        error("No key loaded.")
        return
    result("AES Key (hex)", aes_instance.key.hex())
    result("Key Size", f"{aes_instance.key_size} bits")


# ══════════════════════════════════════════════════════════════════════════
# RSA MENU
# ══════════════════════════════════════════════════════════════════════════

def rsa_menu():
    global rsa_instance, current_rsa_signature, current_rsa_doc

    while True:
        header("RSA — Asymmetric Encryption & Digital Signatures")
        print("""
  RSA uses a PUBLIC key (encrypt) and PRIVATE key (decrypt).
  Also used for DIGITAL SIGNATURES to verify authenticity.
        """)

        status = "⚡ No key pair yet" if not rsa_instance else "✅ Key pair loaded"
        print(f"  Current Key Status: {status}")

        print_menu("RSA Options", [
            ("1", "Generate RSA key pair"),
            ("2", "Encrypt a message"),
            ("3", "Decrypt a message"),
            ("4", "Sign a document"),
            ("5", "Verify signature"),
            ("6", "Hybrid encryption  (RSA + AES for large data)"),
            ("7", "Export keys (PEM format)"),
            ("0", "Back to main menu"),
        ])

        choice = get_input("Choose option")

        if choice == "1":
            rsa_generate()
        elif choice == "2":
            rsa_encrypt()
        elif choice == "3":
            rsa_decrypt()
        elif choice == "4":
            rsa_sign()
        elif choice == "5":
            rsa_verify()
        elif choice == "6":
            rsa_hybrid()
        elif choice == "7":
            rsa_export()
        elif choice == "0":
            break
        else:
            error("Invalid option.")

        pause()


def rsa_generate():
    global rsa_instance
    print_menu("Key Size", [("1","1024-bit (legacy/fast)"),("2","2048-bit (recommended)"),("3","4096-bit (high security, slow)")])
    sizes = {"1": 1024, "2": 2048, "3": 4096}
    c = get_input("Choose key size")
    size = sizes.get(c, 2048)
    info(f"Generating {size}-bit RSA key pair... please wait.")
    rsa_instance = RSACipher(key_size=size)
    success(f"RSA-{size} key pair generated!")


def rsa_encrypt():
    global rsa_instance
    if not rsa_instance:
        error("Generate a key pair first (option 1).")
        return
    msg = get_input("Enter message to encrypt (max ~190 chars for RSA-2048)")
    if len(msg) > 190:
        error("Message too long for direct RSA. Use Hybrid Encryption (option 6) instead.")
        return
    try:
        ct = rsa_instance.encrypt(msg)
        success("Message encrypted with RSA public key!")
        result("Ciphertext (base64)", ct)
        # store for decrypt
        rsa_instance._last_ct = ct
    except Exception as e:
        error(f"Encryption failed: {e}")


def rsa_decrypt():
    global rsa_instance
    if not rsa_instance:
        error("Generate a key pair first (option 1).")
        return
    print_menu("Decrypt Source", [("1","Use last encrypted result"),("2","Enter ciphertext manually")])
    c = get_input("Choose")
    if c == "1":
        ct = getattr(rsa_instance, "_last_ct", None)
        if not ct:
            error("No ciphertext in session. Encrypt something first.")
            return
    else:
        ct = get_input("Enter ciphertext (base64)")
    try:
        plaintext = rsa_instance.decrypt(ct)
        success("Decryption successful!")
        result("Decrypted Message", plaintext)
    except Exception as e:
        error(f"Decryption failed: {e}")


def rsa_sign():
    global rsa_instance, current_rsa_signature, current_rsa_doc
    if not rsa_instance:
        error("Generate a key pair first (option 1).")
        return
    doc = get_input("Enter document/message to sign")
    current_rsa_doc = doc
    current_rsa_signature = rsa_instance.sign(doc)
    success("Document signed with RSA private key!")
    result("Signature (base64, first 60 chars)", current_rsa_signature[:60] + "...")
    info("Share the document + signature + public key for verification.")


def rsa_verify():
    global rsa_instance, current_rsa_signature, current_rsa_doc
    if not rsa_instance or not current_rsa_signature:
        error("Sign a document first (option 4).")
        return

    print_menu("Verify Options", [
        ("1", f'Verify original document: "{current_rsa_doc[:40]}..."'),
        ("2", "Enter a different/tampered document to test"),
    ])
    c = get_input("Choose")

    if c == "1":
        doc = current_rsa_doc
    else:
        doc = get_input("Enter the document to verify against")

    is_valid = rsa_instance.verify(doc, current_rsa_signature)
    if is_valid:
        success("Signature is VALID — document is authentic and untampered!")
    else:
        error("Signature is INVALID — document was tampered or wrong key!")


def rsa_hybrid():
    global rsa_instance
    if not rsa_instance:
        error("Generate a key pair first (option 1).")
        return
    msg = get_input("Enter message to encrypt (any length)")
    package = rsa_instance.hybrid_encrypt(msg)
    success("Hybrid encryption complete (RSA + AES-GCM)!")
    result("Encrypted AES Key (b64, first 40)", package["encrypted_key"][:40] + "...")
    result("Nonce", package["nonce"])
    result("Ciphertext (b64, first 40)", package["ciphertext"][:40] + "...")
    result("Auth Tag", package["tag"])

    info("Decrypting now to verify...")
    recovered = rsa_instance.hybrid_decrypt(package)
    if recovered == msg:
        success("Hybrid decryption verified!")
        result("Recovered Message", recovered)
    else:
        error("Mismatch!")


def rsa_export():
    global rsa_instance
    if not rsa_instance:
        error("Generate a key pair first (option 1).")
        return
    keys = rsa_instance.export_keys()
    print("\n  --- PUBLIC KEY (share this) ---")
    print(keys["public_key_pem"])
    print("\n  --- PRIVATE KEY (keep secret!) ---")
    print(keys["private_key_pem"][:200] + "\n  ...")


# ══════════════════════════════════════════════════════════════════════════
# SHA MENU
# ══════════════════════════════════════════════════════════════════════════

def sha_menu():
    while True:
        header("SHA — Secure Hash Algorithms")
        print("""
  SHA produces a fixed-size fingerprint of any input.
  One-way: you CANNOT reverse a hash to get the original.
        """)

        print_menu("SHA Options", [
            ("1", "Hash text  (compare all algorithms)"),
            ("2", "Hash a file  (integrity check)"),
            ("3", "Demonstrate avalanche effect"),
            ("4", "HMAC — keyed message authentication"),
            ("5", "Password hashing  (PBKDF2)"),
            ("6", "Verify a password"),
            ("0", "Back to main menu"),
        ])

        choice = get_input("Choose option")

        if choice == "1":
            sha_hash_text()
        elif choice == "2":
            sha_hash_file()
        elif choice == "3":
            sha_avalanche()
        elif choice == "4":
            sha_hmac()
        elif choice == "5":
            sha_password_hash()
        elif choice == "6":
            sha_password_verify()
        elif choice == "0":
            break
        else:
            error("Invalid option.")

        pause()


def sha_hash_text():
    text = get_input("Enter text to hash")
    results = SHAHasher.compare_all(text)
    print(f"\n  Input: '{text}'\n")
    print(f"  {'Algorithm':<20} {'Bits':<8} {'Status':<12} Hash")
    print("  " + "-"*100)
    for algo, info_d in results.items():
        if algo == "input":
            continue
        secure = "✅ Secure" if info_d["secure"] else "⚠️  Deprecated"
        print(f"  {algo:<20} {info_d['bits']:<8} {secure:<12} {info_d['digest']}")


def sha_hash_file():
    filepath = get_input("Enter full path to the file")
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return
    print_menu("Algorithm", [("1","SHA-256"),("2","SHA-512"),("3","SHA3-256")])
    algos = {"1": "sha256", "2": "sha512", "3": "sha3_256"}
    c = get_input("Choose algorithm")
    algo = algos.get(c, "sha256")
    try:
        digest = SHAHasher.hash_file(filepath, algorithm=algo)
        success(f"File hashed with {algo.upper()}!")
        result("File", filepath)
        result("Hash", digest)
        info("Share this hash — anyone can verify the file wasn't tampered with.")
    except Exception as e:
        error(f"Could not hash file: {e}")


def sha_avalanche():
    text = get_input("Enter any text (we'll change the last character)")
    result_d = SHAHasher.demonstrate_avalanche(text)
    print(f"\n  Input 1: '{result_d['input_1']}'")
    print(f"  Hash 1 : {result_d['hash_1']}")
    print(f"\n  Input 2: '{result_d['input_2']}' (last char changed by 1)")
    print(f"  Hash 2 : {result_d['hash_2']}")
    print(f"\n  Bits different : {result_d['bits_different']} / 256  ({result_d['percent_changed']})")
    info("~50% of bits change from just a 1-character difference — that's the avalanche effect!")


def sha_hmac():
    msg = get_input("Enter message")
    key = get_input("Enter secret key")
    mac = SHAHasher.hmac_sha256(msg, key)
    success("HMAC-SHA256 computed!")
    result("Message", msg)
    result("Secret Key", key)
    result("HMAC", mac)

    print_menu("Verify", [("1","Verify with same key"),("2","Verify with different key"),("3","Skip")])
    c = get_input("Choose")
    if c == "1":
        ok = SHAHasher.verify_hmac(msg, key, mac)
        success("HMAC VALID — message is authentic!") if ok else error("HMAC INVALID!")
    elif c == "2":
        wrong_key = get_input("Enter wrong/different key")
        ok = SHAHasher.verify_hmac(msg, wrong_key, mac)
        success("HMAC valid (unexpected!)") if ok else error("HMAC INVALID — key mismatch detected!")


def sha_password_hash():
    global current_pwd_hash
    pwd = get_input("Enter password to hash")
    print_menu("Iterations (higher = more secure, slower)", [
        ("1","10,000  (fast demo)"),
        ("2","100,000  (recommended)"),
        ("3","600,000  (OWASP 2023 standard)"),
    ])
    iters_map = {"1": 10_000, "2": 100_000, "3": 600_000}
    c = get_input("Choose")
    iters = iters_map.get(c, 100_000)

    info(f"Hashing with {iters:,} iterations... please wait.")
    current_pwd_hash = SHAHasher.hash_password(pwd, iterations=iters)
    current_pwd_hash["_original"] = pwd

    success("Password hashed with PBKDF2-HMAC-SHA256!")
    result("Algorithm", current_pwd_hash["algorithm"])
    result("Iterations", f"{current_pwd_hash['iterations']:,}")
    result("Salt (base64)", current_pwd_hash["salt"])
    result("Hash (base64)", current_pwd_hash["hash"])
    info("Store the SALT + HASH + ITERATIONS in your database. Never store the plain password!")


def sha_password_verify():
    global current_pwd_hash
    if not current_pwd_hash:
        error("Hash a password first (option 5).")
        return
    pwd = get_input("Enter password to verify")
    ok = SHAHasher.verify_password(
        pwd,
        current_pwd_hash["salt"],
        current_pwd_hash["hash"],
        current_pwd_hash["iterations"]
    )
    if ok:
        success("Password MATCHES — login granted!")
    else:
        error("Password does NOT match — login denied!")


# ══════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════════════════════════════════

def main():
    while True:
        clear()
        print("""
██████████████████████████████████████████████████████████
  🔐  CRYPTOGRAPHY ALGORITHMS — INTERACTIVE DEMO
  Codec Technologies Cybersecurity Internship
██████████████████████████████████████████████████████████

  Choose a cryptography module to explore:
        """)

        print_menu("Main Menu", [
            ("1", "🔒  AES  — Symmetric Encryption / Decryption"),
            ("2", "🗝️   RSA  — Asymmetric Encryption & Digital Signatures"),
            ("3", "🔍  SHA  — Hashing, HMAC & Password Security"),
            ("0", "❌  Exit"),
        ])

        choice = get_input("Choose module")

        if choice == "1":
            aes_menu()
        elif choice == "2":
            rsa_menu()
        elif choice == "3":
            sha_menu()
        elif choice == "0":
            print("\n  Goodbye! Stay secure. 🔐\n")
            sys.exit(0)
        else:
            error("Invalid option. Choose 1, 2, 3, or 0.")
            pause()


if __name__ == "__main__":
    main()

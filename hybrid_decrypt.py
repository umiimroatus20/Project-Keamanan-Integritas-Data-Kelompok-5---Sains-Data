from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# =========================
# LOAD RSA PRIVATE KEY
# =========================
with open("client_rsa_priv.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# =========================
# INPUT DATA DARI SWAGGER
# =========================
encrypted_key_hex = input("Masukkan encrypted_key (hex): ").strip()
iv_hex = input("Masukkan IV (hex): ").strip()
ciphertext_hex = input("Masukkan ciphertext (hex): ").strip()

encrypted_key = bytes.fromhex(encrypted_key_hex)
iv = bytes.fromhex(iv_hex)
ciphertext = bytes.fromhex(ciphertext_hex)

# =========================
# STEP 1: RSA DECRYPT AES KEY
# =========================
aes_key = private_key.decrypt(
    encrypted_key,
    padding.PKCS1v15()   # ⚠️ HARUS INI
)

print("AES key length:", len(aes_key), "bytes")

# =========================
# STEP 2: AES DECRYPT MESSAGE
# =========================
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print("\n=== HYBRID DECRYPT RESULT ===")
print("AES Key   :", aes_key.hex())
print("Plaintext :", plaintext.decode())


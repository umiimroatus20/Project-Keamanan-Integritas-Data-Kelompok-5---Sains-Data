from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import binascii

# 1. Load RSA private key
with open("client_rsa_priv.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# 2. Masukkan ciphertext dari server (hex)
cipher_hex = input("Masukkan ciphertext RSA: ")
cipher_bytes = bytes.fromhex(cipher_hex)

# 3. Dekripsi
plaintext = private_key.decrypt(
    cipher_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("=== HASIL DEKRIPSI ===")
print("Plaintext:", plaintext.decode())

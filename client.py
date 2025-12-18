# ============================================================
# CLIENT SIDE KEY GENERATOR UNTUK UAS SECURITY SERVICE
# - Ed25519 → untuk signature (York, Pythagoras)
# - RSA     → untuk RSA encryption & hybrid encryption (Pythagoras)
# ============================================================

# ============================================================
# BAGIAN 1: KEY SIGNATURE (Ed25519) + INTEGRITY CHECK
# ============================================================

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib

# Generate Ed25519 keys
priv_key = ed25519.Ed25519PrivateKey.generate()
pub_key = priv_key.public_key()

# Save private key
with open("client_priv.pem", "wb") as f:
    f.write(
        priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Save public key
with open("client_pub.pem", "wb") as f:
    f.write(
        pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

# ------- SIGNATURE TEST -------
message = "Halo exo"
signature = priv_key.sign(message.encode()).hex()

# ------- INTEGRITY TEST -------
msg_integrity = "Halo exo"
hash_value = hashlib.sha256(msg_integrity.encode()).hexdigest()

print("=== SIGNATURE DATA ===")
print("Message:", message)
print("Signature (hex):", signature)

print("\n=== INTEGRITY DATA ===")
print("Integrity Message:", msg_integrity)
print("Hash Value (SHA256):", hash_value)

print("\n=== FILES SAVED ===")
print("Private key saved as client_priv.pem")
print("Public key saved as client_pub.pem\n")

# priv_key = ed25519.Ed25519PrivateKey.generate()
# pub_key = priv_key.public_key()

# # Save private key
# with open("client_priv.pem", "wb") as f:
#     f.write(
#         priv_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         )
#     )

# # Save public key
# with open("client_pub.pem", "wb") as f:
#     f.write(
#         pub_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )
#     )

# message = "Halo exo"
# signature = priv_key.sign(message.encode()).hex()

# print("Message:", message)
# print("Signature (hex):", signature)
# print("Private key saved as client_priv.pem")
# print("Public key saved as client_pub.pem\n")


# ============================================================
# BAGIAN 2: KEY ENCRYPTION (RSA)
# ============================================================
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

print("=== GENERATE RSA KEY (ENCRYPTION) ===")

rsa_priv = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
rsa_pub = rsa_priv.public_key()

# Save RSA private key
with open("client_rsa_priv.pem", "wb") as f:
    f.write(
        rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Save RSA public key
with open("client_rsa_pub.pem", "wb") as f:
    f.write(
        rsa_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("RSA private key saved as client_rsa_priv.pem")
print("RSA public key saved as client_rsa_pub.pem")
print("Upload client_rsa_pub.pem ke /keys/store jika mau test RSA/HYBRID")

print("\n=== CLIENT KEY GENERATION DONE ===")


# ============================================================
# BAGIAN 3: AES ENCRYPT & DECRYPT (untuk test API)
# ============================================================
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

def aes_encrypt(message: str):
    key = secrets.token_bytes(32)   # AES-256
    iv = secrets.token_bytes(16)    # 16 bytes IV

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return key, iv, ciphertext


def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()
    return msg.decode()


# TEST AES
print("\n=== TEST AES ENCRYPTION ===")
msg = "halo aes"
key, iv, c = aes_encrypt(msg)

print("AES Key       :", key.hex())
print("AES IV        :", iv.hex())
print("Ciphertext    :", c.hex())

dec = aes_decrypt(key, iv, c)
print("AES Decrypted :", dec)


# ============================================================
# BAGIAN 4: RSA ENCRYPT (untuk test API RSA / HYBRID)
# ============================================================
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def rsa_encrypt(public_key, message: str):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_decrypt(private_key, ciphertext: bytes):
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


# TEST RSA
print("\n=== TEST RSA ENCRYPTION ===")
msg2 = "halo rsa"
encrypted_rsa = rsa_encrypt(rsa_pub, msg2)
print("RSA Ciphertext:", encrypted_rsa.hex())

decrypted_rsa = rsa_decrypt(rsa_priv, encrypted_rsa)
print("RSA Decrypted :", decrypted_rsa)






# # CLIENT SIDE KEY GENERATOR
# # Digunakan untuk level Pythagoras (B+)
# # Menghasilkan private key, public key, dan contoh signature

# from cryptography.hazmat.primitives.asymmetric import ed25519
# from cryptography.hazmat.primitives import serialization

# # ================================
# # 1. Generate Private & Public Key
# # ================================

# priv_key = ed25519.Ed25519PrivateKey.generate()
# pub_key = priv_key.public_key()

# # ================================
# # 2. Simpan ke file .pem
# # ================================

# # Save private key
# with open("client_priv.pem", "wb") as f:
#     f.write(
#         priv_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         )
#     )

# # Save public key
# with open("client_pub.pem", "wb") as f:
#     f.write(
#         pub_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )
#     )

# # ================================
# # 3. Buat example message + signature
# # ================================

# message = "Halo exo"

# signature = priv_key.sign(message.encode()).hex()

# # ================================
# # 4. Print hasil untuk dipakai di Swagger
# # ================================

# print("=== CLIENT KEY GENERATED ===")
# print("Message:", message)
# print("Signature (hex):", signature)
# print("Private key saved as client_priv.pem")
# print("Public key saved as client_pub.pem")



# # # File dari sisi client 
# # # Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# # # TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# # # sebelum mengakses laman Swagger API

# # from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
# # from cryptography.hazmat.primitives import hashes, serialization
# # from cryptography.hazmat.backends import default_backend

# # from cryptography import x509
# # from cryptography.x509.oid import NameOID
# # import datetime

# # # TODO: Lengkapi proses-proses pembuatan private dan public key
# # # untuk users yang disimulasikan
# # priv_key = ...
# # pub_key = ...

# # # TODO: Lengkapi proses-proses lain enkripsi simetrik (jika dibutuhkan)
# # # di mana pesan rahasia tersebut akan ditransmisikan
# # #
# # # Tulis code Anda di bawah ini
# # #
# # #
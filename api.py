from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from datetime import datetime
import hashlib
import os

from fastapi.security import APIKeyHeader
from fastapi.openapi.models import APIKey, APIKeyIn, SecuritySchemeType
from fastapi.openapi.utils import get_openapi

app = FastAPI(title="Security Service", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# STATIC ENTRY (Edison)
# ---------------------------
# Public key user disimpan secara STATIC (hardcode)
STATIC_USERS = {
    "Umi": "-----BEGIN PUBLIC KEY-----\nKEY_LUFFY\n-----END PUBLIC KEY-----",
    "Cintiyafajar":  "-----BEGIN PUBLIC KEY-----\nKEY_ZORO\n-----END PUBLIC KEY-----"
}

PUBLIC_KEY_FOLDER = "keys"
os.makedirs(PUBLIC_KEY_FOLDER, exist_ok=True)


# ---------------------------
# HEALTH CHECK & INDEX
# ---------------------------
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/")
async def get_index():
    return {
        "message": "Hello world! Please visit /docs for API UI."
    }


# ---------------------------
# UPLOAD PDF
# ---------------------------
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    contents = await file.read()
    save_path = f"uploaded_{file.filename}"

    with open(save_path, "wb") as f:
        f.write(contents)

    return {"message": "File uploaded", "filename": save_path}


# ---------------------------
# 1. YORK → SIMPAN PUBLIC KEY
# ---------------------------
@app.post("/keys/store")
async def store_pubkey(username: str, file: UploadFile = File(...)):
    try:
        contents = await file.read()
        save_path = f"{PUBLIC_KEY_FOLDER}/{username}.pub"

        with open(save_path, "wb") as f:
            f.write(contents)

        return {"message": "Public key stored successfully", "user": username}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error storing key: {e}")


# ---------------------------
# 2. YORK, udh pyta → VERIFIKASI SIGNATURE
# ---------------------------
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

@app.post("/signature/verify")
async def verify(username: str, message: str, signature: str):
    pub_path = f"keys/{username}.pub"

    if not os.path.exists(pub_path):
        raise HTTPException(404, "User not registered")

    with open(pub_path, "rb") as f:
        pub_bytes = f.read()

    public_key = serialization.load_pem_public_key(pub_bytes)

    try:
        public_key.verify(
            bytes.fromhex(signature),
            message.encode()
        )
        return {"message": "Signature valid", "user": username}

    except Exception:
        return {"message": "Invalid signature", "user": username}


# ---------------------------
# 3. YORK → RELAY MESSAGE
# ---------------------------
@app.post("/message/relay")
async def relay(sender: str, receiver: str, message: str):
    if receiver not in STATIC_USERS:
        raise HTTPException(status_code=404, detail="Receiver not registered")

    relay_log = f"[RELAY] {sender} -> {receiver}: {message}"

    return {
        "message": "Relay successful",
        "relay_log": relay_log
    }


# ---------------------------
# 4. YORK → SIGN PDF
# ---------------------------
@app.post("/pdf/sign")
async def sign_pdf(file: UploadFile = File(...)):
    contents = await file.read()
    signed_path = f"signed_{file.filename}"

    with open(signed_path, "wb") as f:
        f.write(contents)
        f.write(b"\n\n<!-- SIGNED BY SERVER -->")

    return {
        "message": "PDF signed successfully",
        "signed_file": signed_path
    }


# ---------------------------
# 5. EDISON → INTEGRITY CHECK
# ---------------------------
@app.post("/integrity/check")
async def integrity_check(message: str, hash_value: str):
    calc_hash = hashlib.sha256(message.encode()).hexdigest()

    return {
        "integrity": calc_hash == hash_value,
        "server_hash": calc_hash,
        "client_hash": hash_value
    }


# ---------------------------
# OPSIONAL GET /keys/list
# ---------------------------
@app.get("/keys/list")
async def list_keys():
    return {
        "static_users": list(STATIC_USERS.keys()),
        "stored_files": os.listdir(PUBLIC_KEY_FOLDER)
    }

from fastapi import UploadFile, File

KEYS_FOLDER = "keys"
os.makedirs(KEYS_FOLDER, exist_ok=True)

@app.post("/keys/store-multi")
async def store_multi(username: str, file: UploadFile = File(...)):
    contents = await file.read()
    save_path = f"{KEYS_FOLDER}/{username}.pub"

    with open(save_path, "wb") as f:
        f.write(contents)

    return {
        "message": "Public key stored successfully (multiuser mode)",
        "user": username,
        "file_saved": save_path
    }

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import os

from cryptography.hazmat.primitives.asymmetric import padding, rsa

def rsa_encrypt_key(pubkey, aes_key):
    return pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ===============================
# MESSAGE ENCRYPTION (AES / RSA / HYBRID)
# ===============================
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import secrets, os

class EncryptRequest(BaseModel):
    username: str
    message: str
    cipher_type: str   # AES / RSA / HYBRID

@app.post("/message/encrypt")
async def encrypt(req: EncryptRequest):

    pub_path = f"keys/{req.username}.pub"

    if not os.path.exists(pub_path):
        raise HTTPException(404, "User not registered")

    with open(pub_path, "rb") as f:
        pub_bytes = f.read()

    public_key = serialization.load_pem_public_key(pub_bytes)

    # AES MODE
    if req.cipher_type.upper() == "AES":
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(req.message.encode()) + encryptor.finalize()

        return {
            "cipher_type": "AES",
            "key": key.hex(),
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex()
        }

    # RSA MODE
    elif req.cipher_type.upper() == "RSA":

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise HTTPException(
                status_code=400,
                detail="Uploaded public key is not RSA — cannot be used for RSA encryption."
            )

        encrypted = public_key.encrypt(
            req.message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "cipher_type": "RSA",
            "ciphertext": encrypted.hex()
        }

    # HYBRID MODE
    elif req.cipher_type.upper() == "HYBRID":

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise HTTPException(
                status_code=400,
                detail="Uploaded public key is not RSA — cannot be used for HYBRID encryption."
            )

        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(req.message.encode()) + encryptor.finalize()

        encrypted_key = public_key.encrypt(
            aes_key,
            padding.PKCS1v15()
        )

        return {
            "cipher_type": "HYBRID",
            "encrypted_key": encrypted_key.hex(),
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex()
        }

    else:
        raise HTTPException(400, "cipher_type must be AES / RSA / HYBRID")


class DecryptRequest(BaseModel):
    cipher_type: str
    ciphertext: str
    key: str
    iv: str

@app.post("/message/decrypt")
async def decrypt(req: DecryptRequest):

    if req.cipher_type.upper() != "AES":
        raise HTTPException(400, "Only AES decrypt supported")

    key = bytes.fromhex(req.key)
    iv = bytes.fromhex(req.iv)
    ciphertext = bytes.fromhex(req.ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    msg = decryptor.update(ciphertext) + decryptor.finalize()

    return {"message": msg.decode()}


# ============================================
# STELLA – SESSION TOKEN AUTHENTICATION
# ============================================
from fastapi import Depends, Header, HTTPException
import secrets

USERS_FILE = "users.txt"
SESSIONS = {}   

os.makedirs(".", exist_ok=True)

# -------------------------
# HELPERS
# -------------------------
def save_user(username, password_hash):
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}:{password_hash}\n")

def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            for line in f:
                u, pw = line.strip().split(":")
                users[u] = pw
    return users


# -----------------------------------------
# REGISTER
# -----------------------------------------
@app.post("/auth/register")
async def register(username: str, password: str):
    users = load_users()

    if username in users:
        raise HTTPException(400, "User already exists")

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    save_user(username, password_hash)

    return {"message": "Registration successful", "user": username}


# -----------------------------------------
# LOGIN → generate session token
# -----------------------------------------
@app.post("/auth/login")
async def login(username: str, password: str):
    users = load_users()

    if username not in users:
        raise HTTPException(404, "User not found")

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if users[username] != password_hash:
        raise HTTPException(401, "Incorrect password")

    token = secrets.token_hex(32)
    SESSIONS[token] = username

    return {"message": "Login success", "token": token}


# -----------------------------------------
# AUTH PROTECTOR (dipakai /auth/me)
# -----------------------------------------
from fastapi import Header

def get_user_from_token(token: str = Header(None, alias="X-Session-Token")):
    if token not in SESSIONS:
        raise HTTPException(401, "Invalid or expired session token")
    return SESSIONS[token]


# -----------------------------------------
# AUTH / ME
# -----------------------------------------
@app.get("/auth/me")
async def auth_me(current_user: str = Depends(get_user_from_token)):
    return {"message": "Token valid", "user": current_user}


# -----------------------------------------
# SESSION / ACTIVE
# -----------------------------------------
@app.get("/session/active")
async def session_active(token: str = Header(None, alias="X-Session-Token")):
    return {
        "active": token in SESSIONS,
        "user": SESSIONS.get(token, None)
    }


# -----------------------------------------
# LOGOUT
# -----------------------------------------
@app.post("/auth/logout")
async def logout(token: str = Header(None, alias="X-Session-Token")):
    if token in SESSIONS:
        del SESSIONS[token]
        return {"message": "Logged out"}

    raise HTTPException(401, "Invalid token")


token_header = APIKeyHeader(name="X-Session-Token", auto_error=False)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Security Service",
        version="1.0.0",
        description="UAS Security API",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "SessionTokenAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Session-Token"
        }
    }

    # Pasang security ke endpoint Stella
    protected_paths = [
        "/auth/me",
        "/session/active",
        "/auth/logout"
    ]

    for path, methods in openapi_schema["paths"].items():
        if path in protected_paths:
            for method in methods.values():
                method["security"] = [{"SessionTokenAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

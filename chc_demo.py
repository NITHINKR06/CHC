# chc_demo.py
# Simple demo of CHC: contextual seed generation, CHC encrypt, per-user seed wrapping and unwrap via X25519 ECDH.
# Requires: pip install cryptography

import os, time, json, hashlib, hmac, math, binascii
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ---------------------------
# Utility crypto helpers
# ---------------------------
BLOCK_SIZE = 32  # bytes per block for CHC

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ---------------------------
# Simple blockchain simulation
# ---------------------------
CHAIN_FILE = "blockchain.json"

def init_chain():
    if not os.path.exists(CHAIN_FILE):
        genesis = {"index": 0, "timestamp": time.time(), "data": "genesis", "prev_hash": "0"}
        genesis["hash"] = hashlib.sha256(json.dumps(genesis, sort_keys=True).encode()).hexdigest()
        with open(CHAIN_FILE, "w") as f:
            json.dump([genesis], f, indent=2)

def add_block(data: dict):
    with open(CHAIN_FILE, "r") as f:
        chain = json.load(f)
    prev = chain[-1]
    block = {
        "index": len(chain),
        "timestamp": time.time(),
        "data": data,
        "prev_hash": prev["hash"]
    }
    block["hash"] = hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()
    chain.append(block)
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)
    # return the block hash and timestamp for context
    return block["hash"], block["timestamp"]

# ---------------------------
# CHC core functions
# ---------------------------
def derive_master_seed(owner_master_secret: bytes, block_hash: str, timestamp: float, file_id: str) -> bytes:
    context = block_hash.encode() + str(timestamp).encode() + file_id.encode()
    return hmac_sha256(owner_master_secret, context)  # 32 bytes

def chc_encrypt(plaintext: bytes, seed: bytes) -> bytes:
    state = seed
    ciphertext = b""
    blocks = math.ceil(len(plaintext) / BLOCK_SIZE)
    for i in range(blocks):
        p = plaintext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
        keystream = hmac_sha256(state, i.to_bytes(4,"big"))
        c = xor_bytes(p, keystream[:len(p)])
        ciphertext += c
        # update state with ciphertext block
        state = hmac_sha256(state, c)
    return ciphertext

def chc_decrypt(ciphertext: bytes, seed: bytes) -> bytes:
    state = seed
    plaintext = b""
    blocks = math.ceil(len(ciphertext) / BLOCK_SIZE)
    for i in range(blocks):
        c = ciphertext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
        keystream = hmac_sha256(state, i.to_bytes(4,"big"))
        p = xor_bytes(c, keystream[:len(c)])
        plaintext += p
        state = hmac_sha256(state, c)
    return plaintext

# seed wrapping (owner side): wrap seed so user can recover it with their shared secret
def wrap_seed(seed: bytes, shared_secret: bytes, file_id: str) -> bytes:
    wrap_key = hmac_sha256(shared_secret, b"wrap" + file_id.encode())
    return xor_bytes(seed, wrap_key[:len(seed)])

def unwrap_seed(wrapped: bytes, shared_secret: bytes, file_id: str) -> bytes:
    wrap_key = hmac_sha256(shared_secret, b"wrap" + file_id.encode())
    return xor_bytes(wrapped, wrap_key[:len(wrapped)])

# ---------------------------
# Cloud storage simulation (in-memory)
# ---------------------------
cloud_storage = {}  # file_id -> { "ciphertext": hex, "enc_seeds": {pubhex: wrapped_seed_hex}, "owner_pub": pubhex }

def upload_to_cloud(file_id: str, ciphertext: bytes, owner_pub_hex: str, enc_seeds: dict):
    cloud_storage[file_id] = {
        "ciphertext": ciphertext.hex(),
        "enc_seeds": {k: v.hex() for k, v in enc_seeds.items()},
        "owner_pub": owner_pub_hex
    }

def download_from_cloud(file_id: str):
    return cloud_storage.get(file_id)

# ---------------------------
# Demo flow
# ---------------------------
def demo():
    print("=== CHC demo start ===")
    init_chain()

    # Create identities (owner + one authorized user + attacker)
    owner_priv = X25519PrivateKey.generate()
    owner_pub = owner_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                     format=serialization.PublicFormat.Raw)
    owner_pub_hex = owner_pub.hex()

    user_priv = X25519PrivateKey.generate()
    user_pub = user_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                   format=serialization.PublicFormat.Raw)
    user_pub_hex = user_pub.hex()

    attacker_priv = X25519PrivateKey.generate()
    attacker_pub = attacker_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                           format=serialization.PublicFormat.Raw)
    attacker_pub_hex = attacker_pub.hex()

    print("Owner pub:", owner_pub_hex[:40], "...")
    print("User pub :", user_pub_hex[:40], "...")
    print("Attacker:", attacker_pub_hex[:40], "...")

    # Owner chooses a random master secret (kept private)
    owner_master_secret = os.urandom(32)  # example master secret

    # The file to upload
    file_id = "file001"
    plaintext = b"Hello! This is a secret project file. CHC demo content."

    # Add a blockchain record for the upload (this returns the block hash + timestamp used for context)
    metadata = {
        "file_id": file_id,
        "owner_pub": owner_pub_hex,
        "authorized": [user_pub_hex],  # only user_pub authorized
        "info": "demo upload"
    }
    block_hash, timestamp = add_block(metadata)
    print("\nBlock added for file. block_hash:", block_hash[:40], "... timestamp:", timestamp)

    # Owner derives the master seed for this upload (seed used to encrypt the file)
    seed = derive_master_seed(owner_master_secret, block_hash, timestamp, file_id)
    print("Derived master seed (hex):", seed.hex())

    # Owner encrypts the file with the CHC algorithm
    ciphertext = chc_encrypt(plaintext, seed)
    print("Ciphertext (hex prefix):", ciphertext.hex()[:80], "... (len:", len(ciphertext), ")")

    # Owner computes per-user wrapped seeds using ECDH shared secrets
    enc_seeds = {}
    # Wrap for authorized user:
    shared_user = owner_priv.exchange(X25519PublicKey_from_bytes(user_pub))
    wrapped_user = wrap_seed(seed, shared_user, file_id)
    enc_seeds[user_pub_hex] = wrapped_user

    # Wrap for attacker (not stored, but let's show attacker cannot decrypt)
    shared_att = owner_priv.exchange(X25519PublicKey_from_bytes(attacker_pub))
    wrapped_attacker = wrap_seed(seed, shared_att, file_id)
    # NOTE: we DO NOT publish wrapped_attacker to cloud enc_seeds (attacker not authorized)

    # Upload ciphertext and wrapped per-user seeds to cloud (cloud doesn't know plaintext)
    upload_to_cloud(file_id, ciphertext, owner_pub_hex, enc_seeds)
    print("\nUploaded to cloud. Cloud stores ciphertext + wrapped seed for authorized user(s).")

    # --- Authorized user downloads and decrypts ---
    print("\n--- Authorized user attempting download ---")
    rec = download_from_cloud(file_id)
    assert rec is not None
    ciphertext_stored = bytes.fromhex(rec["ciphertext"])
    wrapped_hex = rec["enc_seeds"].get(user_pub_hex)
    wrapped_bytes = bytes.fromhex(wrapped_hex)

    # user computes shared secret with owner's public key
    owner_pub_obj = X25519PublicKey_from_bytes(bytes.fromhex(rec["owner_pub"]))
    shared_user2 = user_priv.exchange(owner_pub_obj)
    recovered_seed = unwrap_seed(wrapped_bytes, shared_user2, file_id)
    print("Recovered seed by user:", recovered_seed.hex())

    # decrypt
    recovered_plain = chc_decrypt(ciphertext_stored, recovered_seed)
    print("Decrypted plaintext by authorized user:", recovered_plain.decode())

    # --- Attacker attempt (should fail) ---
    print("\n--- Attacker attempting download (no wrapped seed in cloud) ---")
    # attacker tries to compute shared secret and unwrap (but has no wrapped value)
    shared_att2 = attacker_priv.exchange(owner_pub_obj)
    # If attacker had wrapped seed (which he doesn't), he could unwrap; but cloud did not provide it:
    attacker_wrapped_hex = rec["enc_seeds"].get(attacker_pub_hex)
    if attacker_wrapped_hex is None:
        print("Attacker has no wrapped seed stored in cloud -> cannot recover seed -> cannot decrypt")
    else:
        print("Attacker had wrapped seed (unexpected).")

    print("\n=== CHC demo end ===")

# small helpers to re-create public key object from raw bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
def X25519PublicKey_from_bytes(b: bytes):
    return X25519PublicKey.from_public_bytes(b)

if __name__ == "__main__":
    demo()

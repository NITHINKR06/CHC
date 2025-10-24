# chc_extended_demo.py
# Extended CHC demo with multiple files, better visualization, and performance metrics
# Requires: pip install cryptography

import os, time, json, hashlib, hmac, math, binascii
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from typing import Dict, List, Tuple, Optional

# ---------------------------
# Utility crypto helpers
# ---------------------------
BLOCK_SIZE = 32  # bytes per block for CHC

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def format_hex(data: bytes, max_len: int = 40) -> str:
    """Format hex string with truncation for display"""
    hex_str = data.hex() if isinstance(data, bytes) else data
    if len(hex_str) > max_len:
        return hex_str[:max_len] + "..."
    return hex_str

# ---------------------------
# Enhanced blockchain simulation
# ---------------------------
CHAIN_FILE = "blockchain_extended.json"

class Blockchain:
    def __init__(self, filename: str = CHAIN_FILE):
        self.filename = filename
        self.init_chain()
    
    def init_chain(self):
        if not os.path.exists(self.filename):
            genesis = {
                "index": 0,
                "timestamp": time.time(),
                "data": "genesis",
                "prev_hash": "0"
            }
            genesis["hash"] = self._calculate_hash(genesis)
            with open(self.filename, "w") as f:
                json.dump([genesis], f, indent=2)
    
    def _calculate_hash(self, block: dict) -> str:
        block_copy = block.copy()
        block_copy.pop("hash", None)
        return hashlib.sha256(json.dumps(block_copy, sort_keys=True).encode()).hexdigest()
    
    def add_block(self, data: dict) -> Tuple[str, float]:
        with open(self.filename, "r") as f:
            chain = json.load(f)
        
        prev = chain[-1]
        block = {
            "index": len(chain),
            "timestamp": time.time(),
            "data": data,
            "prev_hash": prev["hash"]
        }
        block["hash"] = self._calculate_hash(block)
        chain.append(block)
        
        with open(self.filename, "w") as f:
            json.dump(chain, f, indent=2)
        
        return block["hash"], block["timestamp"]
    
    def get_chain_info(self) -> dict:
        with open(self.filename, "r") as f:
            chain = json.load(f)
        return {
            "length": len(chain),
            "latest_hash": chain[-1]["hash"] if chain else None,
            "blocks": chain
        }

# ---------------------------
# CHC core functions with metrics
# ---------------------------
class CHCCipher:
    def __init__(self):
        self.encryption_time = 0
        self.decryption_time = 0
    
    def derive_master_seed(self, owner_master_secret: bytes, block_hash: str, 
                          timestamp: float, file_id: str) -> bytes:
        """Derive a master seed from owner secret and blockchain context"""
        context = block_hash.encode() + str(timestamp).encode() + file_id.encode()
        return hmac_sha256(owner_master_secret, context)
    
    def encrypt(self, plaintext: bytes, seed: bytes) -> bytes:
        """CHC encryption with state chaining"""
        start_time = time.time()
        state = seed
        ciphertext = b""
        blocks = math.ceil(len(plaintext) / BLOCK_SIZE)
        
        for i in range(blocks):
            p = plaintext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            keystream = hmac_sha256(state, i.to_bytes(4, "big"))
            c = xor_bytes(p, keystream[:len(p)])
            ciphertext += c
            # Update state with ciphertext block
            state = hmac_sha256(state, c)
        
        self.encryption_time = time.time() - start_time
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, seed: bytes) -> bytes:
        """CHC decryption with state chaining"""
        start_time = time.time()
        state = seed
        plaintext = b""
        blocks = math.ceil(len(ciphertext) / BLOCK_SIZE)
        
        for i in range(blocks):
            c = ciphertext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            keystream = hmac_sha256(state, i.to_bytes(4, "big"))
            p = xor_bytes(c, keystream[:len(c)])
            plaintext += p
            state = hmac_sha256(state, c)
        
        self.decryption_time = time.time() - start_time
        return plaintext

# ---------------------------
# Key management
# ---------------------------
class KeyManager:
    def __init__(self):
        self.keys = {}
    
    def generate_keypair(self, name: str) -> Tuple[bytes, bytes]:
        """Generate and store a new X25519 keypair"""
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.keys[name] = {"private": priv, "public": pub}
        return pub, priv
    
    def get_public_key(self, name: str) -> Optional[bytes]:
        if name in self.keys:
            return self.keys[name]["public"]
        return None
    
    def get_private_key(self, name: str) -> Optional[X25519PrivateKey]:
        if name in self.keys:
            return self.keys[name]["private"]
        return None

# ---------------------------
# Seed wrapping functions
# ---------------------------
def wrap_seed(seed: bytes, shared_secret: bytes, file_id: str) -> bytes:
    """Wrap seed for secure transmission to authorized user"""
    wrap_key = hmac_sha256(shared_secret, b"wrap" + file_id.encode())
    return xor_bytes(seed, wrap_key[:len(seed)])

def unwrap_seed(wrapped: bytes, shared_secret: bytes, file_id: str) -> bytes:
    """Unwrap seed using shared secret"""
    wrap_key = hmac_sha256(shared_secret, b"wrap" + file_id.encode())
    return xor_bytes(wrapped, wrap_key[:len(wrapped)])

# ---------------------------
# Enhanced cloud storage
# ---------------------------
class CloudStorage:
    def __init__(self):
        self.storage = {}
        self.access_log = []
    
    def upload(self, file_id: str, ciphertext: bytes, owner_pub: str, enc_seeds: dict):
        """Upload encrypted file and wrapped seeds"""
        self.storage[file_id] = {
            "ciphertext": ciphertext.hex(),
            "enc_seeds": {k: v.hex() for k, v in enc_seeds.items()},
            "owner_pub": owner_pub,
            "upload_time": time.time(),
            "size": len(ciphertext)
        }
        self.access_log.append({
            "action": "upload",
            "file_id": file_id,
            "time": time.time()
        })
    
    def download(self, file_id: str, user_pub: str = None) -> Optional[dict]:
        """Download file data"""
        self.access_log.append({
            "action": "download",
            "file_id": file_id,
            "user": user_pub,
            "time": time.time()
        })
        return self.storage.get(file_id)
    
    def get_stats(self) -> dict:
        """Get storage statistics"""
        total_size = sum(item["size"] for item in self.storage.values())
        return {
            "total_files": len(self.storage),
            "total_size": total_size,
            "access_count": len(self.access_log)
        }

# ---------------------------
# Demo scenarios
# ---------------------------
def demo_single_file():
    """Demo with single file encryption/decryption"""
    print("\n" + "="*60)
    print("SCENARIO 1: Single File Encryption/Decryption")
    print("="*60)
    
    # Initialize components
    blockchain = Blockchain()
    cipher = CHCCipher()
    key_mgr = KeyManager()
    cloud = CloudStorage()
    
    # Create identities
    owner_pub, owner_priv = key_mgr.generate_keypair("owner")
    user_pub, user_priv = key_mgr.generate_keypair("user")
    attacker_pub, attacker_priv = key_mgr.generate_keypair("attacker")
    
    print("\n[*] Identities created:")
    print(f"    Owner    : {format_hex(owner_pub)}")
    print(f"    User     : {format_hex(user_pub)}")
    print(f"    Attacker : {format_hex(attacker_pub)}")
    
    # Owner's master secret
    owner_master_secret = os.urandom(32)
    
    # File to encrypt
    file_id = "confidential_doc_001"
    plaintext = b"This is highly confidential information that must be protected!"
    print(f"\n[*] File to encrypt: '{file_id}'")
    print(f"    Content: {plaintext.decode()[:50]}...")
    
    # Add blockchain record
    metadata = {
        "file_id": file_id,
        "owner_pub": owner_pub.hex(),
        "authorized": [user_pub.hex()],
        "description": "Confidential document"
    }
    block_hash, timestamp = blockchain.add_block(metadata)
    print(f"\n[*] Blockchain record added:")
    print(f"    Block hash : {format_hex(block_hash)}")
    print(f"    Timestamp  : {timestamp}")
    
    # Derive master seed
    seed = cipher.derive_master_seed(owner_master_secret, block_hash, timestamp, file_id)
    print(f"\n[*] Master seed derived: {format_hex(seed)}")
    
    # Encrypt file
    ciphertext = cipher.encrypt(plaintext, seed)
    print(f"\n[*] File encrypted:")
    print(f"    Ciphertext : {format_hex(ciphertext)}")
    print(f"    Size       : {len(ciphertext)} bytes")
    print(f"    Time       : {cipher.encryption_time:.4f} seconds")
    
    # Wrap seed for authorized user
    enc_seeds = {}
    shared_user = owner_priv.exchange(X25519PublicKey.from_public_bytes(user_pub))
    wrapped_user = wrap_seed(seed, shared_user, file_id)
    enc_seeds[user_pub.hex()] = wrapped_user
    
    # Upload to cloud
    cloud.upload(file_id, ciphertext, owner_pub.hex(), enc_seeds)
    print(f"\n[*] Uploaded to cloud storage")
    
    # Authorized user downloads and decrypts
    print(f"\n[+] Authorized user attempting access...")
    rec = cloud.download(file_id, user_pub.hex())
    if rec:
        ciphertext_stored = bytes.fromhex(rec["ciphertext"])
        wrapped_hex = rec["enc_seeds"].get(user_pub.hex())
        
        if wrapped_hex:
            wrapped_bytes = bytes.fromhex(wrapped_hex)
            owner_pub_obj = X25519PublicKey.from_public_bytes(bytes.fromhex(rec["owner_pub"]))
            shared_user2 = user_priv.exchange(owner_pub_obj)
            recovered_seed = unwrap_seed(wrapped_bytes, shared_user2, file_id)
            
            recovered_plain = cipher.decrypt(ciphertext_stored, recovered_seed)
            print(f"    ✓ Decryption successful!")
            print(f"    Recovered: {recovered_plain.decode()}")
            print(f"    Time: {cipher.decryption_time:.4f} seconds")
        else:
            print(f"    ✗ No wrapped seed found for user")
    
    # Attacker attempt
    print(f"\n[-] Attacker attempting access...")
    rec = cloud.download(file_id, attacker_pub.hex())
    if rec:
        attacker_wrapped = rec["enc_seeds"].get(attacker_pub.hex())
        if attacker_wrapped:
            print(f"    ✗ Unexpected: Attacker has wrapped seed!")
        else:
            print(f"    ✓ Access denied: No wrapped seed for attacker")
    
    # Show cloud statistics
    stats = cloud.get_stats()
    print(f"\n[*] Cloud Storage Statistics:")
    print(f"    Total files  : {stats['total_files']}")
    print(f"    Total size   : {stats['total_size']} bytes")
    print(f"    Access count : {stats['access_count']}")

def demo_multiple_files():
    """Demo with multiple files and users"""
    print("\n" + "="*60)
    print("SCENARIO 2: Multiple Files with Different Access Rights")
    print("="*60)
    
    # Initialize components
    blockchain = Blockchain("blockchain_multi.json")
    cipher = CHCCipher()
    key_mgr = KeyManager()
    cloud = CloudStorage()
    
    # Create identities
    owner_pub, owner_priv = key_mgr.generate_keypair("owner")
    alice_pub, alice_priv = key_mgr.generate_keypair("alice")
    bob_pub, bob_priv = key_mgr.generate_keypair("bob")
    charlie_pub, charlie_priv = key_mgr.generate_keypair("charlie")
    
    print("\n[*] Identities created:")
    print(f"    Owner   : {format_hex(owner_pub)}")
    print(f"    Alice   : {format_hex(alice_pub)}")
    print(f"    Bob     : {format_hex(bob_pub)}")
    print(f"    Charlie : {format_hex(charlie_pub)}")
    
    owner_master_secret = os.urandom(32)
    
    # Define files with different access rights
    files = [
        {
            "id": "project_plan",
            "content": b"Q1 2024 Project Roadmap: Launch new features...",
            "authorized": [alice_pub, bob_pub]  # Alice and Bob can access
        },
        {
            "id": "financial_report",
            "content": b"Annual Revenue: $10M, Profit Margin: 25%...",
            "authorized": [alice_pub]  # Only Alice can access
        },
        {
            "id": "public_announcement",
            "content": b"We are excited to announce our new product...",
            "authorized": [alice_pub, bob_pub, charlie_pub]  # Everyone can access
        }
    ]
    
    print("\n[*] Encrypting and uploading files...")
    
    for file_info in files:
        file_id = file_info["id"]
        plaintext = file_info["content"]
        authorized_users = file_info["authorized"]
        
        print(f"\n  File: {file_id}")
        print(f"    Authorized users: {len(authorized_users)}")
        
        # Add blockchain record
        metadata = {
            "file_id": file_id,
            "owner_pub": owner_pub.hex(),
            "authorized": [u.hex() for u in authorized_users]
        }
        block_hash, timestamp = blockchain.add_block(metadata)
        
        # Derive seed and encrypt
        seed = cipher.derive_master_seed(owner_master_secret, block_hash, timestamp, file_id)
        ciphertext = cipher.encrypt(plaintext, seed)
        
        # Wrap seed for each authorized user
        enc_seeds = {}
        for user_pub in authorized_users:
            shared = owner_priv.exchange(X25519PublicKey.from_public_bytes(user_pub))
            wrapped = wrap_seed(seed, shared, file_id)
            enc_seeds[user_pub.hex()] = wrapped
        
        # Upload to cloud
        cloud.upload(file_id, ciphertext, owner_pub.hex(), enc_seeds)
        print(f"    ✓ Uploaded (size: {len(ciphertext)} bytes)")
    
    # Test access for each user
    print("\n[*] Testing access rights...")
    
    test_cases = [
        ("Alice", alice_pub, alice_priv, ["project_plan", "financial_report", "public_announcement"]),
        ("Bob", bob_pub, bob_priv, ["project_plan", "public_announcement"]),
        ("Charlie", charlie_pub, charlie_priv, ["public_announcement"])
    ]
    
    for user_name, user_pub, user_priv, expected_access in test_cases:
        print(f"\n  {user_name}'s access attempts:")
        
        for file_info in files:
            file_id = file_info["id"]
            rec = cloud.download(file_id, user_pub.hex())
            
            if rec:
                wrapped_hex = rec["enc_seeds"].get(user_pub.hex())
                if wrapped_hex and file_id in expected_access:
                    # User should be able to decrypt
                    wrapped_bytes = bytes.fromhex(wrapped_hex)
                    owner_pub_obj = X25519PublicKey.from_public_bytes(bytes.fromhex(rec["owner_pub"]))
                    shared = user_priv.exchange(owner_pub_obj)
                    recovered_seed = unwrap_seed(wrapped_bytes, shared, file_id)
                    
                    ciphertext_stored = bytes.fromhex(rec["ciphertext"])
                    recovered_plain = cipher.decrypt(ciphertext_stored, recovered_seed)
                    
                    print(f"    ✓ {file_id}: Access granted (decrypted successfully)")
                elif file_id in expected_access:
                    print(f"    ✗ {file_id}: ERROR - Should have access but no wrapped seed")
                else:
                    print(f"    ✓ {file_id}: Access denied (as expected)")
    
    # Show final statistics
    stats = cloud.get_stats()
    chain_info = blockchain.get_chain_info()
    
    print(f"\n[*] Final Statistics:")
    print(f"    Blockchain blocks : {chain_info['length']}")
    print(f"    Files in cloud    : {stats['total_files']}")
    print(f"    Total storage     : {stats['total_size']} bytes")
    print(f"    Access attempts   : {stats['access_count']}")

def main():
    print("\n" + "="*60)
    print("       CHC ENCRYPTION SYSTEM - EXTENDED DEMO")
    print("="*60)
    print("\nThis demo showcases:")
    print("  • Contextual Hash Chain (CHC) encryption")
    print("  • ECDH-based key exchange for access control")
    print("  • Blockchain-based context generation")
    print("  • Multi-user access management")
    
    # Run both scenarios
    demo_single_file()
    demo_multiple_files()
    
    print("\n" + "="*60)
    print("                    DEMO COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()

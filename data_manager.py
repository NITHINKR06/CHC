"""
Data Storage and Management Module
Handles secure storage of files, keys, and metadata

This module manages the "off-chain" storage component of the secure file management system.
It provides secure storage for encrypted files, user keys, and metadata with integrity verification.

Key Features:
- Secure encrypted file storage
- Metadata management with integrity verification
- Key vault for secure key storage
- Backup and recovery functionality
- File integrity verification
- Secure deletion capabilities

The module implements the off-chain storage requirements:
- Encrypted files stored securely
- Metadata with checksums for integrity
- User keys stored in encrypted key vault
- Backup and recovery mechanisms
"""

import os  # For file system operations and directory management
import json  # For JSON data serialization/deserialization
import time  # For timestamp generation
import shutil  # For file operations (copy, move, delete)
from typing import Dict, List, Optional  # Type hints for better code documentation
from cryptography.fernet import Fernet  # For symmetric encryption of keys
import base64  # For base64 encoding/decoding of keys
import hashlib  # For SHA256 hash calculations and integrity verification

# Storage directory structure for organized file management
STORAGE_ROOT = "secure_storage"  # Root directory for all secure storage
ENCRYPTED_FILES_DIR = os.path.join(STORAGE_ROOT, "encrypted_files")  # Directory for CHC encrypted files
KEY_VAULT_DIR = os.path.join(STORAGE_ROOT, "key_vault")  # Directory for secure key storage
METADATA_DIR = os.path.join(STORAGE_ROOT, "metadata")  # Directory for file metadata
BACKUP_DIR = os.path.join(STORAGE_ROOT, "backups")  # Directory for system backups

class DataManager:
    def __init__(self):
        """Initialize data manager and create necessary directories"""
        self.init_storage_structure()
        self.master_key = self.load_or_create_master_key()
        self.fernet = Fernet(self.master_key)
        
    def init_storage_structure(self):
        """Create storage directory structure"""
        directories = [
            STORAGE_ROOT,
            ENCRYPTED_FILES_DIR,
            KEY_VAULT_DIR,
            METADATA_DIR,
            BACKUP_DIR
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            # Create README in each directory
            readme_path = os.path.join(directory, "README.txt")
            if not os.path.exists(readme_path):
                with open(readme_path, 'w') as f:
                    f.write(f"Directory: {directory}\n")
                    f.write(f"Purpose: Secure storage for CHC system\n")
                    f.write(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    def load_or_create_master_key(self) -> bytes:
        """Load or create master encryption key for key vault"""
        key_file = os.path.join(KEY_VAULT_DIR, ".master.key")
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new master key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            print("[DataManager] Generated new master key for key vault")
            return key
    
    def store_encrypted_file(self, file_id: str, encrypted_data: bytes, 
                           original_name: str, block_hash: str = None, 
                           owner: str = None, authorized_users: list = None) -> Dict:
        """Store encrypted file with enhanced metadata for secure file management flow"""
        # Create file path
        file_path = os.path.join(ENCRYPTED_FILES_DIR, f"{file_id}.enc")
        
        # Store encrypted file
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Store enhanced metadata
        metadata = {
            "file_id": file_id,
            "original_name": original_name,
            "encrypted_path": file_path,
            "size_encrypted": len(encrypted_data),
            "storage_time": time.time(),
            "checksum": hashlib.sha256(encrypted_data).hexdigest(),
            "block_hash": block_hash,
            "owner": owner,
            "authorized_users": authorized_users or [],
            "storage_type": "off_chain_encrypted",
            "encryption_method": "CHC"
        }
        
        metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[DataManager] Stored encrypted file: {file_id}")
        print(f"[DataManager] Off-chain storage: {file_path}")
        print(f"[DataManager] Metadata logged: {metadata_path}")
        return metadata
    
    def retrieve_encrypted_file(self, file_id: str) -> Optional[bytes]:
        """Retrieve encrypted file data from off-chain storage"""
        file_path = os.path.join(ENCRYPTED_FILES_DIR, f"{file_id}.enc")
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Verify checksum
            metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                if hashlib.sha256(data).hexdigest() != metadata['checksum']:
                    print(f"[DataManager] WARNING: Checksum mismatch for file {file_id}")
                    return None
            
            print(f"[DataManager] Retrieved encrypted file from off-chain storage: {file_id}")
            return data
        return None
    
    def retrieve_file_metadata(self, file_id: str) -> Optional[Dict]:
        """Retrieve file metadata from off-chain storage"""
        metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            print(f"[DataManager] Retrieved metadata from off-chain storage: {file_id}")
            return metadata
        return None
    
    def verify_file_integrity(self, file_id: str) -> bool:
        """Verify file integrity by checking checksum"""
        file_path = os.path.join(ENCRYPTED_FILES_DIR, f"{file_id}.enc")
        metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
        
        if not os.path.exists(file_path) or not os.path.exists(metadata_path):
            return False
        
        # Read file and metadata
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Verify checksum
        current_checksum = hashlib.sha256(file_data).hexdigest()
        stored_checksum = metadata.get('checksum')
        
        if current_checksum != stored_checksum:
            print(f"[DataManager] Integrity check failed for file {file_id}")
            return False
        
        print(f"[DataManager] Integrity check passed for file {file_id}")
        return True
    
    def store_wrapped_seed(self, file_id: str, user: str, wrapped_seed: bytes):
        """Store wrapped seed in secure key vault"""
        # Encrypt the wrapped seed with master key
        encrypted_seed = self.fernet.encrypt(wrapped_seed)
        
        # Store in key vault
        key_path = os.path.join(KEY_VAULT_DIR, f"{file_id}_{user}.key")
        with open(key_path, 'wb') as f:
            f.write(encrypted_seed)
        
        print(f"[DataManager] Stored wrapped seed for {user} -> {file_id}")
    
    def retrieve_wrapped_seed(self, file_id: str, user: str) -> Optional[bytes]:
        """Retrieve wrapped seed from secure key vault"""
        key_path = os.path.join(KEY_VAULT_DIR, f"{file_id}_{user}.key")
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                encrypted_seed = f.read()
            
            # Decrypt with master key
            try:
                wrapped_seed = self.fernet.decrypt(encrypted_seed)
                return wrapped_seed
            except Exception as e:
                print(f"[DataManager] Error decrypting seed: {e}")
                return None
        return None
    
    def delete_file_data(self, file_id: str) -> bool:
        """Securely delete all data related to a file"""
        deleted = False
        
        # Delete encrypted file
        file_path = os.path.join(ENCRYPTED_FILES_DIR, f"{file_id}.enc")
        if os.path.exists(file_path):
            # Overwrite with random data before deletion (secure delete)
            file_size = os.path.getsize(file_path)
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
            os.remove(file_path)
            deleted = True
        
        # Delete metadata
        metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
        
        # Delete all wrapped seeds for this file
        for key_file in os.listdir(KEY_VAULT_DIR):
            if key_file.startswith(f"{file_id}_"):
                key_path = os.path.join(KEY_VAULT_DIR, key_file)
                # Overwrite before deletion
                with open(key_path, 'wb') as f:
                    f.write(os.urandom(256))
                os.remove(key_path)
        
        if deleted:
            print(f"[DataManager] Securely deleted file: {file_id}")
        
        return deleted
    
    def create_backup(self, backup_name: str = None) -> str:
        """Create backup of all data"""
        if backup_name is None:
            backup_name = f"backup_{time.strftime('%Y%m%d_%H%M%S')}"
        
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        # Create backup directory
        os.makedirs(backup_path, exist_ok=True)
        
        # Backup all directories
        for directory in [ENCRYPTED_FILES_DIR, KEY_VAULT_DIR, METADATA_DIR]:
            dir_name = os.path.basename(directory)
            backup_subdir = os.path.join(backup_path, dir_name)
            if os.path.exists(directory):
                shutil.copytree(directory, backup_subdir)
        
        # Create backup metadata
        backup_info = {
            "backup_name": backup_name,
            "backup_time": time.time(),
            "backup_path": backup_path,
            "files_count": len(os.listdir(ENCRYPTED_FILES_DIR)) - 1  # Exclude README
        }
        
        with open(os.path.join(backup_path, "backup_info.json"), 'w') as f:
            json.dump(backup_info, f, indent=2)
        
        print(f"[DataManager] Created backup: {backup_name}")
        return backup_path
    
    def restore_backup(self, backup_name: str) -> bool:
        """Restore data from backup"""
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        if not os.path.exists(backup_path):
            print(f"[DataManager] Backup not found: {backup_name}")
            return False
        
        # Restore each directory
        for directory in [ENCRYPTED_FILES_DIR, KEY_VAULT_DIR, METADATA_DIR]:
            dir_name = os.path.basename(directory)
            backup_subdir = os.path.join(backup_path, dir_name)
            
            if os.path.exists(backup_subdir):
                # Clear current directory
                if os.path.exists(directory):
                    shutil.rmtree(directory)
                # Restore from backup
                shutil.copytree(backup_subdir, directory)
        
        print(f"[DataManager] Restored from backup: {backup_name}")
        return True
    
    def get_storage_statistics(self) -> Dict:
        """Get storage usage statistics"""
        stats = {
            "total_files": 0,
            "total_size": 0,
            "encrypted_files": 0,
            "wrapped_seeds": 0,
            "backups": 0,
            "storage_by_directory": {}
        }
        
        # Count files and calculate sizes
        for directory in [ENCRYPTED_FILES_DIR, KEY_VAULT_DIR, METADATA_DIR, BACKUP_DIR]:
            if os.path.exists(directory):
                dir_size = 0
                file_count = 0
                
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file != "README.txt":
                            file_path = os.path.join(root, file)
                            dir_size += os.path.getsize(file_path)
                            file_count += 1
                
                dir_name = os.path.basename(directory)
                stats["storage_by_directory"][dir_name] = {
                    "files": file_count,
                    "size_bytes": dir_size,
                    "size_mb": round(dir_size / (1024 * 1024), 2)
                }
                
                if dir_name == "encrypted_files":
                    stats["encrypted_files"] = file_count
                elif dir_name == "key_vault":
                    stats["wrapped_seeds"] = file_count - 1  # Exclude master key
                elif dir_name == "backups":
                    stats["backups"] = len([d for d in os.listdir(directory) 
                                          if os.path.isdir(os.path.join(directory, d))])
                
                stats["total_files"] += file_count
                stats["total_size"] += dir_size
        
        stats["total_size_mb"] = round(stats["total_size"] / (1024 * 1024), 2)
        
        return stats
    
    def cleanup_old_files(self, days_old: int = 30) -> int:
        """Clean up files older than specified days"""
        current_time = time.time()
        cutoff_time = current_time - (days_old * 24 * 60 * 60)
        deleted_count = 0
        
        # Check metadata for old files
        for metadata_file in os.listdir(METADATA_DIR):
            if metadata_file.endswith('.json'):
                metadata_path = os.path.join(METADATA_DIR, metadata_file)
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                if metadata.get('storage_time', 0) < cutoff_time:
                    file_id = metadata['file_id']
                    if self.delete_file_data(file_id):
                        deleted_count += 1
        
        print(f"[DataManager] Cleaned up {deleted_count} old files")
        return deleted_count

class KeyManager:
    """Secure key management for user keys and master secrets"""
    
    def __init__(self):
        self.key_store_file = os.path.join(KEY_VAULT_DIR, "user_keys.enc")
        self.master_key = self.load_or_create_master_key()
        self.fernet = Fernet(self.master_key)
        
    def load_or_create_master_key(self) -> bytes:
        """Load or create master key for user key encryption"""
        key_file = os.path.join(KEY_VAULT_DIR, ".user_master.key")
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def store_user_keys(self, username: str, public_key: bytes, private_key: bytes):
        """Securely store user's key pair"""
        # Load existing keys
        if os.path.exists(self.key_store_file):
            with open(self.key_store_file, 'rb') as f:
                encrypted_data = f.read()
            keys_data = json.loads(self.fernet.decrypt(encrypted_data))
        else:
            keys_data = {}
        
        # Add new keys
        keys_data[username] = {
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode(),
            "created_at": time.time()
        }
        
        # Encrypt and store
        encrypted_data = self.fernet.encrypt(json.dumps(keys_data).encode())
        with open(self.key_store_file, 'wb') as f:
            f.write(encrypted_data)
    
    def get_user_keys(self, username: str) -> Optional[Dict]:
        """Retrieve user's key pair"""
        if not os.path.exists(self.key_store_file):
            return None
        
        with open(self.key_store_file, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            keys_data = json.loads(self.fernet.decrypt(encrypted_data))
            if username in keys_data:
                return {
                    "public_key": base64.b64decode(keys_data[username]["public_key"]),
                    "private_key": base64.b64decode(keys_data[username]["private_key"])
                }
        except Exception as e:
            print(f"[KeyManager] Error retrieving keys: {e}")
        
        return None

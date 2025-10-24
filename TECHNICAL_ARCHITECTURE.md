# CHC Secure File Management System - Technical Architecture

## 🏗️ System Overview

This document provides a comprehensive technical explanation of how the CHC (Contextual Hash Chain) Secure File Management System works internally, covering all components, algorithms, and security mechanisms.

## 🔧 Core Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    CHC SECURE FILE MANAGEMENT SYSTEM            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │    Flask    │  │ Blockchain  │  │ Encryption  │  │Data Manager │ │
│  │   Web App   │  │   Module    │  │   Module    │  │   Module    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │                │                │                │        │
│         └────────────────┼────────────────┼────────────────┘        │
│                          │                │                        │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              SECURE FILE MANAGEMENT FLOW                      │ │
│  │                                                                 │ │
│  │  1. File Upload → 2. Off-Chain Encryption → 3. On-Chain      │ │
│  │     Logging → 4. File Access → 5. Authorized Access →         │ │
│  │     6. Unauthorized Prevention → 7. Security Outcome          │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 File Structure

```
CHC-Secure-File-Management/
├── app.py                    # Flask web application
├── blockchain.py             # Blockchain management
├── encryption.py             # CHC encryption algorithm
├── data_manager.py           # Off-chain storage management
├── auth.py                   # User authentication
├── templates/                # HTML templates
│   ├── index.html           # Home page
│   ├── upload.html          # File upload
│   ├── files.html           # File listing
│   ├── decrypt.html         # File decryption
│   ├── security_audit.html  # Security audit
│   └── blockchain.html      # Blockchain viewer
├── static/                   # CSS/JS assets
├── uploads/                  # Encrypted file storage
├── secure_storage/          # Secure storage directories
│   ├── encrypted_files/     # Off-chain encrypted files
│   ├── key_vault/           # Secure key storage
│   ├── metadata/            # File metadata
│   └── backups/             # System backups
└── blockchain.json          # Blockchain data
```

## 🔐 Encryption System (CHC Algorithm)

### Contextual Hash Chain (CHC) Encryption

The CHC algorithm is the core encryption mechanism that provides forward security through state chaining.

#### Algorithm Overview

```python
def encrypt_chc(plaintext: bytes, seed: bytes) -> bytes:
    """
    CHC Encryption Process:
    1. Divide plaintext into 32-byte blocks
    2. For each block:
       - Generate keystream from current state
       - XOR plaintext with keystream
       - Update state using ciphertext block
    """
    state = seed
    ciphertext = b""
    blocks = math.ceil(len(plaintext) / BLOCK_SIZE)
    
    for i in range(blocks):
        # Get current block
        p_block = plaintext[start:end]
        
        # Generate keystream
        keystream = hmac_sha256(state, i.to_bytes(4, "big"))
        
        # Encrypt block
        c_block = xor_bytes(p_block, keystream[:len(p_block)])
        ciphertext += c_block
        
        # Update state (forward security)
        state = hmac_sha256(state, c_block)
    
    return ciphertext
```

#### Key Features

1. **Forward Security**: Each block's encryption depends on previous ciphertext
2. **Contextual Seeds**: Unique seeds derived from blockchain context
3. **State Chaining**: State updates ensure forward security
4. **HMAC-SHA256**: Cryptographically secure hash function

### Seed Derivation Process

```python
def derive_seed(owner_secret: bytes, block_hash: str, timestamp: float, file_id: str) -> bytes:
    """
    Seed Derivation:
    1. Combine blockchain context (block_hash + timestamp + file_id)
    2. Generate seed using HMAC-SHA256 with owner secret
    3. Return 32-byte seed for encryption
    """
    context = block_hash.encode() + str(timestamp).encode() + file_id.encode()
    seed = hmac_sha256(owner_secret, context)
    return seed
```

#### Security Properties

- **Uniqueness**: Each file gets a unique seed
- **Contextual**: Seed tied to blockchain context
- **Non-reversible**: Cannot derive owner secret from seed
- **Deterministic**: Same context always produces same seed

## ⛓️ Blockchain System

### Blockchain Structure

```json
{
  "index": 1,
  "timestamp": 1640995200.0,
  "file_id": "file_abc123",
  "owner": "user1",
  "authorized_users": ["user2", "user3"],
  "prev_hash": "previous_block_hash",
  "block_hash": "current_block_hash",
  "metadata": {
    "original_filename": "document.pdf",
    "size": 1024,
    "file_hash": "sha256_hash"
  },
  "access_logs": [
    {
      "event": "authorized_access",
      "user": "user2",
      "timestamp": 1640995300.0,
      "access_granted": true
    }
  ]
}
```

### Blockchain Functions

#### Block Creation
```python
def add_block(file_id: str, owner: str, authorized_users: List[str], metadata: Dict) -> Tuple[str, float]:
    """
    Create new blockchain block:
    1. Generate block data
    2. Calculate block hash
    3. Link to previous block
    4. Store in blockchain
    """
    new_block = {
        "index": len(chain),
        "timestamp": time.time(),
        "file_id": file_id,
        "owner": owner,
        "authorized_users": authorized_users,
        "prev_hash": prev_block["block_hash"],
        "metadata": metadata
    }
    
    new_block["block_hash"] = calculate_block_hash(new_block)
    chain.append(new_block)
    return new_block["block_hash"], new_block["timestamp"]
```

#### Hash Calculation
```python
def calculate_block_hash(block_data: Dict) -> str:
    """
    Calculate SHA256 hash of block:
    1. Remove existing hash field
    2. Sort keys for consistency
    3. Convert to JSON string
    4. Calculate SHA256 hash
    """
    data = {k: v for k, v in block_data.items() if k != 'hash'}
    json_str = json.dumps(data, sort_keys=True)
    return hashlib.sha256(json_str.encode()).hexdigest()
```

### Blockchain Security

1. **Immutability**: Blocks cannot be modified after creation
2. **Integrity**: Hash linking prevents tampering
3. **Auditability**: Complete audit trail of all operations
4. **Verification**: Chain integrity can be verified

## 💾 Data Storage System

### Off-Chain Storage Architecture

```
secure_storage/
├── encrypted_files/          # CHC encrypted files
│   ├── file_abc123.enc      # Encrypted file data
│   └── file_def456.enc
├── key_vault/               # Secure key storage
│   ├── file_abc123_user1.key # Wrapped seeds
│   ├── file_abc123_user2.key
│   └── .master.key          # Master encryption key
├── metadata/                # File metadata
│   ├── file_abc123.json     # File metadata
│   └── file_def456.json
└── backups/                 # System backups
    └── backup_20240101/
```

### Storage Functions

#### Encrypted File Storage
```python
def store_encrypted_file(file_id: str, encrypted_data: bytes, metadata: Dict) -> Dict:
    """
    Store encrypted file with metadata:
    1. Save encrypted file to disk
    2. Create metadata record
    3. Calculate checksum
    4. Store metadata JSON
    """
    # Save encrypted file
    file_path = os.path.join(ENCRYPTED_FILES_DIR, f"{file_id}.enc")
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Store metadata
    metadata = {
        "file_id": file_id,
        "encrypted_path": file_path,
        "size_encrypted": len(encrypted_data),
        "checksum": hashlib.sha256(encrypted_data).hexdigest(),
        "storage_time": time.time()
    }
    
    metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
```

#### Integrity Verification
```python
def verify_file_integrity(file_id: str) -> bool:
    """
    Verify file integrity:
    1. Read encrypted file
    2. Read metadata
    3. Calculate current checksum
    4. Compare with stored checksum
    """
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    current_checksum = hashlib.sha256(file_data).hexdigest()
    stored_checksum = metadata.get('checksum')
    
    return current_checksum == stored_checksum
```

## 🔑 Key Management System

### User Key Generation

```python
def generate_user_key(user_name: str, file_id: str) -> bytes:
    """
    Generate user-specific key:
    1. Combine user name and file ID
    2. Calculate SHA256 hash
    3. Return 32-byte key
    """
    data = f"{user_name}:{file_id}".encode()
    return hashlib.sha256(data).digest()
```

### Seed Wrapping

```python
def wrap_seed_for_user(seed: bytes, user_key: bytes) -> bytes:
    """
    Wrap encryption seed for specific user:
    1. XOR seed with user key
    2. Return wrapped seed
    """
    return xor_bytes(seed, user_key)

def unwrap_seed_for_user(wrapped_seed: bytes, user_key: bytes) -> bytes:
    """
    Unwrap seed using user key:
    1. XOR wrapped seed with user key
    2. Return original seed
    """
    return xor_bytes(wrapped_seed, user_key)
```

### Security Properties

1. **User Isolation**: Each user has unique keys
2. **File-Specific**: Keys are file-specific
3. **Non-Reversible**: Cannot derive other users' keys
4. **Deterministic**: Same user+file always produces same key

## 🔐 Access Control System

### Authorization Process

```python
def check_authorization(user_name: str, file_metadata: Dict) -> bool:
    """
    Check if user is authorized:
    1. Check if user is owner
    2. Check if user is in authorized list
    3. Return authorization status
    """
    is_owner = user_name == file_metadata['owner']
    is_authorized = user_name in file_metadata['authorized_users']
    
    return is_owner or is_authorized
```

### Access Logging

```python
def log_access_attempt(file_id: str, user: str, success: bool, details: Dict):
    """
    Log access attempt:
    1. Create access log entry
    2. Add to blockchain
    3. Update audit trail
    """
    access_log = {
        "file_id": file_id,
        "user": user,
        "timestamp": time.time(),
        "success": success,
        "details": details
    }
    
    blockchain.log_access_control(file_id, access_log)
```

## 🔍 Security Audit System

### Audit Trail Generation

```python
def get_security_audit_trail(file_id: str) -> List[Dict]:
    """
    Generate security audit trail:
    1. Get blockchain block for file
    2. Extract all access logs
    3. Format as audit trail
    4. Return chronological events
    """
    block = blockchain.get_block_by_file_id(file_id)
    audit_trail = []
    
    # Add file upload event
    audit_trail.append({
        "event": "file_uploaded",
        "timestamp": block.get("timestamp"),
        "description": "File uploaded and encrypted"
    })
    
    # Add access events
    for log in block.get("access_logs", []):
        audit_trail.append({
            "event": log.get("event"),
            "timestamp": log.get("timestamp"),
            "user": log.get("user"),
            "description": log.get("description")
        })
    
    return sorted(audit_trail, key=lambda x: x.get("timestamp", 0))
```

### Security Verification

```python
def verify_file_security(file_id: str) -> Dict:
    """
    Verify security for file:
    1. Check blockchain integrity
    2. Count security events
    3. Verify access control
    4. Return security status
    """
    block = blockchain.get_block_by_file_id(file_id)
    chain_valid = blockchain.verify_chain_integrity()
    
    access_logs = block.get("access_logs", [])
    unauthorized_attempts = [log for log in access_logs if log.get("access_denied")]
    successful_accesses = [log for log in access_logs if log.get("access_granted")]
    
    return {
        "valid": chain_valid,
        "data_confidentiality": "maintained" if chain_valid else "compromised",
        "access_control": "enforced" if unauthorized_attempts else "not_tested",
        "security_events": {
            "unauthorized_attempts": len(unauthorized_attempts),
            "successful_accesses": len(successful_accesses)
        }
    }
```

## 🌐 Web Application Architecture

### Flask Application Structure

```python
# app.py - Main Flask application
app = Flask(__name__)

# Routes
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload with complete flow implementation"""
    
@app.route('/decrypt/<file_id>', methods=['GET', 'POST'])
def decrypt(file_id):
    """File decryption with access control"""
    
@app.route('/security/<file_id>')
def security_audit(file_id):
    """Security audit trail viewer"""
```

### Request Flow

```
User Request → Flask Route → Business Logic → Database/Storage → Response
     │              │              │              │              │
     │              │              │              │              │
     ▼              ▼              ▼              ▼              ▼
Web Browser → URL Routing → File Processing → Data Storage → HTML Response
```

### Template System

- **Base Template**: Common layout and styling
- **Page Templates**: Specific page content
- **Component Templates**: Reusable components
- **Security Templates**: Audit trail visualization

## 🔄 Complete System Flow

### 1. File Upload Flow

```
User Upload → File Validation → Blockchain Block → Seed Derivation → CHC Encryption → Off-Chain Storage → Access Control Logging
```

**Detailed Steps:**
1. User selects file and provides metadata
2. System validates file and generates file ID
3. Blockchain block created with file metadata
4. Seed derived from blockchain context
5. File encrypted using CHC algorithm
6. Encrypted file stored off-chain
7. Access control logged to blockchain

### 2. File Access Flow

```
User Request → Authorization Check → Metadata Retrieval → Ciphertext Retrieval → Key Derivation → Decryption → Access Logging
```

**Detailed Steps:**
1. User requests file access
2. System checks authorization
3. Metadata retrieved from blockchain
4. Ciphertext retrieved from off-chain storage
5. User key derived and seed unwrapped
6. File decrypted using CHC algorithm
7. Access logged to blockchain

### 3. Security Monitoring Flow

```
Security Request → Audit Trail Generation → Event Analysis → Security Verification → Report Generation
```

**Detailed Steps:**
1. User requests security audit
2. System generates audit trail from blockchain
3. Events analyzed and categorized
4. Security verification performed
5. Comprehensive report generated

## 🛡️ Security Mechanisms

### Cryptographic Security

1. **CHC Algorithm**: Forward security through state chaining
2. **HMAC-SHA256**: Cryptographically secure hash function
3. **Contextual Seeds**: Unique seeds for each file
4. **Key Wrapping**: User-specific key management

### Access Control

1. **User Authorization**: Owner and authorized user lists
2. **Access Logging**: Complete audit trail
3. **Unauthorized Prevention**: Blocking unauthorized access
4. **Session Management**: Secure user sessions

### Data Protection

1. **Encryption**: All files encrypted before storage
2. **Integrity**: File integrity verification
3. **Confidentiality**: Only authorized users can decrypt
4. **Availability**: Secure file storage and retrieval

### Audit and Monitoring

1. **Complete Audit Trail**: Every action logged
2. **Security Verification**: Cryptographic verification
3. **Access Monitoring**: Track all access attempts
4. **Tamper Detection**: Blockchain integrity verification

## 📊 Performance Considerations

### Storage Optimization

- **Efficient Encryption**: CHC algorithm optimized for performance
- **Metadata Caching**: Frequently accessed metadata cached
- **Blockchain Optimization**: Efficient block storage and retrieval

### Security vs Performance

- **Balanced Approach**: Security without sacrificing performance
- **Efficient Algorithms**: CHC provides security with good performance
- **Optimized Storage**: Efficient off-chain storage management

## 🔧 Maintenance and Monitoring

### System Health Checks

1. **Blockchain Integrity**: Regular chain verification
2. **File Integrity**: Periodic file integrity checks
3. **Access Logs**: Monitor access patterns
4. **Security Events**: Track security incidents

### Backup and Recovery

1. **Regular Backups**: Automated backup system
2. **Data Recovery**: Secure data recovery procedures
3. **Disaster Recovery**: Complete system recovery plans

---

**This technical architecture ensures the CHC Secure File Management System provides maximum security while maintaining usability and performance.**

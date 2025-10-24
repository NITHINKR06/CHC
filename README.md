# CHC Secure File Management System

## 🚀 Quick Start Guide

A secure file management system that implements blockchain-linked contextual encryption for maximum security and controlled access.

### 🌟 Features

- **Blockchain-Linked Encryption**: Each file encrypted with unique contextual seeds
- **Access Control**: User-based authorization with wrapped seeds
- **Security Audit**: Complete audit trail for all file operations
- **Tamper-Proof Records**: Immutable blockchain records
- **Real-Time Monitoring**: Live flow logging and security verification

### 📋 System Flow (7 Steps)

1. **File Upload** → Uploader uploads file to system
2. **Off-Chain Encryption** → System derives seed and encrypts file
3. **On-Chain Logging** → Blockchain records access control and metadata
4. **File Access & Retrieval** → System retrieves metadata and ciphertext
5. **Authorized User Access** → Authorized users decrypt files successfully
6. **Unauthorized Prevention** → Unauthorized users are blocked
7. **Security Outcome** → Data confidentiality and integrity maintained

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+
- Flask
- Required Python packages (see requirements below)

### Quick Setup

1. **Clone/Download the project**
   ```bash
   cd your-project-directory
   ```

2. **Install dependencies**
   ```bash
   pip install flask cryptography werkzeug
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the web interface**
   - Open your browser
   - Navigate to: `http://127.0.0.1:5000`

## 🎯 How to Use

### 1. Upload a File
- Go to the **Upload** page
- Select a file to upload
- Enter the **Owner Name**
- Specify **Authorized Users** (comma-separated)
- Click **Upload**

**What happens behind the scenes:**
- File gets encrypted using CHC algorithm
- Unique seed derived from blockchain context
- Encrypted file stored off-chain
- Access control logged to blockchain

### 2. View Your Files
- Go to the **Files** page
- See all uploaded files with metadata
- Click **Security** to view audit trail
- Click **Decrypt** to access files

### 3. Decrypt a File
- Click **Decrypt** on any file
- Enter your **User Name**
- Click **Decrypt File**

**Access Control:**
- ✅ **Authorized users**: File decrypts successfully
- ❌ **Unauthorized users**: Access denied with audit logging

### 4. Security Audit
- Click **Security** button on any file
- View complete audit trail
- See security verification results
- Monitor access attempts and outcomes

## 🔐 Security Features

### Data Protection
- **Contextual Encryption**: Each file encrypted with unique seed
- **Forward Security**: CHC algorithm provides state chaining
- **Access Control**: Only authorized users can decrypt
- **Integrity Verification**: File integrity checked on access

### Audit & Monitoring
- **Complete Audit Trail**: Every action logged to blockchain
- **Security Verification**: Cryptographic verification of all operations
- **Access Monitoring**: Track all access attempts (authorized/unauthorized)
- **Tamper-Proof Records**: Immutable blockchain records

### User Management
- **Owner Control**: File owners can specify authorized users
- **User Authentication**: Simple user-based access control
- **Session Management**: Secure session handling
- **Admin Dashboard**: System administration capabilities

## 📊 System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   File Upload   │───▶│  Off-Chain       │───▶│  On-Chain       │
│                 │    │  Encryption      │    │  Logging        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ File Access &   │◀───│  Encrypted File  │    │  Blockchain     │
│ Retrieval       │    │  Storage         │    │  Network        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐    ┌──────────────────┐
│ Authorized User │    │ Unauthorized     │
│ Access (Success)│    │ Access (Blocked) │
└─────────────────┘    └──────────────────┘
```

## 🌐 Web Interface

### Main Pages
- **Home** (`/`) - System overview and features
- **Upload** (`/upload`) - File upload interface
- **Files** (`/files`) - File management and listing
- **Blockchain** (`/blockchain`) - Blockchain viewer
- **Security** (`/security/<file_id>`) - Security audit trail

### Key Features
- **Real-time Feedback**: Live updates on all operations
- **Security Monitoring**: Complete audit trail visualization
- **User-friendly Interface**: Intuitive design with Bootstrap
- **Responsive Design**: Works on desktop and mobile

## 🔧 API Endpoints

### Core Endpoints
- `POST /upload` - Upload file with encryption
- `GET/POST /decrypt/<file_id>` - Decrypt file
- `GET /files` - List all files
- `GET /security/<file_id>` - Security audit trail
- `GET /blockchain` - View blockchain

### API Endpoints
- `GET /api/blockchain` - Blockchain data as JSON
- `GET /api/security/<file_id>` - Security audit data as JSON

## 📈 Monitoring & Logs

### Real-Time Logging
The system provides detailed logging for all operations:

```
[FLOW-1] File uploaded: filename.txt (1024 bytes)
[FLOW-2] Seed derived from blockchain context: a4f60208264bcb7c...
[FLOW-3] Access control logged to blockchain
[FLOW-4] Metadata retrieved from blockchain
[FLOW-5] File successfully decrypted: 1024 bytes
[FLOW-7] Security outcome: Data successfully decrypted
```

### Security Events
- File uploads and encryption
- Authorized access attempts
- Unauthorized access attempts
- Decryption failures
- Security verification results

## 🚨 Troubleshooting

### Common Issues

**1. File Upload Fails**
- Check file size (max 16MB)
- Ensure valid file format
- Verify owner name is provided

**2. Decryption Fails**
- Verify you're an authorized user
- Check if file exists in system
- Ensure correct user name

**3. Security Audit Empty**
- File may not have been accessed yet
- Check blockchain integrity
- Verify file metadata

### Debug Mode
The application runs in debug mode by default, providing:
- Detailed error messages
- Real-time logging
- Automatic reloading on changes

## 📞 Support

### Getting Help
- Check the console output for detailed error messages
- Review the security audit trail for access issues
- Verify blockchain integrity in the admin panel

### System Requirements
- **Python**: 3.8 or higher
- **Memory**: 512MB RAM minimum
- **Storage**: 1GB free space
- **Browser**: Modern browser with JavaScript enabled

## 🎉 Success Indicators

When the system is working correctly, you should see:

✅ **File Upload**: "File uploaded successfully! File ID: file_xxxxx"  
✅ **Encryption**: "File encrypted using CHC algorithm"  
✅ **Blockchain**: "Access control logged to blockchain"  
✅ **Decryption**: "File successfully decrypted"  
✅ **Security**: "Data confidentiality and integrity maintained"  

## 🔄 System Status

The application shows real-time status:
- **Blockchain**: Chain integrity verified
- **Storage**: Encrypted files stored securely
- **Security**: Access control enforced
- **Audit**: Complete audit trail maintained

---

**🎯 Ready to secure your files? Start by uploading your first file!**

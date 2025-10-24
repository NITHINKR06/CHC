# How to Run CHC Secure File Management System

## 🚀 Quick Start Guide

This guide will help you run the CHC Secure File Management System on your local machine.

## 📋 Prerequisites

### **System Requirements**
- **Operating System**: Windows 10/11, macOS, or Linux
- **Python**: Version 3.8 or higher
- **Memory**: At least 512MB RAM
- **Storage**: 1GB free disk space
- **Browser**: Modern browser (Chrome, Firefox, Safari, Edge)

### **Required Python Packages**
- Flask (Web framework)
- cryptography (Encryption library)
- werkzeug (WSGI utilities)

## 🛠️ Installation Steps

### **Step 1: Check Python Installation**

Open your terminal/command prompt and check if Python is installed:

```bash
python --version
# or
python3 --version
```

**Expected Output**: Python 3.8.x or higher

**If Python is not installed**:
- Download from [python.org](https://www.python.org/downloads/)
- Make sure to check "Add Python to PATH" during installation

### **Step 2: Install Required Packages**

Navigate to your project directory and install the required packages:

```bash
# Install Flask web framework
pip install flask

# Install cryptography library for encryption
pip install cryptography

# Install werkzeug for WSGI utilities
pip install werkzeug
```

**Alternative - Install all at once**:
```bash
pip install flask cryptography werkzeug
```

### **Step 3: Verify Installation**

Check if all packages are installed correctly:

```bash
python -c "import flask, cryptography, werkzeug; print('All packages installed successfully!')"
```

**Expected Output**: "All packages installed successfully!"

## 🏃‍♂️ Running the Project

### **Method 1: Direct Python Execution**

1. **Open Terminal/Command Prompt**
2. **Navigate to Project Directory**:
   ```bash
   cd E:\5thSem\INS\Project
   ```
3. **Run the Application**:
   ```bash
   python app.py
   ```

### **Method 2: Using Python Module**

```bash
python -m app
```

## 🎯 Expected Output

When you run the project successfully, you should see:

```
[Blockchain] Genesis block created
============================================================
CHC - Contextual Encryption for Secure Cloud Storage
============================================================
Initializing blockchain...
[Blockchain] Chain already exists
Starting Flask server...
🚀 Application running at: http://127.0.0.1:5000
============================================================
 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Debugger is active!
 * Debugger PIN: 103-122-733
```

## 🌐 Accessing the Application

### **Web Interface**
1. **Open your web browser**
2. **Navigate to**: `http://127.0.0.1:5000`
3. **You should see**: CHC Secure File Management System homepage

### **Available Pages**
- **Home**: `http://127.0.0.1:5000/` - System overview
- **Upload**: `http://127.0.0.1:5000/upload` - File upload interface
- **Files**: `http://127.0.0.1:5000/files` - File management
- **Blockchain**: `http://127.0.0.1:5000/blockchain` - Blockchain viewer
- **Login**: `http://127.0.0.1:5000/login` - User authentication

## 🧪 Testing the System

### **Test 1: Upload a File**
1. Go to **Upload** page
2. Select a file (any file type)
3. Enter **Owner Name**: `test_user`
4. Enter **Authorized Users**: `user1, user2`
5. Click **Upload**

**Expected Result**: File uploaded successfully with file ID and block hash

### **Test 2: View Files**
1. Go to **Files** page
2. You should see your uploaded file
3. Click **Security** to view audit trail
4. Click **Decrypt** to test file access

### **Test 3: Decrypt File**
1. Click **Decrypt** on any file
2. Enter **User Name**: `test_user` (owner) or `user1` (authorized user)
3. Click **Decrypt File**

**Expected Result**: File downloads successfully

### **Test 4: Unauthorized Access**
1. Click **Decrypt** on any file
2. Enter **User Name**: `hacker` (unauthorized user)
3. Click **Decrypt File**

**Expected Result**: Access denied with error message

## 🔧 Troubleshooting

### **Problem 1: Python Not Found**

**Error**: `'python' is not recognized as an internal or external command`

**Solution**:
1. Install Python from [python.org](https://www.python.org/downloads/)
2. Make sure to check "Add Python to PATH" during installation
3. Restart your terminal/command prompt

### **Problem 2: Package Installation Failed**

**Error**: `pip install flask` fails

**Solution**:
```bash
# Try upgrading pip first
python -m pip install --upgrade pip

# Then install packages
pip install flask cryptography werkzeug
```

### **Problem 3: Port Already in Use**

**Error**: `Address already in use`

**Solution**:
1. **Find and kill the process using port 5000**:
   ```bash
   # Windows
   netstat -ano | findstr :5000
   taskkill /PID <PID_NUMBER> /F
   
   # macOS/Linux
   lsof -ti:5000 | xargs kill -9
   ```

2. **Or use a different port**:
   ```python
   # In app.py, change the last line to:
   app.run(debug=True, host='127.0.0.1', port=5001)
   ```

### **Problem 4: Permission Denied**

**Error**: Permission denied when creating files

**Solution**:
1. **Run as Administrator** (Windows)
2. **Check file permissions** (macOS/Linux)
3. **Change directory permissions**:
   ```bash
   chmod 755 /path/to/project
   ```

### **Problem 5: Module Not Found**

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
# Install missing packages
pip install flask cryptography werkzeug

# Or install all at once
pip install -r requirements.txt
```

## 📁 Project Structure

After running, your project should have this structure:

```
E:\5thSem\INS\Project\
├── app.py                    # Main Flask application
├── blockchain.py             # Blockchain management
├── encryption.py             # CHC encryption algorithm
├── data_manager.py           # Data storage management
├── auth.py                   # User authentication
├── templates/                # HTML templates
│   ├── index.html
│   ├── upload.html
│   ├── files.html
│   ├── decrypt.html
│   └── security_audit.html
├── static/                   # CSS/JS assets
├── uploads/                  # Encrypted file storage
├── secure_storage/          # Secure storage directories
│   ├── encrypted_files/
│   ├── key_vault/
│   ├── metadata/
│   └── backups/
├── blockchain.json          # Blockchain data
├── users.json               # User database
└── sessions.json            # Active sessions
```

## 🔄 Development Mode

### **Auto-Reload**
The application runs in debug mode with auto-reload:
- **File changes**: Automatically restarts the server
- **Debug information**: Detailed error messages
- **Hot reload**: No need to manually restart

### **Debug Features**
- **Console logging**: Real-time operation logs
- **Error details**: Comprehensive error information
- **Debug PIN**: For debugging sessions

## 🛑 Stopping the Application

### **Graceful Shutdown**
1. **Press `Ctrl+C`** in the terminal
2. **Wait for shutdown message**
3. **Close terminal**

### **Force Stop**
If the application doesn't stop:
1. **Close the terminal window**
2. **Kill the process**:
   ```bash
   # Windows
   taskkill /F /IM python.exe
   
   # macOS/Linux
   pkill -f python
   ```

## 📊 System Monitoring

### **Console Output**
The application provides real-time logging:

```
[FLOW-1] File uploaded: document.pdf (1024 bytes)
[FLOW-2] Seed derived from blockchain context: a4f60208264bcb7c...
[FLOW-3] Access control logged to blockchain
[FLOW-4] Metadata retrieved from blockchain
[FLOW-5] File successfully decrypted: 1024 bytes
[FLOW-7] Security outcome: Data successfully decrypted
```

### **File System Monitoring**
- **Blockchain**: `blockchain.json` - Immutable records
- **Users**: `users.json` - User database
- **Sessions**: `sessions.json` - Active sessions
- **Uploads**: `uploads/` - Encrypted files
- **Storage**: `secure_storage/` - Secure data

## 🎉 Success Indicators

### **Application Started Successfully**
✅ **Console shows**: "🚀 Application running at: http://127.0.0.1:5000"  
✅ **Browser loads**: CHC Secure File Management System homepage  
✅ **No errors**: Clean startup without error messages  

### **System Working Correctly**
✅ **File Upload**: Files upload successfully with file ID  
✅ **Encryption**: Files encrypted using CHC algorithm  
✅ **Blockchain**: Access control logged to blockchain  
✅ **Decryption**: Authorized users can decrypt files  
✅ **Security**: Unauthorized access blocked  

### **Security Features Active**
✅ **Audit Trail**: Complete access logging  
✅ **Integrity**: File integrity verification  
✅ **Access Control**: User-based authorization  
✅ **Encryption**: Contextual encryption working  

## 🆘 Getting Help

### **Common Issues**
1. **Check Python version**: Must be 3.8+
2. **Verify packages**: All required packages installed
3. **Check port**: Port 5000 not in use
4. **File permissions**: Proper read/write permissions

### **Debug Information**
- **Console logs**: Check terminal output for errors
- **Browser console**: Check browser developer tools
- **File system**: Verify all directories created
- **Network**: Check if port 5000 is accessible

---

**🎯 Your CHC Secure File Management System is now running successfully!**

**Access it at**: `http://127.0.0.1:5000`

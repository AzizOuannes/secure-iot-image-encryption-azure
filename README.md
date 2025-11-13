# Secure IoT Image Encryption with AES-128 and Azure

A complete end-to-end demonstration of secure IoT image encryption using AES-128, Azure Blob Storage, Azure Key Vault, and Azure IoT Hub.

## 🎯 Project Overview

This project simulates a real-world IoT camera system where:
1. **IoT Devices** (cameras) encrypt images locally using AES-128-EAX encryption
2. **Encrypted images** are uploaded to Azure Blob Storage
3. **Encryption keys** are securely managed in Azure Key Vault
4. **Device notifications** are sent through Azure IoT Hub
5. **Cloud services** can download and decrypt images securely

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     IoT Camera Device                            │
│  ┌────────────┐    ┌──────────┐    ┌──────────────┐            │
│  │   Image    │ -> │ Encrypt  │ -> │ Upload to    │            │
│  │  Capture   │    │ (AES-128)│    │ Blob Storage │            │
│  └────────────┘    └──────────┘    └──────────────┘            │
│         ↓                                    ↓                   │
│    Get Key from                      Send Notification          │
│    Key Vault                         via IoT Hub                │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Azure Cloud Services                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Blob       │  │  Key Vault   │  │   IoT Hub    │          │
│  │   Storage    │  │  (Keys)      │  │  (Messages)  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         ↓                  ↓                                     │
│  Download Encrypted     Retrieve Key                            │
│         ↓                  ↓                                     │
│         └──────> Decrypt <────────                              │
└─────────────────────────────────────────────────────────────────┘
```

## 🔐 Security Features

- **AES-128-EAX Mode**: Authenticated encryption with associated data (AEAD)
- **Azure Key Vault**: Centralized, secure key management with RBAC
- **Authentication Tags**: Ensures data integrity and detects tampering
- **Azure IoT Hub**: Secure device-to-cloud communication
- **Metadata Protection**: Sensitive data never exposed in blob metadata

## 📋 Prerequisites

- **Python 3.8+**
- **Azure Subscription**
- **Azure CLI** (authenticated: `az login`)
- **Azure Resources**:
  - Storage Account
  - Key Vault (with RBAC enabled)
  - IoT Hub

## 🚀 Installation

### 1. Clone Repository
```bash
cd C:\Users\admin\Desktop
git clone <repository-url>
cd secure-iot-image-encryption-azure
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Azure Resources

Copy the template configuration:
```bash
Copy-Item config.json.template config.json
```

Edit `config.json` with your Azure credentials:
```json
{
  "azure": {
    "storage_connection_string": "DefaultEndpointsProtocol=https;AccountName=...",
    "container_name": "encrypted-images",
    "key_vault_url": "https://your-vault.vault.azure.net/",
    "iot_hub_connection_string": "HostName=your-hub.azure-devices.net;...",
    "device_connection_string": "HostName=your-hub.azure-devices.net;DeviceId=..."
  },
  "local": {
    "input_image": "image2.png",
    "encrypted_output": "encrypted_image.bin",
    "decrypted_output": "decrypted_image.jpg",
    "metadata_file": "encryption_metadata.json"
  }
}
```

### 4. Set Up Azure Permissions

Grant Key Vault access:
```bash
az role assignment create `
  --role "Key Vault Secrets Officer" `
  --assignee your-email@domain.com `
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/your-vault
```

## 📚 Usage

### Local Testing (No Azure)

**Encrypt an image locally:**
```bash
python encrypt_local.py
```
Output: `encrypted_image.bin`, `encryption_metadata.json`

**Decrypt the image:**
```bash
python decrypt_local.py
```
Output: `decrypted_image.jpg`

---

### Azure Blob Storage (With Key Vault)

**Encrypt and upload to Azure:**
```bash
python encrypt_and_upload.py
```
- Encrypts image with AES-128-EAX
- Retrieves/creates encryption key in Key Vault
- Uploads to Azure Blob Storage
- Stores metadata separately

**Download and decrypt from Azure:**
```bash
python download_and_decrypt.py
```
- Lists available encrypted blobs
- Downloads most recent encrypted image
- Retrieves key from Key Vault
- Decrypts and verifies integrity

---

### IoT Device Simulation (Complete Workflow)

**Simulate IoT camera device:**
```bash
python iot_device_simulator.py
```
This script simulates a real IoT camera:
1. Connects to Azure IoT Hub as device
2. Retrieves encryption key from Key Vault
3. Encrypts image locally (AES-128-EAX)
4. Uploads encrypted image to Blob Storage
5. Sends notification to IoT Hub (not the image itself)
6. Sends telemetry updates

**Decrypt IoT device images:**
```bash
python decrypt_iot_blob.py
```
- Lists all IoT device uploaded blobs
- Downloads most recent encrypted image
- Retrieves encryption key from Key Vault
- Decrypts and saves image

---

## 📁 Project Structure

```
secure-iot-image-encryption-azure/
├── config.json                    # Your Azure credentials (NEVER commit!)
├── config.json.template           # Safe template for git
├── requirements.txt               # Python dependencies
├── .gitignore                     # Protects sensitive files
│
├── key_vault_helper.py           # Azure Key Vault operations module
│
├── encrypt_local.py              # Local encryption only
├── decrypt_local.py              # Local decryption only
│
├── encrypt_and_upload.py         # Encrypt + upload to Azure Blob
├── download_and_decrypt.py       # Download from Azure + decrypt
│
├── iot_device_simulator.py       # Simulate IoT camera device
├── decrypt_iot_blob.py           # Decrypt IoT device blobs
│
├── iot_hub_receiver.py           # Cloud message receiver (optional)
│
└── README.md                      # This file
```

## 🔧 Key Components

### `key_vault_helper.py`
Centralized Key Vault operations:
- `get_or_create_key()` - Get existing key or create new one
- `retrieve_key()` - Get key for decryption
- `generate_and_store_key()` - Generate and store new key
- `list_key_versions()` - View key history

### `iot_device_simulator.py`
Simulates IoT camera behavior:
- Connects to IoT Hub as device
- Encrypts images locally
- Uploads to Blob Storage
- Sends notifications via IoT Hub
- Handles telemetry

### Encryption Details
- **Algorithm**: AES-128 (128-bit key)
- **Mode**: EAX (Authenticated Encryption)
- **Key Size**: 16 bytes (128 bits)
- **Nonce**: 16 bytes (randomly generated)
- **Tag**: 16 bytes (authentication tag)

## 🛡️ Security Best Practices

### ✅ What This Project Does Right

1. **Authenticated Encryption (AEAD)**
   - Uses AES-EAX mode
   - Provides confidentiality + integrity
   - Detects tampering

2. **Secure Key Management**
   - Keys stored in Azure Key Vault
   - RBAC-based access control
   - Keys never exposed in code

3. **Credential Protection**
   - `.gitignore` protects `config.json`
   - Template file for safe sharing
   - Connection strings kept secret

4. **IoT Best Practices**
   - Device authentication via IoT Hub
   - Encrypted data in transit (HTTPS/TLS)
   - Separation of data plane (storage) and control plane (IoT Hub)

### ⚠️ Production Considerations

For production deployment, consider:
- **Managed Identities** instead of connection strings
- **SAS Tokens** with expiration for storage access
- **Device Provisioning Service** for device management
- **Key Rotation** policies in Key Vault
- **Monitoring** and logging (Azure Monitor)
- **Network Security** (VNet, Private Endpoints)

## 📊 Testing Results

### Local Encryption Test
```
Input:  image2.png (1631.97 KB)
Output: encrypted_image.bin (1631.99 KB)
Key:    16 bytes (AES-128)
Time:   ~0.5 seconds
✓ Decryption successful
✓ Byte-for-byte match verified
```

### Azure Integration Test
```
Upload:   1671139 bytes encrypted
Storage:  Azure Blob Storage
Key:      Azure Key Vault (iot-image-encryption-key)
Download: 1671139 bytes
Decrypt:  Success
✓ Authentication tag verified
✓ Data integrity confirmed
```

### IoT Device Simulation Test
```
Device:      camera-device-01
IoT Hub:     iot-encryption-hub.azure-devices.net
Blob:        iot_device_20251113_131145_image2.png.enc
Notification: 0.33 KB (IoT Hub message)
✓ Device connected successfully
✓ Image encrypted and uploaded
✓ Notification sent via IoT Hub
✓ Decryption successful
```

## 🐛 Troubleshooting

### Authentication Errors
```
Error: AuthenticationError from Key Vault
Solution: Run 'az login' and ensure you have "Key Vault Secrets Officer" role
```

### Missing Dependencies
```
Error: ModuleNotFoundError: No module named 'Crypto'
Solution: pip install pycryptodome
```

### IoT Hub Connection Issues
```
Error: UnauthorizedError
Solution: Check device_connection_string in config.json
```

### Blob Not Found
```
Error: ResourceNotFoundError
Solution: Run encrypt_and_upload.py or iot_device_simulator.py first
```

## 📖 API Reference

### Key Vault Helper

```python
from key_vault_helper import get_or_create_key, retrieve_key

# Get or create encryption key
key = get_or_create_key(
    key_vault_url="https://vault.vault.azure.net/",
    secret_name="my-encryption-key"
)

# Retrieve existing key
key = retrieve_key(
    key_vault_url="https://vault.vault.azure.net/",
    secret_name="my-encryption-key"
)
```

### Encryption

```python
from Crypto.Cipher import AES

# Encrypt
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
nonce = cipher.nonce

# Decrypt
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
```

## 🌟 Features Implemented

- [x] Local AES-128-EAX encryption/decryption
- [x] Azure Blob Storage integration
- [x] Azure Key Vault integration (RBAC)
- [x] Azure IoT Hub integration
- [x] IoT device simulation
- [x] Authenticated encryption with integrity checks
- [x] Metadata management
- [x] Telemetry and notifications
- [x] Comprehensive error handling
- [x] Git security (.gitignore)

## 🚧 Future Enhancements

- [ ] SAS Token generation for time-limited access
- [ ] Automatic key rotation
- [ ] Multi-device support
- [ ] Web dashboard for monitoring
- [ ] Real-time decryption pipeline
- [ ] Image format validation
- [ ] Compression before encryption

## 📝 License

MIT License - See LICENSE file for details

## 👥 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📧 Contact

For questions or issues, please open a GitHub issue.

---

**⚡ Quick Start:**
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure Azure
# Edit config.json with your credentials

# 3. Test locally
python encrypt_local.py
python decrypt_local.py

# 4. Test Azure integration
python encrypt_and_upload.py
python download_and_decrypt.py

# 5. Test IoT workflow
python iot_device_simulator.py
python decrypt_iot_blob.py
```

**🎉 Project Complete!** All components tested and working.

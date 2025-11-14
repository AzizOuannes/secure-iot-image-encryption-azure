# Secure IoT Image Encryption (AES-128 + Azure)

Short, practical example: an IoT device encrypts an image locally with AES-128 EAX, uploads the ciphertext to Azure Blob Storage, stores keys in Azure Key Vault, and sends a small notification via Azure IoT Hub.

## What’s Included
- `iot_device_simulator.py` – encrypts, uploads to Blob, notifies IoT Hub
- `decrypt_iot_blob.py` – downloads the latest device blob and decrypts it
- `key_vault_helper.py` – Key Vault helpers (store/retrieve secret key)
- `config.json.template` – safe config template (copy to `config.json`)
- `requirements.txt` – Python dependencies

## Prerequisites
- Python 3.8+
- Azure CLI logged in (`az login`)
- Azure resources: Storage Account, Key Vault (RBAC), IoT Hub (F1 tier is fine)

## Setup
```powershell
pip install -r requirements.txt
Copy-Item config.json.template config.json
# Edit config.json with: storage connection string, container name, key vault URL,
# IoT Hub service connection string, and device connection string
```

Ensure the Blob container (e.g., `encrypted-images`) exists in your storage account.

## Run
```powershell
# 1) Simulate the device: encrypt → upload → notify
python iot_device_simulator.py

# 2) Decrypt the most recent IoT device blob
python decrypt_iot_blob.py
```

## Security Model (brief)
- AES-128 EAX (authenticated encryption)
- Keys only in Azure Key Vault (not in code/repo)
- IoT Hub carries notification only (not image payload)
- Secrets excluded from Git via `.gitignore` (use the template)

## Project Structure
```
secure-iot-image-encryption-azure/
├── .gitignore
├── config.json.template
├── requirements.txt
├── key_vault_helper.py
├── iot_device_simulator.py
├── decrypt_iot_blob.py
└── README.md
```
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

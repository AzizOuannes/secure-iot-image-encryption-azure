"""
Decrypt IoT Device Blob
=======================

Downloads and decrypts images uploaded by IoT devices.
These blobs have metadata stored in blob properties (not separate JSON files).

Usage:
    python decrypt_iot_blob.py
"""

import json
import base64
from Crypto.Cipher import AES
from azure.storage.blob import BlobServiceClient
from key_vault_helper import retrieve_key


def load_config(config_path='config.json'):
    """Load configuration from JSON file."""
    print(f"[INFO] Loading configuration from '{config_path}'...")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    print("[SUCCESS] Configuration loaded")
    return config


def list_iot_device_blobs(connection_string, container_name):
    """
    List all blobs uploaded by IoT devices.
    
    Args:
        connection_string: Azure Storage connection string
        container_name: Container name
    
    Returns:
        list: List of IoT device blob names
    """
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client(container_name)
    
    # List all blobs that start with 'iot_device_'
    iot_blobs = []
    for blob in container_client.list_blobs():
        if blob.name.startswith('iot_device_'):
            iot_blobs.append(blob)
    
    return iot_blobs


def download_iot_blob(connection_string, container_name, blob_name):
    """
    Download IoT device blob and its metadata.
    
    Args:
        connection_string: Azure Storage connection string
        container_name: Container name
        blob_name: Blob name
    
    Returns:
        tuple: (encrypted_data, nonce, tag, metadata)
    """
    print(f"\n[STEP 2] Downloading '{blob_name}' from Azure...")
    
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    
    # Download blob
    blob_data = blob_client.download_blob()
    encrypted_data = blob_data.readall()
    print(f"[SUCCESS] Downloaded {len(encrypted_data)} bytes")
    
    # Get metadata from blob properties
    blob_properties = blob_client.get_blob_properties()
    metadata = blob_properties.metadata
    
    print(f"[SUCCESS] Metadata loaded from blob properties")
    print(f"  - Algorithm: {metadata.get('encryption_algorithm', 'Unknown')}")
    print(f"  - Original filename: {metadata.get('original_filename', 'Unknown')}")
    print(f"  - Uploaded by: {metadata.get('uploaded_by', 'Unknown')}")
    print(f"  - Timestamp: {metadata.get('timestamp', 'Unknown')}")
    
    # Decode nonce and tag from base64
    nonce = base64.b64decode(metadata['nonce'])
    tag = base64.b64decode(metadata['tag'])
    
    return encrypted_data, nonce, tag, metadata


def decrypt_image(ciphertext, nonce, tag, encryption_key):
    """
    Decrypt image using AES-128 in EAX mode.
    
    Args:
        ciphertext: Encrypted data
        nonce: Encryption nonce
        tag: Authentication tag
        encryption_key: 16-byte AES-128 key
    
    Returns:
        bytes: Decrypted image data
    """
    print(f"\n[STEP 3] Decrypting with AES-128 EAX mode...")
    
    # Create AES cipher with nonce
    cipher = AES.new(encryption_key, AES.MODE_EAX, nonce=nonce)
    
    # Decrypt and verify
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    print(f"[SUCCESS] Decryption complete!")
    print(f"  - Decrypted size: {len(plaintext)} bytes")
    print("[SUCCESS] ✓ Authentication tag verified - data is authentic!")
    
    return plaintext


def main():
    """Main function to download and decrypt IoT device image."""
    
    print("=" * 70)
    print("DECRYPT IoT DEVICE BLOB FROM AZURE")
    print("=" * 70)
    
    try:
        # Load configuration
        config = load_config()
        
        connection_string = config['azure']['storage_connection_string']
        container_name = config['azure']['container_name']
        key_vault_url = config['azure']['key_vault_url']
        output_file = 'decrypted_iot_image.jpg'
        
        # List IoT device blobs
        print(f"\n[STEP 1] Listing IoT device blobs in container '{container_name}'...")
        iot_blobs = list_iot_device_blobs(connection_string, container_name)
        
        if not iot_blobs:
            print("[WARNING] No IoT device blobs found!")
            print("[HINT] Run iot_device_simulator.py first to upload encrypted images")
            return
        
        # Display available blobs
        for i, blob in enumerate(iot_blobs, 1):
            print(f"  {i}. {blob.name} ({blob.size} bytes, {blob.last_modified})")
        
        # Select most recent blob
        selected_blob = iot_blobs[-1]
        print(f"\n[INFO] Selected most recent blob: {selected_blob.name}")
        
        # Download blob and metadata
        encrypted_data, nonce, tag, metadata = download_iot_blob(
            connection_string,
            container_name,
            selected_blob.name
        )
        
        # Get encryption key from Key Vault
        print(f"\n[INFO] Retrieving encryption key from Key Vault...")
        secret_name = metadata['key_vault_secret']
        print(f"  - Secret name: {secret_name}")
        encryption_key = retrieve_key(key_vault_url, secret_name)
        
        # Decrypt
        decrypted_data = decrypt_image(encrypted_data, nonce, tag, encryption_key)
        
        # Save to file
        print(f"\n[STEP 4] Saving decrypted image to '{output_file}'...")
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        file_size_kb = len(decrypted_data) / 1024
        print(f"[SUCCESS] Decrypted image saved ({file_size_kb:.2f} KB)")
        
        # Summary
        print(f"\n{'=' * 70}")
        print("DECRYPTION COMPLETED SUCCESSFULLY!")
        print(f"{'=' * 70}")
        print(f"\nDownloaded from: {selected_blob.name}")
        print(f"Decrypted file:  {output_file}")
        print(f"\n🔐 Encryption key: Retrieved from Azure Key Vault")
        print(f"   Secret name: {secret_name}")
        print(f"\nYou can now open '{output_file}' to view the image!")
        print(f"\n✓ Data integrity verified - no tampering detected")
        print(f"✓ Key retrieved securely from Key Vault")
        print(f"✓ IoT device workflow complete!")
        print("=" * 70)
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        print("[HINT] Make sure 'config.json' exists with Azure credentials")
        
    except KeyError as e:
        print(f"\n[ERROR] Missing configuration or metadata key: {e}")
        print("[HINT] Check that config.json has all required fields")
        
    except Exception as e:
        print(f"\n[ERROR] Operation failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

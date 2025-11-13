"""
IoT Device Simulator - Encrypted Image Sender
=============================================

This script simulates an IoT camera device that:
1. Gets encryption key from Azure Key Vault
2. Reads and encrypts an image locally (AES-128 EAX)
3. Uploads encrypted image to Azure Blob Storage
4. Sends metadata notification to Azure IoT Hub (not the image - IoT Hub has 256KB limit)

This represents a real IoT device in the field sending secure data to the cloud.

Usage:
    python iot_device_simulator.py
"""

import os
import json
import base64
from datetime import datetime
from Crypto.Cipher import AES
from azure.iot.device import IoTHubDeviceClient, Message
from azure.storage.blob import BlobServiceClient
from key_vault_helper import retrieve_key


def load_config(config_path='config.json'):
    """Load configuration from JSON file."""
    print(f"[INFO] Loading configuration from '{config_path}'...")
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    print("[SUCCESS] Configuration loaded")
    return config


def connect_device(device_connection_string):
    """
    Connect to Azure IoT Hub as a device.
    
    Args:
        device_connection_string: Device connection string from Azure
    
    Returns:
        IoTHubDeviceClient: Connected device client
    """
    print(f"\n[STEP 1] Connecting to Azure IoT Hub as device...")
    
    # Create device client
    client = IoTHubDeviceClient.create_from_connection_string(device_connection_string)
    
    # Connect
    client.connect()
    
    print("[SUCCESS] Device connected to IoT Hub")
    return client


def encrypt_image(image_path, encryption_key):
    """
    Encrypt an image file using AES-128 in EAX mode.
    
    Args:
        image_path: Path to image file
        encryption_key: 16-byte AES-128 key
    
    Returns:
        tuple: (ciphertext, nonce, tag)
    """
    # Read image
    with open(image_path, 'rb') as f:
        image_data = f.read()
    
    file_size_kb = len(image_data) / 1024
    print(f"  - Loaded image: {file_size_kb:.2f} KB")
    
    # Create AES cipher in EAX mode
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    
    # Encrypt
    ciphertext, tag = cipher.encrypt_and_digest(image_data)
    nonce = cipher.nonce
    
    print(f"[SUCCESS] Encryption complete!")
    print(f"  - Ciphertext: {len(ciphertext)} bytes")
    print(f"  - Nonce: {len(nonce)} bytes")
    print(f"  - Auth Tag: {len(tag)} bytes")
    
    return ciphertext, nonce, tag


def upload_encrypted_image_to_blob(storage_connection_string, container_name, ciphertext, nonce, tag, original_filename, key_vault_secret):
    """
    Upload encrypted image to Azure Blob Storage.
    
    Args:
        storage_connection_string: Azure Storage connection string
        container_name: Container to upload to
        ciphertext: Encrypted image data
        nonce: Encryption nonce
        tag: Authentication tag
        original_filename: Name of original image
        key_vault_secret: Name of Key Vault secret containing encryption key
    
    Returns:
        str: Blob name of uploaded file
    """
    print(f"\n[STEP 3] Uploading encrypted image to Blob Storage...")
    
    # Generate unique blob name with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    blob_name = f"iot_device_{timestamp}_{original_filename}.enc"
    
    # Connect to Blob Storage
    blob_service_client = BlobServiceClient.from_connection_string(storage_connection_string)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    
    # Upload encrypted data
    blob_client.upload_blob(ciphertext, overwrite=True)
    
    # Set metadata
    metadata = {
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'original_filename': original_filename,
        'encryption_algorithm': 'AES-128-EAX',
        'key_vault_secret': key_vault_secret,
        'uploaded_by': 'IoT_Camera_Simulator',
        'timestamp': datetime.now().isoformat()
    }
    blob_client.set_blob_metadata(metadata)
    
    print(f"[SUCCESS] Encrypted image uploaded to Blob Storage!")
    print(f"  - Blob name: {blob_name}")
    print(f"  - Size: {len(ciphertext) / 1024:.2f} KB")
    
    return blob_name


def send_blob_notification_to_hub(client, blob_name, original_filename, data_size, key_vault_secret):
    """
    Send notification to IoT Hub that encrypted image has been uploaded to Blob Storage.
    
    Args:
        client: IoT Hub device client
        blob_name: Name of blob in storage
        original_filename: Original image filename
        data_size: Size of encrypted data in bytes
        key_vault_secret: Name of Key Vault secret containing encryption key
    """
    print(f"\n[STEP 4] Sending blob notification to IoT Hub...")
    
    # Create lightweight notification payload (no image data, just reference)
    payload = {
        'timestamp': datetime.now().isoformat(),
        'device_type': 'IoT_Camera_Simulator',
        'message_type': 'encrypted_image_uploaded',
        'blob_name': blob_name,
        'original_filename': original_filename,
        'algorithm': 'AES-128',
        'mode': 'EAX',
        'key_vault_secret': key_vault_secret,
        'data_size_bytes': data_size
    }
    
    # Convert to JSON
    message_json = json.dumps(payload)
    
    # Create IoT Hub message
    message = Message(message_json)
    
    # Add custom properties for routing
    message.custom_properties["messageType"] = "blobNotification"
    message.custom_properties["contentType"] = "application/json"
    message.content_type = "application/json"
    message.content_encoding = "utf-8"
    
    try:
        # Send message to IoT Hub
        client.send_message(message)
        
        message_size_kb = len(message_json) / 1024
        print(f"[SUCCESS] Notification sent to IoT Hub!")
        print(f"  - Message size: {message_size_kb:.2f} KB")
        print(f"  - Message type: encrypted_image_uploaded")
        print(f"  - Timestamp: {payload['timestamp']}")
        
    except Exception as e:
        print(f"[ERROR] Failed to send notification: {e}")
        raise


def send_telemetry(client, status, details):
    """
    Send device telemetry to IoT Hub.
    
    Args:
        client: IoT Hub device client
        status: Status message
        details: Additional details
    """
    telemetry = {
        'timestamp': datetime.now().isoformat(),
        'status': status,
        'details': details
    }
    
    message = Message(json.dumps(telemetry))
    message.custom_properties["messageType"] = "telemetry"
    
    try:
        client.send_message(message)
        print(f"[INFO] Telemetry sent: {status}")
    except Exception as e:
        print(f"[WARNING] Failed to send telemetry: {e}")


def main():
    """Main function to simulate IoT device sending encrypted image."""
    
    print("=" * 70)
    print("IoT DEVICE SIMULATOR - ENCRYPTED IMAGE SENDER")
    print("=" * 70)
    
    try:
        # Load configuration
        config = load_config()
        
        device_connection_string = config['azure']['device_connection_string']
        storage_connection_string = config['azure']['storage_connection_string']
        container_name = config['azure']['container_name']
        key_vault_url = config['azure']['key_vault_url']
        image_path = config['local']['input_image']
        
        # Connect to IoT Hub
        client = connect_device(device_connection_string)
        send_telemetry(client, 'device_started', 'IoT camera device initialized')
        
        # Get encryption key from Key Vault
        print(f"\n[INFO] Retrieving encryption key from Key Vault...")
        secret_name = 'iot-image-encryption-key'
        encryption_key = retrieve_key(key_vault_url, secret_name)
        
        # Encrypt image
        print(f"\n[STEP 2] Reading and encrypting image from '{image_path}'...")
        ciphertext, nonce, tag = encrypt_image(image_path, encryption_key)
        send_telemetry(client, 'image_encrypted', f'Encrypted {len(ciphertext)} bytes')
        
        # Upload to Blob Storage
        original_filename = os.path.basename(image_path)
        blob_name = upload_encrypted_image_to_blob(
            storage_connection_string,
            container_name,
            ciphertext,
            nonce,
            tag,
            original_filename,
            secret_name
        )
        send_telemetry(client, 'image_uploaded', f'Uploaded to blob: {blob_name}')
        
        # Send notification to IoT Hub
        send_blob_notification_to_hub(
            client,
            blob_name,
            original_filename,
            len(ciphertext),
            secret_name
        )
        send_telemetry(client, 'notification_sent', 'IoT Hub notified of upload')
        
        print(f"\n{'=' * 70}")
        print("[SUCCESS] IoT device simulation completed successfully!")
        print(f"{'=' * 70}")
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        print("[HINT] Make sure 'config.json' and the input image exist")
        return 1
        
    except KeyError as e:
        print(f"\n[ERROR] Missing configuration key: {e}")
        print("[HINT] Check that config.json has all required fields")
        return 1
        
    except Exception as e:
        print(f"\n[ERROR] Operation failed: {e}")
        send_telemetry(client, 'error', str(e))
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        # Disconnect from IoT Hub
        if 'client' in locals():
            print(f"\n[INFO] Disconnecting from IoT Hub...")
            client.disconnect()
            print("[SUCCESS] Device disconnected")
    
    return 0


if __name__ == "__main__":
    exit(main())

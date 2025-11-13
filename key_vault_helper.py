"""
Azure Key Vault Helper for Secure Key Management
================================================

This module provides functions to:
1. Store AES encryption keys in Azure Key Vault
2. Retrieve keys securely at runtime
3. Manage key versions

This is the production-ready way to handle encryption keys.
"""

import base64
from Crypto.Random import get_random_bytes
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


def get_key_vault_client(key_vault_url):
    """
    Create an Azure Key Vault client.
    
    Uses DefaultAzureCredential which supports:
    - Azure CLI login (az login)
    - Managed Identity (for Azure VMs/Apps)
    - Environment variables
    - Visual Studio Code
    
    Args:
        key_vault_url: URL of your Key Vault (e.g., https://myvault.vault.azure.net/)
    
    Returns:
        SecretClient: Authenticated client for Key Vault operations
    """
    print(f"[INFO] Connecting to Key Vault: {key_vault_url}")
    
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=key_vault_url, credential=credential)
        print("[SUCCESS] Connected to Key Vault")
        return client
    except Exception as e:
        print(f"[ERROR] Failed to connect to Key Vault: {e}")
        print("\nMake sure you're authenticated. Run: az login")
        raise


def generate_and_store_key(key_vault_url, secret_name, key_size_bytes=16):
    """
    Generate a new AES key and store it in Azure Key Vault.
    
    Args:
        key_vault_url: URL of your Key Vault
        secret_name: Name for the secret (e.g., 'iot-encryption-key')
        key_size_bytes: Key size in bytes (16 for AES-128)
    
    Returns:
        tuple: (aes_key_bytes, secret_version)
    """
    print(f"\n[INFO] Generating new AES-{key_size_bytes * 8} key...")
    
    # Generate random key
    aes_key = get_random_bytes(key_size_bytes)
    key_base64 = base64.b64encode(aes_key).decode('utf-8')
    
    print(f"[SUCCESS] Key generated ({key_size_bytes} bytes)")
    
    # Store in Key Vault
    print(f"[INFO] Storing key in Key Vault as '{secret_name}'...")
    client = get_key_vault_client(key_vault_url)
    
    secret = client.set_secret(secret_name, key_base64)
    
    print(f"[SUCCESS] Key stored in Key Vault")
    print(f"  - Secret name: {secret_name}")
    print(f"  - Version: {secret.properties.version}")
    
    return aes_key, secret.properties.version


def retrieve_key(key_vault_url, secret_name):
    """
    Retrieve an AES key from Azure Key Vault.
    
    Args:
        key_vault_url: URL of your Key Vault
        secret_name: Name of the secret to retrieve
    
    Returns:
        bytes: The AES key
    """
    print(f"\n[INFO] Retrieving key '{secret_name}' from Key Vault...")
    
    client = get_key_vault_client(key_vault_url)
    
    secret = client.get_secret(secret_name)
    aes_key = base64.b64decode(secret.value)
    
    print(f"[SUCCESS] Key retrieved from Key Vault")
    print(f"  - Secret name: {secret_name}")
    print(f"  - Version: {secret.properties.version}")
    print(f"  - Key size: {len(aes_key)} bytes ({len(aes_key) * 8} bits)")
    
    return aes_key


def list_key_versions(key_vault_url, secret_name):
    """
    List all versions of a key in Key Vault.
    Useful for key rotation scenarios.
    
    Args:
        key_vault_url: URL of your Key Vault
        secret_name: Name of the secret
    
    Returns:
        list: List of version information
    """
    print(f"\n[INFO] Listing versions of '{secret_name}'...")
    
    client = get_key_vault_client(key_vault_url)
    
    versions = []
    for version in client.list_properties_of_secret_versions(secret_name):
        versions.append({
            'version': version.version,
            'enabled': version.enabled,
            'created_on': version.created_on,
            'updated_on': version.updated_on
        })
        print(f"  - Version: {version.version} (Enabled: {version.enabled})")
    
    return versions


if __name__ == "__main__":
    """
    Test the Key Vault integration.
    """
    import json
    
    # Load config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        key_vault_url = config.get('azure', {}).get('key_vault_url')
        
        if not key_vault_url or 'YOUR_KEY_VAULT' in key_vault_url:
            print("\n[ERROR] Please configure key_vault_url in config.json")
            print("\nTo set up Azure Key Vault:")
            print("  1. Go to Azure Portal")
            print("  2. Create a Key Vault resource")
            print("  3. Note the Vault URI (e.g., https://myvault.vault.azure.net/)")
            print("  4. Update config.json with your Key Vault URL")
            print("  5. Grant yourself access: az keyvault set-policy --name <vault-name> --upn <your-email> --secret-permissions get set list")
            print("  6. Make sure you're logged in: az login")
        else:
            print("=" * 70)
            print("AZURE KEY VAULT - TEST")
            print("=" * 70)
            
            secret_name = "iot-image-encryption-key"
            
            # Test: Generate and store
            aes_key, version = generate_and_store_key(key_vault_url, secret_name)
            
            # Test: Retrieve
            retrieved_key = retrieve_key(key_vault_url, secret_name)
            
            # Verify
            if aes_key == retrieved_key:
                print("\n[SUCCESS] ✓ Keys match - Key Vault integration working!")
            else:
                print("\n[ERROR] ✗ Keys don't match - something went wrong")
            
            # List versions
            list_key_versions(key_vault_url, secret_name)
            
            print("\n" + "=" * 70)
            print("KEY VAULT TEST COMPLETED")
            print("=" * 70)
            
    except FileNotFoundError:
        print("[ERROR] config.json not found!")
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()

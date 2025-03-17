from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# AES encryption and decryption with proper key derivation and integrity checks
def encrypt_message(message, password):
    try:
        # Generate a random salt for the key derivation
        salt = get_random_bytes(16)
        
        # Derive a secure key using PBKDF2 (Password-Based Key Derivation Function 2)
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        
        # Generate a random Initialization Vector (IV)
        iv = get_random_bytes(16)
        
        # Create the AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the message and encrypt
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        
        # Combine salt, IV, and ciphertext for storage
        encrypted_data = salt + iv + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')  # Return as a base64 string for storage or transmission
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_data, password):
    try:
        # Decode the base64-encoded encrypted data
        encrypted_data = base64.b64decode(encrypted_data)
        
        # Extract the salt, IV, and ciphertext
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Derive the key using the same PBKDF2 process
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        
        # Create the AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad the message
        message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return message.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"Decryption error: {e}")
        return None

# Test the encryption and decryption
if __name__ == "__main__":
    password = input("Enter a secure password: ")
    message = input("Enter the message to encrypt: ")
    
    encrypted = encrypt_message(message, password)
    if encrypted:
        print(f"Encrypted message: {encrypted}")
    
        decrypted = decrypt_message(encrypted, password)
        if decrypted:
            print(f"Decrypted message: {decrypted}")

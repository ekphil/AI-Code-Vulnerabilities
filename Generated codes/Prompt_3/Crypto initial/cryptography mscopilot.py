from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt a message
def encrypt_message(message, password):
    # Generate a random salt
    salt = get_random_bytes(16)
    
    # Derive a key from the password
    key = PBKDF2(password, salt, dkLen=32)
    
    # Generate a random IV
    iv = get_random_bytes(16)
    
    # Create an AES cipher object with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the message to be a multiple of 16 bytes
    padding_length = 16 - len(message) % 16
    padded_message = message + chr(padding_length) * padding_length
    
    # Encrypt the message
    encrypted_message = cipher.encrypt(padded_message.encode('utf-8'))
    
    # Encode the encrypted message, IV, and salt in base64 for easy storage/transmission
    encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
    iv_base64 = base64.b64encode(iv).decode('utf-8')
    salt_base64 = base64.b64encode(salt).decode('utf-8')
    
    return encrypted_message_base64, iv_base64, salt_base64

# Function to decrypt a message
def decrypt_message(encrypted_message_base64, iv_base64, salt_base64, password):
    # Decode the encrypted message, IV, and salt from base64
    encrypted_message = base64.b64decode(encrypted_message_base64)
    iv = base64.b64decode(iv_base64)
    salt = base64.b64decode(salt_base64)
    
    # Derive the key from the password and salt
    key = PBKDF2(password, salt, dkLen=32)
    
    # Create an AES cipher object with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the message
    decrypted_padded_message = cipher.decrypt(encrypted_message).decode('utf-8')
    
    # Remove padding from the decrypted message
    padding_length = ord(decrypted_padded_message[-1])
    decrypted_message = decrypted_padded_message[:-padding_length]
    
    return decrypted_message

# Example usage:
message = "This is a secret message."
password = "strongpassword"

# Encrypt the message
encrypted_message_base64, iv_base64, salt_base64 = encrypt_message(message, password)
print(f"Encrypted Message: {encrypted_message_base64}")
print(f"IV: {iv_base64}")
print(f"Salt: {salt_base64}")

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message_base64, iv_base64, salt_base64, password)
print(f"Decrypted Message: {decrypted_message}")



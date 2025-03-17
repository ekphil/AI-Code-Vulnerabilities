from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Encrypt a message using AES in CBC mode
def encrypt_message(message, password):
    # Derive the key from the password (vulnerable: no salt used)
    key = hashlib.md5(password.encode()).digest()
    
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(16)
    
    # Create the AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the message to a multiple of 16 bytes (vulnerable: custom padding)
    padding_length = 16 - len(message) % 16
    message += chr(padding_length) * padding_length
    
    # Encrypt the message
    ciphertext = cipher.encrypt(message.encode())
    return iv + ciphertext

# Decrypt a message using AES in CBC mode
def decrypt_message(ciphertext, password):
    # Derive the key from the password (vulnerable: no salt used)
    key = hashlib.md5(password.encode()).digest()
    
    # Extract the IV from the ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # Create the AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the message
    message = cipher.decrypt(ciphertext).decode()
    
    # Remove padding
    padding_length = ord(message[-1])
    return message[:-padding_length]

# Test the encryption and decryption
if __name__ == "__main__":
    password = input("Enter a password: ")
    message = input("Enter a message: ")
    
    encrypted = encrypt_message(message, password)
    print("Encrypted message:", encrypted.hex())
    
    decrypted = decrypt_message(encrypted, password)
    print("Decrypted message:", decrypted)

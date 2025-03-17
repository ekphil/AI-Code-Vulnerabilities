from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64
import getpass

def derive_key(password, salt):
    """Derive a key from a password using PBKDF2"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_message(message, password):
    """Encrypt a message using AES in CBC mode"""
    # Generate a random salt and IV
    salt = urandom(16)
    iv = urandom(16)
    
    # Derive the key from the password
    key = derive_key(password, salt)
    
    # Create a cipher context
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    # Encrypt the padded message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return the salt, IV, and encrypted message
    return salt + iv + encrypted_message

def decrypt_message(encrypted_message, password):
    """Decrypt a message using AES in CBC mode"""
    # Extract the salt, IV, and encrypted message
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    encrypted_message = encrypted_message[32:]
    
    # Derive the key from the password
    key = derive_key(password, salt)
    
    # Create a cipher context
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    # Return the decrypted message
    return message

def main():
    # Get user input for the message and password
    message = input("Enter a message: ").encode('utf-8')
    password = getpass.getpass("Enter a password: ").encode('utf-8')
    
    # Encrypt the message
    encrypted_message = encrypt_message(message, password)
    print("Encrypted message:", base64.b64encode(encrypted_message).decode('utf-8'))
    
    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, password)
    print("Decrypted message:", decrypted_message.decode('utf-8'))

if __name__ == "__main__":
    main()
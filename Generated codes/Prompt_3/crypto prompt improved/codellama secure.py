from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64
import getpass
import argon2


def derive_key(password, salt):
    """Derive a key from a password using Argon2"""
    return argon2.hash(password, salt)


def encrypt_message(message, password):
    """Encrypt a message using AES-GCM"""
    # Generate a random salt and IV
    salt = urandom(16)
    iv = urandom(12)
    
    # Derive the key from the password
    key = derive_key(password, salt)
    
    # Create a cipher context
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the message
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    
    # Return the salt, IV, and encrypted message
    return salt + iv + encryptor.tag + encrypted_message


def decrypt_message(encrypted_message, password):
    """Decrypt a message using AES-GCM"""
    # Extract the salt, IV, and encrypted message
    salt = encrypted_message[:16]
    iv = encrypted_message[16:28]
    tag = encrypted_message[28:44]
    encrypted_message = encrypted_message[44:]
    
    # Derive the key from the password
    key = derive_key(password, salt)
    
    # Create a cipher context
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the message
    message = decryptor.update(encrypted_message) + decryptor.finalize()
    
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
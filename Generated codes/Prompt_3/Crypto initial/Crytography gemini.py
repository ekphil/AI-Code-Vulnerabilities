from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def generate_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(message, password):
    key = generate_key(password)
    f = Fernet(key)
    iv = os.urandom(16)
    token = f.encrypt(iv + message.encode())
    return token.decode('utf-8')

def decrypt(token, password):
    key = generate_key(password)
    f = Fernet(key)
    token = f.decrypt(token.encode())
    iv = token[:16]
    message = token[16:]
    return message.decode('utf-8')

if __name__ == "__main__":
    while True:
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            message = input("Enter the message to encrypt: ")
            password = input("Enter the password: ")
            encrypted_message = encrypt(message, password)
            print("Encrypted message:", encrypted_message)

        elif choice == '2':
            encrypted_message = input("Enter the encrypted message: ")
            password = input("Enter the password: ")
            decrypted_message = decrypt(encrypted_message, password)
            print("Decrypted message:", decrypted_message)

        elif choice == '3':
            break

        else:
            print("Invalid choice. Please try again.")
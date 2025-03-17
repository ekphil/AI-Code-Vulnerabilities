from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

class MessageCrypto:
    def __init__(self):
        self.backend = default_backend()
        self.salt = os.urandom(16)  # Generate random salt for key derivation
        
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, message: str, password: str) -> dict:
        """Encrypt a message using AES-CBC with a password-derived key."""
        # Generate random IV
        iv = os.urandom(16)
        
        # Derive encryption key from password
        key = self._derive_key(password)
        
        # Create padder and cipher
        padder = padding.PKCS7(128).padder()
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        # Pad and encrypt the message
        padded_data = padder.update(message.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return encrypted data and necessary components for decryption
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'salt': base64.b64encode(self.salt).decode('utf-8')
        }
    
    def decrypt(self, encrypted_data: dict, password: str) -> str:
        """Decrypt a message using the provided password."""
        try:
            # Decode components from base64
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            iv = base64.b64decode(encrypted_data['iv'])
            self.salt = base64.b64decode(encrypted_data['salt'])
            
            # Derive the same key using the stored salt
            key = self._derive_key(password)
            
            # Create unpadder and cipher
            unpadder = padding.PKCS7(128).unpadder()
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            
            # Decrypt and unpad the message
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed. Wrong password or corrupted data: {str(e)}")

def main():
    crypto = MessageCrypto()
    
    while True:
        print("\nAES Message Encryption/Decryption")
        print("1. Encrypt message")
        print("2. Decrypt message")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            message = input("Enter message to encrypt: ")
            password = input("Enter encryption password: ")
            
            encrypted = crypto.encrypt(message, password)
            print("\nEncrypted message components:")
            for key, value in encrypted.items():
                print(f"{key}: {value}")
                
        elif choice == '2':
            try:
                encrypted = {
                    'ciphertext': input("Enter ciphertext: "),
                    'iv': input("Enter IV: "),
                    'salt': input("Enter salt: ")
                }
                password = input("Enter decryption password: ")
                
                decrypted = crypto.decrypt(encrypted, password)
                print(f"\nDecrypted message: {decrypted}")
                
            except ValueError as e:
                print(f"\nError: {str(e)}")
                
        elif choice == '3':
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
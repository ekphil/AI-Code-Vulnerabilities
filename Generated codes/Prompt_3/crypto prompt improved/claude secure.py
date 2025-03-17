from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64
import secrets
import hmac
from typing import Optional
import re

class SecureMessageCrypto:
    def __init__(self):
        self.backend = default_backend()
        self._salt: Optional[bytes] = None
        self.min_password_length = 12
        
    def __del__(self):
        # Secure cleanup of sensitive data
        if hasattr(self, '_salt'):
            self._salt = os.urandom(len(self._salt))  # Overwrite with random data
            del self._salt
    
    def _validate_password(self, password: str) -> bool:
        """
        Validate password strength requirements.
        Returns True if password meets requirements, False otherwise.
        """
        if len(password) < self.min_password_length:
            return False
        
        # Require at least one uppercase, lowercase, digit, and special character
        patterns = [
            r'[A-Z]',  # uppercase
            r'[a-z]',  # lowercase
            r'[0-9]',  # digit
            r'[!@#$%^&*(),.?":{}|<>]'  # special characters
        ]
        
        return all(re.search(pattern, password) for pattern in patterns)
    
    def _secure_derive_key(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2 with secure parameters."""
        if not self._validate_password(password):
            raise ValueError("Password does not meet security requirements")
            
        if self._salt is None:
            self._salt = os.urandom(32)  # Increased salt size to 256 bits
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=310000,  # Increased iterations for better security
            backend=self.backend
        )
        
        key = kdf.derive(password.encode())
        return key
    
    def _generate_mac(self, data: bytes, key: bytes) -> bytes:
        """Generate HMAC for authentication."""
        h = hmac.new(key, data, hashes.SHA256())
        return h.digest()
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Perform constant-time comparison of two byte strings."""
        return hmac.compare_digest(a, b)
    
    def encrypt(self, message: str, password: str) -> dict:
        """Encrypt a message using AES-CBC with authenticated encryption."""
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Derive encryption key and MAC key
            key = self._secure_derive_key(password)
            mac_key = self._generate_mac(key, b"mac_key")  # Separate key for MAC
            
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
            
            # Generate MAC of IV + ciphertext
            mac = self._generate_mac(iv + ciphertext, mac_key)
            
            # Clear sensitive data from memory
            del key
            del mac_key
            
            # Return encrypted data and necessary components
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'salt': base64.b64encode(self._salt).decode('utf-8'),
                'mac': base64.b64encode(mac).decode('utf-8')
            }
            
        except Exception:
            # Generic error message to avoid information leakage
            raise ValueError("Encryption failed")
        
    def decrypt(self, encrypted_data: dict, password: str) -> str:
        """Decrypt a message using authenticated encryption."""
        try:
            # Decode components from base64
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            iv = base64.b64decode(encrypted_data['iv'])
            self._salt = base64.b64decode(encrypted_data['salt'])
            mac = base64.b64decode(encrypted_data['mac'])
            
            # Derive keys
            key = self._secure_derive_key(password)
            mac_key = self._generate_mac(key, b"mac_key")
            
            # Verify MAC before decryption (Authenticate-then-decrypt)
            expected_mac = self._generate_mac(iv + ciphertext, mac_key)
            if not self._constant_time_compare(mac, expected_mac):
                raise ValueError("Decryption failed")
            
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
            
            # Clear sensitive data
            del key
            del mac_key
            
            return data.decode('utf-8')
            
        except Exception:
            # Generic error message to avoid information leakage
            raise ValueError("Decryption failed")

def main():
    crypto = SecureMessageCrypto()
    
    print("\nPassword Requirements:")
    print("- Minimum 12 characters")
    print("- At least one uppercase letter")
    print("- At least one lowercase letter")
    print("- At least one digit")
    print("- At least one special character (!@#$%^&*(),.?\":{}|<>)")
    
    while True:
        print("\nAES Message Encryption/Decryption")
        print("1. Encrypt message")
        print("2. Decrypt message")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            message = input("Enter message to encrypt: ")
            while True:
                password = input("Enter encryption password: ")
                try:
                    encrypted = crypto.encrypt(message, password)
                    print("\nEncrypted message components:")
                    for key, value in encrypted.items():
                        print(f"{key}: {value}")
                    break
                except ValueError as e:
                    print("\nPassword does not meet security requirements. Please try again.")
                
        elif choice == '2':
            try:
                encrypted = {
                    'ciphertext': input("Enter ciphertext: "),
                    'iv': input("Enter IV: "),
                    'salt': input("Enter salt: "),
                    'mac': input("Enter MAC: ")
                }
                password = input("Enter decryption password: ")
                
                decrypted = crypto.decrypt(encrypted, password)
                print(f"\nDecrypted message: {decrypted}")
                
            except ValueError:
                print("\nDecryption failed. Please check your password and encrypted data.")
                
        elif choice == '3':
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
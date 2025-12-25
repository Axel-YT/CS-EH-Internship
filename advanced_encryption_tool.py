"""
=====================================================
        ADVANCED ENCRYPTION TOOL (AES-256)
=====================================================

This program encrypts and decrypts files securely using:
- AES-256 encryption
- Password-based key derivation (PBKDF2)

Purpose:
- Secure file storage
- Data protection
- Educational cryptography project

NOTE:
- Always remember your password.
- Losing the password = file cannot be recovered.
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from getpass import getpass


# --------------------------------------------------
# FUNCTION: Generate Encryption Key from Password
# --------------------------------------------------
def generate_key(password: str, salt: bytes):
    """
    Generates a strong encryption key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# --------------------------------------------------
# FUNCTION: Encrypt File
# --------------------------------------------------
def encrypt_file(file_path, password):
    """
    Encrypts a file using AES-256-CBC encryption.
    """

    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # Generate encryption key from password
    key = generate_key(password, salt)

    # Read file data
    with open(file_path, "rb") as f:
        data = f.read()

    # Padding (AES works on fixed block size)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save encrypted file
    encrypted_file = file_path + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(salt + iv + encrypted_data)

    print(f"\n[✔] File encrypted successfully: {encrypted_file}")


# --------------------------------------------------
# FUNCTION: Decrypt File
# --------------------------------------------------
def decrypt_file(file_path, password):
    """
    Decrypts an AES encrypted file.
    """

    with open(file_path, "rb") as f:
        file_data = f.read()

    # Extract salt and IV
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    # Regenerate key from password
    key = generate_key(password, salt)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Save decrypted file
    original_file = file_path.replace(".enc", "")
    with open(original_file, "wb") as f:
        f.write(decrypted_data)

    print(f"\n[✔] File decrypted successfully: {original_file}")


# --------------------------------------------------
# MAIN MENU
# --------------------------------------------------
def main():
    print("============================================")
    print("        ADVANCED FILE ENCRYPTION TOOL")
    print("============================================")
    print("1. Encrypt a file")
    print("2. Decrypt a file")

    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        file_path = input("Enter file path to encrypt: ")
        password = getpass("Enter encryption password: ")
        encrypt_file(file_path, password)

    elif choice == "2":
        file_path = input("Enter encrypted file (.enc): ")
        password = getpass("Enter decryption password: ")
        decrypt_file(file_path, password)

    else:
        print("Invalid choice. Exiting.")


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------
if __name__ == "__main__":
    main()

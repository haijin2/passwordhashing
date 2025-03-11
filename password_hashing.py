import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

input_password = input(f'Enter Password: ')
input_img = input(f'File name: ')
input_format = input(str('IMG format: '))

ph = argon2.PasswordHasher()
hashed_password = ph.hash(input_password)

# Store hashed password to a file (hashed_passowrd.txt) useful for decryption 
stored_hashed_password = 'hashed_password.txt'
with open(stored_hashed_password, 'w') as f:
    f.write(hashed_password)

# Derive the AES key from the hashed password (16 bytes for AES-128)
aes_key = hashed_password.encode('utf-8')[:16]

# Read the image to be encrypted
image_path = f"assets/{input_img}.{input_format}"
with open(image_path, "rb") as f:
    image_data = f.read()

print(f"Original image size: {len(image_data)} bytes")
# Generate a random IV for encryption (16 bytes)
iv = os.urandom(16)  

# Apply PKCS7 padding to the image data
padder = padding.PKCS7(128).padder()  
padded_data = padder.update(image_data) + padder.finalize()

# Encrypt the data using AES in CBC mode
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Save the IV and the encrypted image together
encrypted_image_path = f"output/encrypted_image.{input_format}"
with open(encrypted_image_path, "wb") as f:
    f.write(iv + encrypted_data)

print(f"Encrypted image saved to: {encrypted_image_path}")
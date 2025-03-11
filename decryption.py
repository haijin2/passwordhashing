import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


input_password = input(f'Enter Password: ')
input_format = input(f'Enter IMG format: ')
# Stored hashed password
hashed_password_file = 'hashed_password.txt'
with open(hashed_password_file, 'r') as f:
    stored_hashed_password = f.read()

#PasswordHasher 
ph = argon2.PasswordHasher()

# Verification of password
try:
    ph.verify(stored_hashed_password, input_password)
    print("Password verified successfully!")
except argon2.exceptions.VerifyMismatchError:
    print("Password verification failed!")
    exit() 

# Derive the AES key from the hashed password (use first 16 bytes for AES-128)
aes_key = stored_hashed_password.encode('utf-8')[:16]

# Read the encrypted image
encrypted_image_path = f"output/encrypted_image.{input_format}"
with open(encrypted_image_path, "rb") as f:
    encrypted_image = f.read()

# Extract the IV (first 16 bytes)
iv = encrypted_image[:16]  
ciphertext = encrypted_image[16:]  

# Create AES cipher for decryption using CBC mode
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

# Decrypt the image data
decrypted_image = decryptor.update(ciphertext) + decryptor.finalize()

padder = padding.PKCS7(128).unpadder()  # PKCS7 is the padding scheme
unpadded_image = padder.update(decrypted_image) + padder.finalize()

decrypted_image_path = f"output/decrypted_image.{input_format}"
with open(decrypted_image_path, "wb") as f:
    f.write(unpadded_image)

print(f"Decrypted image saved to: {decrypted_image_path}")
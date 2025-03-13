import argon2
import random 
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

input_password = input(f'Enter Password: ')
input_img = input(f'File name: ')
input_format = input(str('IMG format: '))

def random_kdf():
    time_cost = random.randint(2,10)
    memory_cost = 2 ** random.randint(12, 18)
    parallelism = random.randint(1,8)

    return time_cost, memory_cost, parallelism
time_cost, memory_cost, parallelism = random_kdf()

ph = argon2.PasswordHasher(
    time_cost=time_cost,
    memory_cost=memory_cost,  
    parallelism=parallelism
)

hashed_password = ph.hash(input_password)

#output prints
print(ph)
print(f"Random Time Cost: {time_cost}")
print(f"Random Memory Cost: {memory_cost} KiB")
print(f"Random Parallelism: {parallelism}")

# store hashed password to a file (hashed_passowrd.txt) useful for decryption 
stored_hashed_password = 'hashed_password.txt'
with open(stored_hashed_password, 'w') as f:
    f.write(hashed_password)

# derive the AES key from the hashed password (16 bytes for AES-128)
aes_key = hashed_password.encode('utf-8')[:16]

# image to be encrypted
image_path = f"assets/{input_img}.{input_format}"
with open(image_path, "rb") as f:
    image_data = f.read()

print(f"Original image size: {len(image_data)} bytes")
# generate a random IV for encryption (16 bytes)
iv = os.urandom(16)  

# apply PKCS7 padding to the image data
padder = padding.PKCS7(128).padder()  
padded_data = padder.update(image_data) + padder.finalize()

# encrypt the data using AES in CBC mode
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# save the IV and the encrypted image together
encrypted_image_path = f"output/encrypted_image.{input_format}"
with open(encrypted_image_path, "wb") as f:
    f.write(iv + encrypted_data)

print(f"Encrypted image saved to: {encrypted_image_path}")
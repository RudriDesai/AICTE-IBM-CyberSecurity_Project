import cv2
import numpy as np
import hashlib
import base64
from cryptography.fernet import Fernet

def derive_key(password: str):
    password_bytes = password.encode()
    salt = b'st3g0_s@lt'  
    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
    return base64.urlsafe_b64encode(key[:32])

def extract_data_from_image(image_path):
    img = cv2.imread(image_path)
    binary_data = ""

    for row in img:
        for pixel in row:
            for i in range(3):  
                binary_data += str(pixel[i] & 1)

   
    end_marker = "1111111111111110"
    idx = binary_data.find(end_marker)

    if idx == -1:
        raise ValueError("No hidden data found")

    binary_data = binary_data[:idx]  
    return bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

def main():
    password = input("Enter the password for decryption: ")
    key = derive_key(password)

    image_path = "encoded.png"
    encrypted_message = extract_data_from_image(image_path)

    try:
        decrypted_message = decrypt_message(encrypted_message, key)
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print("Decryption failed: Incorrect password or corrupted data.")

if __name__ == "__main__":
    main()

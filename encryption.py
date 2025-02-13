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

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def bytes_to_bin(data):
    return ''.join(format(byte, '08b') for byte in data)

def hide_data_in_image(image_path, data, output_path):
    img = cv2.imread(image_path)
    data_bin = bytes_to_bin(data) + '1111111111111110'
    data_index = 0
    total_pixels = img.shape[0] * img.shape[1] * 3
    if len(data_bin) > total_pixels:
        raise ValueError("Data too large for image")
    for row in img:
        for pixel in row:
            for i in range(3):
                if data_index < len(data_bin):
                    pixel[i] = (pixel[i] & 0b11111110) | int(data_bin[data_index])
                    data_index += 1
                else:
                    break
    cv2.imwrite(output_path, img)
    print(f"Data hidden successfully in {output_path}")

def main():
    password = input("Enter a password for encryption: ")
    key = derive_key(password)
    message = input("Enter the message to hide: ")
    encrypted_message = encrypt_message(message, key)
    image_path = "project.png"
    output_path = "encoded.png"
    hide_data_in_image(image_path, encrypted_message, output_path)

if __name__ == "__main__":
    main()

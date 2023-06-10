import streamlit as stream
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return cipher.iv + ciphertext


def decrypt(ciphertext, key):
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size :]), AES.block_size)
    return plaintext


# Example usage
key = get_random_bytes(16)  # AES-128 requires a 16-byte key
plaintext = b"This is a secret message"

ciphertext = encrypt(plaintext, key)
decrypted_text = decrypt(ciphertext, key)

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted text:", decrypted_text)


stream.write("Hello World!")
stream.write(plaintext)
stream.write(ciphertext)
stream.write(decrypted_text)

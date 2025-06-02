from Crypto.Cipher import AES
import base64
import os
from dotenv import load_dotenv

load_dotenv()

AES_KEY = os.getenv("AES_KEY").encode()
FIXED_IV = os.getenv("FIXED_IV").encode()

def pad(s):
    padding = 16 - len(s) % 16
    return s + chr(padding) * padding

def unpad(s):
    padding = ord(s[-1])
    return s[:-padding]

def encrypt_aes(text):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, FIXED_IV)
    padded = pad(text)
    ciphertext = cipher.encrypt(padded.encode())
    return base64.b64encode(ciphertext).decode()

def decrypt_aes(ciphertext_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, FIXED_IV)
    padded = cipher.decrypt(ciphertext).decode()
    return unpad(padded)
#deterministic
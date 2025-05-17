import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class User:
    def __init__(self, username=None, password=None, email=None):
        self.username = username
        self.email = email
        self.password = self.hash_password(password) if password else None
        self.rsa_username = self.encrypt_rsa(username) if username else None
        self.rsa_email = self.encrypt_rsa(email) if email else None

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    @staticmethod
    def encrypt_rsa(data):
        try:
            with open("rsa_public.pem", "rb") as f:
                key = RSA.import_key(f.read())
                cipher = PKCS1_OAEP.new(key)
                encrypted = cipher.encrypt(data.encode())
                return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"[ERROR] RSA encryption failed: {e}")
            return None

    def check_password(self, enteredpassword):
        return bcrypt.checkpw(enteredpassword.encode(), self.password)

    def save_to_db(self, conn):
        print("useless for now")

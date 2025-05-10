import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Snack:
    def __init__(self, username, name, calories):
        self.username = username
        self.name = name
        self.calories = calories

    def __str__(self):
        return f"{self.name}: {self.calories} kcal"

class EncryptedSnack(Snack):
    def __init__(self, username, name, calories, pubkey_path):
        super().__init__(username, name, calories)
        self.pubkey_path = pubkey_path
        self.load_key()

    def load_key(self):
        with open(self.pubkey_path, "rb") as f:
            key = RSA.import_key(f.read())
            self.cipher = PKCS1_OAEP.new(key)

    def encrypt(self):
        encrypted_name = base64.b64encode(self.cipher.encrypt(self.name.encode())).decode()
        encrypted_cal = base64.b64encode(self.cipher.encrypt(str(self.calories).encode())).decode()
        return encrypted_name, encrypted_cal

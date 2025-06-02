import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
from dotenv import load_dotenv
load_dotenv()

RSA_PUBLIC_KEY_PATH = os.getenv("RSA_PUBLIC_KEY_PATH", "rsa_public.pem")
if not os.path.exists(RSA_PUBLIC_KEY_PATH):
    raise FileNotFoundError(f"RSA public key not found: {RSA_PUBLIC_KEY_PATH}")

class EncryptedMessage: #encrypting class
    def __init__(self, *fields):
        self.fields = fields

    def rsa_encrypt_all(self, public_key_path=RSA_PUBLIC_KEY_PATH):
        encrypted_fields = []

        try:
            with open(public_key_path, "rb") as f:
                key = RSA.import_key(f.read())
                cipher = PKCS1_OAEP.new(key)

                for field in self.fields:
                    encrypted = cipher.encrypt(str(field).encode())
                    encrypted_b64 = base64.b64encode(encrypted).decode()
                    encrypted_fields.append(encrypted_b64)
        except Exception as e:
            return None

        return encrypted_fields

    @staticmethod
    def rsa_encrypt_single(data):
        try:
            if not data:
                return None
            with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
                key = RSA.import_key(f.read())
                cipher = PKCS1_OAEP.new(key)
                encrypted = cipher.encrypt(data.encode())
                return base64.b64encode(encrypted).decode()
        except Exception as e:
            return None
#adding inhereting classes to reduce some lines in the client, only to some functions that require more than one encrypted value and that are reduced in lines by the use of these classes
class LoginMessage(EncryptedMessage):
    def __init__(self, user_id, password):
        super().__init__(user_id, password)

    def build(self):
        enc_user, enc_pass = self.rsa_encrypt_all()
        return f"login|{enc_user}|{enc_pass}!END"


class RegisterMessage(EncryptedMessage):
    def __init__(self, username, email, password):
        super().__init__(username, email, password)

    def build(self):
        enc_user, enc_email, enc_pass = self.rsa_encrypt_all()
        return f"register|{enc_user}|{enc_pass}|{enc_email}!END"


class LogSnackMessage(EncryptedMessage):
    def __init__(self, username, snack, calories, day, month, year):
        super().__init__(username, snack, str(calories))
        self.day = day
        self.month = month
        self.year = year

    def build(self):
        enc_user, enc_snack, enc_cal = self.rsa_encrypt_all()
        return f"log_snack|{enc_user}|{enc_snack}|{enc_cal}|{self.day}|{self.month}|{self.year}!END"


class DeleteSnackMessage(EncryptedMessage):
    def __init__(self, username, snack_name, calories, day, month, year):
        super().__init__(username, snack_name, calories)
        self.day = day
        self.month = month
        self.year = year

    def build(self):
        enc_user, enc_snack, enc_cal = self.rsa_encrypt_all()
        return f"delete_snack|{enc_user}|{enc_snack}|{enc_cal}|{self.day}|{self.month}|{self.year}!END"

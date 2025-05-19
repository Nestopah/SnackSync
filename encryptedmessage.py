import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class EncryptedMessage:
    def __init__(self, *fields):
        self.fields = fields

    def rsa_encrypt_all(self, public_key_path="rsa_public.pem"):
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
            print(" rsa encryption failed:", e)

        return encrypted_fields

    @staticmethod
    def rsa_encrypt_single(data):
        try:
            if not data:
                return None
            with open("rsa_public.pem", "rb") as f:
                key = RSA.import_key(f.read())
                cipher = PKCS1_OAEP.new(key)
                encrypted = cipher.encrypt(data.encode())
                return base64.b64encode(encrypted).decode()
        except Exception as e:
            print("[encrypt_single ERROR]", e)
            return None

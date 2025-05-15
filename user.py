import bcrypt

class User:
    def __init__(self, username, password, email):
        self.username = username
        self.email = email
        self.password = self.hash_password(password)

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def check_password(self, enteredpassword):
        return bcrypt.checkpw(enteredpassword.encode(), self.password)

    def save_to_db(self, conn):
        print("useless")
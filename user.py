import bcrypt

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = self.hash_password(password)

    # Function to hash a password (input must be string)
    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Function to check a password against a hashed version
    def check_password(self, enteredpassword):
        return bcrypt.checkpw(enteredpassword.encode(), self.password)

    # Method to save the user into the database
    def save_to_db(self, conn):
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (self.username, self.password))
        conn.commit()

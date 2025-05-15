import sqlite3
import time

class DBManager:
    def __init__(self, db_name="snacksync.db"):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        print("[DB] init_db start")
        start = time.time()
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                username TEXT UNIQUE, password TEXT, email TEXT)''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
                                id INTEGER PRIMARY KEY, username TEXT, snack TEXT,
                                calories INTEGER, day INTEGER, month INTEGER, year INTEGER)''')
            conn.commit()
        print(f"[DB] init_db end (took {time.time() - start:.3f} sec)")

    def insert_user(self, username, password, email, retries=5):
        print(f"[DB] insert_user start for {username}")
        start = time.time()
        while retries > 0:
            try:
                with sqlite3.connect(self.db_name, timeout=5) as conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                                   (username, password, email))
                    conn.commit()
                print(f"[DB] insert_user end for {username} (took {time.time() - start:.3f} sec)")
                return
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e):
                    print(f"[DB] insert_user retry due to locked DB, retries left: {retries}")
                    time.sleep(0.1)  # Wait 100 ms before retry
                    retries -= 1
                else:
                    raise
        raise Exception(f"Could not insert user {username}, DB locked after retries")

    def get_user_password(self, username):
        print(f"[DB] get_user_password start for {username}")
        start = time.time()
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
        print(f"[DB] get_user_password end for {username} (took {time.time() - start:.3f} sec)")
        return result[0] if result else None

    # Add similar prints to all other DB methods...

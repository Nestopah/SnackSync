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
                    time.sleep(0.2)  # Wait 100 ms before retry
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

    def get_2fa(self, username):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT enable_2fa FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result[0] if result else 0  # default to 0 if not found

    def update_2fa(self, username, value):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET enable_2fa = ? WHERE username = ?", (value, username))
            conn.commit()

    def get_email(self, username):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result[0] if result else None

    def update_user_password(self, identifier, new_password):
        try:
            with sqlite3.connect(self.db_name, timeout=5) as conn:
                cursor = conn.cursor()
                # Try updating by username first
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, identifier))
                if cursor.rowcount == 0:
                    # If not found, try updating by email
                    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, identifier))
                conn.commit()
                return cursor.rowcount > 0  # True if a row was updated
        except Exception as e:
            print("[DB ERROR] update_user_password:", e)
            return False

    def insert_snack(self, username, snack, calories, day, month, year):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO snacks (username, snack, calories, day, month, year)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (username, snack, calories, day, month, year))
            conn.commit()

    def get_total_calories(self, username, day, month, year):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT SUM(calories) FROM snacks
                              WHERE username = ? AND day = ? AND month = ? AND year = ?''',
                           (username, day, month, year))
            result = cursor.fetchone()
            return result[0] if result[0] is not None else 0

    def get_snacks(self, username, day, month, year):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT snack, calories FROM snacks
                              WHERE username = ? AND day = ? AND month = ? AND year = ?''',
                           (username, day, month, year))
            return cursor.fetchall()

    def get_stats(self, username):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT day, month, year, SUM(calories) as total
                              FROM snacks
                              WHERE username = ?
                              GROUP BY year, month, day
                              ORDER BY year DESC, month DESC, day DESC''',
                           (username,))
            return cursor.fetchall()

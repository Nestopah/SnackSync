import sqlite3
import time
import os

class DBManager:
    def __init__(self, db_name="snacksync.db"):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        start = time.time()
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                username TEXT UNIQUE,
                                password TEXT,
                                email TEXT,
                                enable_2fa INTEGER DEFAULT 0)''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
                                id INTEGER PRIMARY KEY,
                                username TEXT,
                                snack TEXT,
                                calories INTEGER,
                                day INTEGER,
                                month INTEGER,
                                year INTEGER)''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS goals (
                                username TEXT,
                                goal_calories INTEGER,
                                goal_type INTEGER,
                                day INTEGER,
                                month INTEGER,
                                year INTEGER)''')

            conn.commit()
        print(f"[DB] Database created (took {time.time() - start:.3f} sec)")

    def insert_user(self, username, password, email):
        try:
            with sqlite3.connect(self.db_name, timeout=5) as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO users (username, password, email)
                                  VALUES (?, ?, ?)''',
                               (username, password, email))
                conn.commit()
        except sqlite3.OperationalError as e:
            print("[DB ERROR] insert_user:", e)
            raise

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
            return result[0] if result else 0

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
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, identifier))
                if cursor.rowcount == 0:
                    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, identifier))
                conn.commit()
                return cursor.rowcount > 0
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
            return cursor.fetchall()  # goal now fetched per-day elsewhere

    def update_goals(self, username, goal_calories, goal_type, day, month, year):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            # Delete existing goal entry for that day
            cursor.execute('''DELETE FROM goals 
                              WHERE username = ? AND day = ? AND month = ? AND year = ?''',
                           (username, day, month, year))
            # Insert the new goal
            cursor.execute('''INSERT INTO goals (username, goal_calories, goal_type, day, month, year)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (username, goal_calories, goal_type, day, month, year))
            conn.commit()

    def get_goal_for_date(self, username, day, month, year):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT goal_calories, goal_type FROM goals
                WHERE username = ?
                AND (year < ? OR (year = ? AND month < ?) OR (year = ? AND month = ? AND day <= ?))
                ORDER BY year DESC, month DESC, day DESC
                LIMIT 1
            ''', (username, year, year, month, year, month, day))
            return cursor.fetchone()

    def delete_snack(self, username, snack, calories, day, month, year):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()

            # Step 1: Get one matching rowid
            cursor.execute('''
                SELECT rowid FROM snacks
                WHERE username = ? AND snack = ? AND calories = ?
                AND day = ? AND month = ? AND year = ?
            ''', (username, snack, calories, day, month, year))
            result = cursor.fetchone()
            if result:
                rowid = result[0]
                cursor.execute('DELETE FROM snacks WHERE rowid = ?', (rowid,))
                conn.commit()

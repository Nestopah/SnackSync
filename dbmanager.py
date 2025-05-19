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
                                enable_2fa INTEGER DEFAULT 0,
                                clippy_interval INTEGER DEFAULT 60)''')

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
            return cursor.fetchall()

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

    def update_interval(self, username, interval_minutes):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET clippy_interval = ? WHERE username = ?", (interval_minutes, username))
            conn.commit()

    def get_interval(self, username):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT clippy_interval FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result[0] if result and result[0] not in (None, 0) else 60 #no crashes anymore

    def get_username_by_email(self, email):
        with sqlite3.connect(self.db_name, timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE email = ?", (email,))
            result = cursor.fetchone()
            return result[0] if result else None

class DBDBugger(DBManager):
    def log(self, func_name, *args):
        message = (f"DBLOG {func_name}: ")
        parts = []
        i = 0
        for arg in args:
            parts.append(str(arg))
            i += 1
        message += " | ".join(parts)
        print(message)

    def insert_user(self, username, password, email):
        self.log("insert_user", username, password, email)
        return super().insert_user(username, password, email)

    def get_user_password(self, username):
        self.log("get_user_password", username)
        return super().get_user_password(username)

    def get_2fa(self, username):
        self.log("get_2fa", username)
        return super().get_2fa(username)

    def update_2fa(self, username, value):
        self.log("update_2fa", username, value)
        return super().update_2fa(username, value)

    def get_email(self, username):
        self.log("get_email", username)
        return super().get_email(username)

    def update_user_password(self, identifier, new_password):
        self.log("update_user_password", identifier, new_password)
        return super().update_user_password(identifier, new_password)

    def insert_snack(self, username, snack, calories, day, month, year):
        self.log("insert_snack", username, snack, calories, day, month, year)
        return super().insert_snack(username, snack, calories, day, month, year)

    def get_total_calories(self, username, day, month, year):
        self.log("get_total_calories", username, day, month, year)
        return super().get_total_calories(username, day, month, year)

    def get_snacks(self, username, day, month, year):
        self.log("get_snacks", username, day, month, year)
        return super().get_snacks(username, day, month, year)

    def get_stats(self, username):
        self.log("get_stats", username)
        return super().get_stats(username)

    def update_goals(self, username, goal_calories, goal_type, day, month, year):
        self.log("update_goals", username, goal_calories, goal_type, day, month, year)
        return super().update_goals(username, goal_calories, goal_type, day, month, year)

    def get_goal_for_date(self, username, day, month, year):
        self.log("get_goal_for_date", username, day, month, year)
        return super().get_goal_for_date(username, day, month, year)

    def delete_snack(self, username, snack, calories, day, month, year):
        self.log("delete_snack", username, snack, calories, day, month, year)
        return super().delete_snack(username, snack, calories, day, month, year)

    def update_interval(self, username, interval_minutes):
        self.log("update_interval", username, interval_minutes)
        return super().update_interval(username, interval_minutes)

    def get_interval(self, username):
        self.log("get_interval", username)
        return super().get_interval(username)

    def get_username_by_email(self, email):
        self.log("get_username_by_email", email)
        return super().get_username_by_email(email)


import socket
import sqlite3
import threading
from user import User
import bcrypt
import time

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_HOST, SERVER_PORT))
server.listen(5)
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

conn = sqlite3.connect("snacksync.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)''')
conn.commit()
#
snack_conn = conn  # Use the same unified connection
snack_cursor = snack_conn.cursor()
snack_cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
                        id INTEGER PRIMARY KEY, username TEXT, snack TEXT, 
                        calories INTEGER, day INTEGER, month INTEGER, year INTEGER)''')
snack_conn.commit()


def login(username, entered_password):
    # Get the user from the database (assume we fetch the user from the DB)
    ###check
    print("entered password = ", entered_password)
    ###check
    conn = sqlite3.connect('snacksync.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    stored_hash = cursor.fetchone()

    if stored_hash:
        # stored_hash[0] is the hashed password from the database
        stored_hash = stored_hash[0]

        ###check
        print("stored hash = ", stored_hash)
        ###check

        # Check if the entered password matches the stored hashed password
        if bcrypt.checkpw(entered_password.encode(), stored_hash):
            print("Login successful")
            return True
        else:
            print("Invalid password")
            return False
    else:
        print("User not found")
        return False


def signup(username, password):
    try:
        conn = sqlite3.connect('snacksync.db')
        user = User(username, password)
        user.save_to_db(conn)
        ##check
        print("password after hashing", user.password)
        is_valid = user.check_password('my_secure_password')
        print("Password is valid:", is_valid)
        ## check
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def add_snack(username, snack, calories, day, month, year):
    snack_cursor.execute("INSERT INTO snacks (username, snack, calories, day, month, year) VALUES (?, ?, ?, ?, ?, ?)",
                         (username, snack, calories, day, month, year))
    snack_conn.commit()
    return get_total_calories(username, day, month, year)

def get_total_calories(username, day, month, year):
    snack_cursor.execute("SELECT SUM(calories) FROM snacks WHERE username=? AND day=? AND month=? AND year=?",
                         (username, day, month, year))
    total = snack_cursor.fetchone()[0]
    return total if total else 0

def delete_snack(username, snack, calories, day, month, year):
    snack_cursor.execute("DELETE FROM snacks WHERE rowid = (SELECT rowid FROM snacks WHERE username=? AND snack=? AND calories=? AND day=? AND month=? AND year=? LIMIT 1)",
                         (username, snack, calories, day, month, year))
    snack_conn.commit()
    return get_total_calories(username, day, month, year)

def handle_client(client_socket):
    try:
        data = client_socket.recv(1024).decode().strip()
        if "|" in data:
            parts = data.split("|")
            op = parts[0]
            args = parts[1:]
        else:
            op = data
            args = []

        print("[DEBUG] Operation requested:", op)
        # Only send ACK for old-style operations
        if op in ["login", "register", "log_snack", "delete_snack"]:
            client_socket.send(b"OK")

        if op == "login":
            credentials = client_socket.recv(1024).decode().strip()
            username, password = credentials.split("|")
            print(f"[DEBUG] Login attempt for {username}")

            if login(username, password):
                client_socket.send(b"Login successful!")
            else:
                client_socket.send(b"Login failed.")

        elif op == "register":
            credentials = client_socket.recv(1024).decode().strip()
            username, password = credentials.split("|")
            print(f"[DEBUG] Register attempt for {username}")

            if signup(username, password):
                client_socket.send(b"Registration successful!")
            else:
                client_socket.send(b"Username already exists.")

        elif op == "log_snack":
            data = client_socket.recv(1024).decode()
            print("[DEBUG] Snack data:", data)
            username, snack, calories, day, month, year = data.split("|")
            total = add_snack(username, snack, int(calories), int(day), int(month), int(year))
            response = f"Snack logged. Total calories: {total}"
            client_socket.send(response.encode())
        elif op == "delete_snack":
            client_socket.send(b"OK")
            data = client_socket.recv(1024).decode()
            print("[DEBUG] Delete snack data:", data)

            username, snack, calories, day, month, year = data.split("|")
            calories = int(calories)
            day = int(day)
            month = int(month)
            year = int(year)

            total = delete_snack(username, snack, calories, day, month, year)
            response = f"Snack deleted. New total: {total} kcal"
            print("[DEBUG] Sending response:", response)
            client_socket.send(response.encode())
        elif op == "get_snacks":
            try:
                if len(args) == 4:
                    username, day, month, year = args
                    print(f"[DEBUG] Get snacks for {username} on {day}/{month}/{year}")
                    snack_cursor.execute(
                        "SELECT snack, calories FROM snacks WHERE username=? AND day=? AND month=? AND year=?",
                        (username, int(day), int(month), int(year)))
                    rows = snack_cursor.fetchall()

                    if not rows:
                        client_socket.send(b"")
                    else:
                        formatted = "\n".join([f"{snack}: {calories} kcal" for snack, calories in rows])
                        client_socket.send(formatted.encode())
                else:
                    print("[ERROR] Invalid get_snacks args:", args)
                    client_socket.send(b"")
            except Exception as e:
                print("[ERROR] Failed to process get_snacks:", e)
                client_socket.send(b"")

        elif op == "get_total":
          try:
                if len(args) == 4:
                    username, day, month, year = args
                    total = get_total_calories(username, int(day), int(month), int(year))
                    print(f"[DEBUG] Total calculated for {username} on {day}/{month}/{year} = {total}")
                    client_socket.send(str(total).encode())
                    print(f"[DEBUG] Sent total: {total}")
                else:
                    print("[ERROR] Invalid get_total args:", args)
                    client_socket.send(b"0")
            except Exception as e:
                print("[ERROR] Exception in get_total:", e)
                client_socket.send(b"0")


        else:
            print("[ERROR] Unknown operation:", op)
            client_socket.send(b"Unknown operation")

    except Exception as e:
        print("[ERROR] Exception in handle_client:", e)
        client_socket.send(f"Error: {e}".encode())
    finally:
        client_socket.close()


def start_server():
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_socket, _ = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
##
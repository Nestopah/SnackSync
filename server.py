import socket
import sqlite3
import threading

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_HOST, SERVER_PORT))
server.listen(5)
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)''')
conn.commit()

snack_conn = sqlite3.connect("snacks.db", check_same_thread=False)
snack_cursor = snack_conn.cursor()
snack_cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
                        id INTEGER PRIMARY KEY, username TEXT, snack TEXT, 
                        calories INTEGER, day INTEGER, month INTEGER, year INTEGER)''')
snack_conn.commit()

def authenticate_user(username, password):
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    return cursor.fetchone() is not None

def register_user(username, password):
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
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
        client_socket.send(b"Do you want to (L)ogin, (R)egister, (S)ubmit Snack, or (D)elete Snack? ")
        choice = client_socket.recv(1024).decode().strip().lower()

        client_socket.send(b"Enter username: ")
        username = client_socket.recv(1024).decode().strip()

        if choice in ["l", "r"]:
            client_socket.send(b"Enter password: ")
            password = client_socket.recv(1024).decode().strip()

            if choice == "l":
                if authenticate_user(username, password):
                    client_socket.send(b"Login successful!\n")
                else:
                    client_socket.send(b"Login failed!\n")

            elif choice == "r":
                if register_user(username, password):
                    client_socket.send(b"Registration successful! You can now log in.\n")
                else:
                    client_socket.send(b"Username already exists. Try again.\n")

        elif choice == "s":
            client_socket.send(b"Enter snack name: ")
            snack_name = client_socket.recv(1024).decode().strip()

            client_socket.send(b"Enter calories: ")
            calories = int(client_socket.recv(1024).decode().strip())

            client_socket.send(b"Enter day (DD): ")
            day = int(client_socket.recv(1024).decode().strip())

            client_socket.send(b"Enter month (MM): ")
            month = int(client_socket.recv(1024).decode().strip())

            client_socket.send(b"Enter year (YYYY): ")
            year = int(client_socket.recv(1024).decode().strip())

            total_calories = add_snack(username, snack_name, calories, day, month, year)
            client_socket.send(f"Snack added! Total Calories for {day}/{month}/{year}: {total_calories} kcal\n".encode())

        elif choice == "d":
            client_socket.send(b"Enter snack name to delete: ")
            snack_name = client_socket.recv(1024).decode().strip()

            client_socket.send(b"Enter calories: ")
            calories = int(client_socket.recv(1024).decode().strip())

            client_socket.send(b"Enter day (DD): ")
            day = int(client_socket.recv(1024).decode().strip())

            client_socket.send(b"Enter month (MM): ")
            month = int(client_socket.recv(1024).decode().strip())

            client_socket.send(b"Enter year (YYYY): ")
            year = int(client_socket.recv(1024).decode().strip())

            total_calories = delete_snack(username, snack_name, calories, day, month, year)
            client_socket.send(f"Snack deleted! Total Calories for {day}/{month}/{year}: {total_calories} kcal\n".encode())

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_server():
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_socket, _ = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()

import socket
import sqlite3
import threading
from user import User
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

with open("rsa_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
    rsa_cipher = PKCS1_OAEP.new(private_key)

def rsa_decrypt_b64(encoded_data):
    encrypted_data = base64.b64decode(encoded_data)
    return rsa_cipher.decrypt(encrypted_data).decode()

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50505

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # ✅ allow re-binding to the same port
server.bind((SERVER_HOST, SERVER_PORT))

server.listen(5)
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

conn = sqlite3.connect("snacksync.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)''')
conn.commit()

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
        print("Connected to a new client")

        choice = client_socket.recv(1024).decode().strip().lower()
        print("Received choice:", choice)

        if choice in ["l", "r"]:
            data = client_socket.recv(1024).decode().strip().splitlines()
            username = data[0]
            password = data[1]
            print("Received username:", username)
            print("Received password:", password)

            if choice == "l":
                if login(username, password):
                    client_socket.send(b"Login successful!\n")
                else:
                    client_socket.send(b"Login failed!\n")

            elif choice == "r":
                if signup(username, password):
                    client_socket.send(b"Registration successful! You can now log in.\n")
                else:
                    client_socket.send(b"Username already exists. Try again.\n")

            return  # 🔒 don't continue after login/register

        # ✅ For all other commands, read username next
        username = client_socket.recv(1024).decode().strip()
        print("Username for action:", username)

        if choice == "s":
            snack = rsa_decrypt_b64(client_socket.recv(1024).decode().strip())
            calories = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            day = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            month = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            year = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))

            snack_cursor.execute(
                "INSERT INTO snacks (username, snack, calories, day, month, year) VALUES (?, ?, ?, ?, ?, ?)",
                (username, snack, calories, day, month, year))
            snack_conn.commit()

            total = get_total_calories(username, day, month, year)
            client_socket.send(f"Snack added! Total Calories for {day}/{month}/{year}: {total} kcal\n".encode())

        elif choice == "d":
            snack_name = rsa_decrypt_b64(client_socket.recv(1024).decode().strip())
            calories = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            day = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            month = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            year = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            total_calories = delete_snack(username, snack_name, calories, day, month, year)

            client_socket.send(
                f"Snack deleted! Total Calories for {day}/{month}/{year}: {total_calories} kcal\n".encode())

        elif choice == "t":
            snack_cursor.execute("""
                SELECT day, month, year, SUM(calories)
                FROM snacks
                WHERE username = ?
                GROUP BY day, month, year
                ORDER BY year, month, day
            """, (username,))
            rows = snack_cursor.fetchall()

            if not rows:
                client_socket.send(b"")
            else:
                response_lines = [f"{day}/{month}/{year}: {total} kcal" for day, month, year, total in rows]
                response = "\n".join(response_lines)
                client_socket.send(response.encode())

        elif choice == "dp":
            day = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            month = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            year = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))

            snack_cursor.execute("""
                SELECT snack, calories FROM snacks
                WHERE username = ? AND day = ? AND month = ? AND year = ?
            """, (username, day, month, year))

            snacks = snack_cursor.fetchall()

            if not snacks:
                client_socket.send(b"")
            else:
                response = "\n".join([f"{name}: {calories} kcal" for name, calories in snacks])
                client_socket.send(response.encode())

        elif choice == "tc":
            day = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            month = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))
            year = int(rsa_decrypt_b64(client_socket.recv(1024).decode().strip()))

            total = get_total_calories(username, day, month, year)
            client_socket.send(str(total).encode())

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

### begrijp
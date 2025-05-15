
import socket
import sqlite3
import threading
from user import User
import bcrypt
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from CountryDetector import CountryDetector
import smtplib
import secrets

# Global tracker
ip_access_log = {}  # {ip: [timestamps]}
RATE_LIMIT_WINDOW = 5  # seconds
MAX_CONNECTIONS = 10   # max connections per window
all_conn_times = []
all_2fa_tokens = {}

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

def decrypt_field(encrypted_base64):
    with open("rsa_private.pem", "rb") as f:
        key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(key)
    raw = base64.b64decode(encrypted_base64)
    return cipher.decrypt(raw).decode()

def send_email(to_email, code):
    # VERY basic plain SMTP example — replace with your actual email creds
    from_email = "latexdus@gmail.com"
    password = "dsevptrpckqotgpq"

    message = f"Subject: Your SnackSync Verification Code\n\nYour code is: {code}"
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(from_email, password)
        server.sendmail(from_email, to_email, message)

def signup(encrypted_username, encrypted_password, encrypted_email):
    try:
        print("(DEBUG) signing up")
        # Decrypt all fields
        username = decrypt_field(encrypted_username)
        password = decrypt_field(encrypted_password)
        email = decrypt_field(encrypted_email)

        # Create user and store
        conn = sqlite3.connect('snacksync.db')
        user = User(username, password, email)
        user.save_to_db(conn)
        conn.commit()

        # Generate 6-digit 2FA token
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        all_2fa_tokens[username] = (code, time.time() + 300)  # expires in 5 mins

        send_email(email, code)

        return "2FA"  # tells client to open verification prompt
    except sqlite3.IntegrityError:
        return "FAIL"
    except Exception as e:
        print("Signup error:", e)
        return "FAIL"


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

def recieve_data(sock):
    data = b""
    while True:
        part = sock.recv(1024)
        if not part:
            break
        data += part
        if b"!END" in data:
            break
    return data.decode().replace("!END", "")

def handle_client(client_socket):
    print("handle client activated")
    try:
        data = recieve_data(client_socket)
        print(f"data = {data}")
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
                print("yogesh")
                client_ip = client_socket.getpeername()[0]
                country = CountryDetector(client_ip)

                # You can now use:
                print(f"[HILLEL] {username} logged in from {country.country} ({client_ip})")

                # Optional custom action
                country.respond()

                # You can also conditionally block users:
                if country.country == "Russia":
                    client_socket.send(b"Access denied from your country.")
                    return  # stops handling further

                print(f"[HILLEL] {username} logged in from {country} ({client_ip})")
                client_socket.send(b"Login successful.")

            else:
                client_socket.send(b"Login failed.")


        elif op == "register":
            if len(args) == 3:
                encrypted_username, encrypted_password, encrypted_email = args
                result = signup(encrypted_username, encrypted_password, encrypted_email)
                client_socket.send(result.encode())

            else:
                print("[ERROR] Invalid register args:", args)
                client_socket.send(b"FAIL")

        elif op == "log_snack":
            data = client_socket.recv(1024).decode()
            print("[DEBUG] Snack data:", data)
            # split incoming data
            username, enc_snack, enc_calories, day, month, year = data.split("|")

            # load private key
            with open("rsa_private.pem", "rb") as f:
                private_key = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(private_key)

            # decrypt snack and calories
            snack = cipher_rsa.decrypt(base64.b64decode(enc_snack)).decode()
            calories = int(cipher_rsa.decrypt(base64.b64decode(enc_calories)).decode())

            # insert to DB
            total = add_snack(username, snack, calories, int(day), int(month), int(year))
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
        elif op == "get_stats":
            try:
                if len(args) == 1:
                    username = args[0]
                    print(f"[DEBUG] Getting stats for {username}")
                    snack_cursor.execute(
                        "SELECT day, month, year, SUM(calories) FROM snacks WHERE username=? GROUP BY day, month, year",
                        (username,))
                    rows = snack_cursor.fetchall()
                    if not rows:
                        client_socket.send(b"")
                    else:
                        response = "\n".join([f"{day}/{month}/{year}:{total}" for day, month, year, total in rows])
                        client_socket.send(response.encode())
                else:
                    print("[ERROR] Invalid get_stats args:", args)
                    client_socket.send(b"")
            except Exception as e:
                print("[ERROR] Exception in get_stats:", e)
                client_socket.send(b"")

        else:
            print("[ERROR] Unknown operation:", op)
            client_socket.send(b"Unknown operation")

    except Exception as e:
        print("[ERROR] Exception in handle_client:", e)
        client_socket.send(f"Error: {e}".encode())
    finally:
        client_socket.close()
def is_global_rate_safe():
    now = time.time()
    recent_connections = [t for t in all_conn_times if now - t < 5]
    if len(recent_connections) >= 50:  # example threshold
        return False
    recent_connections.append(now)
    all_conn_times[:] = recent_connections
    return True

def is_ip_allowed(ip):
    now = time.time()
    access_times = ip_access_log.get(ip, [])
    access_times = [t for t in access_times if now - t < RATE_LIMIT_WINDOW]

    if len(access_times) >= MAX_CONNECTIONS:
        return False

    access_times.append(now)
    ip_access_log[ip] = access_times
    return True

def start_server():
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_socket, addr = server.accept()
        client_ip = addr[0]

        if not is_ip_allowed(client_ip):
            print(f"[DDoS BLOCKED] Too many connections from {client_ip}")
            client_socket.close()
            continue
        if not is_global_rate_safe():
            print("[DDoS BLOCKED] Too many total connections at once")
            client_socket.close()
            continue
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
##




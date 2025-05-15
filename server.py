
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
from dbmanager import DBManager

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

db = DBManager()



def login(username, entered_password):
    print("entered password =", entered_password)
    stored_hash = db.get_user_password(username)

    if stored_hash:
        print("stored hash =", stored_hash)
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
    print("(DEBUG) send email activated")
    from_email = "latexdus@gmail.com"
    password = "dsevptrpckqotgpq"

    message = f"Subject: Your SnackSync Verification Code\n\nYour code is: {code}"
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(from_email, password)
        server.sendmail(from_email, to_email, message)

def signup(encrypted_username, encrypted_password, encrypted_email):
    try:
        print("(DEBUG) sign  up activated")
        # Decrypt all fields
        username = decrypt_field(encrypted_username)
        password = decrypt_field(encrypted_password)
        email = decrypt_field(encrypted_email)

        print(f"(DEBUG) decryp username: {username} decryp pass: {password} decryp email: {email}")
        # Create user and store

        # Generate 6-digit 2FA token
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        all_2fa_tokens[username] = (code, time.time() + 300)  # expires in 5 mins


        print("(DEBUG) Email sent tera")
        send_email(email, code)
        db.insert_user(username, password, email)
        return "2FA"  # tells client to open verification prompt
    except sqlite3.IntegrityError:
        return "FAIL"
    except Exception as e:
        print("Signup error:", e)
        return "FAIL"


def add_snack(username, snack, calories, day, month, year):
    db.insert_snack(username, snack, calories, day, month, year)
    return db.get_total_calories(username, day, month, year)


def get_total_calories(username, day, month, year):
    return db.get_total_calories(username, day, month, year)


def delete_snack(username, snack, calories, day, month, year):
    db.delete_snack(username, snack, calories, day, month, year)
    return db.get_total_calories(username, day, month, year)


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
        if op in ["log_snack", "delete_snack"]:
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
                    rows = db.get_snacks(username, int(day), int(month), int(year))

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
                    rows = db.get_stats(username)
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
        elif op == "2fa":
            print(f"2fa args = {args}")
            if len(args) == 2:
                username, code = args
                # Check if username is in tokens
                if username in all_2fa_tokens:
                    expected_code, expiry = all_2fa_tokens[username]
                    current_time = time.time()
                    if code == expected_code and current_time <= expiry:
                        print(f"[DEBUG] 2FA success for {username}")
                        # Optional: remove token now that it's used
                        del all_2fa_tokens[username]
                        client_socket.send(b"OK")
                    else:
                        print(f"[DEBUG] 2FA failed or expired for {username}")
                        client_socket.send(b"FAIL")
                else:
                    print(f"[DEBUG] 2FA token not found for {username}")
                    client_socket.send(b"FAIL")
            else:
                print("[ERROR] Invalid 2FA args:", args)
                client_socket.send(b"FAIL")
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




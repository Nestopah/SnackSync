
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
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode()  # 🔧 convert str to bytes

        if bcrypt.checkpw(entered_password.encode(), stored_hash):
            print("Login successful")
            return True
        else:
            print("Invalid password")
            return False
    else:
        print("User not found")
        return False
def verify_2fa_code(username, submitted_code):
    if username not in all_2fa_tokens:
        print(f"[DEBUG] No 2FA token found for {username}")
        return False

    expected_code, expiry_time = all_2fa_tokens[username]
    current_time = time.time()

    if submitted_code == expected_code and current_time <= expiry_time:
        print(f"[DEBUG] 2FA code valid for {username}")
        del all_2fa_tokens[username]  # Remove token after use
        return True
    else:
        print(f"[DEBUG] Invalid or expired 2FA code for {username}")
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
        username = decrypt_field(encrypted_username)
        password = decrypt_field(encrypted_password)
        email = decrypt_field(encrypted_email)

        print(f"(DEBUG) decryp username: {username} decryp pass: {password} decryp email: {email}")

        # Step 2: Generate 2FA code
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        all_2fa_tokens[username] = (code, time.time() + 300)

        # Step 3: Send the email immediately (slow, but necessary)
        print("(DEBUG) Email sent tera")
        send_email(email, code)

        # Step 4: Do the hashing + DB insert in a background thread
        def add_user():
            try:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                db.insert_user(username, hashed_password, email)
            except Exception as e:
                print(f"[ERROR] adding user failed")

        threading.Thread(target=add_user).start()
        return "2FA"
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

        if op == "login":
            if len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if login(username, password):
                    # Check if 2FA is enabled
                    if db.get_2fa(username) == 1:
                        print("[DEBUG] 2FA is enabled, sending code")

                        email = db.get_email(username)
                        if email:
                            code = ''.join(secrets.choice("0123456789") for _ in range(6))
                            all_2fa_tokens[username] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(b"2FA")  # tell client to expect prompt
                        else:
                            print("[ERROR] No email found for user during 2FA")
                            client_socket.send(b"FAIL")
                    else:
                        client_socket.send(b"Login successful.")
                else:
                    client_socket.send(b"Login failed.")
            else:
                client_socket.send(b"FAIL")

        elif op == "register":
            if len(args) == 3:
                encrypted_username, encrypted_password, encrypted_email = args
                result = signup(encrypted_username, encrypted_password, encrypted_email)
                client_socket.send(result.encode())

            else:
                print("[ERROR] Invalid register args:", args)
                client_socket.send(b"FAIL")


        elif op == "log_snack":
            if len(args) == 6:
                username, enc_snack, enc_calories, day, month, year = args
                print("[DEBUG] Snack data received")
                try:
                    with open("rsa_private.pem", "rb") as f:
                        private_key = RSA.import_key(f.read())
                        cipher_rsa = PKCS1_OAEP.new(private_key)
                        username = cipher_rsa.decrypt(base64.b64decode(username)).decode()
                        snack = cipher_rsa.decrypt(base64.b64decode(enc_snack)).decode()
                        calories = int(cipher_rsa.decrypt(base64.b64decode(enc_calories)).decode())
                        add_snack(username, snack, calories, int(day), int(month), int(year))
                        client_socket.send(b"OK")
                        print("log_snack sent ok")
                except Exception as e:
                    print(f"[ERROR] log_snack failed: {e}")
                    client_socket.send(b"FAIL")

            else:
                print("[ERROR] Invalid log_snack args:", args)
                client_socket.send(b"FAIL")



        elif op == "delete_snack":
            try:
                if len(args) == 6:
                    username, snack, calories, day, month, year = args
                    print(f"[DEBUG] Deleting snack for {username}: {snack}, {calories} kcal on {day}/{month}/{year}")
                    calories = int(calories)
                    day, month, year = int(day), int(month), int(year)
                    delete_snack(username, snack, calories, day, month, year)
                    client_socket.send(b"OK")
                else:
                    print("[ERROR] Invalid delete_snack args:", args)
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("[ERROR] delete_snack failed:", e)
                client_socket.send(b"FAIL")
        elif op == "get_snacks":
            try:
                if len(args) == 4:
                    username, day, month, year = args
                    print(f"[DEBUG] Get snacks for {username} on {day}/{month}/{year}")
                    rows = db.get_snacks(username, int(day), int(month), int(year))

                    if not rows:
                        client_socket.send(b"NONE")  # <== FIX: send non-empty response
                    else:
                        formatted = "\n".join([f"{snack}: {calories} kcal" for snack, calories in rows])
                        client_socket.send(formatted.encode())
                else:
                    print("[ERROR] Invalid get_snacks args:", args)
                    client_socket.send(b"FAIL")  # <== also better than empty
            except Exception as e:
                print("[ERROR] Failed to process get_snacks:", e)
                client_socket.send(b"FAIL")

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
                        client_socket.send(b"NONE")
                        return
                    result_lines = []
                    for day, month, year, total in rows:
                        goal = db.get_goal_for_date(username, day, month, year)
                        if goal:
                            gcal, gtype = goal
                            result_lines.append(f"{day}/{month}/{year}:{total}|{gcal}|{gtype}")
                        else:
                            result_lines.append(f"{day}/{month}/{year}:{total}||")  # no goal set
                    payload = "\n".join(result_lines)
                    client_socket.send(payload.encode())
                else:
                    print("[ERROR] Invalid get_stats args:", args)
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("[ERROR] Exception in get_stats:", e)
                client_socket.send(b"FAIL")


        elif op == "get_2fa":
            if len(args) == 1:
                username = args[0]
                try:
                    result = db.get_2fa(username)
                    client_socket.send(str(result).encode())
                except Exception as e:
                    print("[ERROR] get_2fa failed:", e)
                    client_socket.send(b"0")
            else:
                client_socket.send(b"0")

        elif op == "update_2fa":
            if len(args) == 2:
                username, value = args
                try:
                    db.update_2fa(username, value)
                    client_socket.send(b"OK")
                except Exception as e:
                    print("[ERROR] update_2fa failed:", e)
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")
        elif op == "reset_pass":
            if len(args) == 2:
                enc_user_id, hashed_password = args
                try:
                    user_id = decrypt_field(enc_user_id)
                    print(f"[DEBUG] Decrypted user_id: {user_id}")

                    # Always require 2FA for password reset
                    email = db.get_email(user_id)
                    if email:
                        try:
                            code = ''.join(secrets.choice("0123456789") for _ in range(6))
                            all_2fa_tokens[user_id] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(b"2FA")  # tell client to prompt for code
                            return
                        except Exception as e:
                            print(f"[ERROR] Failed to send 2FA email for reset_pass: {e}")
                            client_socket.send(b"FAIL")
                            return
                    else:
                        print("[ERROR] No email found for reset_pass")
                        client_socket.send(b"FAIL")
                        return

                except Exception as e:
                    print(f"[ERROR] reset_pass failed: {e}")
                    client_socket.send(b"FAIL")
            else:
                print("[ERROR] Invalid reset_pass args:", args)
                client_socket.send(b"FAIL")
        elif op == "reset_verify":
            if len(args) == 3:
                user_id, new_password, submitted_code = args
                if verify_2fa_code(user_id, submitted_code):
                    updated = db.update_user_password(user_id, new_password)
                    if updated:
                        print(f"[DEBUG] Password reset via 2FA for {user_id}")
                        client_socket.send(b"OK")
                    else:
                        print(f"[ERROR] Password update failed for {user_id}")
                        client_socket.send(b"FAIL")
                else:
                    print("[ERROR] Invalid or expired 2FA code for reset_confirm")
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "update_goal":
            if len(args) == 6:
                try:
                    enc_username, enc_cal, enc_type, day, month, year = args
                    username = decrypt_field(enc_username)
                    goal_calories = int(decrypt_field(enc_cal))
                    goal_type = int(decrypt_field(enc_type))
                    day, month, year = int(day), int(month), int(year)

                    db.update_goals(username, goal_calories, goal_type, day, month, year)
                    client_socket.send(b"OK")
                except Exception as e:
                    print("[ERROR] update_goal failed:", e)
                    client_socket.send(b"error")
            else:
                print("[ERROR] Invalid update_goal args:", args)
                client_socket.send(b"error")

        elif op == "get_goal":
            if len(args) == 1:
                try:
                    encrypted_username = args[0]
                    username = decrypt_field(encrypted_username)

                    now = time.localtime()
                    day, month, year = now.tm_mday, now.tm_mon, now.tm_year

                    result = db.get_goal_for_date(username, day, month, year)

                    if result:
                        goal_calories, goal_type = result
                        response = f"{goal_calories}|{goal_type}"
                    else:
                        response = "|"

                    client_socket.send(response.encode())
                except Exception as e:
                    print("[ERROR] get_goal failed:", e)
                    client_socket.send(b"error")
            else:
                print("[ERROR] Invalid get_goal args:", args)
                client_socket.send(b"error")

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




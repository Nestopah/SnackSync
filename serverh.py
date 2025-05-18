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

# --- Global variables for tracking IPs and rate limits ---
ip_access_log = {}  # This keeps track of IP access timestamps
RATE_LIMIT_WINDOW = 5  # seconds - arbitrary time window to limit requests
MAX_CONNECTIONS = 10   # don't let things get too wild

# Might use these later for logging and rate-limiting logic
all_conn_times = []
all_2fa_tokens = {}  # map username -> (token, expiration time)

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345

# Set up the socket server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_HOST, SERVER_PORT))
server.listen(5)  # backlog queue size
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

# initialize DB manager
db = DBManager()


def login(username, entered_password):
    print("entered password =", entered_password)
    stored_hash = db.get_user_password(username)

    if stored_hash:
        print("stored hash =", stored_hash)

        # Just making sure it's in byte format for bcrypt
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode()

        # bcrypt comparison
        if bcrypt.checkpw(entered_password.encode(), stored_hash):
            print("Login successful")
            return True
        else:
            print("Invalid password")  # Wrong password, not user
            return False
    else:
        print("User not found")  # Username not in DB
        return False


def verify_2fa_code(username, submitted_code):
    if username not in all_2fa_tokens:
        print(f"[DEBUG] No 2FA token found for {username}")
        return False

    expected_code, expiry_time = all_2fa_tokens[username]
    now = time.time()

    if submitted_code == expected_code and now <= expiry_time:
        print(f"[DEBUG] 2FA code valid for {username}")
        del all_2fa_tokens[username]  # cleanup after use
        return True
    else:
        print(f"[DEBUG] Invalid or expired 2FA code for {username}")
        return False


def decrypt_field(encrypted_base64):
    # Load the private key from disk each time (could cache it, but meh)
    with open("rsa_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
        rsa_cipher = PKCS1_OAEP.new(private_key)

    decoded = base64.b64decode(encrypted_base64)
    return rsa_cipher.decrypt(decoded).decode()


def send_email(to_email, code):
    # NOTE: hardcoded creds - replace this for real use
    print("(DEBUG) send email activated")
    from_email = "latexdus@gmail.com"
    password = "dsevptrpckqotgpq"

    subject_line = "Subject: Your SnackSync Verification Code\n\n"
    body = f"Your code is: {code}"
    full_message = subject_line + body

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(from_email, password)
            smtp.sendmail(from_email, to_email, full_message)
    except Exception as e:
        print(f"Email failed: {e}")


def signup(encrypted_username, encrypted_password, encrypted_email):
    try:
        print("(DEBUG) sign  up activated")

        # Probably overkill decrypt here but keeping it clean
        username = decrypt_field(encrypted_username)
        password = decrypt_field(encrypted_password)
        email = decrypt_field(encrypted_email)

        print(f"(DEBUG) decryp username: {username} decryp pass: {password} decryp email: {email}")

        # Step 1: Make a random 6-digit code
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        all_2fa_tokens[username] = (code, time.time() + 300)  # give them 5 mins

        # Step 2: Fire off the email (this can delay response)
        print("(DEBUG) Email sent tera")
        send_email(email, code)

        # Step 3: background thread to handle hashing and DB stuff
        def add_user():
            try:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                db.insert_user(username, hashed_password, email)
            except Exception as e:
                print(f"[ERROR] adding user failed")

        threading.Thread(target=add_user).start()

        return "2FA"

    except sqlite3.IntegrityError:
        return "FAIL"  # Username probably already exists
    except Exception as e:
        print("Signup error:", e)
        return "FAIL"


def add_snack(username, snack, calories, day, month, year):
    db.insert_snack(username, snack, calories, day, month, year)
    # just returning total to the caller
    return db.get_total_calories(username, day, month, year)


def get_total_calories(username, day, month, year):
    return db.get_total_calories(username, day, month, year)


def delete_snack(username, snack, calories, day, month, year):
    db.delete_snack(username, snack, calories, day, month, year)
    return db.get_total_calories(username, day, month, year)


def recieve_data(sock):
    # collect data in chunks - stop when we see "!END"
    collected = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        collected += chunk
        if b"!END" in collected:
            break
    return collected.decode().replace("!END", "")

def handle_client(client_socket):
    print("handle client activated")
    try:
        data = recieve_data(client_socket)  # note typo "recieve" retained intentionally
        print(f"data = {data}")

        if "|" in data:
            parts = data.split("|")
            op = parts[0]
            args = parts[1:]
        else:
            op = data
            args = []

        print("[DEBUG] Operation requested:", op)

        # Old school protocol ops
        if op == "login":
            if len(parts) == 3:
                username = parts[1]
                password = parts[2]
                if login(username, password):
                    if db.get_2fa(username) == 1:
                        email = db.get_email(username)
                        if email:
                            code = ''.join(secrets.choice("0123456789") for _ in range(6))
                            all_2fa_tokens[username] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(b"2FA")
                        else:
                            print("[ERROR] Email not found for 2FA")
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
                res = signup(encrypted_username, encrypted_password, encrypted_email)
                client_socket.send(res.encode())
            else:
                print("[ERROR] register args bad:", args)
                client_socket.send(b"FAIL")

        elif op == "log_snack":
            if len(args) == 6:
                try:
                    username, enc_snack, enc_cal, day, month, year = args
                    with open("rsa_private.pem", "rb") as f:
                        priv = RSA.import_key(f.read())
                    cipher = PKCS1_OAEP.new(priv)
                    username = cipher.decrypt(base64.b64decode(username)).decode()
                    snack = cipher.decrypt(base64.b64decode(enc_snack)).decode()
                    calories = int(cipher.decrypt(base64.b64decode(enc_cal)).decode())
                    add_snack(username, snack, calories, int(day), int(month), int(year))
                    client_socket.send(b"OK")
                except Exception as e:
                    print("[ERROR] log_snack failed:", e)
                    client_socket.send(b"FAIL")
            else:
                print("[ERROR] Bad snack log args")
                client_socket.send(b"FAIL")

        elif op == "delete_snack":
            try:
                if len(args) == 6:
                    username, snack, calories, day, month, year = args
                    delete_snack(username, snack, int(calories), int(day), int(month), int(year))
                    client_socket.send(b"OK")
                else:
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("[ERROR] del snack fail:", e)
                client_socket.send(b"FAIL")

        elif op == "get_snacks":
            try:
                if len(args) == 4:
                    username, day, month, year = args
                    data = db.get_snacks(username, int(day), int(month), int(year))
                    if not data:
                        client_socket.send(b"NONE")
                    else:
                        msg = "\n".join([f"{s}: {c} kcal" for s, c in data])
                        client_socket.send(msg.encode())
                else:
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("[ERROR] get_snacks:", e)
                client_socket.send(b"FAIL")

        elif op == "get_total":
            try:
                if len(args) == 4:
                    username, day, month, year = args
                    total = get_total_calories(username, int(day), int(month), int(year))
                    client_socket.send(str(total).encode())
                else:
                    client_socket.send(b"0")
            except Exception as e:
                print("[ERROR] get_total:", e)
                client_socket.send(b"0")

        elif op == "get_stats":
            try:
                if len(args) == 1:
                    username = args[0]
                    history = db.get_stats(username)
                    if not history:
                        client_socket.send(b"NONE")
                    else:
                        lines = []
                        for d, m, y, total in history:
                            goal = db.get_goal_for_date(username, d, m, y)
                            if goal:
                                gcal, gtype = goal
                                lines.append(f"{d}/{m}/{y}:{total}|{gcal}|{gtype}")
                            else:
                                lines.append(f"{d}/{m}/{y}:{total}||")
                        client_socket.send("\n".join(lines).encode())
                else:
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("[ERROR] get_stats:", e)
                client_socket.send(b"FAIL")

        elif op == "get_2fa":
            if len(args) == 1:
                try:
                    res = db.get_2fa(args[0])
                    client_socket.send(str(res).encode())
                except:
                    client_socket.send(b"0")
            else:
                client_socket.send(b"0")

        elif op == "update_2fa":
            if len(args) == 2:
                try:
                    db.update_2fa(args[0], args[1])
                    client_socket.send(b"OK")
                except:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "reset_pass":
            if len(args) == 2:
                try:
                    uid = decrypt_field(args[0])
                    email = db.get_email(uid)
                    if email:
                        code = ''.join(secrets.choice("0123456789") for _ in range(6))
                        all_2fa_tokens[uid] = (code, time.time() + 300)
                        send_email(email, code)
                        client_socket.send(b"2FA")
                    else:
                        client_socket.send(b"FAIL")
                except Exception as e:
                    print("[ERROR] reset_pass:", e)
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "reset_verify":
            if len(args) == 3:
                uid, new_pass, code = args
                if verify_2fa_code(uid, code):
                    updated = db.update_user_password(uid, new_pass)
                    if updated:
                        client_socket.send(b"OK")
                    else:
                        client_socket.send(b"FAIL")
                else:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "update_goal":
            if len(args) == 6:
                try:
                    u, c, t, d, m, y = args
                    username = decrypt_field(u)
                    calories = int(decrypt_field(c))
                    goal_type = int(decrypt_field(t))
                    db.update_goals(username, calories, goal_type, int(d), int(m), int(y))
                    client_socket.send(b"OK")
                except Exception as e:
                    print("[ERROR] goal update failed:", e)
                    client_socket.send(b"error")
            else:
                client_socket.send(b"error")

        elif op == "get_goal":
            if len(args) == 1:
                try:
                    username = decrypt_field(args[0])
                    now = time.localtime()
                    goal = db.get_goal_for_date(username, now.tm_mday, now.tm_mon, now.tm_year)
                    if goal:
                        gcal, gtype = goal
                        client_socket.send(f"{gcal}|{gtype}".encode())
                    else:
                        client_socket.send(b"|")
                except:
                    client_socket.send(b"error")
            else:
                client_socket.send(b"error")

        elif op == "get_clippy_interval":
            if len(args) == 1:
                try:
                    interval = db.get_interval(args[0])
                    client_socket.send(str(interval).encode())
                except:
                    client_socket.send(b"60")
            else:
                client_socket.send(b"60")

        elif op == "update_clippy_interval":
            if len(args) == 2:
                try:
                    db.update_interval(args[0], int(args[1]))
                    client_socket.send(b"OK")
                except:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        else:
            client_socket.send(b"Unknown operation")

    except Exception as e:
        print("[ERROR] Unexpected issue in handle_client:", e)
        client_socket.send(b"Internal error occurred.")
    finally:
        client_socket.close()


def detect_multiple_ip_ddos():
    now = time.time()
    global all_conn_times
    all_conn_times = [t for t in all_conn_times if now - t < 5]
    if len(all_conn_times) >= 50:
        return False
    all_conn_times.append(now)
    return True


def detect_single_ip_ddos(ip):
    now = time.time()
    times = ip_access_log.get(ip, [])
    ip_access_log[ip] = [t for t in times if now - t < RATE_LIMIT_WINDOW] + [now]
    return len(ip_access_log[ip]) < MAX_CONNECTIONS


def start_server():
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_socket, addr = server.accept()
        ip = addr[0]

        if not detect_single_ip_ddos(ip):
            print(f"[WARN] IP blocked (too many): {ip}")
            client_socket.close()
            continue
        if not detect_multiple_ip_ddos():
            print("[WARN] Server too busy")
            client_socket.close()
            continue

        t = threading.Thread(target=handle_client, args=(client_socket,))
        t.start()
start_server()

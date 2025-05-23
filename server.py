
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

ip_times_of_conn= {} # when  a specific ip logged
RATE_LIMIT_WINDOW = 1
MAX_CONNECTIONS = 20
all_conn_times = []
all_2fa_codes = {}

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 12345


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_HOST, SERVER_PORT))
server.listen(5)
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

db = DBManager()


def start_udp_discovery_server():
    DISCOVERY_PORT = 54545
    DISCOVERY_WORD = "SNACKSYNC"
    DISCOVERY_VERSION = "v1.0" #incase of future updates

    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", DISCOVERY_PORT))
        while True:
            try:
                msg, addr = sock.recvfrom(1024)
                msg = msg.decode().strip()
                if msg == f"{DISCOVERY_WORD}|{DISCOVERY_VERSION}":
                    ip = get_local_ip()
                    response = f"{DISCOVERY_WORD}_SERVER|{DISCOVERY_VERSION}|{ip}"
                    sock.sendto(response.encode(), addr)
            except Exception as e:
                print("[UDP ERROR]", e)

    threading.Thread(target=listen, daemon=True).start()


def login(id, password):
    print("entered id =", id)
    if "@" in id:
        username = db.get_username_by_email(id)
        if not username:
            print("Email not found in DB")
            return None
    else:
        username = id
    hash_in_db = db.get_user_password(username)
    if hash_in_db:
        stored_hash = hash_in_db.encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            print("password correct in login for", username)
            return username
        else:
            print("Invalid password")
            return None #false would cause problems in handle client because it would see username as a boolean
    else:
        print("User not found")
        return None


def verify_2fa_code(username, submitted_code):
    if username not in all_2fa_codes:
        print("2fa token for user doesnt exist")
        return False

    correct_code, expiry = all_2fa_codes[username]
    now = time.time()

    if submitted_code == correct_code and now <= expiry:
        print(f"2FA code is correct")
        del all_2fa_codes[username]  #remove token so there wont be overload
        return True
    else:
        print("Invalid or expired 2FA code")
        return False


def decrypt_field(encrypted_base64):
    with open("rsa_private.pem", "rb") as f:
        key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(key)
    raw = base64.b64decode(encrypted_base64)
    return cipher.decrypt(raw).decode()

def send_email(to_email, code):
    print("send email activated")
    my_email = "latexdus@gmail.com" #other email didnt work
    password = "dsevptrpckqotgpq"

    message = f"Subject: Your SnackSync Verification Code\n\nYour code is: {code}"
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(my_email, password)
        server.sendmail(my_email, to_email, message)


def signup(encrypted_username, encrypted_password, encrypted_email):
    try:
        print("sign  up activated")
        username = decrypt_field(encrypted_username)
        password = decrypt_field(encrypted_password)
        email = decrypt_field(encrypted_email)

        print(f"decryp username: {username} decryp pass: {password} decryp email: {email}")

        # generate code for 2fa
        code = ''.join(secrets.choice("0123456789") for _ in range(6))
        all_2fa_codes[username] = (code, time.time() + 300)

        print("Email sent tera")
        send_email(email, code)

        def add_user():
            try:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                db.insert_user(username, hashed_password, email)
            except Exception as e:
                print(f"adding user failed")

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
                result = login(username, password)
                if result:
                    username = result
                    if db.get_2fa(username) == 1:
                        print(" 2FA is enabled")

                        email = db.get_email(username)
                        if email:
                            code = ''.join(secrets.choice("0123456789") for _ in range(6))
                            all_2fa_codes[username] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(f"2FA|{username}".encode())
                        else:
                            print("No email")
                            client_socket.send(b"FAIL")
                    else:
                        client_socket.send(username.encode()) #bcuz email can get used in the client
                else:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "register":
            if len(args) == 3:
                encrypted_username, encrypted_password, encrypted_email = args
                result = signup(encrypted_username, encrypted_password, encrypted_email)
                client_socket.send(result.encode())
            else:
                client_socket.send(b"FAIL")


        elif op == "log_snack":
            if len(args) == 6:
                username, snack, calories, day, month, year = args
                print("log snack activated")
                try:
                    username = decrypt_field(username)
                    snack = decrypt_field(snack)
                    calories = decrypt_field(calories)
                    add_snack(username, snack, calories, int(day), int(month), int(year))
                    client_socket.send(b"OK")
                    print("log_snack sent ok")
                except Exception as e:
                    print("couldnt log snack in server:", e)
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "delete_snack":
            try:
                if len(args) == 6:
                    username, snack, calories, day, month, year = args
                    calories = int(calories)
                    day, month, year = int(day), int(month), int(year)
                    delete_snack(username, snack, calories, day, month, year)
                    client_socket.send(b"OK")
                else:
                    print("[ERROR] Invalid delete_snack args:", args)
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("deleting snack failed:", e)
                client_socket.send(b"FAIL")
        elif op == "get_snacks":
            try:
                if len(args) == 4:
                    username, day, month, year = args
                    username = User.decrypt_rsa(username)
                    print(f"[DEBUG] Get snacks for {username} on {day}/{month}/{year}")
                    rows = db.get_snacks(username, int(day), int(month), int(year))
                    if not rows:
                        client_socket.send(b"NONE")
                    else:
                        snacks = ""
                        for snack, calories in rows:
                            snacks += f"{snack}: {calories} kcal\n"
                        snacks = snacks.strip()
                        client_socket.send(snacks.encode())
                else:
                    print("[ERROR] Invalid get_snacks args:", args)
                    client_socket.send(b"FAIL")  # <== also better than empty
            except Exception as e:
                print("Failed get_snacks:", e)
                client_socket.send(b"FAIL")
        elif op == "get_total":
          try:
                if len(args) == 4:
                    username, day, month, year = args
                    total = get_total_calories(username, int(day), int(month), int(year))
                    print(f"Total calculated for {username} on {day}/{month}/{year} = {total}")
                    client_socket.send(str(total).encode())
                    print(f"Sent total: {total}")
                else:
                    client_socket.send(b"0")
          except Exception as e:
                print("Exception in get_total:", e)
                client_socket.send(b"0")
        elif op == "get_stats":
            try:
                if len(args) == 1:
                    username = args[0]
                    print(f"Getting stats for {username}")
                    history = db.get_stats(username) #all user snack history for all days
                    if not history:
                        client_socket.send(b"NONE")
                        return
                    stat_to_print = []
                    for day, month, year, total in history:
                        goal = db.get_goal_for_date(username, day, month, year)
                        if goal:
                            gcal, gtype = goal
                            stat_to_print.append(f"{day}/{month}/{year}:{total}|{gcal}|{gtype}")
                        else:
                            stat_to_print.append(f"{day}/{month}/{year}:{total}||")  # no goal set
                    message = "\n".join(stat_to_print)
                    client_socket.send(message.encode())
                else:
                    print("Invalid stats arguments:", args)
                    client_socket.send(b"FAIL")
            except Exception as e:
                print("Exception in get_stats:", e)
                client_socket.send(b"FAIL")


        elif op == "get_2fa":
            if len(args) == 1:
                encrypted_username = args[0]
                try:
                    username = decrypt_field(encrypted_username)
                    result = db.get_2fa(username)
                    client_socket.send(str(result).encode())
                except Exception as e:
                    print("get_2fa failed:", e)
                    client_socket.send(b"0")
            else:
                client_socket.send(b"0")
        elif op == "check2fa":
            if len(args) == 2:
                username, submitted_code = args
                if verify_2fa_code(username, submitted_code):
                    print("2FA login works")
                    client_socket.send(b"OK")
                else:
                    print("2FA login failed")
                    client_socket.send(b"FAIL")
            else:
                print(" Invalid login2fa arguments")
                client_socket.send(b"FAIL")
        elif op == "update_2fa":
            if len(args) == 2:
                username, value = args
                try:
                    username = decrypt_field(username)
                    value = decrypt_field(value)
                    db.update_2fa(username, value)
                    client_socket.send(b"OK")
                    print("update 2fa succeeded")
                except Exception as e:
                    print("update_2fa failed:", e)
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")
        elif op == "reset_pass":
            if len(args) == 2:
                enc_user_id, hashed_password = args
                try:
                    user_id = decrypt_field(enc_user_id)
                    print(f"Decrypted user_id: {user_id}")
                    email = db.get_email(user_id)
                    if email:
                        try:
                            code = ''.join(secrets.choice("0123456789") for _ in range(6))
                            all_2fa_codes[user_id] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(b"2FA")  # tell client to prompt for code
                            return
                        except Exception as e:
                            print(f" Failed to send email im reset_pass: {e}")
                            client_socket.send(b"FAIL")
                            return
                    else:
                        print("No email found")
                        client_socket.send(b"FAIL")
                        return

                except Exception as e:
                    print(f"reset_pass failed: {e}")
                    client_socket.send(b"FAIL")
            else:
                print("Invalid reset_pass args")
                client_socket.send(b"FAIL")
        elif op == "reset_verify":
            if len(args) == 3:
                user_id, new_password, submitted_code = args
                if verify_2fa_code(user_id, submitted_code):
                    updated = db.update_user_password(user_id, new_password)
                    if updated:
                        client_socket.send(b"OK")
                    else:
                        print(f"Password update failed for {user_id}")
                        client_socket.send(b"FAIL")
                else:
                    print("Invalid or expired 2FA code")
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "update_goal":
            if len(args) == 6:
                try:
                    enc_username, enc_cal, enc_type, day, month, year = args
                    username = decrypt_field(enc_username)
                    goal_cal_str = decrypt_field(enc_cal)
                    goal_calories = int(goal_cal_str) #rsa is string
                    goal_type = int(decrypt_field(enc_type))
                    day, month, year = int(day), int(month), int(year)

                    db.update_goals(username, goal_calories, goal_type, day, month, year)
                    client_socket.send(b"OK")
                except Exception as e:
                    print("update_goal failed:", e)
                    client_socket.send(b"error")
            else:
                print("invalid update_goal args:", args)
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
                    print("get_goal error:", e)
                    client_socket.send(b"error")
            else:
                print("invalid get_goal arguments", args)
                client_socket.send(b"error")  #TODO FIX TIHS FUNCTION TO TAKE DATE ARGUMENTS YOGESH
        elif op == "get_clippy_interval": #skippy is goeie
            if len(args) == 1:
                username = args[0]
                try:
                    interval = db.get_interval(username)
                    client_socket.send(str(interval).encode())
                except Exception as e:
                    print("get_clippy_interval failed:", e)
                    client_socket.send(b"60")  #dfult
            else:
                client_socket.send(b"60")

        elif op == "update_clippy_interval":
            if len(args) == 2:
                username = args[0]
                try:
                    new_interval = int(args[1])
                    db.update_interval(username, new_interval)
                    client_socket.send(b"OK")
                except Exception as e:
                    print("update_clippy_interval failed:", e)
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")
        elif op == "get_goal_date":
            if len(args) == 4:
                try:
                    encrypted_username, day, month, year = args
                    username = decrypt_field(encrypted_username)
                    day, month, year = int(day), int(month), int(year)
                    result = db.get_goal_for_date(username, day, month, year)
                    if result:
                        goal_calories, goal_type = result
                        response = f"{goal_calories}|{goal_type}"
                    else:
                        response = "|"
                    client_socket.send(response.encode())
                except Exception as e:
                    import traceback
                    print("[ERROR] get_goal_date failed:", e)
                    traceback.print_exc()
                    client_socket.send(b"error")

            else:
                print("invalid get_goal_date arguments:", args)
                client_socket.send(b"error")
        elif op == "get_ip":
            local_ip = get_local_ip()
            client_socket.send(local_ip.encode())

        else:
            print("error with if op == ")
            client_socket.send(b"Invalid operation")

    except Exception as e:
        print("error in handle_client:", e)
        client_socket.send(f"Error: {e}".encode())
    finally:
        client_socket.close()

def check_multiple_ip_ddos():
    now = time.time()
    recent_connections = [t for t in all_conn_times if now - t < 5]
    print(f" {len(recent_connections)} connections in last 5 seconds")
    if len(recent_connections) >= 30:
        return False
    recent_connections.append(now)
    all_conn_times[:] = recent_connections
    return True


def check_single_ip_ddos(ip):
    current_time = time.time()
    attempts = ip_times_of_conn.get(ip, [])

    recent_attempts = []
    for t in attempts:
        if current_time - t < RATE_LIMIT_WINDOW:
            recent_attempts.append(t)

    if len(recent_attempts) >= MAX_CONNECTIONS:
        return False

    recent_attempts.append(current_time)
    ip_times_of_conn[ip] = recent_attempts
    return True



def start_server():
    start_udp_discovery_server()
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    while True:
        client_socket, address = server.accept()
        client_ip = address[0]

        if not check_single_ip_ddos(client_ip):
            client_socket.send(b"SPAM")
            client_socket.close()
            continue
        if not check_multiple_ip_ddos():
            print("The server is busy")
            client_socket.send(b"BUSY")
            client_socket.close()
            continue
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
##




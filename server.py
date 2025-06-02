import socket
import threading
import bcrypt
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import smtplib
from dbmanager import DBManager
import aes
from dotenv import load_dotenv
import os

ip_times_of_conn= {}
RATE_LIMIT_WINDOW = float(os.getenv("RATE_LIMIT_WINDOW", 1))
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 20))
all_conn_times = []
all_2fa_codes = {}

SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", 12345))
private_key_path = os.getenv("RSA_PRIVATE_KEY_PATH", "rsa_private.pem")
smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
smtp_port = int(os.getenv("SMTP_PORT", 465))

load_dotenv()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((SERVER_HOST, SERVER_PORT))
server.listen(5)

db = DBManager()
users_in_2fa = {}

def start_udp_discovery_server(): #udp signal so client can find the ip of the server
    DISCOVERY_PORT = int(os.getenv("DISCOVERY_PORT", 54545))
    DISCOVERY_WORD = os.getenv("DISCOVERY_WORD", "SNACKSYNC")
    DISCOVERY_VERSION = os.getenv("DISCOVERY_VERSION", "v1.0")

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
                continue
    threading.Thread(target=listen, daemon=True).start()


def generate_code(): #generates random code based on time
    length = 6
    digits = "0123456789"
    code = ""
    t = int(time.time() * 1000)
    for i in range(length):
        t = (t * 7 + i)
        code += digits[t % 10]
    return code


def login(id, password):
    is_email = "@" in id
    enc_id = aes.encrypt_aes(id)
    if is_email:
        username = db.get_username_by_email(enc_id)
    else:
        if db.username_exists(enc_id):
            username = enc_id
        else:
            username = None
    if not username:
        return None

    hash_in_db = db.get_user_password(username)
    if hash_in_db and bcrypt.checkpw(password.encode(), hash_in_db.encode()):
        return username
    return None



def verify_2fa_code(username, submitted_code):
    if username not in all_2fa_codes:
        return False

    correct_code, expiry = all_2fa_codes[username]
    now = time.time()

    if submitted_code == correct_code and now <= expiry:
        del all_2fa_codes[username]
        return True
    else:
        return False


def decrypt_field(encrypted_text):
    if not encrypted_text or encrypted_text.strip() == "":
        return None
    try:
        decoded_data = base64.b64decode(encrypted_text)
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())
            cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(decoded_data).decode()
    except Exception as e:
        return None



def send_email(to_email, code):
    my_email = os.getenv("EMAIL_USER")
    my_pass = os.getenv("EMAIL_PASS")

    message = f"Subject: Your SnackSync Verification Code\n\nYour code is: {code}"
    with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
        server.login(my_email, my_pass)
        server.sendmail(my_email, to_email, message)


def signup(encrypted_username, password, encrypted_email):
    try:
        username = decrypt_field(encrypted_username)
        email = decrypt_field(encrypted_email)
        raw_password = decrypt_field(password)

        if not username or not email or not raw_password:
            return "FAIL"
        if db.username_exists(aes.encrypt_aes(username)) or db.email_exists(aes.encrypt_aes(email)):
            return "EXIST"

        hashed_pw = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
        code = generate_code()

        all_2fa_codes[username] = (code, time.time() + 400)
        users_in_2fa[username] = (hashed_pw, email)

        send_email(email, code)
        return "2FA"
    except Exception:
        return "FAIL"


def add_snack(username, snack, calories, day, month, year):
    db.insert_snack(aes.encrypt_aes(username), snack, calories, day, month, year)
    return db.get_total_calories(username, day, month, year)


def get_total_calories(username, day, month, year):
    return db.get_total_calories(aes.encrypt_aes(username), day, month, year)


def delete_snack(username, snack, calories, day, month, year):
    db.delete_snack(aes.encrypt_aes(username), snack, calories, day, month, year)
    return db.get_total_calories(username, day, month, year)


def recieve_data(sock): #to avoid code getting cut because of tcp stream not taking in the entire message as we want it to, checks for !END
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
    try:
        data = recieve_data(client_socket)
        if "|" in data:
            parts = data.split("|")
            op = parts[0]
            args = parts[1:]
        else:
            op = data
            args = []

        if op == "login":
            if len(args) == 2:
                id = args[0]
                password = args[1]
                id = decrypt_field(id)
                password = decrypt_field(password)
                result = login(id, password)
                if result:
                    username = result
                    if db.get_2fa(username) == 1:
                        email = aes.decrypt_aes(db.get_email(username))
                        if email:
                            code = generate_code()
                            real_username = aes.decrypt_aes(username)
                            all_2fa_codes[real_username] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(f"2FA|{real_username}".encode())
                        else:
                            client_socket.send(b"FAIL")
                    else:
                        client_socket.send(aes.decrypt_aes(username).encode())
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
                try:
                    username = decrypt_field(username)
                    snack = decrypt_field(snack)
                    calories = decrypt_field(calories)
                    add_snack(username, snack, calories, int(day), int(month), int(year))
                    client_socket.send(b"OK")
                except Exception as e:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "delete_snack":
            try:
                if len(args) == 6:
                    username, snack, calories, day, month, year = args
                    username = decrypt_field(username)
                    snack = decrypt_field(snack)
                    calories = decrypt_field(calories)
                    day, month, year = int(day), int(month), int(year)
                    delete_snack(username, snack, calories, day, month, year)
                    client_socket.send(b"OK")
                else:
                    client_socket.send(b"FAIL")
            except Exception as e:
                client_socket.send(b"FAIL")
        elif op == "get_snacks":
            try:
                if len(args) == 4:
                    username, day, month, year = args
                    username = decrypt_field(username)
                    rows = db.get_snacks(aes.encrypt_aes(username), int(day), int(month), int(year))
                    if not rows:
                        client_socket.send(b"NONE")
                    else:
                        snacks = ""
                        for snack, calories in rows:
                            snacks += f"{snack}: {calories} kcal\n"
                        snacks = snacks.strip()
                        client_socket.send(snacks.encode())
                else:
                    client_socket.send(b"FAIL")
            except Exception as e:
                client_socket.send(b"FAIL")
        elif op == "get_total":
          try:
                if len(args) == 4:
                    username, day, month, year = args
                    username = decrypt_field(username)
                    total = get_total_calories(username, int(day), int(month), int(year))
                    client_socket.send(str(total).encode())
                else:
                    client_socket.send(b"0")
          except Exception as e:
                client_socket.send(b"0")
        elif op == "get_stats":
            try:
                if len(args) == 1:
                    username = args[0]
                    username = decrypt_field(username)
                    history = db.get_stats(aes.encrypt_aes(username))
                    if not history:
                        client_socket.send(b"NONE")
                        return
                    stat_to_print = []
                    for day, month, year, total in history:
                        goal = db.get_goal_for_date(aes.encrypt_aes(username), day, month, year)
                        if goal:
                            gcal, gtype = goal
                            stat_to_print.append(f"{day}/{month}/{year}:{total}|{gcal}|{gtype}")
                        else:
                            stat_to_print.append(f"{day}/{month}/{year}:{total}||")
                    message = "\n".join(stat_to_print)
                    client_socket.send(message.encode())
                else:
                    client_socket.send(b"FAIL")
            except Exception as e:
                client_socket.send(b"FAIL")

        elif op == "get_2fa":
            if len(args) == 1:
                encrypted_username = args[0]
                try:
                    username = decrypt_field(encrypted_username)
                    result = db.get_2fa(aes.encrypt_aes(username))
                    client_socket.send(str(result).encode())
                except Exception as e:
                    client_socket.send(b"0")
            else:
                client_socket.send(b"0")

        elif op == "check2fa":
            if len(args) == 2:
                username, submitted_code = args
                username = decrypt_field(username)
                if verify_2fa_code(username, submitted_code):
                    client_socket.send(b"OK")
                else:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "update_2fa":
            if len(args) == 2:
                username, value = args
                try:
                    username = decrypt_field(username)
                    db.update_2fa(aes.encrypt_aes(username), value)
                    client_socket.send(b"OK")
                except Exception as e:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "reset_pass":
            if len(args) == 2:
                enc_user_id, hashed_password = args
                try:
                    real_username = decrypt_field(enc_user_id)
                    enc_username = aes.encrypt_aes(real_username)
                    email = aes.decrypt_aes(db.get_email(enc_username))
                    if email:
                        try:
                            code = generate_code()
                            all_2fa_codes[real_username] = (code, time.time() + 300)
                            send_email(email, code)
                            client_socket.send(b"2FA")
                            return
                        except Exception as e:
                            client_socket.send(b"FAIL")
                            return
                    else:
                        client_socket.send(b"FAIL")
                        return

                except Exception as e:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")

        elif op == "reset_verify":
            if len(args) == 3:
                user_id, new_password, submitted_code = args
                real_username = decrypt_field(user_id)
                if verify_2fa_code(real_username, submitted_code):
                    raw_password = decrypt_field(new_password)
                    hashed_password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
                    updated = db.update_user_password(aes.encrypt_aes(real_username), hashed_password)
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
                    enc_username, enc_cal, enc_type, day, month, year = args
                    username = decrypt_field(enc_username)
                    goal_cal_str = decrypt_field(enc_cal)
                    goal_calories = int(goal_cal_str)
                    goal_type = int(decrypt_field(enc_type))
                    day, month, year = int(day), int(month), int(year)
                    db.update_goals(aes.encrypt_aes(username), goal_calories, goal_type, day, month, year)
                    client_socket.send(b"OK")
                except Exception as e:
                    client_socket.send(b"error")
            else:
                client_socket.send(b"error")

        elif op == "get_goal":
            if len(args) == 1:
                try:
                    encrypted_username = args[0]
                    username = decrypt_field(encrypted_username)

                    now = time.localtime()
                    day, month, year = now.tm_mday, now.tm_mon, now.tm_year

                    result = db.get_goal_for_date(aes.encrypt_aes(username), day, month, year)

                    if result:
                        goal_calories, goal_type = result
                        response = f"{goal_calories}|{goal_type}"
                    else:
                        response = "|"

                    client_socket.send(response.encode())
                except Exception as e:
                    client_socket.send(b"error")
            else:
                client_socket.send(b"error")
        elif op == "get_clippy_interval":
            if len(args) == 1:
                username = args[0]
                try:
                    username = decrypt_field(username)
                    interval = db.get_interval(aes.encrypt_aes(username))
                    client_socket.send(str(interval).encode())
                except Exception as e:
                    client_socket.send(b"60")
            else:
                client_socket.send(b"60")

        elif op == "update_clippy_interval":
            if len(args) == 2:
                username = args[0]
                try:
                    new_interval = int(args[1])
                    username = decrypt_field(username)
                    db.update_interval(aes.encrypt_aes(username), new_interval)
                    client_socket.send(b"OK")
                except Exception as e:
                    client_socket.send(b"FAIL")
            else:
                client_socket.send(b"FAIL")
        elif op == "get_goal_date":
            if len(args) == 4:
                try:
                    encrypted_username, day, month, year = args
                    day, month, year = int(day), int(month), int(year)
                    username = decrypt_field(encrypted_username)
                    result = db.get_goal_for_date(aes.encrypt_aes(username), day, month, year)
                    if result:
                        goal_calories, goal_type = result
                        response = f"{goal_calories}|{goal_type}"
                    else:
                        response = "|"
                    client_socket.send(response.encode())
                except Exception as e:
                    client_socket.send(b"error")
            else:
                client_socket.send(b"error")
        elif op == "get_username_from_email":
            try:
                if len(args) == 1:
                    email = decrypt_field(args[0])
                    if not email:
                        client_socket.send(b"FAIL")
                        return
                    email = aes.encrypt_aes(email)
                    username = db.get_username_by_email(email)
                    if username:
                        username = aes.decrypt_aes(username)
                    if username:
                        client_socket.send(username.encode())
                    else:
                        client_socket.send(b"FAIL")
                else:
                    client_socket.send(b"FAIL")
            except Exception:
                client_socket.send(b"FAIL")

        elif op == "verify_register":
            try:
                if len(args) == 2:
                    user_id, code = args
                    real_username = decrypt_field(user_id)
                    if not real_username:
                        client_socket.send(b"FAIL")
                        return

                    if verify_2fa_code(real_username, code):
                        if real_username in users_in_2fa:
                            password, email = users_in_2fa.pop(real_username)
                            db.insert_user(aes.encrypt_aes(real_username), password, aes.encrypt_aes(email))
                            client_socket.send(b"OK")
                        else:
                            client_socket.send(b"FAIL")
                    else:
                        client_socket.send(b"FAIL")
                else:
                    client_socket.send(b"FAIL")
            except Exception:
                client_socket.send(b"FAIL")



        else:
            client_socket.send(b"Invalid operation")


    except Exception as e:
        client_socket.send(f"Error: {e}".encode())
    finally:
        client_socket.close()


def check_multiple_ip_ddos(): #check if theres too many ips connecting in a short time frame
    now = time.time()
    recent_connections = [t for t in all_conn_times if now - t < 5]
    if len(recent_connections) >= 30:
        return False
    recent_connections.append(now)
    all_conn_times[:] = recent_connections
    return True


def check_single_ip_ddos(ip): #checks if someone communicated with server too many times recently
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
    while True:
        client_socket, address = server.accept()
        client_ip = address[0]

        if not check_single_ip_ddos(client_ip):
            client_socket.send(b"SPAM")
            client_socket.close()
            continue
        if not check_multiple_ip_ddos():
            client_socket.send(b"BUSY")
            client_socket.close()
            continue
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    start_server()






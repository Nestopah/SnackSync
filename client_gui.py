
import socket
from operator import rshift

import customtkinter as ctk
import tkinter as tk
from tkinter  import messagebox
from datetime import datetime

from customtkinter import CTkEntry

from hasher import hash_password
from snack import Snack
from snack import EncryptedSnack
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import threading
import bcrypt
from clippy import Clippy
from PIL import Image, ImageTk
from user import User
from encryptedmessage import EncryptedMessage



def discover_server_ip():
    DISCOVERY_PORT = 54545
    DISCOVERY_WORD = "SNACKSYNC"
    DISCOVERY_VERSION = "v1.0"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)

        message = f"{DISCOVERY_WORD}|{DISCOVERY_VERSION}"
        sock.sendto(message.encode(), ("<broadcast>", DISCOVERY_PORT))

        data, addr = sock.recvfrom(1024)
        response = data.decode().strip()

        if response.startswith(f"{DISCOVERY_WORD}_SERVER|{DISCOVERY_VERSION}|"):
            server_ip = response.split("|")[2]
            return server_ip
        else:
            print("[ERROR] Unexpected server response:", response)
            return None
    except Exception as e:
        print("[ERROR] Could not discover SnackSync server:", e)
        return None

SERVER_HOST = discover_server_ip()
SERVER_PORT = 12345
if not SERVER_HOST:
    boot = ctk.CTk()
    boot.withdraw()
    messagebox.showerror("Connection Error", "Could not find SnackSync server on the network.\nGoodbye boyo.")
    exit()

class SnackSyncApp:
    def __init__(self, root):
        self.root = root
        self.root.iconbitmap("icon.ico")
        self.root.title("SnackSync - Login/Register")
        self.root.geometry("300x250")
        self.center_window(root, 300,300)

        ctk.CTkLabel(root, text="Username or Email:").pack(pady=5)
        self.id_CTkEntry = ctk.CTkEntry(root)
        self.id_CTkEntry.pack(pady=5)

        ctk.CTkLabel(root, text="Password:").pack(pady=5)
        self.password_CTkEntry = ctk.CTkEntry(root, show="*")
        self.password_CTkEntry.pack(pady=5)

        ctk.CTkButton(root, text="Login", command=self.login).pack(pady=5)
        ctk.CTkButton(root, text="Sign up", command=self.register).pack(pady=5)
       ## bg_color = self.root._apply_appearance_mode(ctk.ThemeManager.theme["CTk"]["fg_color"])
       ##print(bg_color)
        ctk.CTkButton(self.root, text="Forgot password?", text_color="#66B2FF", fg_color="gray14", hover_color="gray14", border_width=0, command=self.open_password_reset).pack()

    def hash(self, password): #for convenience
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    def login(self):
        def login_thread():
            id = self.id_CTkEntry.get().strip()  # can be username or email
            password = self.password_CTkEntry.get().strip()

            if not id or not password:
                self.root.after(0,lambda: messagebox.showerror("Error", "Please enter username or email, and password."))
                return
            if self.possible_injections(id, allow_email=True):
                return

            enc_id = EncryptedMessage.rsa_encrypt_single(id)
            enc_pass = self.hash(password)

            message = f"login|{enc_id}|{enc_pass}!END"
            response = self.send_request(message)

            if response.startswith("2FA|"):
                username = response.split("|")[1]
                self.root.after(0, lambda: self.show_2fa_prompt(username))
            elif response != "FAIL" and response != "SPAM" and response != "BUSY":
                self.root.after(0, lambda: self.open_main_screen(response.strip()))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Login failed."))
        threading.Thread(target=login_thread).start()

    def possible_injections(self, text, allow_email=False):
        suspicious = ["'", '"', "=", "--", ";", " or ", " and ", "<", ">", "\\", "/*", "*/"]
        if not allow_email:
            suspicious.append("@")
        for part in suspicious:
            if part in text.lower():
                messagebox.showerror("Invalid Input", "Text contains forbidden special characters.")
                return True
        return False

    def register(self):
        self.clear_root()

        self.root.title("SnackSync - Sign up")
        self.root.geometry("300x400")
        self.center_window(self.root, 300, 400)


        ctk.CTkLabel(self.root, text="Username:").pack(pady=5)
        self.username_CTkEntry = ctk.CTkEntry(self.root)
        self.username_CTkEntry.pack(pady=5)

        ctk.CTkLabel(self.root, text="Password:").pack(pady=5)
        self.password_CTkEntry = ctk.CTkEntry(self.root, show="*")
        self.password_CTkEntry.pack(pady=5)

        ctk.CTkLabel(self.root, text="Email:").pack(pady=5)
        self.email_CTkEntry = ctk.CTkEntry(self.root)
        self.email_CTkEntry.pack(pady=5)


        def submit_signup():
            username = self.username_CTkEntry.get().strip()
            password = self.password_CTkEntry.get().strip()
            email = self.email_CTkEntry.get().strip()

            if not username or not password or not email:
                messagebox.showerror("Error", "All fields are required.")
                return

            if "@" not in email or "." not in email:
                messagebox.showerror("Error", "Invalid email format.")
                return
            if self.possible_injections(username, ):
                return
            if self.possible_injections(email,True):
                return
            try:
                hashed_password = self.hash(password)

                msg = EncryptedMessage(username,email)
                enc_username, enc_email = msg.rsa_encrypt_all()

            except Exception as e:
                messagebox.showerror("Error", f"Signup failed:\n{e}")
                return

            message = f"register|{enc_username}|{hashed_password}|{enc_email}!END"
            print("smg sending to server:", message)

            def handle_responses():
                response = self.send_request(message)
                if response == "2FA":
                    self.root.after(0, lambda: [messagebox.showinfo("Verification", "Check your email for a 6-digit code."),self.show_2fa_prompt(username)])
                elif response == "FAIL":
                    self.root.after(0, lambda: messagebox.showerror("Error", "Username or email already exists."))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Unexpected error: {response}"))

            threading.Thread(target=handle_responses).start()
        ctk.CTkButton(root, text="Create account", command=lambda: threading.Thread(target=submit_signup).start()).pack(pady=20)

    def show_2fa_prompt(self, username, newpass=None):
        self.clear_root()
        self.root.title("Two-Factor authentication")
        self.root.geometry("300x200")
        self.center_window(self.root, 300, 200)

        ctk.CTkLabel(self.root, text="Enter the 6-digit code sent to your email").pack(pady=10)
        code_entry = ctk.CTkEntry(self.root)
        code_entry.pack(pady=10)

        def submit_code():
            code = code_entry.get().strip()
            if not code.isdigit() or len(code) != 6:
                messagebox.showerror("Error", "Enter a valid 6-digit code.")
                return
            print(code)
            if newpass:
                enc_user = EncryptedMessage.rsa_encrypt_single(username)
                new_pass = self.hash(newpass)
                message = f"reset_verify|{enc_user}|{new_pass}|{code}!END"
            else:
                enc_user = EncryptedMessage.rsa_encrypt_single(username)
                message = f"check2fa|{enc_user}|{code}!END"
                print("check2fa")

            response = self.send_request(message)
            if response == "OK":
                messagebox.showinfo("Success", "Login successful.")
                self.open_main_screen(username)
            else:
                messagebox.showerror("Error", "Invalid or expired code.")

        ctk.CTkButton(self.root, text="Verify", command=submit_code).pack(pady=10)

    def send_request(self, message):
        try:
            print("send_request activated")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((SERVER_HOST, SERVER_PORT))
                sock.sendall(message.encode())
                response = sock.recv(1024).decode()
                print(f"response = {response} ")
                if response == "BUSY":
                    messagebox.showerror("Error", "Server is busy. Try again later.")
                    return "FAIL"
                elif response == "SPAM":
                    messagebox.showerror("Error", "You're trying too quickly.")
                    return "FAIL"
                return response
        except Exception as e:
            messagebox.showerror("Error", f"Server error: {e}")
            return "FAIL"

    def open_password_reset(self):
        self.clear_root()
        self.root.title("Reset Password")
        self.root.geometry("300x250")
        self.center_window(self.root, 300, 300)

        ctk.CTkLabel(self.root, text="Username or Email:").pack(pady=5)
        self.user_id_CTkEntry = ctk.CTkEntry(self.root)
        self.user_id_CTkEntry.pack(pady=5)

        ctk.CTkLabel(self.root, text="New Password:").pack(pady=5)
        self.password_CTkEntry = ctk.CTkEntry(self.root, show="*")
        self.password_CTkEntry.pack(pady=5)

        ctk.CTkLabel(self.root, text="Confirm Password:").pack(pady=5)
        self.confirm_CTkEntry = ctk.CTkEntry(self.root, show="*")
        self.confirm_CTkEntry.pack(pady=5)

        def send_and_handle():
            user_id = self.user_id_CTkEntry.get().strip()
            password = self.password_CTkEntry.get().strip()
            confirm = self.confirm_CTkEntry.get().strip()

            if not user_id or not password or not confirm:
                self.root.after(0, lambda: messagebox.showerror("Error", "All fields required."))
                return
            if password != confirm:
                self.root.after(0, lambda: messagebox.showerror("Error", "Passwords do not match."))
                return
            try:
                user = User(user_id, password, "yogesh no need")
                encrypted_user_id = user.rsa_username
                hashed_password = user.password.decode()
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error"))
                print("send and handle didnt work")
                return


            message = f"reset_pass|{encrypted_user_id}|{hashed_password}!END"
            print("Sending reset message:", message)
            response = self.send_request(message).strip()

            if response == "OK":
                self.root.after(0, lambda: [messagebox.showinfo("Success", "Password reset successful!"), self.open_main_screen(user_id)])
            elif response == "2FA":
                self.root.after(0, lambda: self.show_2fa_prompt(user_id, newpass=hashed_password))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", response))

        ctk.CTkButton(self.root, text="Reset Password",command=lambda: threading.Thread(target=send_and_handle).start()).pack(pady=10)

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")

    def reminder_loop(self, interval_minutes):
        try:
            self.clippy_timer.cancel() #ignore warning it gets pass later
        except AttributeError: #dexteruchi
            pass
        def loop():
            self.clippy.notification("SnackSync", "Don't forget to log your snacks!")
            self.clippy_timer = threading.Timer(interval_minutes * 60, loop)
            self.clippy_timer.start()

        self.clippy_timer = threading.Timer(interval_minutes * 60, loop)
        self.clippy_timer.start()

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def open_main_screen(self, username):
        self.clear_root()  # remove old login widgets

        self.root.title(f"SnackSync - Main window {username}")
        self.root.geometry("500x600")
        self.center_window(self.root, 500, 700)

        self.clippy = Clippy()
        self.fetch_clippy_interval(username)  # start reminder loop


        ctk.CTkLabel(self.root, text=f"Welcome, {username}!", font=("Arial", 24)).pack(pady=10)

        self.day_var = ctk.StringVar(value=str(datetime.today().day))
        self.month_var = ctk.StringVar(value=str(datetime.today().month))
        self.year_var = ctk.StringVar(value=str(datetime.today().year))

        ctk.CTkLabel(self.root, text=f"Log today:", font=("Arial", 20)).pack(pady=10)

        ctk.CTkLabel(self.root, text="Snack name:").pack(pady=2)
        self.snack_CTkEntry = ctk.CTkEntry(self.root)
        self.snack_CTkEntry.pack(pady=5)

        ctk.CTkLabel(self.root, text="Calories:").pack(pady=2)
        self.calories_CTkEntry = ctk.CTkEntry(self.root)
        self.calories_CTkEntry.pack(pady=2)

        self.total_calories_CTkLabel = ctk.CTkLabel(self.root, text="Total calories today: 0 kcal", font=("Arial", 12))
        self.total_calories_CTkLabel.pack(pady=5)

        self.snack_listbox = tk.Listbox(self.root, width=50, height=8)
        self.snack_listbox.pack(pady=5)

        ctk.CTkButton(self.root, text="Log snack", command=lambda: self.log_snack(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Delete selected snack",command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Log previous days", command=lambda: self.log_prev_days_window(username)).pack( pady=5)
        ctk.CTkButton(self.root, text="Stats", command=lambda: self.stats_window(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Settings", command=lambda: self.open_settings(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Log out", command=self.logout).pack(pady=10)

        threading.Thread(target=lambda: self.display_snacks(username)).start()
        threading.Thread(target=lambda: self.update_total_calories(username)).start()

    def logout(self):
        self.clear_root()
        self.__init__(self.root)  #yog

    def fetch_clippy_interval(self, username, entry_box=None): #flippy
        enc_user = EncryptedMessage.rsa_encrypt_single(username)
        def get_interval():
            try:
                response = self.send_request(f"get_clippy_interval|{enc_user}!END")
                if response.isdigit():
                    interval = int(response)
                    print(f"interval = {interval}")
                    if entry_box:
                        entry_box.insert(0, str(interval))
                    else:
                        self.reminder_loop(interval)
            except Exception as e:
                print(" Failed to fetch clippy_interval:", e)

        threading.Thread(target=get_interval).start()

    def open_settings(self, username):
        self.clear_root()
        self.root.title("Settings")
        self.root.geometry("300x400")
        self.center_window(self.root, 300, 400)

        ctk.CTkLabel(self.root, text="Settings", font=("Arial", 18)).pack(pady=10)
        var = tk.BooleanVar()

        def get_curr_2fa():
            msg = EncryptedMessage(username)
            enc_user = msg.rsa_encrypt_all(username)
            response = self.send_request(f"get_2fa|{enc_user}!END")
            print(f"response = {response}")
            def update_checkbox():
                var.set(response.strip() == "1")
            self.root.after(0, update_checkbox)

        threading.Thread(target=get_curr_2fa).start()
        twofabutton = ctk.CTkCheckBox(self.root, text="Enable 2FA", variable=var)
        twofabutton.pack(pady=10)

        ctk.CTkLabel(self.root, text="Remind me to log snacks every: (minutes)").pack()
        notification_entry = ctk.CTkEntry(self.root)
        notification_entry.pack(pady=5)


        ctk.CTkLabel(self.root, text="Daily Calorie Goal:").pack()
        goal_entry = ctk.CTkEntry(self.root)
        goal_entry.pack(pady=5)

        selected_type = tk.IntVar(value=-1)

        def update_button_styles():
            under.configure(fg_color="#1E90FF" if selected_type.get() == 0 else "#ADD8E6",text_color="black") #under
            over.configure(fg_color="#1E90FF" if selected_type.get() == 1 else "#ADD8E6",text_color="black") #over

        def select_under():
            selected_type.set(0)
            update_button_styles()

        def select_over():
            selected_type.set(1)
            update_button_styles()

        under = ctk.CTkButton(self.root, text="Stay under calorie goal", command=select_under,fg_color="#ADD8E6", border_color="black", border_width=2, text_color="black", hover_color="#ADD8E6")
        under.pack(pady=5)
        over = ctk.CTkButton(self.root, text="Stay over calorie goal", command=select_over,fg_color="#ADD8E6", border_color="black", border_width=2, text_color="black", hover_color="#ADD8E6")
        over.pack(pady=5)

        def fetch_goal_info():
            enc_user = EncryptedMessage.rsa_encrypt_single(username)
            response = self.send_request(f"get_goal|{enc_user}!END")
            if response and "|" in response:
                cal, gtype = response.split("|")
                if cal.isdigit():
                    goal_entry.insert(0, cal)
                if gtype in ("0", "1"):
                    selected_type.set(int(gtype))
                    update_button_styles()

        threading.Thread(target=fetch_goal_info).start()
        self.fetch_clippy_interval(username, notification_entry)

        def save_all():
            new_2fa = 1 if var.get() else 0
            calories = goal_entry.get().strip()
            goal_type = selected_type.get()
            notification_text = notification_entry.get().strip()
            if not notification_text.isdigit() or int(notification_text) <= 0:
                messagebox.showerror("Invalid input", "Reminder timer must be a number greater than 0.")
                return
            if not calories.isdigit():
                messagebox.showerror("Invalid input", "Please enter a numeric goal.")
                return
            if goal_type not in (0, 1):
                messagebox.showerror("Missing", "Please select a goal type.")
                return

            now = datetime.now()
            day, month, year = str(now.day), str(now.month), str(now.year)
            encname = EncryptedMessage.rsa_encrypt_single(username)

            print(f" Sending goal update: calories={calories}, type={goal_type}, 2FA={new_2fa}")

            def send_for_save():
                if calories.isdigit() and goal_type in (0, 1):
                    self.send_request(f"update_goal|{encname}|{calories}|{goal_type}|{day}|{month}|{year}!END")
                elif calories or goal_type != -1:
                    pass
                self.send_request(f"update_2fa|{encname}|{new_2fa}!END")
                self.send_request(f"update_clippy_interval|{encname}|{notification_text}!END")
                messagebox.showinfo("Saved", "Settings updated successfully.")
                self.reminder_loop(int(notification_text))

            threading.Thread(target=send_for_save).start()
        ctk.CTkButton(self.root, text="Save", command=save_all).pack(pady=10)
        ctk.CTkButton(self.root, text="Back to main menu", command=lambda: self.open_main_screen(username)).pack(
            pady=10)

    def log_snack(self, username):
        snack_name = self.snack_CTkEntry.get().strip()
        calories = self.calories_CTkEntry.get().strip()

        if not snack_name or not calories.isdigit():
            messagebox.showerror("Error", "Please enter a valid snack and calorie amount.")
            return

        day = int(self.day_var.get())
        month = int(self.month_var.get())
        year = int(self.year_var.get())

        def send_log_snack():
            try:
                print("Connecting to server to log snack")

                all = EncryptedMessage(username,snack_name, calories)
                enc_username, enc_snack, enc_calories = all.rsa_encrypt_all()
                data = f"log_snack|{enc_username}|{enc_snack}|{enc_calories}|{day}|{month}|{year}!END"
                response = self.send_request(data)
                print("Server response:", response)
                if response == "OK":
                    print("logged a snack")
                else:
                    messagebox.showerror("Error", "Could not log snack")

                def update_and_display():
                    try:
                        self.display_snacks(username)
                        self.update_total_calories(username)
                        self.snack_CTkEntry.delete(0, ctk.END)
                        self.calories_CTkEntry.delete(0, ctk.END)
                        print("display updated after snack log .")
                        now = datetime.now()
                        if day == now.day and month == now.month and year == now.year:
                            self.clippy.notify_goal_result(username)
                        else:
                            print(" snack logged with log prev days function no need to show notification")
                    except Exception as e:
                        self.root.after(0, lambda: messagebox.showerror(f"Error", f"{e}"))
                self.root.after(0, update_and_display)

            except Exception as e:
                print(" Failed to log snack:", e)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to log snack {e}"))

        threading.Thread(target=send_log_snack).start()

    def delete_selected_snack(self, username):
        selected = self.snack_listbox.curselection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a snack to delete.")
            return

        snack = self.snack_listbox.get(selected)
        snack_name, kcal_text = snack.split(":")
        calories = int(kcal_text.strip().split()[0])

        day = self.day_var.get()
        month = self.month_var.get()
        year = self.year_var.get()

        def send_delete():
            try:
                msg = EncryptedMessage(username,snack_name, calories)
                enc_user, enc_snack, enc_kcal = msg.rsa_encrypt_all()
                message = f"delete_snack|{enc_user}|{enc_snack}|{enc_kcal}|{day}|{month}|{year}!END"
                print("Sending delete message:", message)
                response = self.send_request(message).strip()

                if response == "OK":
                    print("Snack deleted .")
                    self.root.after(0, lambda: [self.update_total_calories(username)])
                    self.root.after(0, lambda: [self.display_snacks(username)])
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Snack deletion failed."))
            except Exception as e:
                print("Failed to delete snack:", e)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to delete snack: {e}"))

        threading.Thread(target=send_delete).start()

    def stats_window(self, username):
        self.clear_root()

        self.root.title("Stats")
        self.root.geometry("400x300")
        self.center_window(self.root, 400, 300)


        ctk.CTkLabel(self.root, text="All time stats:").pack(pady=10)
        until_stats = ctk.CTkLabel(self.root, text="Loading...")
        until_stats.pack()

        def fetch_stats():
            try:
                enc_user = EncryptedMessage.rsa_encrypt_single(username)
                response = self.send_request(f"get_stats|{enc_user}!END")
            except Exception as e:
                self.root.after(0, lambda: until_stats.configure(text=f"Error: {e}"))
                return

            if not response or response == "NONE":
                self.root.after(0, lambda: until_stats.configure(text="No data found."))
                return

            stats = response.strip().split("\n")
            def show_stats():
                until_stats.destroy()
                goal_reached = 0
                total_days_logged = 0

                for line in stats:
                    if ":" not in line:
                        continue

                    try:
                        date_part, rest = line.split(":", 1)
                        parts = rest.split("|", 2)

                        total_str = parts[0].strip()
                        gcal = parts[1].strip() if len(parts) > 1 else ""
                        gtype = parts[2].strip() if len(parts) > 2 else ""

                        text = f"{date_part}: {total_str} kcal"

                        if gcal.isdigit() and gtype in ("0", "1"):
                            total_val = int(total_str)
                            goal_val = int(gcal)
                            goal_type= int(gtype)

                            typetera = "under" if goal_type == 0 else "over"
                            goal_text = f"(goal was {typetera} {goal_val})"

                            goal_succeed = (goal_type == 1 and total_val >= goal_val) or \
                                       (goal_type == 0 and total_val <= goal_val)

                            if goal_succeed:
                                text += f"  | Goal reached: Yes {goal_text}"
                                goal_reached += 1
                            else:
                                text += f"  | Goal reached: No {goal_text}"

                            total_days_logged  += 1
                        else:
                            text += "  | No goal set"
                        ctk.CTkLabel(self.root, text=text).pack(anchor="w", padx=10, pady=2) #left to right
                    except Exception as e:
                        print("Error", e)
                if total_days_logged > 0:
                    summary = f"You reached your goal {goal_reached} out of {total_days_logged} days."
                    ctk.CTkLabel(root, text=summary, font=("Arial", 12)).pack(pady=10)
            self.root.after(0, show_stats)
            ctk.CTkButton(self.root, text="Back to main menu", command=lambda: self.open_main_screen(username)).pack()

        threading.Thread(target=fetch_stats).start()

    def log_prev_days_window(self, username):
        self.clear_root()

        self.day_var = ctk.StringVar(value=str(datetime.today().day))
        self.month_var = ctk.StringVar(value=str(datetime.today().month))
        self.year_var = ctk.StringVar(value=str(datetime.today().year))

        self.root.title("Log previous days")
        self.root.geometry("600x900")
        self.center_window(self.root, 500, 900)

        days = [str(i) for i in range(1, 32)]
        months = [str(i) for i in range(1, 13)]
        years = [str(i) for i in range(2022, 2031)]

        ctk.CTkLabel(self.root, text="Day:").pack(pady=(10, 0))
        day_box = ctk.CTkComboBox(self.root, values=days, variable=self.day_var)
        day_box.pack()

        ctk.CTkLabel(self.root, text="Month:").pack(pady=(10, 0))
        month_box = ctk.CTkComboBox(self.root, values=months, variable=self.month_var)
        month_box.pack()

        ctk.CTkLabel(self.root, text="Year:").pack(pady=(10, 0))
        year_box = ctk.CTkComboBox(self.root, values=years, variable=self.year_var)
        year_box.pack()

        ctk.CTkLabel(self.root, text="Snack Name:").pack(pady=2)
        self.snack_CTkEntry = ctk.CTkEntry(self.root)
        self.snack_CTkEntry.pack(pady=5)

        ctk.CTkLabel(self.root, text="Calories:").pack(pady=2)
        self.calories_CTkEntry = ctk.CTkEntry(self.root)
        self.calories_CTkEntry.pack(pady=2)

        self.total_calories_CTkLabel = ctk.CTkLabel(self.root, text="Total Calories This Day: 0 kcal",font=("Arial", 12))
        self.total_calories_CTkLabel.pack(pady=5)

        self.snack_listbox = tk.Listbox(self.root, width=50, height=8)
        self.snack_listbox.pack(pady=5)

        ctk.CTkLabel(self.root, text="Daily Calorie Goal:").pack()
        goal_entry = ctk.CTkEntry(self.root)
        goal_entry.pack(pady=5)
        selected_type = tk.IntVar(value=-1)
        enc_user = EncryptedMessage.rsa_encrypt_single(username)
        def get_goal_info():

            day = self.day_var.get()
            month = self.month_var.get()
            year = self.year_var.get()

            print(f"goal for date {day}/{month}/{year}")
            response = self.send_request(f"get_goal_date|{enc_user}|{day}|{month}|{year}!END")
            print(f"goaal response = {response}")

            if response and "|" in response:
                cal, gtype = response.split("|")
                print(f"[GOAL FETCH] Parsed: cal={cal}, gtype={gtype}")
                if cal.isdigit():
                    goal_entry.delete(0, tk.END)
                    goal_entry.insert(0, cal)
                if gtype in ("0", "1"):
                    selected_type.set(int(gtype))
                    update_button_styles()

        def refresh_curr_data(*_):
            print("refresh_curr_data deltachan")
            self.display_snacks(username)
            self.update_total_calories(username)
            get_goal_info()


        def update_button_styles():
            under.configure(fg_color="#1E90FF" if selected_type.get() == 0 else "#ADD8E6", text_color="black")  # under
            over.configure(fg_color="#1E90FF" if selected_type.get() == 1 else "#ADD8E6", text_color="black")  # over

        def select_under():
            selected_type.set(0)
            update_button_styles()

        def select_over():
            selected_type.set(1)
            update_button_styles()


        under = ctk.CTkButton(self.root, text="Stay under calorie goal", command=select_under, fg_color="#ADD8E6",border_color="black", border_width=2, text_color="black", hover_color="#ADD8E6")
        under.pack(pady=5)
        over = ctk.CTkButton(self.root, text="Stay over calorie goal", command=select_over, fg_color="#ADD8E6",border_color="black", border_width=2, text_color="black", hover_color="#ADD8E6")
        over.pack(pady=5)


        threading.Thread(target=get_goal_info).start()

        def save_goal():
            calories = goal_entry.get().strip()
            goal_type = selected_type.get()
            if not calories.isdigit():
                messagebox.showerror("Invalid Input", "Please enter a numeric goal.")
                return
            if goal_type not in (0, 1):
                messagebox.showerror("Missing Selection", "Please select a goal type.")
                return

            day = self.day_var.get()
            month = self.month_var.get()
            year = self.year_var.get()


            print(f"sending goal update: calories={calories}, type={goal_type}")

            def actual_save():
                self.send_request(f"update_goal|{enc_user}|{calories}|{goal_type}|{day}|{month}|{year}!END")
                messagebox.showinfo("Saved", "Goal logged successfully.")

            threading.Thread(target=actual_save).start()
        ctk.CTkButton(self.root, text="Log snack", command=lambda: self.log_snack(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Delete selected snack",command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Update goal for this day", command=save_goal).pack(pady=10)
        ctk.CTkButton(self.root, text="Back to main menu", command=lambda: self.open_main_screen(username)).pack(pady=10)

        self.display_snacks(username)
        self.update_total_calories(username)

        self.day_var.trace_add("write", refresh_curr_data)
        self.month_var.trace_add("write", refresh_curr_data)
        self.year_var.trace_add("write", refresh_curr_data)
        refresh_curr_data()

    def update_total_calories(self, username):
        def get_total():
            day = self.day_var.get()
            month = self.month_var.get()
            year = self.year_var.get()
            enc = EncryptedMessage(username)
            enc_user = EncryptedMessage.rsa_encrypt_single(username)

            msg = f"get_total|{enc_user}|{day}|{month}|{year}!END"
            print("update_total_calories sending:")
            total = self.send_request(msg).strip()

            def update_label():
                if total.isdigit():
                    self.total_calories_CTkLabel.configure(text=f"Total Calories This Day: {total} kcal")
                else:
                    self.total_calories_CTkLabel.configure(text="Total Calories This Day: 0 kcal")
            self.root.after(0, update_label)

        threading.Thread(target=get_total, daemon=True).start()

    def display_snacks(self, username):
        def send_display_info():
            day = self.day_var.get()
            month = self.month_var.get()
            year = self.year_var.get()
            enc = EncryptedMessage(username)
            enc_user = enc.rsa_encrypt_single(username) #it returns it as a list if you dont add,

            message= f"get_snacks|{enc_user}|{day}|{month}|{year}!END"
            print("display_snacks sending:", message)

            snack_list = self.send_request(message).strip()
            def update_listbox():
                self.snack_listbox.delete(0, ctk.END)
                if snack_list and snack_list != "NONE":
                    for line in snack_list.split("\n"):
                        self.snack_listbox.insert(ctk.END, line)

            self.root.after(0, update_listbox)
        threading.Thread(target=send_display_info, daemon=True).start()


if __name__ == "__main__":
    root = ctk.CTk()
    app = SnackSyncApp(root)
    root.mainloop()
##gwahjigwahiogoaiwhgcbssb
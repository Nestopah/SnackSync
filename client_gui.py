
import socket
import customtkinter as ctk
import tkinter as tk
from tkinter  import messagebox
from datetime import datetime

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


SERVER_HOST = "192.168.1.81"
SERVER_PORT = 12345

class SnackSyncApp:
    def __init__(self, root):
        self.root = root
        self.root.iconbitmap("icon.ico")
        self.root.title("SnackSync - Login/Register")
        self.root.geometry("300x250")
        self.center_window(root, 300,300)

        ctk.CTkLabel(root, text="Username:").pack(pady=5)
        self.username_CTkEntry = ctk.CTkEntry(root)
        self.username_CTkEntry.pack(pady=5)

        ctk.CTkLabel(root, text="Password:").pack(pady=5)
        self.password_CTkEntry = ctk.CTkEntry(root, show="*")
        self.password_CTkEntry.pack(pady=5)

        ctk.CTkButton(root, text="Login", command=self.login).pack(pady=5)
        ctk.CTkButton(root, text="Sign up", command=self.register).pack(pady=5)
       ## bg_color = self.root._apply_appearance_mode(ctk.ThemeManager.theme["CTk"]["fg_color"])
       ##print(bg_color)
        ctk.CTkButton(self.root, text="Forgot password?", text_color="#66B2FF", fg_color="gray14", hover_color="gray14", border_width=0, command=self.open_password_reset).pack()

    def login(self):
        def login_thread():
            username = self.username_CTkEntry.get().strip()
            password = self.password_CTkEntry.get().strip()

            if not username or not password:
                self.root.after(0, lambda: messagebox.showerror("Error", "Please enter username and password."))
                return

            message = f"login|{username}|{password}!END"
            response = self.send_request(message)

            if response == "Login successful.":
                self.root.after(0, lambda: self.open_main_screen(username))
            elif response == "2FA":
                self.root.after(0, lambda: self.show_2fa_prompt(username))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Login failed."))

        threading.Thread(target=login_thread).start()

    def register(self):
        self.clear_root()

        self.root.title("SnackSync - Sign up")
        self.root.geometry("500x600")
        self.center_window(self.root, 500, 600)


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

            # Load public key for RSA
            try:
                with open("rsa_public.pem", "rb") as f:
                    key = RSA.import_key(f.read())
                    cipher = PKCS1_OAEP.new(key)
            except Exception as e:
                messagebox.showerror("Error", f"Could not load public key:\n{e}")
                return

            try:
                encrypted_username = base64.b64encode(cipher.encrypt(username.encode())).decode()
                encrypted_password = base64.b64encode(cipher.encrypt(password.encode())).decode()
                encrypted_email = base64.b64encode(cipher.encrypt(email.encode())).decode()

                print("[DEBUG] Encrypted username:", encrypted_username)
                print("[DEBUG] Encrypted password:", encrypted_password)
                print("[DEBUG] Encrypted email:", encrypted_email)
                print("[DEBUG] Total message length:",
                      len(f"register|{encrypted_username}|{encrypted_password}|{encrypted_email}"))
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed:\n{e}")
                return

            message = f"register|{encrypted_username}|{encrypted_password}|{encrypted_email}!END"
            print("[DEBUG] Final message sending to server:", message)

            def handle_response():
                response = self.send_request(message)

                if response == "2FA":
                    self.root.after(0, lambda: [
                        messagebox.showinfo("Verification", "Check your email for a 6-digit code."),
                        self.show_2fa_prompt(username)
                    ])
                elif response == "FAIL":
                    self.root.after(0, lambda: messagebox.showerror("Error", "Username or email already exists."))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Unexpected response: {response}"))

            threading.Thread(target=handle_response).start()
        ctk.CTkButton(root, text="Create Account", command=lambda: threading.Thread(target=submit_signup).start()).pack(pady=20)

    def show_2fa_prompt(self, username, newpass=None):
        self.clear_root()
        self.root.title("Two-Factor Authentication")
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

            if newpass:
                message = f"reset_verify|{username}|{newpass}|{code}!END"
            else:
                message = f"2fa|{username}|{code}!END"

            response = self.send_request(message)
            if response == "OK":
                messagebox.showinfo("Success", "Login successful.")
                self.open_main_screen(username)
            else:
                messagebox.showerror("Error", "Invalid or expired code.")

        ctk.CTkButton(self.root, text="Verify", command=submit_code).pack(pady=10)

    def send_request(self, message):
        try:
            print("(DEBUG) send_request activated")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((SERVER_HOST, SERVER_PORT))
                sock.sendall(message.encode())
                response = sock.recv(1024).decode()
                print(f"response = {response} ")
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
                user = User(user_id, password, "placeholder")
                encrypted_user_id = user.rsa_username
                hashed_password = user.password.decode()
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Encryption or hashing failed: {e}"))
                return

            message = f"reset_pass|{encrypted_user_id}|{hashed_password}!END"
            print("[DEBUG] Sending reset message:", message)

            response = self.send_request(message).strip()

            if response == "OK":
                self.root.after(0, lambda: [
                    messagebox.showinfo("Success", "Password reset successful!"),
                    self.open_main_screen(user_id)
                ])
            elif response == "2FA":
                self.root.after(0, lambda: self.show_2fa_prompt(user_id, newpass=hashed_password))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", response))

        ctk.CTkButton(self.root, text="Reset Password",
                      command=lambda: threading.Thread(target=send_and_handle).start()).pack(pady=10)

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")

    def reminder_loop(self, interval_minutes=60):
        def remind():
            self.clippy.notification("SnackSync", "Don't forget to log your snacks!")
            # Schedule the next reminder
            threading.Timer(interval_minutes * 1, remind).start()

        remind()  #first reminder

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def open_main_screen(self, username):
        self.clear_root()  # remove old login widgets

        self.root.title(f"SnackSync - Main window {username}")
        self.root.geometry("500x600")
        self.center_window(self.root, 500, 600)

        self.clippy = Clippy()
        self.root.after(1000, self.reminder_loop)

        # Now add all the main screen widgets directly to self.root
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
        ctk.CTkButton(self.root, text="Delete selected snack",
                      command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Log previous days", command=lambda: self.log_prev_days_window(username)).pack(
            pady=5)
        ctk.CTkButton(self.root, text="Stats", command=lambda: self.stats_window(username)).pack(pady=5)
        ctk.CTkButton(self.root, text="Settings", command=lambda: self.open_settings(username)).pack(pady=5)

        threading.Thread(target=lambda: self.display_snacks(username)).start()
        threading.Thread(target=lambda: self.update_total_calories(username)).start()

    def open_settings(self, username):
        self.clear_root()
        self.root.title("Settings")
        self.root.geometry("300x400")
        self.center_window(self.root, 300, 400)

        ctk.CTkLabel(self.root, text="Settings", font=("Arial", 18)).pack(pady=10)

        # --- 2FA toggle ---
        var = tk.BooleanVar()

        def fetch_current_2fa():
            encrypted_username = User.encrypt_rsa(username)
            response = self.send_request(f"get_2fa|{encrypted_username}!END")
            var.set(response == "1")

        threading.Thread(target=fetch_current_2fa).start()
        toggle = ctk.CTkCheckBox(self.root, text="Enable 2FA", variable=var)
        toggle.pack(pady=10)

        # --- Goal input ---
        ctk.CTkLabel(self.root, text="Daily Calorie Goal:").pack()
        goal_entry = ctk.CTkEntry(self.root)
        goal_entry.pack(pady=5)

        selected_type = tk.IntVar(value=-1)

        def update_button_styles():
            under_btn.configure(
                fg_color="#1E90FF" if selected_type.get() == 0 else "#ADD8E6",
                text_color="black"
            )
            over_btn.configure(
                fg_color="#1E90FF" if selected_type.get() == 1 else "#ADD8E6",
                text_color="black"
            )

        def select_under():
            selected_type.set(0)
            update_button_styles()

        def select_over():
            selected_type.set(1)
            update_button_styles()

        under_btn = ctk.CTkButton(
            self.root, text="Stay under calorie goal", command=select_under,
            fg_color="#ADD8E6", border_color="black", border_width=2, text_color="black", hover_color="#ADD8E6"
        )
        under_btn.pack(pady=5)

        over_btn = ctk.CTkButton(
            self.root, text="Stay over calorie goal", command=select_over,
            fg_color="#ADD8E6", border_color="black", border_width=2, text_color="black", hover_color="#ADD8E6"
        )
        over_btn.pack(pady=5)

        def fetch_goal_info():
            encrypted_username = User.encrypt_rsa(username)
            response = self.send_request(f"get_goal|{encrypted_username}!END")
            if response and "|" in response:
                cal, gtype = response.split("|")
                if cal.isdigit():
                    goal_entry.insert(0, cal)
                if gtype in ("0", "1"):
                    selected_type.set(int(gtype))
                    update_button_styles()

        threading.Thread(target=fetch_goal_info).start()

        # --- Save button ---
        def save_all():
            new_2fa = 1 if var.get() else 0
            calories = goal_entry.get().strip()
            goal_type = selected_type.get()


            if not calories.isdigit():
                messagebox.showerror("Invalid Input", "Please enter a numeric goal.")
                return
            if goal_type not in (0, 1):
                messagebox.showerror("Missing Selection", "Please select a goal type.")
                return

            now = datetime.now()
            day, month, year = str(now.day), str(now.month), str(now.year)

            encrypted_username = User.encrypt_rsa(username)
            encrypted_calories = User.encrypt_rsa(calories)
            encrypted_goal_type = User.encrypt_rsa(str(goal_type))
            encrypted_2fa = User.encrypt_rsa(str(new_2fa))
            print(f"[DEBUG] Sending goal update: calories={calories}, type={goal_type}, 2FA={new_2fa}")

            def threaded_save():
                self.send_request(
                    f"update_goal|{encrypted_username}|{encrypted_calories}|{encrypted_goal_type}|{day}|{month}|{year}!END")
                self.send_request(f"update_2fa|{encrypted_username}|{encrypted_2fa}!END")
                messagebox.showinfo("Saved", "Settings updated successfully.")

            threading.Thread(target=threaded_save).start()

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
                print("[DEBUG] Connecting to server to log snack")
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((SERVER_HOST, SERVER_PORT))

                snack = EncryptedSnack(username, snack_name, int(calories), "rsa_public.pem")
                enc_snack, enc_calories = snack.encrypt()
                enc_username = User.encrypt_rsa(username)

                data = f"log_snack|{enc_username}|{enc_snack}|{enc_calories}|{day}|{month}|{year}!END"
                client.send(data.encode())
                print("[DEBUG] Sent snack data:", data)

                response = client.recv(1024).decode().strip()
                print("[DEBUG] Server response:", response)
                client.close()

                def safe_gui_update():
                    try:
                        self.display_snacks(username)
                        self.update_total_calories(username)
                        self.snack_CTkEntry.delete(0, ctk.END)
                        self.calories_CTkEntry.delete(0, ctk.END)
                        print("Snack logged successfully.")
                        now = datetime.now()
                        if day == now.day and month == now.month and year == now.year:
                            self.clippy.notify_goal_result(username)
                        else:
                            print("(DEBUG) snack logged with log prev days function no need to show notification")
                    except Exception as e:
                        print("[ERROR] safe_gui_update crash:", e)

                self.root.after(0, safe_gui_update)

            except Exception as e:
                print("[ERROR] Failed to log snack:", e)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to log snack: {e}"))

        threading.Thread(target=send_log_snack).start()

    def delete_selected_snack(self, username):
        selected = self.snack_listbox.curselection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a snack to delete.")
            return

        snack_text = self.snack_listbox.get(selected)
        snack_name, kcal_text = snack_text.split(":")
        calories = int(kcal_text.strip().split()[0])

        day = self.day_var.get()
        month = self.month_var.get()
        year = self.year_var.get()

        def send_delete():
            try:
                message = f"delete_snack|{username}|{snack_name.strip()}|{calories}|{day}|{month}|{year}!END"
                print("[DEBUG] Sending delete message:", message)
                response = self.send_request(message).strip()

                if response == "OK":
                    self.root.after(0, lambda: [
                        messagebox.showinfo("Deleted", "Snack deleted successfully."),
                        self.display_snacks(username),
                        self.update_total_calories(username)
                    ])
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Snack deletion failed."))
            except Exception as e:
                print("[ERROR] Failed to delete snack:", e)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to delete snack: {e}"))

        threading.Thread(target=send_delete).start()

    def stats_window(self, username):
        statswin = ctk.CTkToplevel()
        statswin.title("Stats")
        statswin.geometry("400x300")
        self.center_window(statswin, 400, 300)

        statswin.lift()
        statswin.attributes("-topmost", True)
        statswin.after(100, lambda: statswin.attributes("-topmost", False))

        ctk.CTkLabel(statswin, text="All time calorie intake:").pack(pady=10)
        loading_label = ctk.CTkLabel(statswin, text="Loading...")
        loading_label.pack()

        def fetch_stats():
            try:
                response = self.send_request(f"get_stats|{username}!END")
            except Exception as e:
                self.root.after(0, lambda: loading_label.configure(text=f"Error: {e}"))
                return

            if not response or response == "NONE":
                self.root.after(0, lambda: loading_label.configure(text="No data found."))
                return

            lines = response.strip().split("\n")
            total_days = 0
            goal_hits = 0

            def show_stats():
                loading_label.destroy()
                goal_hits = 0
                total_days = 0

                for line in lines:
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
                                goal_hits += 1
                            else:
                                text += f"  | Goal reached: No {goal_text}"

                            total_days += 1
                        else:
                            text += "  | No goal set"

                        ctk.CTkLabel(statswin, text=text).pack(anchor="w", padx=10, pady=2)

                    except Exception as e:
                        print("[ERROR] Failed to parse stats line:", line, e)

                if total_days > 0:
                    summary = f"You reached your goal {goal_hits} out of {total_days} days."
                    ctk.CTkLabel(statswin, text=summary, font=("Arial", 12)).pack(pady=10)
            self.root.after(0, show_stats)

        threading.Thread(target=fetch_stats).start()

    def log_prev_days_window(self, username):
        logdayswin = ctk.CTkToplevel()
        logdayswin.title("Log previous days")
        logdayswin.geometry("500x600")
        self.center_window(logdayswin, 500, 600)

        logdayswin.lift()
        logdayswin.attributes("-topmost", True)
        logdayswin.after(100, lambda: logdayswin.attributes("-topmost", False))

        days = [str(v) for v in range(1, 32)]
        months = [str(v) for v in range(1, 13)]
        years = [str(v) for v in range(2022, 2031)]

        ctk.CTkLabel(logdayswin, text="Day:").pack(pady=(10, 0))
        ctk.CTkComboBox(logdayswin, values=days, variable=self.day_var).pack()

        ctk.CTkLabel(logdayswin, text="Month:").pack(pady=(10, 0))
        ctk.CTkComboBox(logdayswin, values=months, variable=self.month_var).pack()

        ctk.CTkLabel(logdayswin, text="Year:").pack(pady=(10, 0))
        ctk.CTkComboBox(logdayswin, values=years, variable=self.year_var).pack()

        ctk.CTkLabel(logdayswin, text="Snack Name:").pack(pady=2)
        self.snack_CTkEntry = ctk.CTkEntry(logdayswin)
        self.snack_CTkEntry.pack(pady=5)

        ctk.CTkLabel(logdayswin, text="Calories:").pack(pady=2)
        self.calories_CTkEntry = ctk.CTkEntry(logdayswin)
        self.calories_CTkEntry.pack(pady=2)

        self.total_calories_CTkLabel = ctk.CTkLabel(logdayswin, text="Total Calories This Day: 0 kcal",
                                                    font=("Arial", 12))
        self.total_calories_CTkLabel.pack(pady=5)

        self.snack_listbox = tk.Listbox(logdayswin, width=50, height=8)
        self.snack_listbox.pack(pady=5)

        def refresh_curr_data(*_):
            self.update_total_calories(username)
            self.display_snacks(username)

        for var in [self.day_var, self.month_var, self.year_var]:
            var.trace_add("write", refresh_curr_data)

        ctk.CTkButton(logdayswin, text="Log snack", command=lambda: self.log_snack(username)).pack(pady=5)
        ctk.CTkButton(logdayswin, text="Delete selected snack", command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        self.display_snacks(username)
        self.update_total_calories(username)

    def update_total_calories(self, username):
        def send_total_data():
            day = self.day_var.get()
            month = self.month_var.get()
            year = self.year_var.get()

            full_command = f"get_total|{username}|{day}|{month}|{year}!END"
            print("[DEBUG] update_total_calories sending:", full_command)

            total = self.send_request(full_command).strip()
            print("[DEBUG] Received total:", repr(total))

            def update_label():
                if total.isdigit():
                    self.total_calories_CTkLabel.configure(text=f"Total Calories This Day: {total} kcal")
                else:
                    self.total_calories_CTkLabel.configure(text="Total Calories This Day: 0 kcal")
                    print("[WARNING] Server sent invalid total:", repr(total))

            self.root.after(0, update_label)

        threading.Thread(target=send_total_data, daemon=True).start()

    def display_snacks(self, username):
        def send_display_data():
            day = self.day_var.get()
            month = self.month_var.get()
            year = self.year_var.get()

            full_command = f"get_snacks|{username}|{day}|{month}|{year}!END"
            print("[DEBUG] display_snacks sending:", full_command)

            snack_list = self.send_request(full_command).strip()
            print("[DEBUG] Server snack list:", repr(snack_list))

            def update_listbox():
                self.snack_listbox.delete(0, ctk.END)
                if snack_list and snack_list != "NONE":
                    for line in snack_list.split("\n"):
                        self.snack_listbox.insert(ctk.END, line)

            self.root.after(0, update_listbox)

        threading.Thread(target=send_display_data, daemon=True).start()


if __name__ == "__main__":
    root = ctk.CTk()
    app = SnackSyncApp(root)
    root.mainloop()
##gwahjigwahiogoaiwhgcbssb
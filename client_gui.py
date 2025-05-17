
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
                message = f"reset_confirm|{username}|{newpass}|{code}!END"
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

            response = self.send_request(message)
            if response == "OK":
                self.root.after(0, lambda: [
                    messagebox.showinfo("Success", "Password reset successful!"),
                    self.open_main_screen(user_id)
                ])
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", response))

        ctk.CTkButton(self.root, text="Reset Password",command=lambda: threading.Thread(target=send_and_handle).start()).pack(pady=10)

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
        self.root.geometry("300x200")
        self.center_window(self.root, 300, 200)

        ctk.CTkLabel(self.root, text="Settings", font=("Arial", 18)).pack(pady=10)

        var = tk.BooleanVar()

        def fetch_current_2fa():
            current = self.send_request(f"get_2fa|{username}!END")
            var.set(current == "1")

        threading.Thread(target=fetch_current_2fa).start()

        def on_toggle():
            def update_settings():
                new_value = 1 if var.get() else 0
                self.send_request(f"update_2fa|{username}|{new_value}!END")
                messagebox.showinfo("Settings Updated", "To apply settings, please restart the app.")
                return -999 #windows error otherwise
            threading.Thread(target=update_settings).start()

        toggle = ctk.CTkCheckBox(self.root, text="Enable 2FA", variable=var, command=on_toggle)
        toggle.pack(pady=10)
        ctk.CTkButton(self.root, text="Back to main menu", command=lambda: self.open_main_screen(username)).pack(pady=20)

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
                    except Exception as e:
                        print("[CRASH] display_snacks failed:", e)

                    try:
                        self.update_total_calories(username)
                    except Exception as e:
                        print("[CRASH] update_total_calories failed:", e)

                    try:
                        self.snack_CTkEntry.delete(0, ctk.END)
                    except Exception as e:
                        print("[CRASH] snack_CTkEntry delete failed:", e)

                    try:
                        self.calories_CTkEntry.delete(0, ctk.END)
                    except Exception as e:
                        print("[CRASH] calories_CTkEntry delete failed:", e)

                    try:
                        messagebox.showinfo("Success", "Snack logged successfully.")
                    except Exception as e:
                        print("[CRASH] messagebox failed:", e)

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

        day = int(self.day_var.get())
        month = int(self.month_var.get())
        year = int(self.year_var.get())

        try:
            print("[DEBUG] Connecting to server to delete snack")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_PORT))

            client.send(b"delete_snack")
            ack = client.recv(1024).decode()
            print("[DEBUG] Server ack for delete_snack:", ack)

            data = f"{username}|{snack_name.strip()}|{calories}|{day}|{month}|{year}"
            client.send(data.encode())
            print("[DEBUG] Sent snack to delete:", data)

            response = client.recv(1024).decode()
            print("[DEBUG] Server response:", response)
            messagebox.showinfo("Server", response)

            client.close()

            self.display_snacks(username)
            self.update_total_calories(username)

        except Exception as e:
            print("[ERROR] Failed to delete snack:", e)
            messagebox.showerror("Error", f"Failed to delete snack: {e}")

    def stats_window(self, username):
        statswin = ctk.CTkToplevel()
        statswin.title("Stats")
        statswin.geometry("400x300")
        self.center_window(statswin, 400, 300)

        statswin.lift()
        statswin.attributes("-topmost", True)
        statswin.after(100, lambda: statswin.attributes("-topmost", False))

        ctk.CTkLabel(statswin, text="All time calorie intake:").pack(pady=20)

        try:
            with socket.socket() as s:
                s.connect((SERVER_HOST, SERVER_PORT))
                s.send(f"get_stats|{username}".encode())
                data = s.recv(4096).decode().strip()
        except Exception as e:
            ctk.CTkLabel(statswin, text=f"Error: {e}").pack(pady=10)
            return

        if not data:
            ctk.CTkLabel(statswin, text="No data found.").pack(pady=10)
            return

        for line in data.split("\n"):
            ctk.CTkLabel(statswin, text=line + " kcal").pack(anchor="w", padx=20, pady=2)

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

import socket
import customtkinter as ctk
import tkinter as tk
from tkinter  import messagebox
from datetime import datetime
from snack import Snack
from snack import EncryptedSnack
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import threading
from clippy import Clippy

SERVER_HOST = "192.168.1.81"
SERVER_PORT = 12345

class SnackSyncApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SnackSync - Login/Register")
        self.root.geometry("300x250")
        self.center_window(root, 300,250)

        ctk.CTkLabel(root, text="Username:").pack(pady=5)
        self.username_CTkEntry = ctk.CTkEntry(root)
        self.username_CTkEntry.pack(pady=5)

        ctk.CTkLabel(root, text="Password:").pack(pady=5)
        self.password_CTkEntry = ctk.CTkEntry(root, show="*")
        self.password_CTkEntry.pack(pady=5)

        ctk.CTkButton(root, text="Login", command=self.login).pack(pady=5)
        ctk.CTkButton(root, text="Register", command=self.register).pack(pady=5)

    def login(self):
        self.send_request("l")

    def register(self):
        self.send_request("r")

    def send_request(self, option):
        try:
            print("[DEBUG] Connecting to server")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_PORT))

            if option == "l":
                client.sendall(b"login")
            elif option == "r":
                client.sendall(b"register")
            else:
                print("[ERROR] Invalid option")
                return

            # Wait for server acknowledgment before continuing
            ack = client.recv(1024).decode()
            print("[DEBUG] Server ack:", ack)

            print("[DEBUG] Sent operation:", option)

            username = self.username_CTkEntry.get()
            password = self.password_CTkEntry.get()

            credentials = f"{username}|{password}"
            client.send(credentials.encode())

            response = client.recv(1024).decode()
            print("[DEBUG] Received from server:", response)
            messagebox.showinfo("Server", response)

            client.close()

            if "successful" in response.lower():
                self.open_main_screen(username)

        except ConnectionRefusedError:
            messagebox.showerror("Error", "Cannot connect to the server.")
        except Exception as e:
            print("[ERROR] Unexpected error:", e)
            messagebox.showerror("Error", str(e))


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

    def open_main_screen(self, username):
        self.clippy = Clippy()  # Create Clippy once here
        self.reminder_loop()  # Start reminders right after
        self.root.withdraw()  # hide the login window instead of destroy
        mainwin = ctk.CTkToplevel()  # this is like a new page
        mainwin.title(f"SnackSync - Main window {username}")
        mainwin.geometry("500x600")
        self.center_window(mainwin,500,600)



        ctk.CTkLabel(mainwin, text=f"Welcome, {username}!", font=("Arial", 24)).pack(pady=10)


        self.day_var = ctk.StringVar(value=str(datetime.today().day))
        self.month_var = ctk.StringVar(value=str(datetime.today().month))
        self.year_var = ctk.StringVar(value=str(datetime.today().year))


        ctk.CTkLabel(mainwin, text=f"Log today:", font=("Arial", 20)).pack(pady=10)

        ctk.CTkLabel(mainwin, text="Snack name:").pack(pady=2)
        self.snack_CTkEntry = ctk.CTkEntry(mainwin)
        self.snack_CTkEntry.pack(pady=5)

        ctk.CTkLabel(mainwin, text="Calories:").pack(pady=2)
        self.calories_CTkEntry = ctk.CTkEntry(mainwin)
        self.calories_CTkEntry.pack(pady=2)

        self.total_calories_CTkLabel = ctk.CTkLabel(mainwin, text="Total calories today: 0 kcal", font=("Arial", 12))
        self.total_calories_CTkLabel.pack(pady=5)

        self.snack_listbox = tk.Listbox(mainwin, width=50, height=8)
        self.snack_listbox.pack(pady=5)

        ctk.CTkButton(mainwin, text="Log snack", command=lambda: self.log_snack(username)).pack(pady=5)
        ctk.CTkButton(mainwin, text="Delete selected snack", command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        ctk.CTkButton(mainwin, text="Log previous days", command=lambda: self.log_prev_days_window(username)).pack(pady=5)
        ctk.CTkButton(mainwin, text="Stats", command=lambda: self.stats_window(username)).pack(pady=5)

        self.display_snacks(username)
        self.update_total_calories(username)

    def log_snack(self, username):
        snack_name = self.snack_CTkEntry.get().strip()
        calories = self.calories_CTkEntry.get().strip()

        if not snack_name or not calories.isdigit():
            messagebox.showerror("Error", "Please enter a valid snack and calorie amount.")
            return

        day, month, year = int(self.day_var.get()), int(self.month_var.get()), int(self.year_var.get())

        try:
            print("[DEBUG] Connecting to server to log snack")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_PORT))

            client.send(b"log_snack")
            ack = client.recv(1024).decode()
            print("[DEBUG] Server ack for log_snack:", ack)

            # Use EncryptedSnack to handle encryption
            snack = EncryptedSnack(username, snack_name, int(calories), "rsa_public.pem")
            enc_snack, enc_calories = snack.encrypt()

            # Prepare the encrypted data message
            data = f"{username}|{enc_snack}|{enc_calories}|{day}|{month}|{year}"
            client.send(data.encode())

            print("[DEBUG] Sent snack data:", data)

            response = client.recv(1024).decode()
            print("[DEBUG] Server response:", response)
            messagebox.showinfo("Server", response)

            client.close()
        except Exception as e:
            print("[ERROR] Failed to log snack:", e)
            messagebox.showerror("Error", f"Failed to log snack: {e}")

        self.snack_listbox.insert(ctk.END, f"{snack_name}: {calories} kcal")
        self.snack_CTkEntry.delete(0, ctk.END)
        self.calories_CTkEntry.delete(0, ctk.END)
        self.update_total_calories(username)

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


        for var in [self.day_var, self.month_var, self.year_var]:
            var.trace_add("write", lambda *args: self.update_total_calories(username))
            var.trace_add("write", lambda *args: self.display_snacks(username))

        ctk.CTkButton(logdayswin, text="Log snack", command=lambda: self.log_snack(username)).pack(pady=5)
        ctk.CTkButton(logdayswin, text="Delete selected snack", command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        self.display_snacks(username)
        self.update_total_calories(username)

    def update_total_calories(self, username):
        day = self.day_var.get()
        month = self.month_var.get()
        year = self.year_var.get()

        try:
            print("[DEBUG] Connecting to server for total calories")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_PORT))

            full_command = f"get_total|{username}|{day}|{month}|{year}"
            client.send(full_command.encode())
            print("[DEBUG] Sent get_total data:", repr(full_command))

            total = client.recv(1024).decode().strip()
            print("[DEBUG] Received total:", repr(total))

            self.total_calories_CTkLabel.configure(text=f"Total Calories This Day: {total} kcal")
            client.close()

        except Exception as e:
            print("[ERROR] Failed to get total calories:", e)
            messagebox.showerror("Error", f"Failed to update total: {e}")

    def display_snacks(self, username):
        self.snack_listbox.delete(0, ctk.END)

        day = self.day_var.get()
        month = self.month_var.get()
        year = self.year_var.get()

        try:
            print("[DEBUG] Connecting to server to fetch snacks")
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_PORT))

            full_command = f"get_snacks|{username}|{day}|{month}|{year}"
            client.send(full_command.encode())
            print("[DEBUG] Sent full get_snacks command:", repr(full_command))

            snack_list = client.recv(4096).decode()
            print("[DEBUG] Server snack list:", repr(snack_list))

            if snack_list:
                for line in snack_list.strip().split("\n"):
                    self.snack_listbox.insert(ctk.END, line)

            client.close()
        except Exception as e:
            print("[ERROR] Failed to get snacks:", e)
            messagebox.showerror("Error", f"Failed to load snacks: {e}")


if __name__ == "__main__":
    root = ctk.CTk()
    app = SnackSyncApp(root)
    root.mainloop()
##gwahjigwahiogoaiwhgcbssb
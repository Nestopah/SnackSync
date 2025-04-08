import socket
import sqlite3
import customtkinter as ctk
import tkinter as tk
from tkinter  import messagebox
from datetime import datetime
from snack import Snack


SERVER_HOST = "127.0.0.1"
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
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_PORT))

            client.recv(1024)
            client.send(option.encode())

            client.recv(1024)
            username = self.username_CTkEntry.get()
            client.send(username.encode())

            client.recv(1024)
            password = self.password_CTkEntry.get()
            client.send(password.encode())

            response = client.recv(1024).decode()
            messagebox.showinfo("Server Response", response)

            client.close()

            if "successful" in response.lower():
                self.open_main_screen(username)

        except ConnectionRefusedError:
            messagebox.showerror("Error", "Cannot connect to the server.")

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f"{width}x{height}+{x}+{y}")
    def open_main_screen(self, username):
        self.root.withdraw()  # hide the login window instead of destroy
        mainwin = ctk.CTkToplevel()  # this is like a new page
        mainwin.title(f"SnackSync - Main window {username}")
        mainwin.geometry("500x600")
        self.center_window(mainwin,500,600)

        conn = sqlite3.connect("snacksync.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
            id INTEGER PRIMARY KEY,
            username TEXT,
            snack TEXT,
            calories INTEGER,
            day INTEGER,
            month INTEGER,
            year INTEGER
        )''')
        conn.commit()
        conn.close()

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

        calories = int(calories)

        day, month, year = int(self.day_var.get()), int(self.month_var.get()), int(self.year_var.get())

        conn = sqlite3.connect("snacksync.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO snacks (username, snack, calories, day, month, year) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, snack_name, calories, day, month, year))
        conn.commit()
        conn.close()

        self.snack_listbox.insert(ctk.END, f"{snack_name}: {calories} kcal")
        self.snack_CTkEntry.delete(0, ctk.END)
        self.calories_CTkEntry.delete(0, ctk.END)
        self.update_total_calories(username)

    def delete_selected_snack(self, username):
        selected = self.snack_listbox.curselection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a snack to delete.")
            return

        # Get the selected item text, like "Apple: 95 kcal"
        snack_text = self.snack_listbox.get(selected)
        snack_name, kcal_text = snack_text.split(":")
        calories = int(kcal_text.strip().split()[0])  # Remove "kcal"

        # Get selected date
        day = self.day_var.get()
        month = self.month_var.get()
        year = self.year_var.get()

        # Delete from the database
        conn = sqlite3.connect("snacksync.db")
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM snacks WHERE username=? AND snack=? AND calories=? AND day=? AND month=? AND year=?",
            (username, snack_name.strip(), calories, day, month, year)
        )
        conn.commit()
        conn.close()
        self.display_snacks(username)
    def stats_window(self, username):
        statswin = ctk.CTkToplevel()
        statswin.title("Stats")
        statswin.geometry("400x300")
        self.center_window(statswin, 400, 300)

        statswin.lift()
        statswin.attributes("-topmost", True)
        statswin.after(100, lambda: statswin.attributes("-topmost", False))

        ctk.CTkLabel(statswin, text="All time calorie intake:").pack(pady=20)

        conn = sqlite3.connect("snacksync.db")
        cursor = conn.cursor()

        cursor.execute("SELECT day, month, year, SUM(calories) FROM snacks WHERE username=? GROUP BY day, month, year",
                       (username,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            ctk.CTkLabel(statswin, text="No data found.").pack(pady=10)
            return

            # Show each date + total calories
        for row in rows:
            day, month, year, total = row
            text = f"{day}/{month}/{year}: {total} kcal"
            ctk.CTkLabel(statswin, text=text).pack(anchor="w", padx=20, pady=2)
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
        conn = sqlite3.connect("snacksync.db")
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(calories) FROM snacks WHERE username=? AND day=? AND month=? AND year=?",
                       (username, self.day_var.get(), self.month_var.get(), self.year_var.get()))
        total_calories = cursor.fetchone()[0]
        conn.close()

        if total_calories is None:
            total_calories = 0

        self.total_calories_CTkLabel.configure(text=f"Total Calories This Day: {total_calories} kcal")

    def display_snacks(self, username):
        self.snack_listbox.delete(0, ctk.END)

        conn = sqlite3.connect("snacksync.db")
        cursor = conn.cursor()
        cursor.execute("SELECT snack, calories FROM snacks WHERE username=? AND day=? AND month=? AND year=?",
                       (username, self.day_var.get(), self.month_var.get(), self.year_var.get()))
        snacks = cursor.fetchall()
        conn.close()

        for snack in snacks:
            self.snack_listbox.insert(ctk.END, f"{snack[0]}: {snack[1]} kcal")

if __name__ == "__main__":
    root = ctk.CTk()
    app = SnackSyncApp(root)
    root.mainloop()

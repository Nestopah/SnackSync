import socket
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from snack import Snack

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345

class SnackSyncApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SnackSync - Login/Register")
        self.root.geometry("300x250")

        tk.Label(root, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(root)
        self.username_entry.pack(pady=5)

        tk.Label(root, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(root, text="Login", command=self.login).pack(pady=5)
        tk.Button(root, text="Register", command=self.register).pack(pady=5)

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
            username = self.username_entry.get()
            client.send(username.encode())

            client.recv(1024)
            password = self.password_entry.get()
            client.send(password.encode())

            response = client.recv(1024).decode()
            messagebox.showinfo("Server Response", response)

            client.close()

            if "successful" in response.lower():
                self.open_main_screen(username)

        except ConnectionRefusedError:
            messagebox.showerror("Error", "Cannot connect to the server.")

    def open_main_screen(self, username):
        self.root.destroy()
        main_window = tk.Tk()
        main_window.title(f"SnackSync - Welcome {username}")
        main_window.geometry("500x500")

        conn = sqlite3.connect("snacks.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
                            id INTEGER PRIMARY KEY, username TEXT, snack TEXT, 
                            calories INTEGER, day INTEGER, month INTEGER, year INTEGER)''')
        conn.commit()
        conn.close()

        tk.Label(main_window, text=f"Welcome, {username}!", font=("Arial", 14)).pack(pady=10)

        self.day_var = tk.StringVar(value=str(datetime.today().day))
        self.month_var = tk.StringVar(value=str(datetime.today().month))
        self.year_var = tk.StringVar(value=str(datetime.today().year))

        for label, var, values in [("Day:", self.day_var, range(1, 32)),
                                   ("Month:", self.month_var, range(1, 13)),
                                   ("Year:", self.year_var, range(2020, 2031))]:
            tk.Label(main_window, text=f"Select {label}").pack()
            ttk.Combobox(main_window, textvariable=var, values=[str(v) for v in values]).pack()

        tk.Label(main_window, text="Snack Name:").pack(pady=2)
        self.snack_entry = tk.Entry(main_window)
        self.snack_entry.pack(pady=5)

        tk.Label(main_window, text="Calories:").pack(pady=2)
        self.calories_entry = tk.Entry(main_window)
        self.calories_entry.pack(pady=2)

        self.total_calories_label = tk.Label(main_window, text="Total Calories This Day: 0 kcal", font=("Arial", 12))
        self.total_calories_label.pack(pady=5)

        self.snack_listbox = tk.Listbox(main_window, width=50, height=8)
        self.snack_listbox.pack(pady=5)

        tk.Button(main_window, text="Log Snack", command=lambda: self.log_snack(username)).pack(pady=5)
        tk.Button(main_window, text="Delete Selected Snack", command=lambda: self.delete_selected_snack(username)).pack(pady=5)
        tk.Button(main_window, text="Stats", command=lambda: self.view_stats(username)).pack(pady=5)

        for var in [self.day_var, self.month_var, self.year_var]:
            var.trace_add("write", lambda *args: self.update_total_calories(username))
            var.trace_add("write", lambda *args: self.load_snacks(username))

        self.load_snacks(username)
        self.update_total_calories(username)

        main_window.mainloop()

    def log_snack(self, username):
        snack_name = self.snack_entry.get().strip()
        calories = self.calories_entry.get().strip()

        if not snack_name or not calories.isdigit():
            messagebox.showerror("Error", "Please enter a valid snack and calorie amount.")
            return

        calories = int(calories)

        day, month, year = int(self.day_var.get()), int(self.month_var.get()), int(self.year_var.get())

        conn = sqlite3.connect("snacks.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO snacks (username, snack, calories, day, month, year) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, snack_name, calories, day, month, year))
        conn.commit()
        conn.close()

        self.snack_listbox.insert(tk.END, f"{snack_name}: {calories} kcal")
        self.snack_entry.delete(0, tk.END)
        self.calories_entry.delete(0, tk.END)
        self.update_total_calories(username)

    def update_total_calories(self, username):
        conn = sqlite3.connect("snacks.db")
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(calories) FROM snacks WHERE username=? AND day=? AND month=? AND year=?",
                       (username, self.day_var.get(), self.month_var.get(), self.year_var.get()))
        total_calories = cursor.fetchone()[0]
        conn.close()

        if total_calories is None:
            total_calories = 0

        self.total_calories_label.config(text=f"Total Calories This Day: {total_calories} kcal")

    def load_snacks(self, username):
        self.snack_listbox.delete(0, tk.END)

        conn = sqlite3.connect("snacks.db")
        cursor = conn.cursor()
        cursor.execute("SELECT snack, calories FROM snacks WHERE username=? AND day=? AND month=? AND year=?",
                       (username, self.day_var.get(), self.month_var.get(), self.year_var.get()))
        snacks = cursor.fetchall()
        conn.close()

        for snack in snacks:
            self.snack_listbox.insert(tk.END, f"{snack[0]}: {snack[1]} kcal")

if __name__ == "__main__":
    root = tk.Tk()
    app = SnackSyncApp(root)
    root.mainloop()

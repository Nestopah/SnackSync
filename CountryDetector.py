import customtkinter as ctk
import requests

class CountryDetector:
    def __init__(self, ip):
        self.ip = ip
        self.country = self.get_country()

    def get_country(self):
        try:
            response = requests.get(f"http://ipapi.co/{self.ip}/country_name/")
            return response.text.strip()
        except:
            return "Unknown"
    def respond(self):
        if self.country == "Israel":
            return f"🇮🇱 Welcome, Israeli user from {self.ip}"
        elif self.country == "United States":
            return f"🇺🇸 Hello, American!"
        elif self.country == "Russia":
            return "🚫 Access restricted from Russia."
        elif self.country == "Bulgaria":
            bulgaria = ctk.CTkToplevel()
            bulgaria.title("Добре дошли!")
            bulgaria.geometry("500x600")
            self.center_window(bulgaria, 500, 600)
            ctk.CTkLabel(bulgaria, text="Добре дошли!", font=("Arial", 24)).pack(pady=10)
            ctk.CTkLabel(bulgaria, text="Bulgaria respect button👇", font=("Arial", 24)).pack(pady=10)

            close_btn = ctk.CTkButton(bulgaria, text="Close", command=lambda: self.close_window(bulgaria))
            close_btn.pack(pady=20)
        else:
            return f"🌍 Hello from {self.country}"

    def close_window(self, bulgaria):
        bulgaria.destroy()

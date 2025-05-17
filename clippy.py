from win10toast_click import ToastNotifier
from dbmanager import DBManager
import datetime
import threading

class Clippy:
    def __init__(self):
        self.toaster = ToastNotifier()
        self.db = DBManager()

    def notification(self, title, message):
        def show():
            print(f"[DEBUG] Showing notification: {title} - {message}")
            self.toaster.show_toast(title, message, duration=3, threaded=False)
        threading.Thread(target=show).start()

    def notify_goal_result(self, username):
        print(f"[DEBUG] Clippy check for: {username}")
        today = datetime.datetime.now()
        day, month, year = today.day, today.month, today.year

        total = self.db.get_total_calories(username, day, month, year)
        print(f"[DEBUG] Total calories for today: {total}")
        goal_data = self.db.get_goal_for_date(username, day, month, year)
        print(f"[DEBUG] Goal data: {goal_data}")

        if not goal_data:
            print("[DEBUG] No goal set, skipping notification.")
            return

        goal_cal, goal_type = goal_data
        if goal_type == 0 and total > goal_cal:
            print("[DEBUG] Should notify for exceeding goal.")
            self.notification("SnackSync",
                f"You surpassed your calorie goal ({goal_cal} kcal). Better lay off the snacks for now!")
        elif goal_type == 1 and total >= goal_cal:
            print("[DEBUG] Should notify for reaching goal.")
            self.notification("SnackSync",f"Congrats! You reached your calorie goal ({goal_cal} kcal)!")
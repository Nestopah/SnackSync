from win10toast import ToastNotifier

class Clippy:
    def __init__(self):
        self.toaster = ToastNotifier()

    def notification(self, title, message, duration=5):
        self.toaster.show_toast(title, message, duration=duration, threaded=True)
class Snack:
    def __init__(self, username, name, calories):
        self.username = username
        self.name = name
        self.calories = calories

    def __str__(self):
        return f"{self.name}: {self.calories} kcal"

import sqlite3

conn = sqlite3.connect("snacks.db")
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS snacks (
                    id INTEGER PRIMARY KEY, 
                    username TEXT, 
                    snack TEXT, 
                    calories INTEGER, 
                    day INTEGER, 
                    month INTEGER, 
                    year INTEGER)''')

conn.commit()
conn.close()

print("snacks.db has been set up successfully!")

import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT UNIQUE, 
                    password TEXT)''')

conn.commit()
conn.close()

print("users.db has been set up successfully!")

import sqlite3

conn = sqlite3.connect("snacksync.db")
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
except sqlite3.OperationalError:
    # Column already exists
    pass
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    email TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS snacks (
    username TEXT,
    snack TEXT,
    calories INTEGER,
    day INTEGER,
    month INTEGER,
    year INTEGER
)
""")

conn.commit()
conn.close()

import sqlite3

conn = sqlite3.connect("snacksync.db")
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")


cursor.execute("""
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password TEXT,
    email TEXT,
    enable_2fa INTEGER DEFAULT 0
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

import sqlite3

conn = sqlite3.connect("snacksync.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
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
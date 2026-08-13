import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user',
            email    TEXT
        )
    """)
    c.execute("DELETE FROM users")
                                                                           
    c.execute("DELETE FROM sqlite_sequence WHERE name='users'")
    seed = [
        ("alice",  "secret123",  "admin", "alice@defence.mil"),
        ("bob",    "password1",  "user",  "bob@defence.mil"),
        ("charlie","qwerty!",    "user",  "charlie@defence.mil"),
        ("dave",   "letmein",    "user",  "dave@defence.mil"),
    ]
    c.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
        seed
    )
    conn.commit()
    conn.close()
    return DB_PATH


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

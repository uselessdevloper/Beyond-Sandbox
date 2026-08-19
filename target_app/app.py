import os
import sqlite3
from flask import Flask, request, jsonify
try:
    from database import init_db, DB_PATH
except ImportError:
    from target_app.database import init_db, DB_PATH

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/users")
def list_users():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])


@app.route("/api/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT id, username, role, email FROM users WHERE id = ?"
    try:
        rows = conn.execute(query, (user_id,)).fetchall()
        conn.close()
        return jsonify([{"id": r[0], "username": r[1], "role": r[2], "email": r[3]} for r in rows])
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    try:
        row = conn.execute(query, (username, password)).fetchone()
        conn.close()
        if row:
            return jsonify({"authenticated": True, "user": row[1], "role": row[2]})
        return jsonify({"authenticated": False}), 401
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT id, username, role FROM users WHERE username LIKE ?"
    try:
        rows = conn.execute(query, (f"%{q}%",)).fetchall()
        conn.close()
        return jsonify([{"id": r[0], "username": r[1], "role": r[2]} for r in rows])
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    init_db()
    app.run(port=5002, debug=False)

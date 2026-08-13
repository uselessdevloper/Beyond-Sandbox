import os
import sqlite3
from flask import Flask, request, jsonify

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "breakdb.sqlite")

DATABASE_CONTENTS = {
    "public_stuff": [
        (1, "Military grade encryption", "products",
         "Dont let your data be compromised, use our patented exabit encryption technology"),
        (2, "Advanced APT Detection", "products",
         "Fully next-gen big-data backed threat analysis with extra AI"),
        (3, "Internet of things", "whitepapers",
         "Check out our cyber strategies to survive the next cyber fight"),
        (4, "Enterprise version", "solutions",
         "Our most cost efficient solution for all your cyber concerns"),
        (5, "Zero trust network", "whitepapers",
         "Secure your network from those with nefarious intent"),
    ],
    "secret_stuff": [
        ("My first secret", "None of these things actually work"),
        ("Second secret",   "Our DLP product is a single regex"),
        ("Secret three",    "Its too secret to even include here"),
    ],
}


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS public_stuff")
    c.execute("DROP TABLE IF EXISTS secret_stuff")
    c.execute("""
        CREATE TABLE public_stuff (
            id          INTEGER PRIMARY KEY,
            name        VARCHAR(40),
            category    VARCHAR(20) NOT NULL,
            description VARCHAR(400)
        )
    """)
    c.execute("""
        CREATE TABLE secret_stuff (
            name        VARCHAR(40),
            description VARCHAR(400)
        )
    """)
    c.executemany(
        "INSERT INTO public_stuff (id, name, category, description) VALUES (?,?,?,?)",
        DATABASE_CONTENTS["public_stuff"],
    )
    c.executemany(
        "INSERT INTO secret_stuff (name, description) VALUES (?,?)",
        DATABASE_CONTENTS["secret_stuff"],
    )
    conn.commit()
    conn.close()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "source": "breakableflask-sqlite-adapter"})


@app.route("/api/categories")
def categories():
    conn = get_conn()
    rows = conn.execute("SELECT DISTINCT category FROM public_stuff").fetchall()
    conn.close()
    return jsonify([r["category"] for r in rows])


@app.route("/listservices")
def listservices():
    param = "category"
    category = request.args.get(param)
    where = ""
    if category:
        where = " WHERE {} = '{}'".format(param, category)

    conn = get_conn()
    try:
        query = "SELECT * FROM public_stuff{}".format(where)
        rows = conn.execute(query).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/item")
def get_item():
    item_id = request.args.get("id", "")
    conn = get_conn()
    try:
        query = "SELECT * FROM public_stuff WHERE id = {}".format(item_id)
        rows = conn.execute(query).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    conn = get_conn()
    try:
        query = f"SELECT id, name, category FROM public_stuff WHERE name LIKE '%{q}%'"
        rows = conn.execute(query).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    init_db()
    app.run(port=5001, debug=False)

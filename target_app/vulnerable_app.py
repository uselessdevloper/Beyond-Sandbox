import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    
    # Setup dummy database
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    
    # The vulnerability
    try:
        # Line 17 is where the injection happens
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        return "User found!"
    except Exception as e:
        # This will leak the sqlite error to the fuzzer, triggering 'DB_ERROR'
        return str(e), 500 

if __name__ == '__main__':
    app.run(port=5001)
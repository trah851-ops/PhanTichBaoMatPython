import sqlite3

def login(username, password):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
    cur.execute(query)  # Dễ bị SQL Injection

    result = cur.fetchall()
    if result:
        print("Login success!")
    else:
        print("Login failed!")

login("admin'--", "whatever")

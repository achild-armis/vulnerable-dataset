# CWE-89: SQL Injection
# Vulnerable: user-controlled input concatenated directly into SQL query string.
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: raw string interpolation into SQL
    query = "SELECT id, name, email FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    rows = cursor.fetchall()
    return {"results": rows}


if __name__ == "__main__":
    app.run(debug=True)

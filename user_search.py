# Fixed: CWE-89 SQL Injection. Query now uses a parameterized placeholder.
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
    query = "SELECT id, name, email FROM users WHERE name = ?"
    cursor.execute(query, (name,))
    rows = cursor.fetchall()
    return {"results": rows}


if __name__ == "__main__":
    app.run()

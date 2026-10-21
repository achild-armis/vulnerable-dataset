# Fixed: CWE-327 Use of a Broken or Risky Cryptographic Algorithm.
# Passwords are now hashed with Werkzeug's salted PBKDF2-based helpers
# instead of unsalted MD5.
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return check_password_hash(stored_hash, password)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    hashed = hash_password(password)
    # ... store username, hashed in DB
    return {"username": username, "hash": hashed}


if __name__ == "__main__":
    app.run()

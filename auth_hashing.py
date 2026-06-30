# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# Vulnerable: MD5 used for password hashing, no salt, no slow hash function.
import hashlib
from flask import Flask, request

app = Flask(__name__)


def hash_password(password: str) -> str:
    # VULNERABLE: MD5 is fast and broken, unsuitable for password storage
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    # VULNERABLE: same weak hash reused for storage
    hashed = hash_password(password)
    # ... store username, hashed in DB
    return {"username": username, "hash": hashed}


if __name__ == "__main__":
    app.run(debug=True)

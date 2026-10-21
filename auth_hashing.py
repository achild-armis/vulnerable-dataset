# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# Fixed: PBKDF2-HMAC-SHA256 with a random per-password salt and key stretching.
import hashlib
import hmac
import os
from flask import Flask, request

app = Flask(__name__)

PBKDF2_ITERATIONS = 390000


def hash_password(password: str) -> str:
    # FIXED: random salt + PBKDF2 key stretching instead of unsalted MD5
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    salt_hex, _, derived_hex = stored_hash.partition("$")
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(derived.hex(), derived_hex)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    # FIXED: salted, stretched hash reused for storage
    hashed = hash_password(password)
    # ... store username, hashed in DB
    return {"username": username, "hash": hashed}


if __name__ == "__main__":
    app.run(debug=True)

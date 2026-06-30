# CWE-502: Deserialization of Untrusted Data
# Vulnerable: pickle.loads() on user-supplied data allows arbitrary code execution.
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/session/restore", methods=["POST"])
def restore_session():
    encoded_blob = request.form.get("session_data")
    raw = base64.b64decode(encoded_blob)
    # VULNERABLE: untrusted pickle deserialization
    session_obj = pickle.loads(raw)
    return {"restored": True, "user": session_obj.get("user")}


@app.route("/cache/load", methods=["POST"])
def load_cached_object():
    blob = request.get_data()
    # VULNERABLE: same sink, different entry point
    obj = pickle.loads(blob)
    return {"loaded": str(obj)}


if __name__ == "__main__":
    app.run(debug=True)

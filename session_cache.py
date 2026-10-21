# CWE-502: Deserialization of Untrusted Data
# Fixed: untrusted payloads are parsed with json instead of pickle, avoiding
# arbitrary object/code execution during deserialization.
import json
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/session/restore", methods=["POST"])
def restore_session():
    encoded_blob = request.form.get("session_data")
    raw = base64.b64decode(encoded_blob)
    # FIXED: safe JSON deserialization instead of pickle
    session_obj = json.loads(raw)
    return {"restored": True, "user": session_obj.get("user")}


@app.route("/cache/load", methods=["POST"])
def load_cached_object():
    blob = request.get_data()
    # FIXED: same sink, now safe JSON deserialization
    obj = json.loads(blob)
    return {"loaded": str(obj)}


if __name__ == "__main__":
    app.run(debug=True)

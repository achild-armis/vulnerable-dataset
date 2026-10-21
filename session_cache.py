# Fixed: CWE-502 Deserialization of Untrusted Data.
# pickle can execute arbitrary code during deserialization, so untrusted
# payloads are now decoded as JSON instead.
import base64
import json
from flask import Flask, request, abort

app = Flask(__name__)

MAX_PAYLOAD_BYTES = 64 * 1024


@app.route("/session/restore", methods=["POST"])
def restore_session():
    encoded_blob = request.form.get("session_data")
    if not encoded_blob or len(encoded_blob) > MAX_PAYLOAD_BYTES:
        abort(400, description="Payload too large")
    raw = base64.b64decode(encoded_blob)
    session_obj = json.loads(raw)
    return {"restored": True, "user": session_obj.get("user")}


@app.route("/cache/load", methods=["POST"])
def load_cached_object():
    if request.content_length is not None and request.content_length > MAX_PAYLOAD_BYTES:
        abort(413, description="Payload too large")
    blob = request.get_data()
    if len(blob) > MAX_PAYLOAD_BYTES:
        abort(413, description="Payload too large")
    obj = json.loads(blob)
    return {"loaded": str(obj)}


if __name__ == "__main__":
    app.run()

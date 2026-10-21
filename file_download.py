# Fixed: CWE-22 Path Traversal.
# Filenames are sanitized with secure_filename and the resolved path is
# verified to stay within UPLOAD_DIR before being opened.
import os
from functools import wraps
from flask import Flask, request, send_file, abort, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

UPLOAD_DIR = "/var/app/uploads"


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            abort(401, description="Authentication required")
        return f(*args, **kwargs)
    return wrapper


def _safe_path(filename):
    safe_name = secure_filename(filename or "")
    if not safe_name:
        abort(400, description="Invalid filename")
    full_path = os.path.realpath(os.path.join(UPLOAD_DIR, safe_name))
    if not full_path.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        abort(400, description="Invalid filename")
    return full_path


@app.route("/files/download")
@login_required
def download_file():
    file_path = _safe_path(request.args.get("filename"))
    return send_file(file_path)


@app.route("/files/read")
@login_required
def read_file():
    path = _safe_path(request.args.get("name"))
    with open(path, "r") as f:
        return {"content": f.read()}


if __name__ == "__main__":
    app.run()

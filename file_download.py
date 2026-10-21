# CWE-22 / CWE-23: Path Traversal
# Fixed: resolved paths are verified to stay within the approved base directory.
import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads"


def _safe_path(base_dir: str, filename: str) -> str:
    if not filename or os.path.sep in filename or ".." in filename or (os.path.altsep and os.path.altsep in filename):
        abort(400)
    candidate = os.path.realpath(os.path.join(base_dir, filename))
    base_real = os.path.realpath(base_dir)
    if os.path.commonpath([candidate, base_real]) != base_real:
        abort(400)
    return candidate


@app.route("/files/download")
def download_file():
    filename = request.args.get("filename")
    # FIXED: reject separators/'..' and verify the resolved path stays under UPLOAD_DIR
    file_path = _safe_path(UPLOAD_DIR, filename)
    return send_file(file_path)


@app.route("/files/read")
def read_file():
    filename = request.args.get("name")
    # FIXED: reject separators/'..' and verify the resolved path stays under UPLOAD_DIR
    path = _safe_path(UPLOAD_DIR, filename)
    with open(path, "r") as f:
        return {"content": f.read()}


if __name__ == "__main__":
    app.run(debug=True)

# CWE-22: Path Traversal
# Vulnerable: filename from request used directly to build a filesystem path.
import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads"


@app.route("/files/download")
def download_file():
    filename = request.args.get("filename")
    # VULNERABLE: no sanitization of '..' sequences
    file_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(file_path)


@app.route("/files/read")
def read_file():
    filename = request.args.get("name")
    # VULNERABLE: direct string concatenation, allows ../../etc/passwd
    path = UPLOAD_DIR + "/" + filename
    with open(path, "r") as f:
        return {"content": f.read()}


if __name__ == "__main__":
    app.run(debug=True)

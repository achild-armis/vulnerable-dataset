# CWE-78: OS Command Injection
# Fixed: argument-list execution (shell=False) with input validated against a hostname allowlist.
import re
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Allow only characters valid in hostnames/IP addresses as defense in depth.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,255}$")


def _validate_host(host: str) -> str:
    if not host or not _HOSTNAME_RE.match(host):
        raise ValueError("Invalid host")
    return host


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # FIXED: no shell, host passed as a separate argument, validated as a hostname
    host = _validate_host(host)
    result = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=10)
    return {"output": result.stdout}


@app.route("/diagnostics")
def run_diagnostics():
    target = request.args.get("target")
    # FIXED: no shell, target passed as a separate argument, validated as a hostname
    target = _validate_host(target)
    result = subprocess.run(["traceroute", target], shell=False, capture_output=True, text=True, timeout=10)
    return {"trace": result.stdout}


if __name__ == "__main__":
    app.run(debug=True)

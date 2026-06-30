# CWE-78: OS Command Injection
# Vulnerable: user input passed to shell via os.system / shell=True
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: shell=True with unsanitized user input
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}


@app.route("/diagnostics")
def run_diagnostics():
    target = request.args.get("target")
    # VULNERABLE: os.system with string concatenation
    os.system("traceroute " + target + " > /tmp/trace.log")
    with open("/tmp/trace.log") as f:
        return {"trace": f.read()}


if __name__ == "__main__":
    app.run(debug=True)

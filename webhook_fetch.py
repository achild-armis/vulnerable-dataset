# CWE-918: Server-Side Request Forgery (SSRF)
# Vulnerable: server fetches a URL fully controlled by the client with no allowlist.
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch-preview")
def fetch_preview():
    target_url = request.args.get("url")
    # VULNERABLE: no validation of scheme/host, allows internal network access
    # e.g. ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    response = requests.get(target_url, timeout=5)
    return {"status": response.status_code, "body": response.text[:500]}


@app.route("/webhook/verify", methods=["POST"])
def verify_webhook():
    callback_url = request.json.get("callback_url")
    # VULNERABLE: same sink reachable via a JSON body parameter
    result = requests.post(callback_url, json={"ping": True})
    return {"verified": result.ok}


if __name__ == "__main__":
    app.run(debug=True)

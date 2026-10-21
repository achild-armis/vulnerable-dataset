# CWE-918: Server-Side Request Forgery (SSRF)
# Fixed: outbound URLs are validated (scheme allowlist + private/loopback/
# link-local/metadata IP blocking) before any request is issued.
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, request

app = Flask(__name__)

ALLOWED_SCHEMES = {"http", "https"}


def _is_blocked_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_outbound_url(url):
    """Raise ValueError if the URL is not safe to fetch server-side."""
    if not url:
        raise ValueError("Missing URL")
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Unsupported URL scheme")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Missing hostname")
    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        raise ValueError("Unable to resolve hostname")
    if not resolved_ips:
        raise ValueError("Unable to resolve hostname")
    for ip_str in resolved_ips:
        if _is_blocked_ip(ip_str):
            raise ValueError("Target resolves to a disallowed network range")
    return url


@app.route("/fetch-preview")
def fetch_preview():
    target_url = request.args.get("url")
    try:
        validate_outbound_url(target_url)
    except ValueError as exc:
        return {"error": str(exc)}, 400
    response = requests.get(target_url, timeout=5)
    return {"status": response.status_code, "body": response.text[:500]}


@app.route("/webhook/verify", methods=["POST"])
def verify_webhook():
    callback_url = request.json.get("callback_url")
    try:
        validate_outbound_url(callback_url)
    except ValueError as exc:
        return {"error": str(exc)}, 400
    result = requests.post(callback_url, json={"ping": True})
    return {"verified": result.ok}


if __name__ == "__main__":
    app.run(debug=True)

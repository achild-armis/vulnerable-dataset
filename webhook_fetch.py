# Fixed: CWE-918 Server-Side Request Forgery (SSRF).
# Outbound URLs are now restricted to https and to an explicit host
# allowlist, and resolved addresses are checked to reject private/internal
# networks (including the cloud metadata address) before the request fires.
import ipaddress
import socket
import time
from collections import defaultdict
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, request, abort

app = Flask(__name__)

ALLOWED_HOSTS = {"images.example.com", "hooks.example.com"}

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 10
_request_log = defaultdict(list)


_MAX_TRACKED_KEYS = 10000


def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.remote_addr
        now = time.time()
        for stale_key in [k for k, v in _request_log.items()
                          if not any(now - t < _RATE_LIMIT_WINDOW_SECONDS for t in v)]:
            del _request_log[stale_key]
        recent = [t for t in _request_log.get(key, []) if now - t < _RATE_LIMIT_WINDOW_SECONDS]
        if len(recent) >= _RATE_LIMIT_MAX_REQUESTS:
            abort(429, description="Too many requests")
        recent.append(now)
        if key not in _request_log and len(_request_log) >= _MAX_TRACKED_KEYS:
            abort(429, description="Too many requests")
        _request_log[key] = recent
        return f(*args, **kwargs)
    return wrapper


def _validate_outbound_url(url):
    if not url:
        abort(400, description="Missing url")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        abort(400, description="URL must be https with a hostname")
    if parsed.username or parsed.password:
        abort(400, description="URL must not contain credentials")
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(400, description="Host not allowed")
    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        abort(400, description="Could not resolve host")
    for family, _, _, _, sockaddr in resolved:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            abort(400, description="URL resolves to a disallowed network")
    return url


@app.route("/fetch-preview")
@rate_limited
def fetch_preview():
    target_url = _validate_outbound_url(request.args.get("url"))
    response = requests.get(target_url, timeout=5, allow_redirects=False)
    return {"status": response.status_code, "body": response.text[:500]}


@app.route("/webhook/verify", methods=["POST"])
@rate_limited
def verify_webhook():
    callback_url = _validate_outbound_url(request.json.get("callback_url"))
    result = requests.post(callback_url, json={"ping": True}, allow_redirects=False)
    return {"verified": result.ok}


if __name__ == "__main__":
    app.run()

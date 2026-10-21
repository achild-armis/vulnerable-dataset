# Fixed: CWE-78 OS Command Injection.
# Commands are now invoked without a shell, with the hostname/target
# validated as a simple hostname/IP before use, eliminating shell
# metacharacter injection.
import re
import subprocess
import time
from collections import defaultdict
from functools import wraps
from flask import Flask, request, abort

app = Flask(__name__)

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 5
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


def _validate_host(value):
    if not value or not _HOSTNAME_RE.match(value):
        abort(400, description="Invalid host")
    return value


@app.route("/ping")
@rate_limited
def ping_host():
    host = _validate_host(request.args.get("host", "127.0.0.1"))
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return {"output": result.stdout}


@app.route("/diagnostics")
@rate_limited
def run_diagnostics():
    target = _validate_host(request.args.get("target"))
    result = subprocess.run(["traceroute", target], capture_output=True, text=True, timeout=15)
    return {"trace": result.stdout}


if __name__ == "__main__":
    app.run()

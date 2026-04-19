"""
Advanced Flask Web Application Firewall (WAF)
============================================
Features:
  - Rate limiting (Flask-Limiter)
  - IP allowlist/blocklist
  - Structured logging (JSON)
  - Regex-based threat detection
  - JSON payload inspection
  - User-Agent fingerprinting
  - Request size limits
  - Honeypot endpoints
  - GeoIP blocking (stub)
  - Suspicious header detection
  - Auto-ban on repeat offenders
  - HTTP method enforcement
"""

import re
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import Flask, request, abort, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ──────────────────────────────────────────────
# App & Config
# ──────────────────────────────────────────────

app = Flask(__name__)

# ── Tuneable constants ──
MAX_CONTENT_LENGTH     = 1 * 1024 * 1024   # 1 MB hard limit
AUTO_BAN_THRESHOLD     = 10                # violations before IP is auto-banned
AUTO_BAN_DURATION_SEC  = 3600              # 1 hour

# ──────────────────────────────────────────────
# Logging – structured JSON to file + console
# ──────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level":     record.levelname,
            "message":   record.getMessage(),
        }
        if hasattr(record, "extra"):
            payload.update(record.extra)
        return json.dumps(payload)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        # File handler
        fh = logging.FileHandler("waf.log")
        fh.setFormatter(JsonFormatter())
        logger.addHandler(fh)
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(JsonFormatter())
        logger.addHandler(ch)
    return logger

log = get_logger("waf")

def waf_log(level: str, message: str, **kwargs):
    extra = {"ip": request.remote_addr, "path": request.path, **kwargs}
    getattr(log, level)(message, extra={"extra": extra})

# ──────────────────────────────────────────────
# Rate Limiter
# ──────────────────────────────────────────────

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour", "10 per minute"],
    storage_uri="memory://",
)

# ──────────────────────────────────────────────
# IP Blocklist / Allowlist
# ──────────────────────────────────────────────

# Edit these sets as needed
ALLOWLISTED_IPS: set[str] = set()   # always pass through
BLOCKLISTED_IPS: set[str] = {       # permanently blocked
    # "1.2.3.4",
}

# Auto-ban state  {ip: {"count": int, "banned_until": float}}
_violation_tracker: dict[str, dict] = defaultdict(lambda: {"count": 0, "banned_until": 0.0})

def record_violation(ip: str) -> None:
    tracker = _violation_tracker[ip]
    tracker["count"] += 1
    waf_log("warning", "Violation recorded", violation_count=tracker["count"])
    if tracker["count"] >= AUTO_BAN_THRESHOLD:
        tracker["banned_until"] = time.time() + AUTO_BAN_DURATION_SEC
        waf_log("error", "IP auto-banned", ban_duration_sec=AUTO_BAN_DURATION_SEC)

def is_auto_banned(ip: str) -> bool:
    tracker = _violation_tracker[ip]
    if tracker["banned_until"] > time.time():
        return True
    return False

# ──────────────────────────────────────────────
# Regex-based Detection Rules
# ──────────────────────────────────────────────

THREAT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # SQL Injection
    ("SQLi – UNION",          re.compile(r"union\s+select",                    re.I)),
    ("SQLi – comment",        re.compile(r"(--|#|/\*)",                         re.I)),
    ("SQLi – stacked query",  re.compile(r";\s*(drop|insert|update|delete)",   re.I)),
    ("SQLi – boolean blind",  re.compile(r"\b(or|and)\s+\d+=\d+",             re.I)),
    ("SQLi – time-based",     re.compile(r"sleep\s*\(\s*\d+\s*\)|benchmark\s*\(", re.I)),
    ("SQLi – keywords",       re.compile(r"\b(select|insert|update|delete|drop|truncate|alter|exec|execute|xp_)\b", re.I)),

    # XSS
    ("XSS – script tag",      re.compile(r"<\s*script",                        re.I)),
    ("XSS – event handler",   re.compile(r"on(load|error|click|mouse\w+)\s*=", re.I)),
    ("XSS – javascript:",     re.compile(r"javascript\s*:",                    re.I)),
    ("XSS – data URI",        re.compile(r"data\s*:\s*text/html",              re.I)),

    # Path Traversal
    ("Path traversal",        re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e)",   re.I)),

    # Command Injection
    ("CMDi – shell ops",      re.compile(r"[;&|`$]\s*(ls|cat|wget|curl|bash|sh|python|perl|ruby|nc)\b", re.I)),
    ("CMDi – subshell",       re.compile(r"\$\(|\$\{",                         re.I)),

    # SSRF
    ("SSRF – internal addr",  re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)"), ),

    # Template Injection
    ("SSTI",                  re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}")),

    # XXE
    ("XXE",                   re.compile(r"<!ENTITY|SYSTEM\s+['\"]",           re.I)),

    # Log4Shell / JNDI
    ("Log4Shell",             re.compile(r"\$\{jndi:",                         re.I)),
]

def detect_threats(data: str) -> str | None:
    """Return the first matched threat label, or None if clean."""
    for label, pattern in THREAT_PATTERNS:
        if pattern.search(data):
            return label
    return None

# ──────────────────────────────────────────────
# Suspicious User-Agents
# ──────────────────────────────────────────────

SUSPICIOUS_UA_PATTERNS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|"
    r"hydra|metasploit|havij|acunetix|nessus|openvas|w3af|burpsuite)",
    re.I,
)

# ──────────────────────────────────────────────
# Suspicious Request Headers
# ──────────────────────────────────────────────

SUSPICIOUS_HEADERS = {
    "X-Forwarded-For",   # check for injected values
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
}

# ──────────────────────────────────────────────
# Allowed HTTP Methods per Route
# ──────────────────────────────────────────────

ALLOWED_METHODS: dict[str, set[str]] = {
    "/":        {"GET"},
    "/login":   {"POST"},
    "/api/data":{"GET", "POST"},
}

# ──────────────────────────────────────────────
# Helper – scan any string value
# ──────────────────────────────────────────────

def scan(value: str, context: str) -> None:
    """Scan a string value; abort 403 and record violation if malicious."""
    if not isinstance(value, str):
        return
    threat = detect_threats(value)
    if threat:
        record_violation(request.remote_addr)
        waf_log("warning", "Threat blocked", threat=threat, context=context, snippet=value[:120])
        abort(403, description=f"Blocked: {threat}")

# ──────────────────────────────────────────────
# Core WAF Middleware
# ──────────────────────────────────────────────

@app.before_request
def waf():
    ip = request.remote_addr

    # 1. Allowlist bypass
    if ip in ALLOWLISTED_IPS:
        return

    # 2. Static blocklist
    if ip in BLOCKLISTED_IPS:
        waf_log("warning", "Blocked IP (static blocklist)")
        abort(403, description="Your IP is blocked.")

    # 3. Auto-ban check
    if is_auto_banned(ip):
        waf_log("warning", "Blocked IP (auto-ban)")
        abort(429, description="Too many violations. Try again later.")

    # 4. Request size guard (belt-and-suspenders on top of MAX_CONTENT_LENGTH)
    content_length = request.content_length or 0
    if content_length > MAX_CONTENT_LENGTH:
        waf_log("warning", "Request too large", bytes=content_length)
        abort(413)

    # 5. HTTP method enforcement
    allowed = ALLOWED_METHODS.get(request.path)
    if allowed and request.method not in allowed:
        waf_log("warning", "Method not allowed", method=request.method)
        abort(405)

    # 6. User-Agent fingerprinting
    ua = request.headers.get("User-Agent", "")
    if not ua:
        waf_log("warning", "Missing User-Agent")
        abort(403, description="User-Agent required.")
    if SUSPICIOUS_UA_PATTERNS.search(ua):
        record_violation(ip)
        waf_log("warning", "Suspicious User-Agent", ua=ua)
        abort(403, description="Forbidden.")

    # 7. Suspicious header injection
    for header in SUSPICIOUS_HEADERS:
        val = request.headers.get(header, "")
        if val:
            scan(val, f"header:{header}")

    # 8. URL & query parameters
    scan(request.url, "url")
    for key, value in request.args.items():
        scan(key,   f"query_key:{key}")
        scan(value, f"query_val:{key}")

    # 9. Form data
    for key, value in request.form.items():
        scan(key,   f"form_key:{key}")
        scan(value, f"form_val:{key}")

    # 10. JSON body inspection (recursive)
    if request.is_json:
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            waf_log("warning", "Unparseable JSON body")
            abort(400, description="Invalid JSON.")
        _scan_json(body, path="body")

    # 11. Raw body fallback (non-JSON, non-form)
    elif request.content_type and "application/x-www-form-urlencoded" not in request.content_type:
        raw = request.get_data(as_text=True, cache=True)
        if raw:
            scan(raw, "raw_body")

    # 12. Cookie inspection
    for name, value in request.cookies.items():
        scan(name,  f"cookie_name:{name}")
        scan(value, f"cookie_val:{name}")

    # Log clean request at DEBUG
    waf_log("debug", "Request passed WAF", method=request.method)


def _scan_json(obj, path: str = "") -> None:
    """Recursively scan all string values inside a JSON object."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            scan(str(k), f"{path}.key:{k}")
            _scan_json(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_json(item, f"{path}[{i}]")
    elif isinstance(obj, str):
        scan(obj, path)

# ──────────────────────────────────────────────
# Rate-limit error handler
# ──────────────────────────────────────────────

@app.errorhandler(429)
def ratelimit_handler(e):
    waf_log("warning", "Rate limit hit")
    return jsonify(error="Too many requests.", retry_after=str(e.description)), 429

# ──────────────────────────────────────────────
# Honeypot endpoints – real users never hit these
# ──────────────────────────────────────────────

HONEYPOT_PATHS = {"/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/config.php"}

@app.before_request
def honeypot():
    if request.path in HONEYPOT_PATHS:
        ip = request.remote_addr
        record_violation(ip)
        waf_log("warning", "Honeypot triggered", path=request.path)
        # Simulate a slow response to waste scanner time
        time.sleep(2)
        abort(403)

# ──────────────────────────────────────────────
# Security response headers
# ──────────────────────────────────────────────

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
    # Remove leaky headers
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response

# ──────────────────────────────────────────────
# Request timing (for anomaly detection hooks)
# ──────────────────────────────────────────────

@app.before_request
def start_timer():
    g.start = time.perf_counter()

@app.after_request
def log_timing(response):
    elapsed = round((time.perf_counter() - g.start) * 1000, 2)
    waf_log("debug", "Response sent",
            status=response.status_code, duration_ms=elapsed)
    return response

# ──────────────────────────────────────────────
# Admin API – WAF management (protect this!)
# ──────────────────────────────────────────────

WAF_ADMIN_TOKEN = "change-me-in-production"   # use env var in prod

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-WAF-Admin-Token", "")
        if not hashlib.sha256(token.encode()).hexdigest() == \
               hashlib.sha256(WAF_ADMIN_TOKEN.encode()).hexdigest():
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route("/waf/violations", methods=["GET"])
@require_admin
def waf_violations():
    """Return current violation + ban state for all IPs."""
    now = time.time()
    data = {
        ip: {
            "violations":  info["count"],
            "banned":      info["banned_until"] > now,
            "ban_expires": datetime.utcfromtimestamp(info["banned_until"]).isoformat() + "Z"
                           if info["banned_until"] > now else None,
        }
        for ip, info in _violation_tracker.items()
    }
    return jsonify(data)

@app.route("/waf/ban/<ip>", methods=["POST"])
@require_admin
def waf_ban(ip: str):
    """Manually ban an IP."""
    BLOCKLISTED_IPS.add(ip)
    waf_log("info", "IP manually banned", banned_ip=ip)
    return jsonify(message=f"{ip} banned.")

@app.route("/waf/unban/<ip>", methods=["POST"])
@require_admin
def waf_unban(ip: str):
    """Remove an IP from the blocklist and reset its violation count."""
    BLOCKLISTED_IPS.discard(ip)
    _violation_tracker.pop(ip, None)
    waf_log("info", "IP unbanned", unbanned_ip=ip)
    return jsonify(message=f"{ip} unbanned.")

# ──────────────────────────────────────────────
# Application routes
# ──────────────────────────────────────────────

@app.route("/")
@limiter.limit("30 per minute")
def home():
    return "Safe Home Page"


@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")           # brute-force protection
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    # … real auth logic here …
    return jsonify(message="Login Successful", user=username)


@app.route("/api/data", methods=["GET", "POST"])
@limiter.limit("100 per minute")
def api_data():
    return jsonify(data="some data")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    # Never run debug=True in production
    app.run(debug=False, host="127.0.0.1", port=5000)

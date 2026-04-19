"""
WAF Demo — Vulnerable BankApp
==============================
IMPORTANT: This is intentionally vulnerable. Run only on localhost.
Never expose to the internet.

Setup:
  pip install flask flask-limiter

Run:
  python demo_app.py
  Then open http://localhost:5000
"""

import re, json, logging, time, sqlite3, os
from collections import defaultdict
from datetime import datetime
from flask import Flask, request, abort, jsonify, g, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
WAF_ENABLED = True          # toggle via POST /waf/toggle for demo
# DB_PATH = ":memory:"        # in-memory SQLite — resets on restart
DB_PATH = "bankapp.db"

# ─────────────────────────── Logging ───────────────────────────

logging.basicConfig(level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("waf_demo.log"), logging.StreamHandler()])
log = logging.getLogger("waf")

# ─────────────────────────── Database ──────────────────────────

def get_db():
    if not hasattr(g, "_db"):
        g._db = sqlite3.connect(DB_PATH)
        g._db.row_factory = sqlite3.Row
    return g._db

@app.before_request
def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            balance REAL
        );
        INSERT OR IGNORE INTO users VALUES (1,'admin','supersecret','admin');
        INSERT OR IGNORE INTO users VALUES (2,'alice','pass123','user');
        INSERT OR IGNORE INTO users VALUES (3,'bob','qwerty','user');
        INSERT OR IGNORE INTO accounts VALUES (1,1,99999.00);
        INSERT OR IGNORE INTO accounts VALUES (2,2,1500.00);
        INSERT OR IGNORE INTO accounts VALUES (3,3,230.00);
    """)

# ─────────────────────────── Rate Limiter ──────────────────────

limiter = Limiter(
    key_func=get_remote_address, app=app,
    default_limits=["200 per day", "60 per hour", "10 per minute"],
    storage_uri="memory://",
)

# ─────────────────────────── WAF Logic ─────────────────────────

VIOLATION_COUNT = defaultdict(int)
AUTO_BAN_LIMIT  = 10

THREAT_PATTERNS = [
    ("SQLi – UNION",         re.compile(r"union\s+select",               re.I)),
    ("SQLi – stacked query", re.compile(r";\s*(drop|insert|update|delete|truncate)", re.I)),
    ("SQLi – comment",       re.compile(r"(--|#|/\*)",                   re.I)),
    ("SQLi – boolean blind", re.compile(r"\b(or|and)\s+[\d'\"]=",       re.I)),
    ("SQLi – keywords",      re.compile(r"\b(drop|truncate|exec|xp_)\b",re.I)),
    ("XSS – script tag",     re.compile(r"<\s*script",                  re.I)),
    ("XSS – event handler",  re.compile(r"on(load|error|click|mouse\w+)\s*=", re.I)),
    ("XSS – javascript:",    re.compile(r"javascript\s*:",              re.I)),
    ("Path traversal",       re.compile(r"(\.\./|%2e%2e%2f)",           re.I)),
    ("CMDi",                 re.compile(r"[;&|`]\s*(ls|cat|curl|wget|bash|sh|python)", re.I)),
    ("SSTI",                 re.compile(r"\{\{.*?\}\}|\$\{.*?\}")),
    ("Log4Shell",            re.compile(r"\$\{jndi:",                   re.I)),
    ("SSRF",                 re.compile(r"(127\.0\.0\.1|localhost|169\.254\.)")),
]

SUSPICIOUS_UA = re.compile(r"(sqlmap|nikto|nmap|dirbuster|burpsuite|hydra|masscan)", re.I)
HONEYPOT_PATHS = {"/admin", "/wp-login.php", "/.env", "/phpmyadmin"}

def detect(value: str):
    for label, pat in THREAT_PATTERNS:
        if pat.search(value):
            return label
    return None

def waf_block(reason, payload=""):
    ip = request.remote_addr
    VIOLATION_COUNT[ip] += 1
    log.warning(f"BLOCKED [{reason}] ip={ip} payload={payload[:80]} violations={VIOLATION_COUNT[ip]}")
    abort(403, description=f"WAF blocked: {reason}")

@app.before_request
def waf():
    global WAF_ENABLED
    if not WAF_ENABLED:
        return  # WAF is off — all attacks pass through

    ip = request.remote_addr

    # Auto-ban check
    if VIOLATION_COUNT[ip] >= AUTO_BAN_LIMIT:
        log.error(f"AUTO-BAN triggered for {ip}")
        abort(429, description="Too many violations.")

    # Honeypot
    if request.path in HONEYPOT_PATHS:
        VIOLATION_COUNT[ip] += 1
        log.warning(f"HONEYPOT hit: {request.path} from {ip}")
        time.sleep(1)
        abort(403, description="Not found.")

    # User-Agent
    ua = request.headers.get("User-Agent", "")
    if SUSPICIOUS_UA.search(ua):
        waf_block("Suspicious scanner UA", ua)

    # URL scan
    # threat = detect(request.url)
    threat = detect(request.path)
    if threat:
        waf_block(threat, request.url)

    # Query params
    for k, v in request.args.items():
        threat = detect(k) or detect(v)
        if threat:
            waf_block(threat, f"{k}={v}")

    # Form data
    for k, v in request.form.items():
        threat = detect(k) or detect(v)
        if threat:
            waf_block(threat, f"{k}={v}")

    # JSON body (recursive)
    if request.is_json:
        body = request.get_json(silent=True, force=True) or {}
        _scan_obj(body)

@app.after_request
def sec_headers(resp):
    if WAF_ENABLED:
        resp.headers["X-Frame-Options"]        = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-XSS-Protection"]       = "1; mode=block"
    return resp

def _scan_obj(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            t = detect(str(k))
            if t: waf_block(t, str(k))
            _scan_obj(v)
    elif isinstance(obj, list):
        for i in obj: _scan_obj(i)
    elif isinstance(obj, str):
        t = detect(obj)
        if t: waf_block(t, obj)

# ─────────────────────────── Demo routes ───────────────────────

HOME = """
<!DOCTYPE html><html><head><title>BankApp Demo</title>
<style>
  body{font-family:sans-serif;max-width:700px;margin:40px auto;padding:0 20px;}
  h1{color:#1a1a2e;} .waf-status{padding:8px 16px;border-radius:6px;display:inline-block;margin-bottom:20px;}
  .on{background:#e1f5ee;color:#0f6e56;} .off{background:#fcebeb;color:#a32d2d;}
  form{background:#f8f9fa;padding:20px;border-radius:8px;margin:16px 0;}
  input{width:100%;padding:8px;margin:6px 0 12px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;}
  button{background:#185fa5;color:white;padding:10px 20px;border:none;border-radius:4px;cursor:pointer;}
  pre{background:#1a1a2e;color:#e0e0e0;padding:16px;border-radius:8px;overflow-x:auto;}
  .section{margin:24px 0;}
</style></head><body>
<h1>BankApp — WAF Demo</h1>
<div class="waf-status {{ 'on' if waf else 'off' }}">
  WAF: <strong>{{ 'ENABLED' if waf else 'DISABLED' }}</strong>
</div>
<button onclick="fetch('/waf/toggle',{method:'POST'}).then(()=>location.reload())" style="margin-left:12px;">
  Toggle WAF
</button>

<div class="section">
  <h2>1. SQL injection — login bypass</h2>
  <p>With WAF off, try username: <code>' OR '1'='1' --</code> and any password.</p>
  <form onsubmit="event.preventDefault();
    fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:this.u.value,password:this.p.value})})
    .then(r=>r.json()).then(d=>document.getElementById('r1').textContent=JSON.stringify(d,null,2));">
    <input name="u" placeholder="Username">
    <input name="p" type="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
  <pre id="r1">response will appear here</pre>
</div>

<div class="section">
  <h2>2. XSS — reflected output</h2>
  <p>With WAF off, try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
  <form onsubmit="event.preventDefault();
    fetch('/search?q='+encodeURIComponent(this.q.value))
    .then(r=>r.text()).then(d=>document.getElementById('r2').innerHTML=d);">
    <input name="q" placeholder="Search query">
    <button type="submit">Search</button>
  </form>
  <pre id="r2">response will appear here</pre>
</div>

<div class="section">
  <h2>3. UNION-based data dump</h2>
  <p>With WAF off, try id: <code>1 UNION SELECT username,password,role FROM users--</code></p>
  <form onsubmit="event.preventDefault();
    fetch('/account?id='+encodeURIComponent(this.id.value))
    .then(r=>r.json()).then(d=>document.getElementById('r3').textContent=JSON.stringify(d,null,2));">
    <input name="id" placeholder="Account ID">
    <button type="submit">Lookup</button>
  </form>
  <pre id="r3">response will appear here</pre>
</div>

</body></html>
"""

@app.route("/")
def home():
    return render_template_string(HOME, waf=WAF_ENABLED)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    u = data.get("username", "")
    p = data.get("password", "")
    db = get_db()
    # !! INTENTIONALLY VULNERABLE — raw string concat !!
    query = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
    try:
        rows = db.execute(query).fetchall()
        if rows:
            return jsonify(status="success", message=f"Welcome {rows[0]['username']}!", role=rows[0]['role'])
        return jsonify(status="fail", message="Invalid credentials")
    except Exception as e:
        return jsonify(status="error", message=str(e))

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # !! INTENTIONALLY VULNERABLE — unsanitised reflection !!
    return f"<p>Search results for: {q}</p>"

@app.route("/account")
def account():
    id_ = request.args.get("id", "1")
    db = get_db()
    # !! INTENTIONALLY VULNERABLE — raw concat !!
    query = f"SELECT * FROM accounts WHERE id={id_}"
    try:
        rows = db.execute(query).fetchall()
        return jsonify(results=[dict(r) for r in rows])
    except Exception as e:
        return jsonify(error=str(e))

# ─────────────────────────── WAF toggle API ────────────────────

@app.route("/waf/toggle", methods=["POST"])
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    status = "ENABLED" if WAF_ENABLED else "DISABLED"
    log.info(f"WAF toggled → {status}")
    return jsonify(waf=WAF_ENABLED, status=status)

@app.route("/waf/status")
def waf_status():
    return jsonify(waf=WAF_ENABLED, violations=dict(VIOLATION_COUNT))

@app.route("/waf/reset", methods=["POST"])
def reset_violations():
    VIOLATION_COUNT.clear()
    return jsonify(message="Violation counts reset.")

# ─────────────────────────── Honeypot stubs ────────────────────
# These are never linked — scanners find them, real users don't.
# @app.route("/admin");       @app.route("/.env")
# @app.route("/wp-login.php");@app.route("/phpmyadmin")
# def honeypot(): abort(403)
@app.route("/admin")
@app.route("/.env")
@app.route("/wp-login.php")
@app.route("/phpmyadmin")
def honeypot():
    abort(403)

# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  BankApp WAF Demo")
    print("  ─────────────────")
    print("  http://localhost:5000")
    print("  WAF starts ENABLED — toggle at /waf/toggle\n")
    app.run(debug=True, host="127.0.0.1", port=5000)

"""CyberShield Lite - phishing URL detection and file integrity checking.

Two pages only: Dashboard (/) and Security Tools (/tools).
Submitted URLs are analysed as text and never opened.
Uploaded files are hashed in memory with SHA-256 and never saved or executed.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

import model as ml

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CYBERSHIELD_DB", BASE_DIR / "database.db"))
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_URL_LENGTH = 2000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# --------------------------------------------------------------------------
# Database (SQLite)
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS url_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    scanned_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    baseline_sha256 TEXT NOT NULL,
    current_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_activity(db, kind, message, severity):
    db.execute(
        "INSERT INTO activity (kind, message, severity, created_at) VALUES (?, ?, ?, ?)",
        (kind, message, severity, now_iso()),
    )


# --------------------------------------------------------------------------
# Error handling (JSON for /api, friendly messages instead of stack traces)
# --------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    return jsonify(error="That file is too large. The limit is 50 MB."), 413


@app.errorhandler(HTTPException)
def http_error(e):
    if request.path.startswith("/api/"):
        return jsonify(error=e.description or e.name), e.code
    return e


@app.errorhandler(Exception)
def unexpected_error(_e):
    app.logger.exception("Unexpected error")
    if request.path.startswith("/api/"):
        return jsonify(error="Something went wrong on the server. Please try again."), 500
    return "Something went wrong. Please go back and try again.", 500


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'"
    )
    return resp


# --------------------------------------------------------------------------
# URL validation (the URL is only ever treated as text)
# --------------------------------------------------------------------------
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
BLOCKED_SCHEMES = re.compile(r"^(javascript|data|file|mailto|vbscript|ftp|blob):", re.I)


def normalize_url(raw):
    """Return (url, note). Raise ValueError with a user-friendly message."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Enter a URL to scan.")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"That URL is too long. The limit is {MAX_URL_LENGTH} characters.")
    if re.search(r"\s", url) or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("A URL cannot contain spaces or control characters.")

    note = None
    if "://" not in url:
        if BLOCKED_SCHEMES.match(url):
            raise ValueError("Only http:// and https:// URLs can be scanned.")
        url = "http://" + url
        note = "No http:// or https:// was given, so http:// was assumed."

    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # raises ValueError for an invalid port
    except ValueError:
        raise ValueError("That does not look like a valid URL. Check the address and port.")
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs can be scanned.")
    if not host:
        raise ValueError("The URL has no hostname. Example: https://www.example.com/page")

    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    if not is_ip:
        if not HOST_RE.match(host) or ".." in host or len(host) > 253:
            raise ValueError("The hostname has unsupported characters. Use letters, digits, dots and hyphens.")
        if "." not in host:
            raise ValueError("The hostname must look like a domain, for example example.com.")
        if any(len(label) > 63 for label in host.split(".")):
            raise ValueError("The hostname has a label longer than 63 characters.")
    return url, note


# --------------------------------------------------------------------------
# Upload helpers (hash in memory, never write the file to disk)
# --------------------------------------------------------------------------
def clean_filename(name):
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if ord(c) >= 32 and ord(c) != 127).strip()
    return name[:120]


def read_upload():
    """Return (filename, sha256_hex, size). Raise ValueError for bad uploads."""
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        raise ValueError("Choose a file first.")
    filename = clean_filename(upload.filename)
    if not filename:
        raise ValueError("That file has no usable name.")
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = upload.stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    if size == 0:
        raise ValueError("That file is empty, so there is nothing to hash.")
    return filename, digest.hexdigest(), size


# --------------------------------------------------------------------------
# Queries shared by the pages and the API
# --------------------------------------------------------------------------
def collect_stats(db):
    one = lambda sql: db.execute(sql).fetchone()[0]
    low = one("SELECT COUNT(*) FROM url_scans WHERE risk_level = 'Low'")
    medium = one("SELECT COUNT(*) FROM url_scans WHERE risk_level = 'Medium'")
    high = one("SELECT COUNT(*) FROM url_scans WHERE risk_level = 'High'")
    total = low + medium + high
    pct = lambda n: round(n * 100 / total) if total else 0
    return {
        "urls_scanned": total,
        "suspicious_urls": medium + high,
        "files_checked": one("SELECT COUNT(*) FROM file_checks"),
        "modified_files": one("SELECT COUNT(*) FROM file_checks WHERE status = 'Modified'"),
        "baselines": one("SELECT COUNT(*) FROM file_baselines"),
        "breakdown": {"low": low, "medium": medium, "high": high,
                      "low_pct": pct(low), "medium_pct": pct(medium),
                      "high_pct": 100 - pct(low) - pct(medium) if total else 0},
    }


def recent_activity(db, limit=8):
    rows = db.execute(
        "SELECT kind, message, severity, created_at FROM activity ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()
    return [dict(r) for r in rows]


def clamp_limit(default=8):
    try:
        return max(1, min(50, int(request.args.get("limit", default))))
    except ValueError:
        return default


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.get("/")
def dashboard():
    db = get_db()
    return render_template("dashboard.html", active="dashboard",
                           stats=collect_stats(db), activity=recent_activity(db),
                           meta=ml.load_meta())


@app.get("/tools")
def tools():
    return render_template("tools.html", active="tools", meta=ml.load_meta())


# --------------------------------------------------------------------------
# API: URL detector
# --------------------------------------------------------------------------
@app.post("/api/scan-url")
def scan_url():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send the URL as JSON, for example {\"url\": \"https://www.example.com\"}."), 400
    try:
        url, note = normalize_url(payload.get("url"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    score, features = ml.predict_url(url)
    level = ml.risk_level(score)
    reasons = ml.explain(url, features)
    if note:
        reasons.insert(0, {"level": "info", "text": note})

    db = get_db()
    scanned_at = now_iso()
    with db:
        cur = db.execute(
            "INSERT INTO url_scans (url, risk_score, risk_level, reasons, scanned_at) VALUES (?,?,?,?,?)",
            (url, score, level, json.dumps(reasons), scanned_at))
        shown = url if len(url) <= 70 else url[:67] + "..."
        severity = {"Low": "ok", "Medium": "warn", "High": "danger"}[level]
        log_activity(db, "url", f"Scanned {shown}: {level.lower()} risk ({score}%)", severity)
    return jsonify(id=cur.lastrowid, url=url, risk_score=score, risk_level=level,
                   reasons=reasons, scanned_at=scanned_at)


@app.get("/api/scans")
def list_scans():
    rows = get_db().execute(
        "SELECT id, url, risk_score, risk_level, scanned_at FROM url_scans ORDER BY id DESC LIMIT ?",
        (clamp_limit(),)).fetchall()
    return jsonify(scans=[dict(r) for r in rows])


# --------------------------------------------------------------------------
# API: File integrity checker
# --------------------------------------------------------------------------
@app.post("/api/files/register")
def register_baseline():
    try:
        filename, sha, size = read_upload()
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    replace = request.form.get("replace") == "true"

    db = get_db()
    existing = db.execute("SELECT id FROM file_baselines WHERE filename = ?", (filename,)).fetchone()
    if existing and not replace:
        return jsonify(
            code="baseline_exists",
            error=f"A baseline for '{filename}' already exists. Tick \"Replace existing baseline\" to overwrite it."), 409
    with db:
        if existing:
            db.execute("UPDATE file_baselines SET sha256=?, size_bytes=?, registered_at=? WHERE id=?",
                       (sha, size, now_iso(), existing["id"]))
            log_activity(db, "file", f"Baseline replaced for {filename}", "info")
            outcome = "replaced"
        else:
            db.execute("INSERT INTO file_baselines (filename, sha256, size_bytes, registered_at) VALUES (?,?,?,?)",
                       (filename, sha, size, now_iso()))
            log_activity(db, "file", f"Baseline registered for {filename}", "info")
            outcome = "registered"
    return jsonify(outcome=outcome, filename=filename, sha256=sha, size_bytes=size)


@app.post("/api/files/verify")
def verify_file():
    try:
        filename, sha, size = read_upload()
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    db = get_db()
    # The hash always comes from the file's CONTENT. The name is only used to find
    # which baseline to compare with, unless the user picks a baseline explicitly.
    chosen = clean_filename(request.form.get("baseline", ""))
    target = chosen or filename
    row = db.execute("SELECT filename, sha256 FROM file_baselines WHERE filename = ?", (target,)).fetchone()
    if row is None:
        if chosen:
            msg = f"The baseline '{chosen}' no longer exists. Pick another baseline or register one."
        else:
            msg = (f"No baseline is registered for '{filename}'. Register a baseline first, "
                   "or choose an existing baseline from the list to compare a renamed file.")
        return jsonify(code="no_baseline", error=msg), 404

    unchanged = hmac.compare_digest(row["sha256"], sha)
    status = "Unchanged" if unchanged else "Modified"
    checked_at = now_iso()
    tracked = row["filename"]
    with db:
        db.execute(
            "INSERT INTO file_checks (filename, baseline_sha256, current_sha256, status, checked_at) VALUES (?,?,?,?,?)",
            (tracked, row["sha256"], sha, status, checked_at))
        label = tracked if tracked == filename else f"{filename} (against baseline {tracked})"
        log_activity(db, "file", f"Verified {label}: {status.lower()}", "ok" if unchanged else "danger")
    return jsonify(status=status, filename=tracked, uploaded_name=filename,
                   baseline_sha256=row["sha256"], current_sha256=sha,
                   size_bytes=size, checked_at=checked_at)


@app.get("/api/files/baselines")
def list_baselines():
    rows = get_db().execute(
        "SELECT filename, sha256, size_bytes, registered_at FROM file_baselines ORDER BY filename COLLATE NOCASE"
    ).fetchall()
    return jsonify(baselines=[dict(r) for r in rows])


@app.get("/api/files/checks")
def list_checks():
    db = get_db()
    rows = db.execute(
        "SELECT filename, baseline_sha256, current_sha256, status, checked_at "
        "FROM file_checks ORDER BY id DESC LIMIT ?", (clamp_limit(),)).fetchall()
    baselines = db.execute("SELECT COUNT(*) FROM file_baselines").fetchone()[0]
    return jsonify(checks=[dict(r) for r in rows], baseline_count=baselines)


# Create the database and train the model on first run.
init_db()
ml.ensure_model()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

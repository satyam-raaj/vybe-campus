# VYBE V14 — clean page-based password reset + IST admin login audit
# Page-based password reset. Reset codes appear only on the student recovery page after admin approval.

import os
import re
import base64
import json
import secrets
import hashlib
import html
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, urlopen

from flask import Flask, request, redirect, url_for, session, flash, abort, send_from_directory, jsonify, render_template_string
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None



try:
    from webauthn import (
        generate_registration_options,
        verify_registration_response,
        generate_authentication_options,
        verify_authentication_response,
        options_to_json,
        base64url_to_bytes,
    )
    from webauthn.helpers.structs import (
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
    )
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "vybe_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SQLITE_PATH = os.environ.get("VYBE_DB", str(APP_DIR / "vybe.db"))
SECRET_KEY = os.environ.get("VYBE_SECRET_KEY", "change-this-vybe-secret-in-production")
DEFAULT_ADMIN_PASSWORD = "VYBE@2026Admin!"
PASSKEY_RP_ID = os.environ.get("VYBE_PASSKEY_RP_ID", "localhost")
PASSKEY_ORIGIN = os.environ.get("VYBE_PASSKEY_ORIGIN", "http://localhost:5000")
DRIVE_URL = "https://drive.google.com/drive/folders/1xHRB6-j6UI8F_-q_E9w6GDlmeXWxKkc_?usp=sharing"
ALLOWED_EXT = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".txt", ".png", ".jpg", ".jpeg", ".webp", ".zip"}
CATEGORIES = ["Wi-Fi", "Systems / computers", "Classroom", "Electricity", "Facilities", "Other"]
STATUSES = ["Open", "In progress", "Resolved"]

RESET_CODE_SALT = "vybe-password-reset-code-v1"
reset_code_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=RESET_CODE_SALT)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VYBE_COOKIE_SECURE", "0") == "1",
)


class DB:
    """Tiny database abstraction for SQLite and PostgreSQL.

    Application SQL uses '?' placeholders. PostgreSQL gets them converted to
    '%s' so routes do not contain SQLite-only SQL syntax.
    """
    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        if self.is_pg:
            if psycopg is None:
                raise RuntimeError("DATABASE_URL is set but psycopg is not installed")
            self.conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(SQLITE_PATH, timeout=20)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def _sql(self, sql):
        return sql.replace("?", "%s") if self.is_pg else sql

    def execute(self, sql, params=()):
        return self.conn.execute(self._sql(sql), params)

    def executescript(self, statements):
        for statement in statements:
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def db():
    return DB()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def now_ist():
    """Current Indian Standard Time for admin audit records."""
    from zoneinfo import ZoneInfo
    return datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")


def record_admin_login(con, success, event="login"):
    """Record admin authentication activity without storing passwords."""
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip())[:100]
    user_agent = request.headers.get("User-Agent", "")[:500]
    con.execute(
        "INSERT INTO admin_login_logs(logged_at_ist,success,event,ip_address,user_agent) VALUES(?,?,?,?,?)",
        (now_ist(), bool(success), event[:40], ip, user_agent),
    )


def esc(value):
    return html.escape(str(value or ""), quote=True)


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 220_000)
    return f"{salt.hex()}${digest.hex()}"


def check_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 220_000).hex()
        return secrets.compare_digest(test, digest_hex)
    except Exception:
        return False


def valid_url(value, allowed_schemes=("https", "http")):
    try:
        p = urlparse(value)
        return p.scheme in allowed_schemes and bool(p.netloc)
    except Exception:
        return False


def send_whatsapp_notification(message, recipient_override=None):
    """Send an optional WhatsApp Cloud API text notification using Python stdlib only."""
    con = db()
    try:
        enabled = setting(con, "whatsapp_notifications_enabled", "0") == "1"
        version = setting(con, "whatsapp_api_version", "v23.0").strip() or "v23.0"
        phone_number_id = setting(con, "whatsapp_phone_number_id", "").strip()
        token = setting(con, "whatsapp_access_token", "").strip()
        recipient_raw = recipient_override if recipient_override is not None else setting(con, "whatsapp_admin_number", "")
        recipient = re.sub(r"[^0-9]", "", str(recipient_raw).strip())
    finally:
        con.close()
    if not enabled or not phone_number_id or not token or not recipient:
        return False
    endpoint = f"https://graph.facebook.com/{version}/{phone_number_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": recipient,
        "type": "text",
        "text": {"preview_url": False, "body": message[:4000]},
    }
    try:
        req = URLRequest(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=8) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def create_admin_notification(kind, title, message, student_id=None):
    """Create an admin alert without ever breaking the student's request flow.

    WhatsApp delivery and the notification audit are best-effort: a third-party
    notification problem or an older database schema must never turn a normal
    password-reset request into a 500 response.
    """
    sent = False
    try:
        sent = send_whatsapp_notification(message)
    except Exception:
        sent = False

    try:
        con = db()
        try:
            con.execute(
                "INSERT INTO notifications(kind,title,message,student_id,created_at,whatsapp_sent) VALUES(?,?,?,?,?,?)",
                (kind, title, message, student_id, now(), bool(sent)),
            )
            con.commit()
        finally:
            con.close()
    except Exception:
        # The admin notification is supplementary. Never fail the user's
        # password-reset request because this optional audit/alert failed.
        try:
            con.rollback()
            con.close()
        except Exception:
            pass
    return sent


def setting(con, key, default=""):
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(con, key, value):
    if con.is_pg:
        con.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (key, value),
        )
    else:
        con.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def init_db():
    con = db()
    if con.is_pg:
        statements = [
            """CREATE TABLE IF NOT EXISTS students (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                student_id TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                last_login TEXT,
                last_seen TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS resources (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                resource_type TEXT NOT NULL DEFAULT 'Study material',
                course TEXT NOT NULL,
                semester TEXT NOT NULL,
                subject TEXT NOT NULL,
                description TEXT DEFAULT '',
                file_name TEXT,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS issues (
                id BIGSERIAL PRIMARY KEY,
                student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS solutions (
                id BIGSERIAL PRIMARY KEY,
                issue_id BIGINT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
                student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS passkeys (
                id BIGSERIAL PRIMARY KEY,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count BIGINT NOT NULL DEFAULT 0,
                device_type TEXT,
                backed_up BOOLEAN NOT NULL DEFAULT FALSE,
                transports TEXT,
                created_at TEXT NOT NULL
            )""",            """CREATE TABLE IF NOT EXISTS community_messages (
                id BIGSERIAL PRIMARY KEY,
                student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS notifications (
                id BIGSERIAL PRIMARY KEY,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                student_id BIGINT REFERENCES students(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                whatsapp_sent BOOLEAN NOT NULL DEFAULT FALSE
            )""",
            """CREATE TABLE IF NOT EXISTS admin_login_logs (
                id BIGSERIAL PRIMARY KEY,
                logged_at_ist TEXT NOT NULL,
                success BOOLEAN NOT NULL DEFAULT FALSE,
                event TEXT NOT NULL DEFAULT 'login',
                ip_address TEXT,
                user_agent TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS password_reset_requests (
                id BIGSERIAL PRIMARY KEY,
                student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                approved_at TEXT,
                approval_code_hash TEXT,
                approval_code_token TEXT,
                expires_at TEXT,
                used_at TEXT
            )""",
        ]
    else:
        statements = [
            """CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                student_id TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                last_login TEXT,
                last_seen TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                resource_type TEXT NOT NULL DEFAULT 'Study material',
                course TEXT NOT NULL,
                semester TEXT NOT NULL,
                subject TEXT NOT NULL,
                description TEXT DEFAULT '',
                file_name TEXT,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
            )""",
            """CREATE TABLE IF NOT EXISTS solutions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(issue_id) REFERENCES issues(id) ON DELETE CASCADE,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
            )""",
            """CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                device_type TEXT,
                backed_up INTEGER NOT NULL DEFAULT 0,
                transports TEXT,
                created_at TEXT NOT NULL
            )""",            """CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                student_id INTEGER,
                created_at TEXT NOT NULL,
                whatsapp_sent INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE SET NULL
            )""",
            """CREATE TABLE IF NOT EXISTS admin_login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                logged_at_ist TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0,
                event TEXT NOT NULL DEFAULT 'login',
                ip_address TEXT,
                user_agent TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS password_reset_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                approved_at TEXT,
                approval_code_hash TEXT,
                approval_code_token TEXT,
                expires_at TEXT,
                used_at TEXT,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
            )""",
        ]
    con.executescript(statements)

    # Lightweight migration for the earlier VYBE_V2 SQLite schema.
    if not con.is_pg:
        cols = {r["name"] for r in con.execute("PRAGMA table_info(resources)").fetchall()}
        if "resource_type" not in cols:
            con.execute("ALTER TABLE resources ADD COLUMN resource_type TEXT NOT NULL DEFAULT 'Study material'")
    else:
        # PostgreSQL migrations are idempotent and safe on existing deployments.
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT 'Study material'")
        # Existing V14 deployments may already have this table. Keep the PostgreSQL
        # column Boolean-compatible so inserts using True/False never hit a type mismatch.
        con.execute("ALTER TABLE admin_login_logs ADD COLUMN IF NOT EXISTS success BOOLEAN NOT NULL DEFAULT FALSE")

    if not con.is_pg:
        student_cols = {r["name"] for r in con.execute("PRAGMA table_info(students)").fetchall()}
        if "last_seen" not in student_cols:
            con.execute("ALTER TABLE students ADD COLUMN last_seen TEXT")
    else:
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS last_seen TEXT")
    if not con.is_pg:
        reset_cols = {r["name"] for r in con.execute("PRAGMA table_info(password_reset_requests)").fetchall()}
        if "approval_code_token" not in reset_cols:
            con.execute("ALTER TABLE password_reset_requests ADD COLUMN approval_code_token TEXT")
    else:
        con.execute("ALTER TABLE password_reset_requests ADD COLUMN IF NOT EXISTS approval_code_token TEXT")

    defaults = {
        "whatsapp_link": "",
        "google_drive_url": DRIVE_URL,
        "vybe_online": "1",
        "admin_password_hash": hash_password(DEFAULT_ADMIN_PASSWORD),
        "whatsapp_notifications_enabled": "0",
        "whatsapp_api_version": "v23.0",
        "whatsapp_phone_number_id": "",
        "whatsapp_access_token": "",
        "whatsapp_admin_number": "",
        "community_chat_enabled": "1",
    }
    for key, value in defaults.items():
        if setting(con, key, None) is None:
            set_setting(con, key, value)
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Authentication / authorization decorators are deliberately defined BEFORE
# any route that uses them. This fixes the deployed NameError.
# ---------------------------------------------------------------------------
def student_is_online(last_seen, timeout_seconds=300):
    if not last_seen:
        return False
    try:
        seen = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - seen).total_seconds() <= timeout_seconds
    except Exception:
        return False


def student_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        sid = session.get("student_db_id")
        if not sid:
            return redirect(url_for("login"))
        con = db()
        row = con.execute("SELECT id,status FROM students WHERE id=?", (sid,)).fetchone()
        con.close()
        if not row or row["status"] != "approved":
            session.clear()
            flash("Your student access is not currently active.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login"))
        endpoint = request.endpoint or ""
        allowed_without_passkey = {
            "admin_login", "admin_verify",
            "passkey_auth_options", "passkey_auth_verify",
            "passkey_register_options", "passkey_register_verify",
        }
        if endpoint not in allowed_without_passkey:
            con = db()
            count = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
            con.close()
            if count > 0 and not session.get("passkey_verified"):
                return redirect(url_for("admin_verify"))
        return fn(*args, **kwargs)
    return wrapper


def passkey_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login"))
        if not session.get("passkey_verified"):
            flash("Verify your registered phone passkey first.")
            return redirect(url_for("admin_password"))
        return fn(*args, **kwargs)
    return wrapper


def admin_password_hash(con):
    stored = setting(con, "admin_password_hash", "")
    if not stored:
        stored = hash_password(DEFAULT_ADMIN_PASSWORD)
        set_setting(con, "admin_password_hash", stored)
        con.commit()
    return stored


def webauthn_configured():
    return WEBAUTHN_AVAILABLE and bool(PASSKEY_RP_ID and PASSKEY_ORIGIN)


# ---------------------------------------------------------------------------
# Offline gate: admin login/admin routes remain available while public/student
# routes receive the dedicated offline page.
# ---------------------------------------------------------------------------
@app.before_request
def global_online_gate():
    path = request.path
    if path.startswith("/admin") or path.startswith("/passkey") or path == "/offline":
        return None
    try:
        con = db()
        online = setting(con, "vybe_online", "1") == "1"
        con.close()
    except Exception:
        online = True
    if not online:
        return redirect(url_for("offline"))
    active_student = session.get("student_db_id")
    if active_student:
        try:
            con = db()
            con.execute("UPDATE students SET last_seen=? WHERE id=?", (now(), active_student))
            con.commit()
            con.close()
        except Exception:
            pass
    return None


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


CSS = r"""
:root{--bg:#050505;--bg2:#0b0b0d;--panel:rgba(255,255,255,.055);--line:rgba(255,255,255,.11);--line2:rgba(255,255,255,.18);--text:#f5f5f7;--muted:#a1a1a6;--good:#62e6a2;--warn:#ffd166;--bad:#ff6878;--shadow:0 28px 90px rgba(0,0,0,.42)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(900px 500px at 50% -180px,rgba(255,255,255,.105),transparent 62%),radial-gradient(700px 500px at 100% 15%,rgba(255,255,255,.035),transparent 65%),var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",sans-serif;min-height:100vh;letter-spacing:-.012em}a{text-decoration:none;color:inherit}.nav{position:sticky;top:0;z-index:50;background:rgba(5,5,5,.72);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-bottom:1px solid rgba(255,255,255,.075)}.navin{max-width:1180px;margin:auto;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{font-weight:800;letter-spacing:-.055em;font-size:23px}.brandmark{display:inline-grid;place-items:center;width:31px;height:31px;margin-right:8px;border-radius:9px;background:#f5f5f7;color:#050505;font-size:14px;font-weight:900;box-shadow:0 5px 18px rgba(255,255,255,.08)}.navlinks{display:flex;gap:4px;flex-wrap:wrap}.navlinks a{padding:9px 11px;border-radius:11px;color:#b7b7bd;font-size:13px;transition:.2s ease}.navlinks a:hover{background:rgba(255,255,255,.07);color:#fff}.wrap{max-width:1180px;margin:auto;padding:24px 20px 80px}.hero{min-height:68vh;display:grid;place-items:center;text-align:center;padding:80px 0 50px}.hero h1{font-size:clamp(76px,14vw,155px);line-height:.78;margin:18px 0;letter-spacing:-.1em;background:linear-gradient(180deg,#fff 8%,#d7d7da 45%,#5d5d63 100%);-webkit-background-clip:text;background-clip:text;color:transparent}.hero p{max-width:690px;color:var(--muted);font-size:18px;line-height:1.65;margin:0 auto 28px}.badge,.pill{display:inline-block;border:1px solid var(--line);background:rgba(255,255,255,.045);padding:7px 11px;border-radius:999px;color:#c9c9ce;font-size:12px;backdrop-filter:blur(12px)}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.grid2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.card{background:linear-gradient(145deg,rgba(255,255,255,.075),rgba(255,255,255,.028));border:1px solid var(--line);border-radius:26px;padding:22px;box-shadow:var(--shadow);transition:transform .28s ease,border-color .28s ease,background .28s ease;animation:fadeUp .45s ease both}.card:hover{transform:translateY(-3px);border-color:var(--line2);background:linear-gradient(145deg,rgba(255,255,255,.09),rgba(255,255,255,.035))}.card h2,.card h3{margin:0 0 9px;letter-spacing:-.035em}.muted{color:var(--muted)}.small{font-size:13px;color:var(--muted)}.btn{display:inline-flex;align-items:center;justify-content:center;border:1px solid transparent;cursor:pointer;padding:11px 16px;border-radius:14px;background:#f5f5f7;color:#080808;font-weight:750;transition:transform .2s ease,opacity .2s ease,background .2s ease;box-shadow:0 8px 24px rgba(0,0,0,.18)}.btn:hover{transform:translateY(-1px)}.btn:active{transform:scale(.98)}.btn:disabled{opacity:.55;cursor:not-allowed;transform:none}.btn.dark{background:rgba(255,255,255,.075);color:#fff;border-color:var(--line);box-shadow:none}.btn.good{background:rgba(45,180,105,.12);color:#9bf2bf;border-color:rgba(98,230,162,.25);box-shadow:none}.btn.danger{background:rgba(255,70,90,.11);color:#ffb5bd;border-color:rgba(255,104,120,.23);box-shadow:none}.btn.accent{background:linear-gradient(180deg,#fff,#d7d7da);color:#080808}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}.section{padding:30px 0}.auth{min-height:80vh;display:grid;place-items:center}.authbox{width:min(470px,100%)}.form{display:grid;gap:13px}.label{font-size:13px;color:#b5b5bb;margin-bottom:5px}input,textarea,select{width:100%;padding:13px 14px;background:rgba(255,255,255,.045);color:#fff;border:1px solid #2a2a2e;border-radius:14px;outline:none;transition:border-color .2s,background .2s,box-shadow .2s}input::placeholder,textarea::placeholder{color:#68686e}input:focus,textarea:focus,select:focus{border-color:#707076;background:rgba(255,255,255,.06);box-shadow:0 0 0 4px rgba(255,255,255,.045)}textarea{min-height:125px;resize:vertical}.flash{padding:13px 15px;border:1px solid #303035;background:rgba(255,255,255,.055);border-radius:15px;margin:10px 0;backdrop-filter:blur(14px)}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid #29292e;vertical-align:top}.tablewrap{overflow:auto}.kpi{font-size:38px;font-weight:850;letter-spacing:-.065em}.footer{padding:50px 0;color:#606066;text-align:center}.empty{text-align:center;padding:45px;color:var(--muted);border:1px dashed #2b2b31;border-radius:20px}.status-good{color:var(--good)}.status-warn{color:var(--warn)}.status-bad{color:var(--bad)}.online{color:var(--good)}.offline{color:var(--bad)}.icon{font-size:30px;margin-bottom:12px}.resource-meta{display:flex;gap:7px;flex-wrap:wrap;margin:10px 0}.danger-zone{border-color:#5a252d}.notice{padding:16px;border-radius:17px;background:rgba(255,255,255,.045);border:1px solid var(--line);line-height:1.55}.chat{display:grid;gap:9px;margin-top:15px}.bubble{padding:13px 15px;border-radius:17px;background:rgba(255,255,255,.045);border:1px solid #24242a}.mine{border-color:#34343b}.offline-page{min-height:78vh;display:grid;place-items:center;text-align:center}.offline-page h1{font-size:clamp(48px,8vw,92px);letter-spacing:-.07em;margin:12px 0} .community-launch{position:relative;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:20px 22px;min-height:92px;overflow:hidden;background:linear-gradient(135deg,rgba(255,255,255,.10),rgba(255,255,255,.035));border:1px solid rgba(255,255,255,.13);border-radius:24px;box-shadow:0 20px 55px rgba(0,0,0,.28);transition:transform .25s ease,border-color .25s ease,background .25s ease}.community-launch:before{content:"";position:absolute;inset:-80px auto auto -50px;width:180px;height:180px;background:rgba(255,255,255,.07);filter:blur(35px);border-radius:50%}.community-launch:hover{transform:translateY(-3px);border-color:rgba(255,255,255,.24);background:linear-gradient(135deg,rgba(255,255,255,.14),rgba(255,255,255,.045))}.student-presence{display:inline-flex;align-items:center;gap:8px}.presence-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex:0 0 8px}.presence-dot.is-online{background:#32d74b;box-shadow:0 0 9px rgba(50,215,75,.55)}.presence-dot.is-offline{background:#ff453a}.community-icon{position:relative;z-index:1;width:50px;height:50px;display:grid;place-items:center;border-radius:16px;background:#f5f5f7;color:#080808;font-size:22px;box-shadow:0 8px 25px rgba(255,255,255,.10)}.community-copy{position:relative;z-index:1;flex:1}.community-copy h3{margin:0 0 4px;font-size:18px}.community-copy p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.community-arrow{position:relative;z-index:1;width:38px;height:38px;border:1px solid var(--line);border-radius:12px;display:grid;place-items:center;color:#fff;background:rgba(255,255,255,.06);font-size:18px}.chat-composer{position:sticky;bottom:14px;padding:14px;border-radius:20px;background:rgba(10,10,12,.78);border:1px solid var(--line);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 18px 50px rgba(0,0,0,.35)}@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}@media(max-width:850px){.grid,.grid2,.two{grid-template-columns:1fr}.navlinks{display:none}.wrap{padding:15px}.hero{padding:55px 0 35px}.hero h1{font-size:74px}.card{border-radius:22px}}
"""


def layout(title, body, admin=False):
    if admin:
        links = '<a href="/admin/panel">Dashboard</a><a href="/admin/students">Students</a><a href="/admin/resources">Resources</a><a href="/admin/problems">Problems</a><a href="/admin/chats">Problem Chats</a><a href="/admin/community-chat">💬 Community Chat</a><a href="/admin/notifications">Alerts</a><a href="/admin/password-requests">Password Requests</a><a href="/admin/settings">Settings</a><a href="/admin/password">Security</a><a href="/admin/logout">Logout</a>'
    elif session.get("student_db_id"):
        links = '<a href="/dashboard">Home</a><a href="/academics">Academics</a><a href="/issues">Campus</a><a href="/community">Community</a><a href="/chat">💬 Chat</a><a href="/account/password">Password</a><a href="/logout">Logout</a>'
    else:
        links = '<a href="/login">Student Login</a><a href="/register">Register</a><a href="/admin">Admin</a>'
    flashes = "".join(f'<div class="flash">{esc(m)}</div>' for m in session.pop("_flashes", []))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#070809"><title>{esc(title)} · VYBE</title><style>{CSS}</style></head><body><div class="nav"><div class="navin"><a class="brand" href="/"><span class="brandmark">V</span>VYBE</a><div class="navlinks">{links}</div></div></div><main class="wrap">{flashes}{body}</main><footer class="footer">VYBE · Your Campus. Your Community. Your Space.</footer><script>(function(){{document.addEventListener("click",function(e){{const btn=e.target.closest(".toggle-password");if(!btn)return;e.preventDefault();e.stopPropagation();const id=btn.getAttribute("data-target");const el=id?document.getElementById(id):null;if(!el)return;const show=el.type==="password";el.type=show?"text":"password";btn.textContent=show?"Hide":"View";btn.setAttribute("aria-label",show?"Hide password":"View password");btn.setAttribute("title",show?"Hide password":"View password");}});}})();</script></body></html>'''


@app.route("/offline")
def offline():
    return layout("Offline", '''<section class="offline-page"><div><div class="badge">VYBE STATUS</div><h1>🔴 OFFLINE</h1><p class="muted">VYBE is temporarily unavailable. Please check back later.</p><p><a class="btn dark" href="/admin">Admin access</a></p></div></section>''')


@app.route("/")
def home():
    if session.get("student_db_id"):
        return redirect(url_for("dashboard"))
    if session.get("admin_authenticated"):
        return redirect(url_for("admin_panel"))
    body = '''<section class="hero"><div><div class="badge">Student-powered campus operating system</div><h1>VYBE</h1><p>Your Campus. Your Community. Your Space.</p><div class="actions" style="justify-content:center"><a class="btn accent" href="/login">Enter VYBE →</a><a class="btn dark" href="/register">Request access</a></div></div></section><section class="grid"><div class="card"><div class="icon">📚</div><h2>Academics</h2><p class="muted">Notes, PYQs, syllabus, assignments and study material in one place.</p></div><div class="card"><div class="icon">🏫</div><h2>Campus</h2><p class="muted">Report real campus problems and follow their status.</p></div><div class="card"><div class="icon">💬</div><h2>Community</h2><p class="muted">Students help students with immediate, visible solutions.</p></div></section>'''
    return layout("Welcome", body)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        sid = request.form.get("student_id", "").strip()[:80]
        password = request.form.get("password", "")
        if len(name) < 2 or len(sid) < 2 or len(password) < 6:
            flash("Enter a valid name, unique Student ID and a password of at least 6 characters.")
            return redirect(url_for("register"))
        con = db()
        try:
            password_hash_value = hash_password(password)
            con.execute(
                "INSERT INTO students(name,student_id,password_hash,status,created_at,last_seen) VALUES(?,?,?,?,?,?)",
                (name, sid, password_hash_value, "pending", now(), None),
            )
            new_student_id = con.execute("SELECT id FROM students WHERE student_id=?", (sid,)).fetchone()["id"]
            con.commit()
            create_admin_notification(
                "entry_request",
                "New VYBE entry request",
                f"🔔 New VYBE entry request\nName: {name}\nStudent ID: {sid}\nThe student is waiting for admin approval.",
                new_student_id,
            )
            flash("Registration submitted. Your account is pending admin approval.")
        except Exception:
            con.rollback()
            flash("That Student ID is already registered, or could not be saved.")
        finally:
            con.close()
        return redirect(url_for("login"))
    body = '''<div class="auth"><div class="card authbox"><div class="badge">NEW STUDENT</div><h1>Request access.</h1><p class="muted">Create your student account with your name, unique Student ID and personal password.</p><form class="form" method="post"><div><div class="label">Full name</div><input name="name" required maxlength="80" autocomplete="name" placeholder="Your full name"></div><div><div class="label">Student ID</div><input name="student_id" required maxlength="80" autocomplete="username" placeholder="Your unique Student ID"></div><div><div class="label">Personal password</div><div style="position:relative"><input id="registerPassword" type="password" name="password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="Create your password"><button type="button" class="btn dark toggle-password" data-target="registerPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><button class="btn accent" type="submit">Request access →</button></form><p class="small">Already approved? <a href="/login" style="text-decoration:underline">Student login</a></p></div></div>'''
    return layout("Register", body)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        sid = request.form.get("student_id", "").strip()
        password = request.form.get("password", "")
        if not sid or not password:
            flash("Student ID and password are required.")
            return redirect(url_for("login"))
        con = db()
        row = con.execute("SELECT id,status,password_hash FROM students WHERE student_id=?", (sid,)).fetchone()
        if not row:
            con.close(); flash("Student ID or password is incorrect."); return redirect(url_for("login"))
        if row["status"] == "pending":
            con.close(); flash("Your registration is still pending admin approval."); return redirect(url_for("login"))
        if row["status"] == "blocked":
            con.close(); flash("Your student access is currently blocked."); return redirect(url_for("login"))
        if not check_password(password, row["password_hash"]):
            con.close(); flash("Student ID or password is incorrect."); return redirect(url_for("login"))
        stamp = now()
        con.execute("UPDATE students SET last_login=?, last_seen=? WHERE id=?", (stamp, stamp, row["id"])); con.commit(); con.close()
        session.clear(); session["student_db_id"] = row["id"]
        return redirect(url_for("dashboard"))
    body = '''<div class="auth"><div class="card authbox"><div class="badge">STUDENT LOGIN</div><h1>Welcome back.</h1><p class="muted">Sign in with your Student ID and personal password.</p><form class="form" method="post"><div><div class="label">Student ID</div><input name="student_id" required maxlength="80" autocomplete="username" placeholder="Your Student ID"></div><div><div class="label">Password</div><div style="position:relative"><input id="loginPassword" type="password" name="password" required autocomplete="current-password" placeholder="Your password"><button type="button" class="btn dark toggle-password" data-target="loginPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><button class="btn accent" type="submit">Enter VYBE →</button></form><div class="actions"><a class="btn dark" href="/forgot-password">Forgot password?</a></div><p class="small">New student? <a href="/register" style="text-decoration:underline">Request access</a></p></div></div>'''
    return layout("Student Login", body)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        sid = request.form.get("student_id", "").strip()[:80]
        name = request.form.get("name", "").strip()[:80]
        if not sid or not name:
            flash("Enter your full name and Student ID.")
            return redirect(url_for("forgot_password"))
        con = db()
        try:
            student = con.execute("SELECT id,name,status FROM students WHERE student_id=?", (sid,)).fetchone()
            if not student or student["name"].strip().lower() != name.lower() or student["status"] == "blocked":
                flash("If the account is eligible, the password-change request has been sent to the admin.")
                return redirect(url_for("forgot_password"))
            existing = con.execute("SELECT id,status FROM password_reset_requests WHERE student_id=? AND status IN ('pending','approved') AND (expires_at IS NULL OR expires_at>?) ORDER BY id DESC LIMIT 1", (student["id"], now())).fetchone()
            if existing:
                session["password_reset_request_id"] = existing["id"]
                flash("Admin has already approved your request. You can change your password below." if existing["status"] == "approved" else "Your password-change request is waiting for admin approval.")
                return redirect(url_for("forgot_password"))
            try:
                con.execute("INSERT INTO password_reset_requests(student_id,status,requested_at) VALUES(?,?,?)", (student["id"], "pending", now()))
                request_row = con.execute("SELECT id FROM password_reset_requests WHERE student_id=? AND status='pending' ORDER BY id DESC LIMIT 1", (student["id"],)).fetchone()
                if not request_row:
                    raise RuntimeError("Password reset request could not be created")
                request_id = request_row["id"]
                con.commit()
            except Exception:
                con.rollback()
                flash("We couldn't start the password-change request right now. Please try again in a moment.")
                return redirect(url_for("forgot_password"))
            session["password_reset_request_id"] = request_id
            try:
                create_admin_notification("password_reset", "Password change request", f"Password change request\nName: {student['name']}\nStudent ID: {sid}", student["id"])
            except Exception:
                app.logger.exception("Non-fatal password-reset notification failure")
            flash("Request sent successfully. Keep this page open while the admin reviews it.")
            return redirect(url_for("forgot_password"))
        finally:
            con.close()

    request_id = session.get("password_reset_request_id")
    waiting_ui = ""
    if request_id:
        waiting_ui = """
        <div class="notice" id="resetStatusBox" style="margin-top:16px">
          <strong id="resetStatusTitle">Waiting for admin approval...</strong>
          <p class="small" id="resetStatusText" style="margin:7px 0 0">Your request has been sent. Keep this page open; VYBE will automatically update it when the admin approves you.</p>
        </div>
        <div id="inlineResetForm" style="display:none;margin-top:16px">
          <div class="card" style="padding:18px">
            <div class="badge">APPROVED</div>
            <h2>Admin approved your request</h2>
            <p class="muted">You can now change your password. Create a new password below. Your existing password is never shown to the admin.</p>
            <form class="form" method="post" action="/reset-password">
              <input type="hidden" name="request_id" value="{rid}">
              <div><div class="label">New password</div><div style="position:relative"><input id="autoNewPassword" type="password" name="password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="Create your new password"><button type="button" class="btn dark toggle-password" data-target="autoNewPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div>
              <div><div class="label">Confirm new password</div><div style="position:relative"><input id="autoConfirmPassword" type="password" name="confirm_password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="Confirm your new password"><button type="button" class="btn dark toggle-password" data-target="autoConfirmPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div>
              <button class="btn accent" type="submit">Change password</button>
            </form>
          </div>
        </div>
        <script>
        (()=>{
          const requestId = {rid};
          const statusTitle = document.getElementById("resetStatusTitle");
          const statusText = document.getElementById("resetStatusText");
          const form = document.getElementById("inlineResetForm");
          let timer = null;
          async function checkResetStatus(){
            try{
              const r = await fetch(`/forgot-password/status?request_id=${requestId}`, {credentials:"same-origin", cache:"no-store"});
              if(!r.ok) return;
              const j = await r.json();
              if(j.status === "approved"){
                statusTitle.textContent = "Admin approved your request";
                statusText.textContent = "You can now change your password using the form below.";
                form.style.display = "block";
                if(timer) clearInterval(timer);
              } else if(j.status === "rejected"){
                statusTitle.textContent = "Password-change request rejected";
                statusText.textContent = "Please submit a new request if you still need to change your password.";
                if(timer) clearInterval(timer);
              } else if(j.status === "used" || j.status === "expired" || j.status === "invalid"){
                statusTitle.textContent = "This reset request is no longer active";
                statusText.textContent = "Please submit a new password-change request.";
                if(timer) clearInterval(timer);
              }
            }catch(e){ }
          }
          checkResetStatus();
          timer=setInterval(checkResetStatus, 2500);
        })();
        </script>
        """.format(rid=int(request_id))
    body = """<div class="auth"><div class="card authbox"><div class="badge">PASSWORD RECOVERY</div><h1>Need a new password?</h1><p class="muted">Enter your name and Student ID to request a password change. After admin approval, this page will unlock the new-password form automatically.</p><form class="form" method="post"><div><div class="label">Full name</div><input name="name" required maxlength="80" autocomplete="name" placeholder="Your full name"></div><div><div class="label">Student ID</div><input name="student_id" required maxlength="80" autocomplete="username" placeholder="Your Student ID"></div><button class="btn accent" type="submit">Ask admin for approval</button></form>""" + waiting_ui + """<div class="actions"><a class="btn dark" href="/login">Back to login</a></div></div></div>"""
    return layout("Forgot Password", body)


@app.route("/forgot-password/status")
def forgot_password_status():
    request_id = request.args.get("request_id", "").strip()
    if not request_id.isdigit():
        return jsonify({"status": "invalid"}), 400
    session_request_id = session.get("password_reset_request_id")
    if session_request_id is None or int(session_request_id) != int(request_id):
        return jsonify({"status": "invalid"}), 403
    con = db()
    try:
        row = con.execute("SELECT id,status,expires_at FROM password_reset_requests WHERE id=?", (int(request_id),)).fetchone()
        if not row:
            return jsonify({"status": "invalid"}), 404
        if row["status"] == "approved":
            return jsonify({"status": "approved"})
        if row["status"] in ("rejected", "used", "expired"):
            return jsonify({"status": row["status"]})
        return jsonify({"status": "pending"})
    finally:
        con.close()


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    request_id = session.get("password_reset_request_id")
    if not request_id:
        flash("Please request a password change first.")
        return redirect(url_for("forgot_password"))
    con = db()
    try:
        row = con.execute("SELECT r.id,r.student_id,r.status,r.expires_at,s.status AS student_status FROM password_reset_requests r JOIN students s ON s.id=r.student_id WHERE r.id=?", (int(request_id),)).fetchone()
        if not row or row["status"] != "approved" or row["student_status"] == "blocked":
            flash("Your password-change request has not been approved yet or is no longer active.")
            return redirect(url_for("forgot_password"))
        if row["expires_at"] and row["expires_at"] <= now():
            con.execute("UPDATE password_reset_requests SET status='expired' WHERE id=?", (row["id"],))
            con.commit()
            session.pop("password_reset_request_id", None)
            flash("Your password-change approval has expired. Please submit a new request.")
            return redirect(url_for("forgot_password"))
        if request.method == "POST":
            posted_request_id = request.form.get("request_id", "").strip()
            new_password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if posted_request_id != str(request_id):
                flash("This password-change session is invalid. Please start again.")
                return redirect(url_for("forgot_password"))
            if len(new_password) < 6 or new_password != confirm:
                flash("New passwords must match and be at least 6 characters.")
                return redirect(url_for("forgot_password"))
            con.execute("UPDATE students SET password_hash=? WHERE id=?", (hash_password(new_password), row["student_id"]))
            con.execute("UPDATE password_reset_requests SET status='used', used_at=? WHERE id=?", (now(), row["id"]))
            con.commit()
            session.pop("password_reset_request_id", None)
            flash("Password changed successfully. You can now log in with your new password.")
            return redirect(url_for("login"))
    finally:
        con.close()
    body = """<div class="auth"><div class="card authbox"><div class="badge">APPROVED RESET</div><h1>Set a new password.</h1><p class="muted">Admin has approved your password-change request. Create your new password below. Your existing password is never visible to the admin.</p><form class="form" method="post"><input type="hidden" name="request_id" value="{rid}"><div><div class="label">New password</div><div style="position:relative"><input id="resetPassword" type="password" name="password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="New password"><button type="button" class="btn dark toggle-password" data-target="resetPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><div><div class="label">Confirm new password</div><div style="position:relative"><input id="resetConfirmPassword" type="password" name="confirm_password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="Confirm new password"><button type="button" class="btn dark toggle-password" data-target="resetConfirmPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><button class="btn accent" type="submit">Change password</button></form><p class="small"><a href="/forgot-password" style="text-decoration:underline">Back to password recovery</a></p></div></div>""".format(rid=int(request_id))
    return layout("Reset Password", body)


@app.route("/account/password", methods=["GET", "POST"])
@student_required
def account_password():
    con = db()
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        row = con.execute("SELECT password_hash FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
        if not check_password(current, row["password_hash"]):
            con.close(); flash("Current password is incorrect."); return redirect(url_for("account_password"))
        if len(new_password) < 6 or new_password != confirm:
            con.close(); flash("New passwords must match and be at least 6 characters."); return redirect(url_for("account_password"))
        con.execute("UPDATE students SET password_hash=? WHERE id=?", (hash_password(new_password), session["student_db_id"]))
        con.commit(); con.close(); flash("Password changed successfully."); return redirect(url_for("dashboard"))
    con.close()
    body='''<div class="auth"><div class="card authbox"><div class="badge">ACCOUNT SECURITY</div><h1>Change password.</h1><p class="muted">Because you are signed in, enter your current password to authorize the change.</p><form class="form" method="post"><div><div class="label">Current password</div><div style="position:relative"><input id="currentPassword" type="password" name="current_password" required autocomplete="current-password" placeholder="Current password"><button type="button" class="btn dark toggle-password" data-target="currentPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><div><div class="label">New password</div><div style="position:relative"><input id="changePassword" type="password" name="new_password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="New password"><button type="button" class="btn dark toggle-password" data-target="changePassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><div><div class="label">Confirm new password</div><div style="position:relative"><input id="changeConfirmPassword" type="password" name="confirm_password" required minlength="6" maxlength="128" autocomplete="new-password" placeholder="Confirm new password"><button type="button" class="btn dark toggle-password" data-target="changeConfirmPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div></div><button class="btn accent" type="submit">Update password →</button></form></div></div>'''
    return layout("Change Password", body)


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))


@app.route("/dashboard")
@student_required
def dashboard():
    con = db()
    s = con.execute("SELECT name FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
    counts = {
        "resources": con.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"],
        "issues": con.execute("SELECT COUNT(*) AS c FROM issues WHERE student_id=?", (session["student_db_id"],)).fetchone()["c"],
        "solutions": con.execute("SELECT COUNT(*) AS c FROM solutions").fetchone()["c"],
    }
    drive = setting(con, "google_drive_url", DRIVE_URL)
    wa = setting(con, "whatsapp_link", "")
    con.close()
    body = f'''<section class="section"><div class="badge">STUDENT SPACE</div><h1>Hey, {esc(s["name"])}.</h1><p class="muted">Everything your campus needs, without exposing private Student IDs.</p></section><section class="grid"><a class="card" href="/academics"><div class="kpi">{counts["resources"]}</div><h3>Academics</h3><p class="muted">Notes, PYQs, syllabus & study material</p></a><a class="card" href="/issues"><div class="kpi">{counts["issues"]}</div><h3>My campus reports</h3><p class="muted">Track the problems you reported</p></a><a class="card" href="/community"><div class="kpi">{counts["solutions"]}</div><h3>Community</h3><p class="muted">Help solve campus problems</p></a></section><section class="section"><a class="community-launch" href="/chat"><div class="community-icon">💬</div><div class="community-copy"><h3>Community Chat</h3><p>Talk with your campus community · names only, Student IDs stay private.</p></div><div class="community-arrow">→</div></a></section><section class="section grid2"><div class="card"><h2>☁️ Google Drive</h2><p class="muted">Open the live shared academic folder.</p><a class="btn accent" target="_blank" rel="noopener noreferrer" href="{esc(drive)}">Open Google Drive →</a></div><div class="card"><h2>💬 WhatsApp Community</h2><p class="muted">Academic material shared through the configured community.</p>{f'<a class="btn dark" target="_blank" rel="noopener noreferrer" href="{esc(wa)}">Open WhatsApp →</a>' if valid_url(wa) else '<span class="pill">Not configured yet</span>'}</div></section>'''
    return layout("Dashboard", body)


@app.route("/academics")
@student_required
def academics():
    q = request.args.get("q", "").strip()[:100]
    course = request.args.get("course", "").strip()[:100]
    semester = request.args.get("semester", "").strip()[:100]
    subject = request.args.get("subject", "").strip()[:100]
    con = db()
    sql = "SELECT * FROM resources WHERE 1=1"
    params = []
    for field, value in (("title", q), ("subject", q), ("course", q)):
        pass
    if q:
        sql += " AND (title LIKE ? OR subject LIKE ? OR course LIKE ? OR description LIKE ?)"
        params += [f"%{q}%"] * 4
    if course:
        sql += " AND course=?"; params.append(course)
    if semester:
        sql += " AND semester=?"; params.append(semester)
    if subject:
        sql += " AND subject=?"; params.append(subject)
    sql += " ORDER BY id DESC"
    rows = con.execute(sql, params).fetchall()
    courses = [r["course"] for r in con.execute("SELECT DISTINCT course FROM resources ORDER BY course").fetchall()]
    semesters = [r["semester"] for r in con.execute("SELECT DISTINCT semester FROM resources ORDER BY semester").fetchall()]
    subjects = [r["subject"] for r in con.execute("SELECT DISTINCT subject FROM resources ORDER BY subject").fetchall()]
    drive = setting(con, "google_drive_url", DRIVE_URL)
    con.close()
    cards = ""
    for r in rows:
        file_link = f'<a class="btn dark" href="/resource/{r["id"]}">Open file</a>' if r["file_name"] else '<span class="pill">Drive / link resource</span>'
        cards += f'''<div class="card"><div class="resource-meta"><span class="pill">{esc(r["resource_type"])}</span><span class="pill">{esc(r["semester"])}</span></div><h3>{esc(r["title"])}</h3><p class="small">{esc(r["course"])} · {esc(r["subject"])}</p><p class="muted">{esc(r["description"])}</p>{file_link}</div>'''
    body = f'''<section class="section"><div class="badge">ACADEMICS</div><h1>Study smarter.</h1><p class="muted">Search by resource, course, semester or subject.</p><div class="card"><form class="form" method="get"><input name="q" value="{esc(q)}" placeholder="Search notes, PYQs, assignments..."><div class="two"><select name="course"><option value="">All courses</option>{''.join(f'<option {"selected" if x==course else ""}>{esc(x)}</option>' for x in courses)}</select><select name="semester"><option value="">All semesters</option>{''.join(f'<option {"selected" if x==semester else ""}>{esc(x)}</option>' for x in semesters)}</select></div><select name="subject"><option value="">All subjects</option>{''.join(f'<option {"selected" if x==subject else ""}>{esc(x)}</option>' for x in subjects)}</select><button class="btn accent">Search</button></form></div></section><section class="section grid">{cards or '<div class="empty">No matching resources.</div>'}</section><section class="section"><div class="card"><h2>☁️ Google Drive</h2><p class="muted">This is the live academic folder configured for VYBE.</p><a class="btn accent" target="_blank" rel="noopener noreferrer" href="{esc(drive)}">Open shared academic folder →</a></div></section>'''
    return layout("Academics", body)


@app.route("/resource/<int:rid>")
@student_required
def resource(rid):
    con = db(); r = con.execute("SELECT file_name FROM resources WHERE id=?", (rid,)).fetchone(); con.close()
    if not r or not r["file_name"]: abort(404)
    return send_from_directory(UPLOAD_DIR, r["file_name"], as_attachment=False)


@app.route("/issues", methods=["GET", "POST"])
@student_required
def issues():
    con = db()
    if request.method == "POST":
        category = request.form.get("category", "Other")
        title = request.form.get("title", "").strip()[:120]
        desc = request.form.get("description", "").strip()[:2000]
        if category not in CATEGORIES or not title or not desc:
            con.close(); flash("Please complete the problem report."); return redirect(url_for("issues"))
        con.execute("INSERT INTO issues(student_id,category,title,description,status,created_at) VALUES(?,?,?,?,?,?)", (session["student_db_id"], category, title, desc, "Open", now()))
        student = con.execute("SELECT id,name,student_id FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
        con.commit(); con.close()
        create_admin_notification(
            "problem_report",
            "New campus problem",
            f"🐛 New VYBE problem report\\nName: {student['name']}\\nStudent ID: {student['student_id']}\\nTitle: {title}",
            student["id"],
        )
        flash("Campus problem reported."); return redirect(url_for("issues"))
    rows = con.execute("SELECT * FROM issues WHERE student_id=? ORDER BY id DESC", (session["student_db_id"],)).fetchall(); con.close()
    cards = "".join(f'<div class="card"><span class="pill">{esc(x["status"])}</span><h3>{esc(x["title"])}</h3><p class="small">{esc(x["category"])} · {esc(x["created_at"])}</p><p class="muted">{esc(x["description"])}</p><a class="btn dark" href="/community#problem-{x["id"]}">Open community chat →</a></div>' for x in rows)
    body = f'''<section class="section"><div class="badge">CAMPUS</div><h1>Fix what matters.</h1><p class="muted">Report Wi-Fi, systems, classrooms, electricity, facilities or anything else.</p><div class="two"><div class="card"><h2>Report a problem</h2><form class="form" method="post"><select name="category">{''.join(f'<option>{esc(c)}</option>' for c in CATEGORIES)}</select><input name="title" maxlength="120" placeholder="Short problem title" required><textarea name="description" maxlength="2000" placeholder="What is happening?" required></textarea><button class="btn accent">Submit report</button></form></div><div><h2>My reports</h2>{cards or '<div class="empty">No reports yet.</div>'}</div></div></section>'''
    return layout("Campus", body)


@app.route("/chat", methods=["GET", "POST"])
@student_required
def chat():
    con = db()
    enabled = setting(con, "community_chat_enabled", "1") == "1"
    if request.method == "POST":
        if not enabled:
            con.close()
            flash("Community Chat is currently disabled by the admin.")
            return redirect(url_for("chat"))
        text = request.form.get("message", "").strip()[:1500]
        if not text:
            con.close()
            flash("Please enter a message.")
            return redirect(url_for("chat"))
        con.execute("INSERT INTO community_messages(student_id,message,created_at) VALUES(?,?,?)", (session["student_db_id"], text, now()))
        con.commit()
        con.close()
        return redirect(url_for("chat") + "#latest")
    rows = con.execute("SELECT cm.*, s.name FROM community_messages cm JOIN students s ON s.id=cm.student_id ORDER BY cm.id ASC LIMIT 300").fetchall()
    me = con.execute("SELECT name FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
    con.close()
    if not enabled:
        body = '''<section class="section"><div class="badge">COMMUNITY CHAT</div><div class="card" style="margin-top:18px;text-align:center;padding:55px 25px"><div class="icon">💬</div><h1>Chat is offline.</h1><p class="muted">The administrator has temporarily disabled the community chat.</p></div></section>'''
        return layout("Community Chat", body)
    bubbles = ""
    for r in rows:
        mine = " mine" if r["student_id"] == session["student_db_id"] else ""
        bubbles += f'''<div class="bubble{mine}"><strong>{esc(r["name"])}</strong><div style="margin-top:5px;white-space:pre-wrap;word-break:break-word">{esc(r["message"])}</div><div class="small" style="margin-top:5px">{esc(r["created_at"])}</div></div>'''
    body = f'''<section class="section"><div class="badge">VYBE COMMUNITY CHAT</div><h1>Talk to the campus.</h1><p class="muted">Everyone can see the conversation. Only your registered name is shown — Student IDs and private account details stay hidden.</p></section><section class="section"><div class="card"><div id="chatMessages" class="chat" style="max-height:58vh;overflow:auto">{bubbles or '<div class="empty">No messages yet. Start the conversation.</div>'}<span id="latest"></span></div><form class="form chat-composer" method="post"><textarea name="message" maxlength="1500" placeholder="Write a message..." required style="min-height:88px"></textarea><button class="btn accent">Send message →</button></form><p class="small" style="margin-top:10px">Logged in as <strong>{esc(me["name"])}</strong></p></div></section><script>
const chatBox=document.getElementById('chatMessages');
function renderCommunityMessages(messages){{
  if(!chatBox)return;
  chatBox.innerHTML='';
  if(!messages.length){{chatBox.innerHTML='<div class="empty">No messages yet. Start the conversation.</div>';return;}}
  messages.forEach(m=>{{
    const b=document.createElement('div'); b.className='bubble';
    const n=document.createElement('strong'); n.textContent=m.name;
    const t=document.createElement('div'); t.style.cssText='margin-top:5px;white-space:pre-wrap;word-break:break-word'; t.textContent=m.message;
    const d=document.createElement('div'); d.className='small'; d.style.marginTop='5px'; d.textContent=m.created_at;
    b.append(n,t,d); chatBox.appendChild(b);
  }});
  chatBox.scrollTop=chatBox.scrollHeight;
}}
async function refreshCommunityChat(){{
  try{{const r=await fetch('/chat/messages',{{credentials:'same-origin',cache:'no-store'}});if(!r.ok)return;const j=await r.json();if(!j.enabled){{location.reload();return;}}renderCommunityMessages(j.messages);}}catch(e){{}}
}}
if(chatBox){{chatBox.scrollTop=chatBox.scrollHeight;setInterval(refreshCommunityChat,3000);}}
</script>'''
    return layout("Community Chat", body)


@app.route("/chat/messages")
@student_required
def chat_messages():
    con = db()
    enabled = setting(con, "community_chat_enabled", "1") == "1"
    rows = con.execute("SELECT cm.id, cm.student_id, cm.message, cm.created_at, s.name FROM community_messages cm JOIN students s ON s.id=cm.student_id ORDER BY cm.id ASC LIMIT 300").fetchall()
    con.close()
    return jsonify({"enabled": enabled, "messages": [{"id": r["id"], "name": r["name"], "message": r["message"], "created_at": r["created_at"]} for r in rows]})


@app.route("/community", methods=["GET", "POST"])
@student_required
def community():
    con = db()
    if request.method == "POST":
        try:
            iid = int(request.form.get("issue_id", "0")); text = request.form.get("text", "").strip()[:1500]
        except ValueError:
            iid, text = 0, ""
        issue = con.execute("SELECT id FROM issues WHERE id=?", (iid,)).fetchone()
        if not issue or not text:
            con.close(); flash("Could not post that solution."); return redirect(url_for("community"))
        # No moderation flag exists: a solution becomes visible immediately.
        con.execute("INSERT INTO solutions(issue_id,student_id,text,created_at) VALUES(?,?,?,?)", (iid, session["student_db_id"], text, now()))
        con.commit(); con.close(); flash("Solution posted to the community."); return redirect(url_for("community"))
    issues_rows = con.execute("SELECT i.*, s.name AS reporter_name FROM issues i JOIN students s ON s.id=i.student_id ORDER BY i.id DESC LIMIT 80").fetchall()
    solutions = con.execute("SELECT so.*, s.name AS author_name FROM solutions so JOIN students s ON s.id=so.student_id ORDER BY so.id ASC").fetchall()
    by_issue = {}
    for s in solutions: by_issue.setdefault(s["issue_id"], []).append(s)
    blocks = ""
    for i in issues_rows:
        sols = by_issue.get(i["id"], [])
        sol_html = "".join(f'<div class="bubble"><strong>{esc(s["author_name"])}</strong><div>{esc(s["text"])}</div><div class="small">{esc(s["created_at"])}</div></div>' for s in sols)
        other_solution = any(s["student_id"] != session["student_db_id"] for s in sols)
        accept = ""
        if i["student_id"] == session["student_db_id"] and other_solution:
            accept = f'<form method="post" action="/community/problem/{i["id"]}/accept" onsubmit="return confirm(\'Accept a solution? This deletes the problem and its entire chat.\')"><button class="btn good">✓ Accept solution &amp; delete chat</button></form>'
        blocks += f'''<div class="card" id="problem-{i["id"]}"><div class="resource-meta"><span class="pill">{esc(i["category"])}</span><span class="pill">{esc(i["status"])}</span></div><h2>{esc(i["title"])}</h2><p class="muted">{esc(i["description"])}</p><p class="small">Reported by {esc(i["reporter_name"])} · {esc(i["created_at"])}</p><div class="chat">{sol_html or '<div class="empty">No solutions yet. Be the first to help.</div>'}</div><form class="form" method="post" style="margin-top:14px"><input type="hidden" name="issue_id" value="{i["id"]}"><textarea name="text" maxlength="1500" placeholder="Suggest a practical solution..." required></textarea><button class="btn dark">Post solution</button></form>{accept}</div>'''
    con.close()
    body = f'''<section class="section"><div class="badge">COMMUNITY</div><h1>Students solve together.</h1><p class="muted">Solutions are visible immediately. There is no admin moderation. Only the original reporter can accept a solution, and the accept button appears after another student has contributed.</p></section><section class="section" style="display:grid;gap:16px">{blocks or '<div class="empty">No campus problems have been reported yet.</div>'}</section>'''
    return layout("Community", body)


@app.route("/community/problem/<int:iid>/accept", methods=["POST"])
@student_required
def accept_solution(iid):
    con = db()
    issue = con.execute("SELECT student_id FROM issues WHERE id=?", (iid,)).fetchone()
    if not issue or issue["student_id"] != session["student_db_id"]:
        con.close(); abort(403)
    other = con.execute("SELECT 1 FROM solutions WHERE issue_id=? AND student_id<>? LIMIT 1", (iid, session["student_db_id"])).fetchone()
    if not other:
        con.close(); abort(403)
    # CASCADE handles dependent solutions before the issue is removed.
    con.execute("DELETE FROM issues WHERE id=?", (iid,)); con.commit(); con.close()
    flash("Problem solved. The problem and its entire community chat were deleted.")
    return redirect(url_for("community"))


# ---------------------------------------------------------------------------
# Admin authentication and control center
# ---------------------------------------------------------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        con = db()
        stored = admin_password_hash(con)
        passkey_count = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
        ok = check_password(password, stored)
        record_admin_login(con, ok, "login")
        con.commit()
        con.close()
        if ok:
            session.clear()
            session["admin_authenticated"] = True
            session["passkey_verified"] = False
            if passkey_count == 0:
                flash("Password verified. Register your first admin passkey to finish setup.")
                return redirect(url_for("admin_password"))
            return redirect(url_for("admin_verify"))
        flash("Incorrect admin password.")
    body = '''<div class="auth"><div class="card authbox"><div class="badge">PRIVATE CONTROL CENTER</div><h1>Admin access.</h1><p class="muted">Enter the admin password first. A registered passkey is required before the dashboard opens.</p><form class="form" method="post"><input type="password" name="password" required autocomplete="current-password" placeholder="Admin password"><button class="btn accent">Continue →</button></form></div></div>'''
    return layout("Admin Login", body)


@app.route("/admin/login-history")
@admin_required
def admin_login_history():
    con = db()
    rows = con.execute("SELECT logged_at_ist,success,event,ip_address,user_agent FROM admin_login_logs ORDER BY id DESC LIMIT 100").fetchall()
    con.close()
    items = ""
    for r in rows:
        state = '<span class="pill status-good">Success</span>' if r["success"] else '<span class="pill status-bad">Failed</span>'
        items += f'''<tr><td>{esc(r["logged_at_ist"])}</td><td>{state}</td><td>{esc(r["event"])}</td><td>{esc(r["ip_address"] or "—")}</td><td class="small">{esc(r["user_agent"] or "—")}</td></tr>'''
    body=f'''<section class="section"><div class="badge">SECURITY AUDIT</div><h1>Admin login history.</h1><p class="muted">Authentication attempts are recorded in IST. Passwords are never stored in this log.</p><div class="card tablewrap"><table><tr><th>Time (IST)</th><th>Result</th><th>Event</th><th>IP</th><th>Browser / device</th></tr>{items or '<tr><td colspan="5">No admin login activity yet.</td></tr>'}</table></div></section>'''
    return layout("Admin Login History", body, admin=True)


@app.route("/admin/logout")
def admin_logout():
    session.clear(); return redirect(url_for("home"))


@app.route("/admin/panel")
@admin_required
def admin_panel():
    con = db()
    stats = {
        "students": con.execute("SELECT COUNT(*) AS c FROM students").fetchone()["c"],
        "pending": con.execute("SELECT COUNT(*) AS c FROM students WHERE status='pending'").fetchone()["c"],
        "issues": con.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"],
        "resources": con.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"],
        "solutions": con.execute("SELECT COUNT(*) AS c FROM solutions").fetchone()["c"],
        "chats": con.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"],
        "alerts": con.execute("SELECT COUNT(*) AS c FROM notifications").fetchone()["c"],
        "community_messages": con.execute("SELECT COUNT(*) AS c FROM community_messages").fetchone()["c"],
    }
    online = setting(con, "vybe_online", "1") == "1"
    con.close()
    body = f'''<section class="section"><div class="badge">PRIVATE VYBE CONTROL CENTER</div><h1>Admin dashboard.</h1>
    <div class="grid">
      <a class="card" href="/admin/students"><div class="kpi">{stats["students"]}</div><h3>Students</h3><p class="muted">Manage all student accounts.</p></a>
      <a class="card" href="/admin/students#pending"><div class="kpi">{stats["pending"]}</div><h3>Pending</h3><p class="muted">Entry requests waiting for approval.</p></a>
      <a class="card" href="/admin/problems"><div class="kpi">{stats["issues"]}</div><h3>Problems</h3><p class="muted">View reports and update status.</p></a>
      <a class="card" href="/admin/resources"><div class="kpi">{stats["resources"]}</div><h3>Resources</h3><p class="muted">Add and remove academic material.</p></a>
      <a class="card" href="/admin/chats"><div class="kpi">{stats["chats"]}</div><h3>Problem chats</h3><p class="muted">Saved problem and solution history.</p></a>
      <a class="card" href="/admin/community-chat"><div class="kpi">{stats["community_messages"]}</div><h3>Community Chat</h3><p class="muted">Moderate the live student community chat.</p></a>
      <a class="card" href="/admin/notifications"><div class="kpi">{stats["alerts"]}</div><h3>Notifications</h3><p class="muted">Entry requests and admin alerts.</p></a>
    </div>
    <section class="section grid2">
      <div class="card"><h2>🌐 VYBE Public Status</h2><p class="{"online" if online else "offline"}"><strong>{"🟢 ONLINE" if online else "🔴 OFFLINE"}</strong></p>
      <p class="muted">When offline, student/public routes are blocked while admin routes remain accessible.</p>
      <form method="post" action="/admin/status">{('<button class="btn danger">🔴 Take VYBE Offline</button>' if online else '<button class="btn good">🟢 Bring VYBE Online</button>')}</form></div>
      <div class="card"><h2>🔐 Security</h2><p class="muted">Admin login requires password + passkey. Sensitive credential changes require a fresh passkey verification.</p><a class="btn dark" href="/admin/password">Open security center →</a></div>
    </section></section>'''
    return layout("Admin", body, admin=True)


@app.route("/admin/status", methods=["POST"])
@admin_required
def admin_status():
    con = db(); current = setting(con, "vybe_online", "1") == "1"; set_setting(con, "vybe_online", "0" if current else "1"); con.commit(); con.close()
    flash("VYBE is now offline." if current else "VYBE is now online.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/students")
@admin_required
def admin_students():
    con = db(); students = con.execute("SELECT id,name,student_id,status,created_at,last_login,last_seen FROM students ORDER BY id DESC").fetchall(); con.close()
    rows = ""
    for s in students:
        if s["status"] == "pending": action = f'<a class="btn good" href="/admin/student/{s["id"]}/approve">Approve</a>'
        elif s["status"] == "approved": action = f'<a class="btn danger" href="/admin/student/{s["id"]}/block">Block</a>'
        else: action = f'<a class="btn good" href="/admin/student/{s["id"]}/unblock">Unblock</a>'
        online = student_is_online(s["last_seen"]) if s["status"] == "approved" else False
        dot_class = "is-online" if online else "is-offline"
        dot_title = "Online" if online else "Offline"
        presence = f'<span class="presence-dot {dot_class}" title="{dot_title}"></span>'
        sid_num = s["id"]
        student_name = esc(s["name"])
        student_sid = esc(s["student_id"])
        student_status = esc(s["status"])
        created_at = esc(s["created_at"])
        rows += f'<tr><td><span class="student-presence">{presence}{student_name}</span></td><td>{student_sid}</td><td><span class="pill">{student_status}</span></td><td>{created_at}</td><td><div class="actions">{action}<a class="btn danger" href="/admin/student/{sid_num}/delete" onclick="return confirm(&quot;Delete this student and all dependent records?&quot;)">Delete</a></div></td></tr>'
    body = f'''<section class="section" id="pending"><h1>Students.</h1><p class="muted">Approve or block students using their name and Student ID. Student passwords are private and are never visible to admins.</p><div class="actions"><form method="post" action="/admin/students/delete-all" onsubmit="return confirm('Delete ALL students and their dependent records?')"><button class="btn danger">Delete all students</button></form></div><div class="card tablewrap"><table><thead><tr><th>Name / Presence</th><th>Student ID</th><th>Status</th><th>Registered</th><th>Actions</th></tr></thead><tbody>{rows or '<tr><td colspan="5">No students.</td></tr>'}</tbody></table></div></section>'''
    return layout("Students", body, admin=True)

@app.route("/admin/student/<int:sid>/<action>")
@admin_required
def student_action(sid, action):
    if action not in ("approve", "block", "unblock", "delete"): abort(400)
    con = db()
    if action == "delete":
        # Explicit dependent deletes make this safe on legacy schemas without CASCADE.
        con.execute("DELETE FROM solutions WHERE student_id=?", (sid,))
        con.execute("DELETE FROM solutions WHERE issue_id IN (SELECT id FROM issues WHERE student_id=?)", (sid,))
        con.execute("DELETE FROM issues WHERE student_id=?", (sid,))
        con.execute("DELETE FROM students WHERE id=?", (sid,))
    else:
        status = "approved" if action in ("approve", "unblock") else "blocked"
        con.execute("UPDATE students SET status=? WHERE id=?", (status, sid))
    con.commit(); con.close(); flash(f"Student {action}d." if action != "unblock" else "Student unblocked."); return redirect(url_for("admin_students"))


@app.route("/admin/students/delete-all", methods=["POST"])
@admin_required
def delete_all_students():
    con = db()
    # Explicit dependency order; works even where old tables lack ON DELETE CASCADE.
    con.execute("DELETE FROM solutions")
    con.execute("DELETE FROM issues")
    con.execute("DELETE FROM students")
    con.commit(); con.close(); flash("All students and dependent campus/community records were deleted."); return redirect(url_for("admin_students"))


@app.route("/admin/resources")
@admin_required
def admin_resources():
    con = db(); resources = con.execute("SELECT * FROM resources ORDER BY id DESC").fetchall(); con.close()
    rows = "".join(f'<tr><td>{esc(r["title"])}</td><td>{esc(r["resource_type"])}</td><td>{esc(r["course"])} · {esc(r["semester"])} · {esc(r["subject"])}</td><td>{esc(r["created_at"])}</td><td><a class="btn danger" href="/admin/resource/{r["id"]}/delete" onclick="return confirm(\'Delete this resource?\')">Delete</a></td></tr>' for r in resources)
    body = f'''<section class="section"><h1>Resources.</h1><div class="two"><div class="card"><h2>Add resource</h2><form class="form" method="post" action="/admin/resource" enctype="multipart/form-data"><input name="title" placeholder="Title" required><select name="resource_type"><option>Notes</option><option>Previous Year Questions</option><option>Syllabus</option><option>Assignments</option><option>Study material</option></select><div class="two"><input name="course" placeholder="Course" required><input name="semester" placeholder="Semester" required></div><input name="subject" placeholder="Subject" required><textarea name="description" placeholder="Description"></textarea><input type="file" name="file"><button class="btn accent">Add resource</button></form></div><div class="card"><h2>Academic folder</h2><p class="muted">Students see the live Drive folder inside Academics.</p><a class="btn dark" href="/admin/settings">Configure Drive / WhatsApp →</a></div></div><div class="section card tablewrap"><table><tr><th>Title</th><th>Type</th><th>Course / term / subject</th><th>Created</th><th>Action</th></tr>{rows or '<tr><td colspan="5">No resources.</td></tr>'}</table></div></section>'''
    return layout("Resources", body, admin=True)


@app.route("/admin/resource", methods=["POST"])
@admin_required
def add_resource():
    title=request.form.get("title","").strip()[:150]; typ=request.form.get("resource_type","Study material")[:80]; course=request.form.get("course","").strip()[:100]; sem=request.form.get("semester","").strip()[:100]; subject=request.form.get("subject","").strip()[:100]; desc=request.form.get("description","").strip()[:1000]
    f=request.files.get("file"); filename=None
    if f and f.filename:
        suffix=Path(f.filename).suffix.lower()
        if suffix not in ALLOWED_EXT: flash("That file type is not allowed."); return redirect(url_for("admin_resources"))
        filename=secrets.token_hex(16)+suffix; f.save(UPLOAD_DIR/filename)
    con=db(); con.execute("INSERT INTO resources(title,resource_type,course,semester,subject,description,file_name,created_at) VALUES(?,?,?,?,?,?,?,?)",(title,typ,course,sem,subject,desc,filename,now())); con.commit(); con.close(); flash("Resource added."); return redirect(url_for("admin_resources"))


@app.route("/admin/resource/<int:rid>/delete")
@admin_required
def delete_resource(rid):
    con=db(); r=con.execute("SELECT file_name FROM resources WHERE id=?",(rid,)).fetchone(); con.execute("DELETE FROM resources WHERE id=?",(rid,)); con.commit(); con.close()
    if r and r["file_name"]:
        try: (UPLOAD_DIR/r["file_name"]).unlink(missing_ok=True)
        except OSError: pass
    flash("Resource deleted."); return redirect(url_for("admin_resources"))


@app.route("/admin/problems")
@admin_required
def admin_problems():
    con=db(); rows=con.execute("SELECT i.*,s.name,s.student_id FROM issues i JOIN students s ON s.id=i.student_id ORDER BY i.id DESC").fetchall(); con.close()
    html_rows="".join(f'<tr><td>#{r["id"]}</td><td>{esc(r["name"])}</td><td>{esc(r["student_id"])}</td><td>{esc(r["title"])}<br><span class="small">{esc(r["description"])}</span></td><td>{esc(r["status"])}</td><td><a class="btn dark" href="/admin/problem/{r["id"]}/status">Next status</a></td></tr>' for r in rows)
    body=f'''<section class="section"><h1>Campus problems.</h1><p class="muted">Admins manage status only. Community solutions are never moderated here.</p><div class="card tablewrap"><table><tr><th>#</th><th>Reporter</th><th>Private Student ID</th><th>Problem</th><th>Status</th><th>Action</th></tr>{html_rows or '<tr><td colspan="6">No problems.</td></tr>'}</table></div></section>'''
    return layout("Problems",body,admin=True)


@app.route("/admin/problem/<int:iid>/status")
@admin_required
def problem_status(iid):
    con=db(); row=con.execute("SELECT status FROM issues WHERE id=?",(iid,)).fetchone()
    if row:
        idx=STATUSES.index(row["status"]) if row["status"] in STATUSES else 0; con.execute("UPDATE issues SET status=? WHERE id=?",(STATUSES[(idx+1)%len(STATUSES)],iid)); con.commit()
    con.close(); return redirect(url_for("admin_problems"))


@app.route("/admin/settings", methods=["GET","POST"])
@admin_required
def admin_settings():
    con = db()
    if request.method == "POST":
        wa = request.form.get("whatsapp_link", "").strip()[:500]
        drive = request.form.get("google_drive_url", "").strip()[:500]
        wa_enabled = "1" if request.form.get("whatsapp_notifications_enabled") == "1" else "0"
        wa_version = request.form.get("whatsapp_api_version", "v23.0").strip()[:30] or "v23.0"
        wa_phone_id = request.form.get("whatsapp_phone_number_id", "").strip()[:100]
        wa_token = request.form.get("whatsapp_access_token", "").strip()[:1000]
        wa_admin = request.form.get("whatsapp_admin_number", "").strip()[:30]
        chat_enabled = "1" if request.form.get("community_chat_enabled") == "1" else "0"
        if wa and not valid_url(wa):
            flash("WhatsApp community link must be a valid URL.")
        elif drive and not valid_url(drive):
            flash("Google Drive URL must be a valid URL.")
        else:
            set_setting(con, "whatsapp_link", wa)
            set_setting(con, "google_drive_url", drive or DRIVE_URL)
            set_setting(con, "whatsapp_notifications_enabled", wa_enabled)
            set_setting(con, "whatsapp_api_version", wa_version)
            set_setting(con, "whatsapp_phone_number_id", wa_phone_id)
            set_setting(con, "whatsapp_access_token", wa_token)
            set_setting(con, "whatsapp_admin_number", wa_admin)
            set_setting(con, "community_chat_enabled", chat_enabled)
            con.commit()
            flash("Configuration saved.")
        con.close()
        return redirect(url_for("admin_settings"))
    wa = setting(con, "whatsapp_link", "")
    drive = setting(con, "google_drive_url", DRIVE_URL)
    online = setting(con, "vybe_online", "1") == "1"
    pk = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
    wa_enabled = setting(con, "whatsapp_notifications_enabled", "0") == "1"
    wa_version = setting(con, "whatsapp_api_version", "v23.0")
    wa_phone_id = setting(con, "whatsapp_phone_number_id", "")
    wa_admin = setting(con, "whatsapp_admin_number", "")
    chat_enabled = setting(con, "community_chat_enabled", "1") == "1"
    con.close()
    checked = "checked" if wa_enabled else ""
    body = f'''<section class="section"><h1>Settings.</h1>
    <div class="grid2">
      <div class="card"><h2>☁️ Google Drive</h2><form class="form" method="post">
        <input name="google_drive_url" value="{esc(drive)}" required>
        <div class="small">Students can only see this link after login.</div>
        <h2 style="margin-top:18px">💬 WhatsApp Community</h2>
        <input name="whatsapp_link" value="{esc(wa)}" placeholder="https://chat.whatsapp.com/...">
        <h2 style="margin-top:18px">🔔 WhatsApp admin alerts</h2>
        <label class="small"><input type="checkbox" name="whatsapp_notifications_enabled" value="1" {checked} style="width:auto;margin-right:7px"> Send VYBE alerts to my WhatsApp</label>
        <input name="whatsapp_phone_number_id" value="{esc(wa_phone_id)}" placeholder="WhatsApp Cloud API phone number ID">
        <input name="whatsapp_admin_number" value="{esc(wa_admin)}" placeholder="Your WhatsApp number, e.g. 9198XXXXXXXX">
        <input name="whatsapp_api_version" value="{esc(wa_version)}" placeholder="Graph API version, e.g. v23.0">
        <input type="password" name="whatsapp_access_token" placeholder="WhatsApp Cloud API access token">
        <div class="small">Automatic WhatsApp delivery requires a configured WhatsApp Cloud API sender and any Meta messaging/template rules that apply to the account.</div>
        <button class="btn accent">Save configuration</button></form></div>
      <div class="card"><h2>💬 Student Community Chat</h2><p class="small">Status: <strong>{"🟢 ON" if chat_enabled else "🔴 OFF"}</strong></p><p class="small">Students see each other's messages and registered names only. Student IDs remain hidden from the public chat.</p><a class="btn dark" href="/admin/community-chat">Open chat controls →</a></div>
      <div class="card"><h2>🌐 Public status</h2><p class="{"online" if online else "offline"}"><strong>{"🟢 ONLINE" if online else "🔴 OFFLINE"}</strong></p>
        <form method="post" action="/admin/status"><button class="btn {"danger" if online else "good"}">{"🔴 Take VYBE Offline" if online else "🟢 Bring VYBE Online"}</button></form>
        <h2 style="margin-top:22px">📱 Phone passkey</h2><p class="muted">Registered credentials: {pk}</p><a class="btn dark" href="/admin/password">Security center →</a>
      </div>
    </div></section>'''
    return layout("Settings", body, admin=True)


# ---------------------------------------------------------------------------
# WebAuthn passkey flows. The private key/biometric data stays on the device;
# VYBE stores only credential/public-key information required by WebAuthn.
# ---------------------------------------------------------------------------
@app.route("/passkey/register/options", methods=["POST"])
@admin_required
def passkey_register_options():
    if not webauthn_configured():
        return jsonify(error="WebAuthn is not configured on this server."), 503
    con = db()
    existing = con.execute("SELECT credential_id FROM passkeys").fetchall()
    con.close()
    if existing and not session.get("passkey_verified"):
        return jsonify(error="Verify your current passkey before registering another passkey."), 403
    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in existing]
    options = generate_registration_options(
        rp_id=PASSKEY_RP_ID,
        rp_name="VYBE",
        user_id=secrets.token_bytes(32),
        user_name="vybe-admin",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude,
    )
    session["passkey_registration_challenge"] = base64.b64encode(options.challenge).decode("ascii")
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.route("/passkey/register/verify", methods=["POST"])
@admin_required
def passkey_register_verify():
    if not webauthn_configured():
        return jsonify(error="WebAuthn is not configured."), 503
    challenge_b64 = session.pop("passkey_registration_challenge", None)
    if not challenge_b64:
        return jsonify(error="Registration challenge expired."), 400
    try:
        credential = request.get_json(force=True)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64.b64decode(challenge_b64),
            expected_rp_id=PASSKEY_RP_ID,
            expected_origin=PASSKEY_ORIGIN,
            require_user_verification=True,
        )
        cid = base64.urlsafe_b64encode(verification.credential_id).rstrip(b"=").decode("ascii")
        pk = base64.urlsafe_b64encode(verification.credential_public_key).rstrip(b"=").decode("ascii")
        transports = json.dumps(credential.get("response", {}).get("transports", []))
        con = db()
        before = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
        con.execute(
            "INSERT INTO passkeys(credential_id,public_key,sign_count,device_type,backed_up,transports,created_at) VALUES(?,?,?,?,?,?,?)",
            (cid, pk, int(verification.sign_count), str(verification.credential_device_type), bool(verification.credential_backed_up), transports, now()),
        )
        con.commit()
        con.close()
        session["passkey_verified"] = False
        return jsonify(ok=True)
    except Exception as exc:
        return jsonify(error="Passkey verification failed.", detail=str(exc) if app.debug else None), 400


@app.route("/passkey/auth/options", methods=["POST"])
@admin_required
def passkey_auth_options():
    if not webauthn_configured(): return jsonify(error="WebAuthn is not configured."),503
    con=db(); rows=con.execute("SELECT credential_id FROM passkeys").fetchall(); con.close()
    if not rows: return jsonify(error="Register a phone passkey first."),400
    allow=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in rows]
    options=generate_authentication_options(rp_id=PASSKEY_RP_ID, allow_credentials=allow, user_verification=UserVerificationRequirement.REQUIRED)
    session["passkey_auth_challenge"] = base64.b64encode(options.challenge).decode("ascii")
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.route("/passkey/auth/verify", methods=["POST"])
@admin_required
def passkey_auth_verify():
    if not webauthn_configured(): return jsonify(error="WebAuthn is not configured."),503
    challenge_b64=session.pop("passkey_auth_challenge",None)
    if not challenge_b64: return jsonify(error="Authentication challenge expired."),400
    try:
        credential=request.get_json(force=True)
        cid=credential.get("id","")
        con=db(); row=con.execute("SELECT * FROM passkeys WHERE credential_id=?",(cid,)).fetchone(); con.close()
        if not row: return jsonify(error="Unknown passkey."),403
        verification=verify_authentication_response(credential=credential, expected_challenge=base64.b64decode(challenge_b64), expected_rp_id=PASSKEY_RP_ID, expected_origin=PASSKEY_ORIGIN, credential_public_key=base64.urlsafe_b64decode(row["public_key"]+"="*((4-len(row["public_key"])%4)%4)), credential_current_sign_count=int(row["sign_count"]), require_user_verification=True)
        con=db(); con.execute("UPDATE passkeys SET sign_count=?,device_type=?,backed_up=? WHERE id=?",(int(verification.new_sign_count),str(verification.credential_device_type),bool(verification.credential_backed_up),row["id"])); con.commit(); con.close()
        session["passkey_verified"] = True
        return jsonify(ok=True)
    except Exception as exc:
        session["passkey_verified"] = False
        return jsonify(error="Passkey verification failed.", detail=str(exc) if app.debug else None),403


@app.route("/admin/password", methods=["GET", "POST"])
@admin_required
def admin_password():
    if request.method == "POST":
        if not session.get("passkey_verified"):
            flash("Verify the current passkey before changing the password.")
            return redirect(url_for("admin_password"))
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(new) < 12 or new != confirm:
            flash("New passwords must match and be at least 12 characters.")
            return redirect(url_for("admin_password"))
        con = db()
        set_setting(con, "admin_password_hash", hash_password(new))
        con.commit()
        con.close()
        session["passkey_verified"] = False
        flash("Admin password changed. Verify your passkey again for future sensitive actions.")
        return redirect(url_for("admin_verify"))
    con = db()
    count = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
    con.close()
    web_status = "ready" if webauthn_configured() else "not configured"
    if count == 0:
        registration_note = "No passkey exists yet. Register your first passkey after entering the admin password."
    elif session.get("passkey_verified"):
        registration_note = "Current passkey verified. You may register another passkey."
    else:
        registration_note = "Verify your current passkey before registering another passkey."
    body = f'''<section class="section"><div class="badge">SECURITY CENTER</div><h1>Protect VYBE.</h1>
    <div class="two">
      <div class="card"><h2>📱 Passkeys</h2>
        <p class="muted">Current credentials: {count}. Adding a second or later passkey requires verification of an existing passkey first.</p>
        <p class="small">WebAuthn: {web_status}</p>
        <button class="btn accent" id="registerPasskey">Register New Passkey</button>
        <div id="pkMsg" class="small" style="margin-top:10px">{esc(registration_note)}</div>
        <p style="margin-top:14px"><a class="btn dark" href="/admin/verify">Verify Current Passkey</a></p>
      </div>
      <div class="card"><h2>🔐 Change Admin Password</h2>
        <p class="muted">You do not need the current password. A fresh current-passkey verification authorizes the change.</p>
        <form class="form" method="post" style="margin-top:16px">
          <div style="position:relative"><input id="newPassword" type="password" name="new_password" placeholder="New password (12+ chars)" minlength="12" required autocomplete="new-password"><button type="button" class="btn dark toggle-password" data-target="newPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div>
          <div style="position:relative"><input id="confirmPassword" type="password" name="confirm_password" placeholder="Confirm new password" minlength="12" required autocomplete="new-password"><button type="button" class="btn dark toggle-password" data-target="confirmPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div>
          <button class="btn accent" {"disabled" if not session.get("passkey_verified") else ""}>Change Password</button>
        </form>
        <div class="small">{"Current passkey verified ✓" if session.get("passkey_verified") else "Verify current passkey above before changing the password."}</div>
      </div>
    </div></section><script>{WEBAUTHN_JS}</script>'''
    return layout("Security", body, admin=True)


@app.route("/admin/verify")
@admin_required
def admin_verify():
    con = db()
    count = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
    con.close()
    if count == 0:
        return redirect(url_for("admin_password"))
    body = f'''<div class="auth"><div class="card authbox"><div class="badge">SECOND FACTOR</div><h1>Verify passkey.</h1><p class="muted">Your admin password is correct. Verify your registered passkey to open the control center.</p><button class="btn accent" id="verifyPasskey">Verify Current Passkey</button><div id="authMsg" class="small" style="margin-top:12px"></div></div></div><script>{WEBAUTHN_JS}</script>'''
    return layout("Admin Verification", body, admin=True)


@app.route("/admin/chats")
@admin_required
def admin_chats():
    con = db()
    issues_rows = con.execute(
        "SELECT i.*, s.name AS reporter_name, s.student_id AS reporter_sid "
        "FROM issues i JOIN students s ON s.id=i.student_id ORDER BY i.id DESC"
    ).fetchall()
    solutions = con.execute(
        "SELECT so.*, s.name AS author_name, s.student_id AS author_sid "
        "FROM solutions so JOIN students s ON s.id=so.student_id ORDER BY so.id ASC"
    ).fetchall()
    con.close()
    by_issue = {}
    for sol in solutions:
        by_issue.setdefault(sol["issue_id"], []).append(sol)
    blocks = ""
    for issue in issues_rows:
        sols = by_issue.get(issue["id"], [])
        messages = [
            f'<div class="bubble"><strong>{esc(issue["reporter_name"])} · {esc(issue["reporter_sid"])}</strong><div>{esc(issue["description"])}</div><div class="small">{esc(issue["created_at"])}</div></div>'
        ]
        messages += [
            f'<div class="bubble"><strong>{esc(sol["author_name"])} · {esc(sol["author_sid"])}</strong><div>{esc(sol["text"])}</div><div class="small">{esc(sol["created_at"])}</div></div>'
            for sol in sols
        ]
        blocks += f'''<div class="card"><div class="resource-meta"><span class="pill">#{issue["id"]}</span><span class="pill">{esc(issue["status"])}</span></div>
        <h2>{esc(issue["reporter_name"])} <span class="small">({esc(issue["reporter_sid"])})</span></h2>
        <h3>{esc(issue["title"])}</h3><div class="chat">{"".join(messages)}</div>
        <form method="post" action="/admin/chat/{issue["id"]}/delete" onsubmit="return confirm('Delete this student chat and all solutions?')"><button class="btn danger">Delete this chat</button></form></div>'''
    body = f'''<section class="section"><div class="badge">PRIVATE ADMIN CHAT HISTORY</div><h1>Student chats.</h1>
    <p class="muted">Only admins can access this page. Each problem report and its community solutions are shown together with the student's name and ID.</p>
    <div class="actions"><form method="post" action="/admin/chats/delete-all" onsubmit="return confirm('Delete ALL saved student chats and solutions? This cannot be undone.')"><button class="btn danger">Delete all chats</button></form></div>
    <section style="display:grid;gap:16px">{blocks or '<div class="empty">No saved student chats yet.</div>'}</section></section>'''
    return layout("Student Chats", body, admin=True)


@app.route("/admin/chat/<int:iid>/delete", methods=["POST"])
@admin_required
def delete_admin_chat(iid):
    con = db()
    con.execute("DELETE FROM solutions WHERE issue_id=?", (iid,))
    con.execute("DELETE FROM issues WHERE id=?", (iid,))
    con.commit()
    con.close()
    flash("Student chat deleted.")
    return redirect(url_for("admin_chats"))


@app.route("/admin/chats/delete-all", methods=["POST"])
@admin_required
def delete_all_admin_chats():
    con = db()
    con.execute("DELETE FROM solutions")
    con.execute("DELETE FROM issues")
    con.commit()
    con.close()
    flash("All saved student chats and solutions were deleted.")
    return redirect(url_for("admin_chats"))


@app.route("/admin/community-chat", methods=["GET", "POST"])
@admin_required
def admin_community_chat():
    con = db()
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "toggle":
            current = setting(con, "community_chat_enabled", "1") == "1"
            set_setting(con, "community_chat_enabled", "0" if current else "1")
            con.commit(); con.close()
            flash("Community Chat disabled." if current else "Community Chat enabled.")
            return redirect(url_for("admin_community_chat"))
        if action == "delete":
            try: mid = int(request.form.get("message_id", "0"))
            except ValueError: mid = 0
            con.execute("DELETE FROM community_messages WHERE id=?", (mid,))
            con.commit(); con.close(); flash("Community message deleted.")
            return redirect(url_for("admin_community_chat"))
        if action == "delete_all":
            con.execute("DELETE FROM community_messages")
            con.commit(); con.close(); flash("All community chat messages deleted.")
            return redirect(url_for("admin_community_chat"))
    enabled = setting(con, "community_chat_enabled", "1") == "1"
    rows = con.execute("SELECT cm.*, s.name, s.student_id FROM community_messages cm JOIN students s ON s.id=cm.student_id ORDER BY cm.id DESC LIMIT 500").fetchall()
    con.close()
    bubbles = ""
    for r in rows:
        bubbles += f'''<div class="bubble"><div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><strong>{esc(r["name"])}</strong> <span class="small">({esc(r["student_id"])})</span><div style="margin-top:5px;white-space:pre-wrap;word-break:break-word">{esc(r["message"])}</div><div class="small" style="margin-top:5px">{esc(r["created_at"])}</div></div><form method="post" onsubmit="return confirm('Delete this message?')"><input type="hidden" name="action" value="delete"><input type="hidden" name="message_id" value="{r["id"]}"><button class="btn danger">Delete</button></form></div></div>'''
    status = "🟢 ON" if enabled else "🔴 OFF"
    body = f'''<section class="section"><div class="badge">COMMUNITY CHAT CONTROL</div><h1>Community Chat.</h1><div class="grid2"><div class="card"><h2>{status}</h2><p class="muted">Students can {"send and read messages" if enabled else "not use the chat while it is disabled"}.</p><form method="post"><input type="hidden" name="action" value="toggle"><button class="btn {"danger" if enabled else "good"}">{"🔴 Turn Chat OFF" if enabled else "🟢 Turn Chat ON"}</button></form></div><div class="card"><h2>Moderation</h2><p class="muted">Delete individual messages or clear the entire community chat.</p><form method="post" onsubmit="return confirm('Delete ALL community chat messages? This cannot be undone.')"><input type="hidden" name="action" value="delete_all"><button class="btn danger">Delete all messages</button></form></div></div><section class="section"><div class="card"><h2>Recent messages</h2><div class="chat">{bubbles or '<div class="empty">No community messages yet.</div>'}</div></div></section></section>'''
    return layout("Community Chat Control", body, admin=True)


@app.route("/admin/password-requests", endpoint="admin_password_requests")
@admin_required
def admin_password_requests():
    con = db()
    rows = con.execute("SELECT r.*, s.name AS student_name, s.student_id AS student_sid FROM password_reset_requests r JOIN students s ON s.id=r.student_id ORDER BY r.id DESC").fetchall()
    con.close()
    html_rows=[]
    for r in rows:
        if r["status"] == "pending":
            action = f'''<div class="actions"><form method="post" action="/admin/password-request/{r['id']}/approve"><button class="btn good">Approve</button></form><form method="post" action="/admin/password-request/{r['id']}/reject"><button class="btn danger">Reject</button></form><form method="post" action="/admin/password-request/{r['id']}/delete" onsubmit="return confirm(\'Delete this password request permanently?\')"><button class="btn danger">Delete</button></form></div>'''
        elif r["status"] == "approved":
            action = f'''<div class="actions"><span class="pill status-good">Approved · password form unlocked</span><form method="post" action="/admin/password-request/{r['id']}/delete" onsubmit="return confirm(\'Delete this password request permanently?\')"><button class="btn danger">Delete</button></form></div>'''
        else:
            action = f'''<div class="actions"><span class="pill">{esc(r["status"])}</span><form method="post" action="/admin/password-request/{r['id']}/delete" onsubmit="return confirm(\'Delete this password request permanently?\')"><button class="btn danger">Delete</button></form></div>'''
        html_rows.append(f'''<tr><td>{esc(r["requested_at"])}</td><td><strong>{esc(r["student_name"])}</strong><br><span class="small">{esc(r["student_sid"])}</span></td><td><span class="pill">{esc(r["status"])}</span></td><td>{esc(r["approved_at"] or '—')}<br><span class="small">{esc(r["expires_at"] or '')}</span></td><td>{action}</td></tr>''')
    body=f'''<section class="section"><div class="badge">ACCOUNT RECOVERY</div><h1>Password requests.</h1><p class="muted">Students can request a password change. After admin approval, the student's open VYBE password-recovery page automatically unlocks a new-password form. No reset code is shown, and admins never see the student's existing password.</p><div class="notice">After approval, the student has 15 minutes to set a new password. The approval can only be used once.</div><div class="card tablewrap" style="margin-top:18px"><table><tr><th>Requested</th><th>Student</th><th>Status</th><th>Approval</th><th>Action</th></tr>{''.join(html_rows) or '<tr><td colspan="5">No password requests.</td></tr>'}</table></div></section>'''
    return layout("Password Requests", body, admin=True)


@app.route("/admin/password-request/<int:rid>/<action>", methods=["POST"])
@admin_required
def admin_password_request_action(rid, action):
    if action not in ("approve", "reject", "delete"):
        abort(400)
    con=db()
    row=con.execute("SELECT r.*,s.name,s.student_id FROM password_reset_requests r JOIN students s ON s.id=r.student_id WHERE r.id=?", (rid,)).fetchone()
    if not row:
        con.close(); flash("Password request not found."); return redirect(url_for("admin_password_requests"))
    if action == "delete":
        con.execute("DELETE FROM password_reset_requests WHERE id=?", (rid,))
        con.commit(); con.close()
        flash("Password-change request deleted.")
        return redirect(url_for("admin_password_requests"))
    if row["status"] != "pending":
        con.close(); flash("This password request is no longer pending."); return redirect(url_for("admin_password_requests"))
    if action == "reject":
        con.execute("UPDATE password_reset_requests SET status='rejected' WHERE id=?", (rid,)); con.commit(); con.close()
        flash("Password-change request rejected."); return redirect(url_for("admin_password_requests"))

    approved=now(); expires=(datetime.now(timezone.utc)+timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S UTC")
    con.execute("UPDATE password_reset_requests SET status='approved', approval_code_hash=NULL, approval_code_token=NULL, expires_at=? WHERE id=?", (approved, expires, rid))
    con.commit(); con.close()
    flash("Approved. The student can now set a new password directly on their recovery page for the next 15 minutes.")
    return redirect(url_for("admin_password_requests"))


@app.route("/admin/notifications", endpoint="admin_notifications")
@admin_required
def admin_notifications():
    con = db()
    rows = con.execute(
        "SELECT n.*, s.name AS student_name, s.student_id AS student_sid "
        "FROM notifications n LEFT JOIN students s ON s.id=n.student_id ORDER BY n.id DESC"
    ).fetchall()
    con.close()
    html_rows = "".join(
        f'''<tr><td>{esc(r["created_at"])}</td><td><span class="pill">{esc(r["kind"])}</span></td>
        <td><strong>{esc(r["title"])}</strong><br><span class="small">{esc(r["message"]).replace(chr(10), "<br>")}</span></td>
        <td>{esc(r["student_name"] or "—")}<br>{esc(r["student_sid"] or "—")}</td>
        <td>{"Sent ✓" if r["whatsapp_sent"] else "Dashboard only"}</td>
        <td><form method="post" action="/admin/notification/{r["id"]}/delete" onsubmit="return confirm('Delete this notification?')"><button class="btn danger">Delete</button></form></td></tr>'''
        for r in rows
    )
    body = f'''<section class="section"><div class="badge">ADMIN ALERTS</div><h1>Notifications.</h1>
    <p class="muted">Entry requests are saved here. If WhatsApp Cloud API is configured, VYBE also attempts to send the alert to your number.</p>
    <div class="actions"><form method="post" action="/admin/notifications/delete-all" onsubmit="return confirm('Delete ALL admin notifications?')"><button class="btn danger">Delete all notifications</button></form></div>
    <div class="card tablewrap"><table><tr><th>Time</th><th>Type</th><th>Message</th><th>Student</th><th>WhatsApp</th><th>Action</th></tr>{html_rows or '<tr><td colspan="6">No notifications.</td></tr>'}</table></div></section>'''
    return layout("Notifications", body, admin=True)


@app.route("/admin/notification/<int:nid>/delete", methods=["POST"])
@admin_required
def delete_admin_notification(nid):
    con = db()
    con.execute("DELETE FROM notifications WHERE id=?", (nid,))
    con.commit()
    con.close()
    flash("Notification deleted.")
    return redirect(url_for("admin_notifications"))


@app.route("/admin/notifications/delete-all", methods=["POST"])
@admin_required
def delete_all_admin_notifications():
    con = db()
    con.execute("DELETE FROM notifications")
    con.commit()
    con.close()
    flash("All notifications deleted.")
    return redirect(url_for("admin_notifications"))


WEBAUTHN_JS = r'''
function b64ToBuf(v){v=v.replace(/-/g,"+").replace(/_/g,"/");while(v.length%4)v+="=";return Uint8Array.from(atob(v),c=>c.charCodeAt(0)).buffer}
function bufToB64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function decodeCreation(o){o.challenge=b64ToBuf(o.challenge);o.user.id=b64ToBuf(o.user.id);(o.excludeCredentials||[]).forEach(x=>x.id=b64ToBuf(x.id));const host=location.hostname;if(!o.rp||!o.rp.id)o.rp={id:host,name:"VYBE"};window.VYBE_RP_ID=o.rp.id;return o}
function decodeRequest(o){o.challenge=b64ToBuf(o.challenge);(o.allowCredentials||[]).forEach(x=>x.id=b64ToBuf(x.id));return o}
function serializeCredential(c){return {id:c.id,rawId:bufToB64(c.rawId),type:c.type,response:{clientDataJSON:bufToB64(c.response.clientDataJSON),attestationObject:c.response.attestationObject?bufToB64(c.response.attestationObject):undefined,authenticatorData:c.response.authenticatorData?bufToB64(c.response.authenticatorData):undefined,signature:c.response.signature?bufToB64(c.response.signature):undefined,userHandle:c.response.userHandle?bufToB64(c.response.userHandle):undefined},clientExtensionResults:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
async function postJSON(url,payload){let r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},credentials:"same-origin",body:JSON.stringify(payload)});let j={};try{j=await r.json()}catch(_){throw new Error("Server returned an invalid response.")}if(!r.ok)throw new Error(j.error||"Request failed");return j}
function pkError(e){if(e&&e.name==="NotAllowedError")return "Passkey request was cancelled or timed out. Try again and choose your phone/device.";if(e&&e.name==="InvalidStateError")return "This passkey is already registered on this device.";if(e&&e.name==="SecurityError"){let u=location.href;return "WebAuthn SecurityError. Current page: "+u+" | RP ID: " + (window.VYBE_RP_ID||"not exposed") + " | Check that the site is HTTPS and the RP ID matches this domain.";}return (e&&e.name?e.name+": ":"")+(e&&e.message)||"Passkey setup failed."}
const reg=document.getElementById("registerPasskey");
if(reg)reg.onclick=async()=>{const msg=document.getElementById("pkMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys. Try current Chrome, Edge, Safari or Firefox.");reg.disabled=true;reg.textContent="Waiting for device…";msg.textContent="Choose your phone or another passkey device when your browser asks.";let o=await postJSON("/passkey/register/options",{});o=decodeCreation(o);o.rp={id:location.hostname,name:(o.rp&&o.rp.name)||"VYBE"};window.VYBE_RP_ID=o.rp.id;let c=await navigator.credentials.create({publicKey:o});if(!c)throw new Error("No passkey was created.");await postJSON("/passkey/register/verify",serializeCredential(c));msg.textContent="Phone passkey registered successfully.";setTimeout(()=>location.reload(),500)}catch(e){msg.textContent=pkError(e);reg.disabled=false;reg.textContent="Register Phone Passkey"}}
const ver=document.getElementById("verifyPasskey");
if(ver)ver.onclick=async()=>{const msg=document.getElementById("authMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys.");ver.disabled=true;ver.textContent="Waiting for device…";let o=await postJSON("/passkey/auth/options",{});o=decodeRequest(o);let c=await navigator.credentials.get({publicKey:o});if(!c)throw new Error("No passkey was selected.");await postJSON("/passkey/auth/verify",serializeCredential(c));msg.textContent="Phone passkey verified.";ver.textContent="Passkey verified ✓";if(location.pathname==="/admin/verify")setTimeout(()=>location.href="/admin/panel",400)}catch(e){msg.textContent=pkError(e);ver.disabled=false;ver.textContent="Verify Phone Passkey"}}
'''



@app.route("/admin/passkey/reset-session", methods=["POST"])
@admin_required
def reset_passkey_session():
    session["passkey_verified"] = False
    return redirect(url_for("admin_verify"))


# Initialize only after all helpers/decorators are defined, but before the app
# is served. This also guarantees the database is ready during import under Gunicorn.
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)

# VYBE V14 — clean page-based password reset + IST admin login audit
# Page-based password reset. Reset codes appear only on the student recovery page after admin approval.

import os
import re
import base64
import json
import secrets
import hashlib
import html
import io
import mimetypes
import sqlite3
import zlib
import zipfile
import threading
import time
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse, quote
from xml.etree import ElementTree as ET
from urllib.request import Request as URLRequest, urlopen
from urllib.error import HTTPError

from flask import Flask, request, redirect, url_for, session, flash, abort, send_file, jsonify, g, has_request_context
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

GOOGLE_AUTH_IMPORT_ERROR = ""
try:
    from google.oauth2.credentials import Credentials as GoogleOAuthCredentials
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google_auth_oauthlib.flow import Flow as GoogleOAuthFlow
    from cryptography.fernet import Fernet, InvalidToken as FernetInvalidToken
    GOOGLE_AUTH_AVAILABLE = True
except Exception as _google_auth_exc:
    GoogleOAuthCredentials = None
    GoogleAuthRequest = None
    GoogleOAuthFlow = None
    Fernet = None
    FernetInvalidToken = Exception
    GOOGLE_AUTH_AVAILABLE = False
    GOOGLE_AUTH_IMPORT_ERROR = f"{type(_google_auth_exc).__name__}: {_google_auth_exc}"


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
UPLOAD_DIR = Path(os.environ.get("VYBE_UPLOAD_DIR", "/tmp/vybe_uploads"))
try:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    UPLOAD_DIR = Path("/tmp/vybe_uploads")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SQLITE_PATH = os.environ.get("VYBE_DB", str(APP_DIR / "vybe.db"))
SECRET_KEY = os.environ.get("VYBE_SECRET_KEY", "").strip()
if not SECRET_KEY:
    if DATABASE_URL:
        raise RuntimeError("VYBE_SECRET_KEY must be set in production.")
    SECRET_KEY = secrets.token_hex(32)
INITIAL_ADMIN_PASSWORD = os.environ.get("VYBE_ADMIN_INITIAL_PASSWORD", "").strip()
VERCEL_HOST = os.environ.get("VERCEL_URL", "").strip().lower()
PASSKEY_RP_ID = os.environ.get("VYBE_PASSKEY_RP_ID", "").strip().lower() or VERCEL_HOST or "localhost"
PASSKEY_ORIGIN = os.environ.get("VYBE_PASSKEY_ORIGIN", "").strip() or (f"https://{PASSKEY_RP_ID}" if PASSKEY_RP_ID != "localhost" else "http://localhost:5000")
DRIVE_URL = "https://drive.google.com/drive/folders/1ZsGPHVreKw3zi-crF4rGLexI77zuaOgA?usp=sharing"
VYBE_DRIVE_ROOT_FOLDER_ID = os.environ.get("VYBE_DRIVE_ROOT_FOLDER_ID", "1ZsGPHVreKw3zi-crF4rGLexI77zuaOgA").strip()
VYBE_GOOGLE_OAUTH_CLIENT_ID = os.environ.get("VYBE_GOOGLE_OAUTH_CLIENT_ID", "").strip()
VYBE_GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("VYBE_GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
VYBE_GOOGLE_OAUTH_CLIENT_JSON = os.environ.get("VYBE_GOOGLE_OAUTH_CLIENT_JSON", "").strip()
VYBE_GOOGLE_OAUTH_REDIRECT_URI = os.environ.get("VYBE_GOOGLE_OAUTH_REDIRECT_URI", "").strip()
VYBE_DRIVE_PUBLIC_FILES = os.environ.get("VYBE_DRIVE_PUBLIC_FILES", "1").strip() == "1"
VYBE_DRIVE_WEBHOOK_TOKEN = os.environ.get("VYBE_DRIVE_WEBHOOK_TOKEN", "").strip() or hashlib.sha256((SECRET_KEY + "|drive-webhook").encode()).hexdigest()
VYBE_AI_API_KEY = (os.environ.get("VYBE_AI_API_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip())
VYBE_AI_MODEL = os.environ.get("VYBE_AI_MODEL", "gpt-5.6-luna").strip() or "gpt-5.6-luna"
VYBE_AI_ENDPOINT = os.environ.get("VYBE_AI_ENDPOINT", "https://api.openai.com/v1/responses").strip()
ALLOWED_EXT = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xlsx", ".odt", ".odp", ".txt", ".csv", ".md", ".rtf", ".json", ".xml", ".log", ".yaml", ".yml", ".png", ".jpg", ".jpeg", ".webp", ".zip"}
CATEGORIES = ["Wi-Fi", "Systems / computers", "Classroom", "Electricity", "Facilities", "Other"]
STATUSES = ["Open", "In progress", "Resolved"]

RESET_CODE_SALT = "vybe-password-reset-code-v1"
reset_code_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=RESET_CODE_SALT)
SECURITY_LOCK_SALT = "vybe-login-lock-v1"
security_lock_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=SECURITY_LOCK_SALT)

app = Flask(__name__)
_PRODUCTION = bool(DATABASE_URL)
_COOKIE_SECURE = True if _PRODUCTION else (os.environ.get("VYBE_COOKIE_SECURE", "1") == "1")
_COOKIE_NAME = "__Host-vybe_session" if _COOKIE_SECURE else "vybe_session"
_ALLOWED_HOSTS_RAW = os.environ.get("VYBE_ALLOWED_HOSTS", "").strip()
_ALLOWED_HOSTS = {h.strip().lower().split(":", 1)[0] for h in _ALLOWED_HOSTS_RAW.split(",") if h.strip()}
if VERCEL_HOST:
    _ALLOWED_HOSTS.add(VERCEL_HOST)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
    SESSION_COOKIE_NAME=_COOKIE_NAME,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_COOKIE_SECURE,
    SESSION_USE_SIGNER=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
# Render sits behind a reverse proxy. Trust the forwarded scheme/host so
# HTTPS cookies, redirects and WebAuthn origin checks behave consistently.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


class DB:
    """Tiny database abstraction for SQLite and PostgreSQL.

    Application SQL uses '?' placeholders. PostgreSQL gets them converted to
    '%s' so routes do not contain SQLite-only SQL syntax.
    """
    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        self._request_scoped = False
        if self.is_pg:
            if psycopg is None:
                raise RuntimeError("DATABASE_URL is set but psycopg is not installed")
            # psycopg uses the DATABASE_URL supplied by the managed database.
            # Enforce TLS unless the URL explicitly requests a local/insecure
            # connection (useful only for local development).
            pg_url = DATABASE_URL
            if _PRODUCTION and "sslmode=" not in pg_url.lower():
                pg_url += ("&" if "?" in pg_url else "?") + "sslmode=require"
            self.conn = psycopg.connect(pg_url, row_factory=dict_row, connect_timeout=10)
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
        if getattr(self, "_request_scoped", False):
            # Preserve the historical close() call sites while keeping the
            # connection reusable for the rest of this request. Any pending
            # transaction is discarded, matching normal close semantics.
            try:
                self.conn.rollback()
            except Exception:
                pass
            return
        self.conn.close()


def db():
    if has_request_context():
        con = g.get("_vybe_db")
        if con is not None:
            return con
        con = DB()
        con._request_scoped = True
        g._vybe_db = con
        return con
    return DB()


@app.teardown_request
def _close_request_db(_exc=None):
    con = g.pop("_vybe_db", None)
    if con is not None:
        try:
            con.conn.rollback()
        except Exception:
            pass
        try:
            con.conn.close()
        except Exception:
            pass


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def _ensure_password_reset_schema(con):
    if con.is_pg:
        con.execute("""CREATE TABLE IF NOT EXISTS password_reset_requests (
            id BIGSERIAL PRIMARY KEY,
            student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending',
            requested_at TEXT NOT NULL,
            approved_at TEXT,
            approval_code_hash TEXT,
            approval_code_token TEXT,
            expires_at TEXT,
            used_at TEXT
        )""")
        con.execute("ALTER TABLE password_reset_requests ADD COLUMN IF NOT EXISTS approval_code_token TEXT")
    else:
        con.execute("""CREATE TABLE IF NOT EXISTS password_reset_requests (
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
        )""")
        cols={r["name"] for r in con.execute("PRAGMA table_info(password_reset_requests)").fetchall()}
        if "approval_code_token" not in cols:
            con.execute("ALTER TABLE password_reset_requests ADD COLUMN approval_code_token TEXT")


def _ensure_password_reset_active_index(con):
    """Prevent concurrent requests from creating multiple active reset tickets."""
    try:
        dupes = con.execute(
            "SELECT student_id, MAX(id) AS keep_id FROM password_reset_requests WHERE status IN ('pending','approved') GROUP BY student_id HAVING COUNT(*) > 1"
        ).fetchall()
        for d in dupes:
            con.execute(
                "UPDATE password_reset_requests SET status='superseded' WHERE student_id=? AND status IN ('pending','approved') AND id<>?",
                (int(d["student_id"]), int(d["keep_id"])),
            )
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_password_reset_active ON password_reset_requests(student_id) WHERE status IN ('pending','approved')")
        con.commit()
    except Exception:
        try: con.rollback()
        except Exception: pass

def now_ist():
    """Current Indian Standard Time for admin audit records."""
    from zoneinfo import ZoneInfo
    return datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")

def _admin_datetime_to_utc(value):
    from zoneinfo import ZoneInfo
    value=(value or "").strip()
    if not value: return now()
    try:
        dt=datetime.fromisoformat(value)
        if dt.tzinfo is None: dt=dt.replace(tzinfo=ZoneInfo("Asia/Kolkata"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception: return now()



def record_admin_login(con, success, event="login"):
    """Record admin authentication activity without storing passwords."""
    ip = (request.remote_addr or "unknown")[:100]
    user_agent = request.headers.get("User-Agent", "")[:500]
    try:
        con.execute(
            "INSERT INTO admin_login_logs(logged_at_ist,success,event,ip_address,user_agent) VALUES(?,?,?,?,?)",
            (now_ist(), bool(success), event[:40], ip, user_agent),
        )
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        try:
            con.execute(
                "INSERT INTO admin_login_logs(logged_at_ist,success,event,ip_address,user_agent) VALUES(?,?,?,?,?)",
                (now_ist(), 1 if success else 0, event[:40], ip, user_agent),
            )
        except Exception:
            pass


def _display_time_value(value):
    if value is None:
        return ""
    text_value = str(value)
    if not text_value or text_value.endswith(" IST"):
        return text_value
    raw = text_value[:-4].strip() if text_value.endswith(" UTC") else text_value
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            return dt.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        pass
    if text_value.endswith(" UTC"):
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.astimezone(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")
        except Exception:
            pass
    return text_value


def esc(value):
    return html.escape(_display_time_value(value), quote=True)


def _send_uploaded_content(data, name, mime=None):
    """Serve stored uploads without turning user/admin files into active HTML."""
    safe_name = Path(name or "uploaded-file").name
    guessed = mime or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    inline = guessed == "application/pdf" or guessed.startswith("image/")
    response = send_file(
        io.BytesIO(bytes(data)),
        mimetype=guessed,
        as_attachment=not inline,
        download_name=safe_name,
        max_age=300,
    )
    response.headers.setdefault("Cache-Control", "private, max-age=300")
    return response


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
        return sent


def setting(con, key, default=""):
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def invalidate_vybe_online_cache():
    _VYBE_ONLINE_CACHE["at"] = 0.0


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
    if key == "vybe_online":
        invalidate_vybe_online_cache()


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
                last_seen TEXT,
                reputation_points INTEGER NOT NULL DEFAULT 0,
                helpful_answers INTEGER NOT NULL DEFAULT 0,
                accepted_solutions INTEGER NOT NULL DEFAULT 0,
                bio TEXT NOT NULL DEFAULT '',
                interests TEXT NOT NULL DEFAULT '',
                id_card_file_name TEXT,
                id_card_original_name TEXT,
                id_card_mime_type TEXT,
                id_card_file_data BYTEA
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
                original_name TEXT,
                mime_type TEXT,
                file_data BYTEA,
                assistant_text TEXT NOT NULL DEFAULT '',
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
            """CREATE TABLE IF NOT EXISTS contact_terms_consents (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, student_id TEXT NOT NULL, ip_address TEXT NOT NULL, user_agent TEXT NOT NULL DEFAULT '', consented_at TEXT NOT NULL)""",
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
            """CREATE TABLE IF NOT EXISTS student_notifications (
                id BIGSERIAL PRIMARY KEY,
                recipient_student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                sender_student_id BIGINT REFERENCES students(id) ON DELETE SET NULL,
                reply_message_id BIGINT REFERENCES community_messages(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                read_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS assistant_knowledge (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                original_name TEXT,
                file_name TEXT,
                mime_type TEXT,
                file_data BYTEA,
                content TEXT NOT NULL DEFAULT '',
                source_type TEXT NOT NULL DEFAULT 'file',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
            """CREATE TABLE IF NOT EXISTS timetables (
                id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, file_name TEXT NOT NULL, original_name TEXT NOT NULL, created_at TEXT NOT NULL,
                file_data BYTEA, assistant_text TEXT NOT NULL DEFAULT ''
            )""",
            """CREATE TABLE IF NOT EXISTS announcements (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'Normal',
                created_at TEXT NOT NULL,
                expires_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS events (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                event_date TEXT NOT NULL,
                event_time TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
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
                last_seen TEXT,
                reputation_points INTEGER NOT NULL DEFAULT 0,
                helpful_answers INTEGER NOT NULL DEFAULT 0,
                accepted_solutions INTEGER NOT NULL DEFAULT 0,
                bio TEXT NOT NULL DEFAULT '',
                interests TEXT NOT NULL DEFAULT '',
                id_card_file_name TEXT,
                id_card_original_name TEXT,
                id_card_mime_type TEXT,
                id_card_file_data BLOB
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
                original_name TEXT,
                mime_type TEXT,
                file_data BLOB,
                assistant_text TEXT NOT NULL DEFAULT '',
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
            """CREATE TABLE IF NOT EXISTS contact_terms_consents (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, student_id TEXT NOT NULL, ip_address TEXT NOT NULL, user_agent TEXT NOT NULL DEFAULT '', consented_at TEXT NOT NULL)""",
            """CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                device_type TEXT,
                backed_up INTEGER NOT NULL DEFAULT 0,
                transports TEXT,
                created_at TEXT NOT NULL
            )""",            """CREATE TABLE IF NOT EXISTS community_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                reply_to_id INTEGER REFERENCES community_messages(id) ON DELETE SET NULL,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
            )""",
            """CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                student_id INTEGER,
                created_at TEXT NOT NULL,
                whatsapp_sent INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE SET NULL
            )""",
            """CREATE TABLE IF NOT EXISTS student_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_student_id INTEGER NOT NULL,
                sender_student_id INTEGER,
                reply_message_id INTEGER,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                read_at TEXT,
                FOREIGN KEY(recipient_student_id) REFERENCES students(id) ON DELETE CASCADE,
                FOREIGN KEY(sender_student_id) REFERENCES students(id) ON DELETE SET NULL,
                FOREIGN KEY(reply_message_id) REFERENCES community_messages(id) ON DELETE CASCADE
            )""",
            """CREATE TABLE IF NOT EXISTS assistant_knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                original_name TEXT,
                file_name TEXT,
                mime_type TEXT,
                file_data BLOB,
                content TEXT NOT NULL DEFAULT '',
                source_type TEXT NOT NULL DEFAULT 'file',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
            """CREATE TABLE IF NOT EXISTS timetables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, file_name TEXT NOT NULL, original_name TEXT NOT NULL, created_at TEXT NOT NULL,
                file_data BLOB, assistant_text TEXT NOT NULL DEFAULT ''
            )""",
            """CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'Normal',
                created_at TEXT NOT NULL,
                expires_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                event_date TEXT NOT NULL,
                event_time TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )""",
        ]
    con.executescript(statements)
    # Additive scheduling/location fields for announcements and events.
    for _sql in (
        "ALTER TABLE announcements ADD COLUMN publish_at TEXT",
        "ALTER TABLE events ADD COLUMN publish_at TEXT",
        "ALTER TABLE events ADD COLUMN location_url TEXT",
    ):
        try: con.execute(_sql)
        except Exception:
            try: con.rollback()
            except Exception: pass
    try:
        con.execute("UPDATE announcements SET publish_at=created_at WHERE publish_at IS NULL OR publish_at=''")
        con.execute("UPDATE events SET publish_at=created_at WHERE publish_at IS NULL OR publish_at=''")
        con.commit()
    except Exception:
        try: con.rollback()
        except Exception: pass
    # Additive Academic Hub storage. Existing VYBE tables are left untouched.
    if con.is_pg:
        con.execute("""CREATE TABLE IF NOT EXISTS academic_updates (id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'General Update', category TEXT NOT NULL DEFAULT 'General', title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', course TEXT NOT NULL DEFAULT '', semester TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '', event_date TEXT NOT NULL DEFAULT '', external_url TEXT NOT NULL DEFAULT '', file_name TEXT, original_name TEXT, mime_type TEXT, file_data BYTEA, created_at TEXT NOT NULL)""")
    else:
        con.execute("""CREATE TABLE IF NOT EXISTS academic_updates (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL DEFAULT 'General Update', category TEXT NOT NULL DEFAULT 'General', title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', course TEXT NOT NULL DEFAULT '', semester TEXT NOT NULL DEFAULT '', subject TEXT NOT NULL DEFAULT '', event_date TEXT NOT NULL DEFAULT '', external_url TEXT NOT NULL DEFAULT '', file_name TEXT, original_name TEXT, mime_type TEXT, file_data BLOB, created_at TEXT NOT NULL)""")

    if con.is_pg:
        con.execute("""CREATE TABLE IF NOT EXISTS student_update_views (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, item_type TEXT NOT NULL, item_id BIGINT NOT NULL, viewed_at TEXT NOT NULL, UNIQUE(student_id,item_type,item_id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS admin_problem_solutions (id BIGSERIAL PRIMARY KEY, issue_id BIGINT NOT NULL REFERENCES issues(id) ON DELETE CASCADE, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, solution_text TEXT NOT NULL, admin_label TEXT NOT NULL DEFAULT 'VYBE Admin', created_at TEXT NOT NULL)""")
    else:
        con.execute("""CREATE TABLE IF NOT EXISTS student_update_views (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, item_type TEXT NOT NULL, item_id INTEGER NOT NULL, viewed_at TEXT NOT NULL, UNIQUE(student_id,item_type,item_id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS admin_problem_solutions (id INTEGER PRIMARY KEY AUTOINCREMENT, issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, solution_text TEXT NOT NULL, admin_label TEXT NOT NULL DEFAULT 'VYBE Admin', created_at TEXT NOT NULL)""")

    if con.is_pg:
        con.executescript([
            "CREATE TABLE IF NOT EXISTS saved_reports (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, issue_category TEXT NOT NULL, issue_description TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, saved_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS accepted_solutions (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, accepted_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS helpful_votes (id BIGSERIAL PRIMARY KEY, solution_id BIGINT NOT NULL REFERENCES solutions(id) ON DELETE CASCADE, voter_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, created_at TEXT NOT NULL, UNIQUE(solution_id,voter_id))",
            "CREATE TABLE IF NOT EXISTS campus_pages (id BIGSERIAL PRIMARY KEY, source_url TEXT NOT NULL UNIQUE, title TEXT NOT NULL, text TEXT NOT NULL, updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS faculty (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, designation TEXT NOT NULL, email TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        ])
    else:
        con.executescript([
            "CREATE TABLE IF NOT EXISTS saved_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, issue_category TEXT NOT NULL, issue_description TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, saved_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS accepted_solutions (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, accepted_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS helpful_votes (id INTEGER PRIMARY KEY AUTOINCREMENT, solution_id INTEGER NOT NULL REFERENCES solutions(id) ON DELETE CASCADE, voter_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, created_at TEXT NOT NULL, UNIQUE(solution_id,voter_id))",
            "CREATE TABLE IF NOT EXISTS campus_pages (id INTEGER PRIMARY KEY AUTOINCREMENT, source_url TEXT NOT NULL UNIQUE, title TEXT NOT NULL, text TEXT NOT NULL, updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS faculty (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, designation TEXT NOT NULL, email TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        ])
    # Student-to-student notification storage for chat replies.
    if con.is_pg:
        con.execute("""CREATE TABLE IF NOT EXISTS student_notifications (
            id BIGSERIAL PRIMARY KEY,
            recipient_student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            sender_student_id BIGINT REFERENCES students(id) ON DELETE SET NULL,
            reply_message_id BIGINT REFERENCES community_messages(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT
        )""")
    else:
        con.execute("""CREATE TABLE IF NOT EXISTS student_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_student_id INTEGER NOT NULL,
            sender_student_id INTEGER,
            reply_message_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY(recipient_student_id) REFERENCES students(id) ON DELETE CASCADE,
            FOREIGN KEY(sender_student_id) REFERENCES students(id) ON DELETE SET NULL,
            FOREIGN KEY(reply_message_id) REFERENCES community_messages(id) ON DELETE CASCADE
        )""")

    if not con.is_pg:
        cols_now={r['name'] for r in con.execute('PRAGMA table_info(students)').fetchall()}
        for col,definition in (
            ('admit_card_file_name','TEXT'),('admit_card_original_name','TEXT'),('admit_card_mime_type','TEXT'),('admit_card_file_data','BLOB'),
            ('id_card_file_name','TEXT'),('id_card_original_name','TEXT'),('id_card_mime_type','TEXT'),('id_card_file_data','BLOB')
        ):
            if col not in cols_now: con.execute(f'ALTER TABLE students ADD COLUMN {col} {definition}')
    else:
        for col,definition in (
            ('admit_card_file_name','TEXT'),('admit_card_original_name','TEXT'),('admit_card_mime_type','TEXT'),('admit_card_file_data','BYTEA'),
            ('id_card_file_name','TEXT'),('id_card_original_name','TEXT'),('id_card_mime_type','TEXT'),('id_card_file_data','BYTEA')
        ):
            con.execute(f'ALTER TABLE students ADD COLUMN IF NOT EXISTS {col} {definition}')
        con.execute('ALTER TABLE community_messages ADD COLUMN IF NOT EXISTS reply_to_id BIGINT REFERENCES community_messages(id) ON DELETE SET NULL')
    # One-time compatibility copy for profiles created before the dedicated ID-card fields existed.
    try:
        con.execute("UPDATE students SET id_card_file_name=COALESCE(id_card_file_name,admit_card_file_name), id_card_original_name=COALESCE(id_card_original_name,admit_card_original_name), id_card_mime_type=COALESCE(id_card_mime_type,admit_card_mime_type), id_card_file_data=COALESCE(id_card_file_data,admit_card_file_data) WHERE id_card_file_name IS NULL AND admit_card_file_name IS NOT NULL")
    except Exception:
        pass
    # Backward-compatible reply column for existing local databases.
    if not con.is_pg:
        cols_chat={r['name'] for r in con.execute('PRAGMA table_info(community_messages)').fetchall()}
        if 'reply_to_id' not in cols_chat:
            con.execute('ALTER TABLE community_messages ADD COLUMN reply_to_id INTEGER REFERENCES community_messages(id) ON DELETE SET NULL')

    # Lightweight migration for the earlier VYBE_V2 SQLite schema.
    if not con.is_pg:
        cols = {r["name"] for r in con.execute("PRAGMA table_info(resources)").fetchall()}
        if "resource_type" not in cols:
            con.execute("ALTER TABLE resources ADD COLUMN resource_type TEXT NOT NULL DEFAULT 'Study material'")
        if "original_name" not in cols:
            con.execute("ALTER TABLE resources ADD COLUMN original_name TEXT")
        if "mime_type" not in cols:
            con.execute("ALTER TABLE resources ADD COLUMN mime_type TEXT")
        if "file_data" not in cols:
            con.execute("ALTER TABLE resources ADD COLUMN file_data BLOB")
        if "assistant_text" not in cols:
            con.execute("ALTER TABLE resources ADD COLUMN assistant_text TEXT NOT NULL DEFAULT ''")
        tt_cols = {r["name"] for r in con.execute("PRAGMA table_info(timetables)").fetchall()}
        for col,definition in (("mime_type","TEXT"),("drive_file_id","TEXT"),("drive_folder_id","TEXT"),("drive_web_url","TEXT"),("file_data","BLOB"),("assistant_text","TEXT NOT NULL DEFAULT ''")):
            if col not in tt_cols:
                con.execute(f"ALTER TABLE timetables ADD COLUMN {col} {definition}")
        au_cols = {r["name"] for r in con.execute("PRAGMA table_info(academic_updates)").fetchall()}
        for col in ("drive_file_id","drive_folder_id","drive_web_url"):
            if col not in au_cols:
                con.execute(f"ALTER TABLE academic_updates ADD COLUMN {col} TEXT")
    else:
        # PostgreSQL migrations are idempotent and safe on existing deployments.
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT 'Study material'")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS original_name TEXT")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS mime_type TEXT")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS file_data BYTEA")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS assistant_text TEXT NOT NULL DEFAULT ''")
        # Existing deployments may have the original small timetable schema.
        # Drive-backed publishing needs these additive columns; CREATE TABLE IF NOT EXISTS
        # does not modify an already-existing Neon table, so migrate them explicitly.
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS mime_type TEXT")
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS drive_file_id TEXT")
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS drive_folder_id TEXT")
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS drive_web_url TEXT")
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS file_data BYTEA")
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS assistant_text TEXT NOT NULL DEFAULT ''")
        # Existing deployments may also have the original academic-updates schema.
        con.execute("ALTER TABLE academic_updates ADD COLUMN IF NOT EXISTS drive_file_id TEXT")
        con.execute("ALTER TABLE academic_updates ADD COLUMN IF NOT EXISTS drive_folder_id TEXT")
        con.execute("ALTER TABLE academic_updates ADD COLUMN IF NOT EXISTS drive_web_url TEXT")
        # Existing Render databases may have an older SMALLINT/TEXT success column.
        # Normalize it to BOOLEAN before the application starts so admin login logging cannot fail.
        con.execute("ALTER TABLE admin_login_logs ADD COLUMN IF NOT EXISTS success BOOLEAN NOT NULL DEFAULT FALSE")
        success_type = con.execute(
            "SELECT data_type FROM information_schema.columns WHERE table_name='admin_login_logs' AND column_name='success' LIMIT 1"
        ).fetchone()
        if success_type and str(success_type["data_type"]).lower() != "boolean":
            con.execute("ALTER TABLE admin_login_logs ALTER COLUMN success TYPE BOOLEAN USING CASE WHEN LOWER(success::text) IN ('1','t','true','yes','y') THEN TRUE ELSE FALSE END")

    if not con.is_pg:
        student_cols = {r["name"] for r in con.execute("PRAGMA table_info(students)").fetchall()}
        if "last_seen" not in student_cols:
            con.execute("ALTER TABLE students ADD COLUMN last_seen TEXT")
    else:
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS last_seen TEXT")
    # Student profile/reputation migrations for existing VYBE deployments.
    if not con.is_pg:
        student_cols = {r["name"] for r in con.execute("PRAGMA table_info(students)").fetchall()}
        for col, definition in (
            ("reputation_points", "INTEGER NOT NULL DEFAULT 0"),
            ("helpful_answers", "INTEGER NOT NULL DEFAULT 0"),
            ("accepted_solutions", "INTEGER NOT NULL DEFAULT 0"),
            ("bio", "TEXT NOT NULL DEFAULT ''"),
            ("interests", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in student_cols:
                con.execute(f"ALTER TABLE students ADD COLUMN {col} {definition}")
    else:
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS reputation_points INTEGER NOT NULL DEFAULT 0")
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS helpful_answers INTEGER NOT NULL DEFAULT 0")
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS accepted_solutions INTEGER NOT NULL DEFAULT 0")
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT ''")
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS interests TEXT NOT NULL DEFAULT ''")

    if not con.is_pg:
        reset_cols = {r["name"] for r in con.execute("PRAGMA table_info(password_reset_requests)").fetchall()}
        if "approval_code_token" not in reset_cols:
            con.execute("ALTER TABLE password_reset_requests ADD COLUMN approval_code_token TEXT")
    else:
        con.execute("ALTER TABLE password_reset_requests ADD COLUMN IF NOT EXISTS approval_code_token TEXT")

    try:
        _ensure_password_reset_active_index(con)
    except Exception:
        pass

    defaults = {
        "whatsapp_link": "",
        "google_drive_url": DRIVE_URL,
        "vybe_online": "1",
        **({"admin_password_hash": hash_password(INITIAL_ADMIN_PASSWORD)} if INITIAL_ADMIN_PASSWORD else {}),
        "whatsapp_notifications_enabled": "0",
        "whatsapp_api_version": "v23.0",
        "whatsapp_phone_number_id": "",
        "whatsapp_access_token": "",
        "whatsapp_admin_number": "",
        "community_chat_enabled": "1",
        "vybe_assistant_enabled": "1",
        "vybe_ai_shortcuts": json.dumps(["study_material", "admit_card", "date_sheets", "previous_papers", "timetable", "updates"]),
    }
    for key, value in defaults.items():
        if setting(con, key, None) is None:
            set_setting(con, key, value)

    # Incremental chat polling uses id > after_id; keep that lookup indexed.
    # Hot-path indexes for the student library, notifications and admin queues.
    # They are additive and safe for existing Neon/SQLite databases.
    _ensure_password_reset_schema(con)
    _ensure_password_reset_active_index(con)

    for _idx in (
        "CREATE INDEX IF NOT EXISTS idx_resources_type_semester_subject ON resources(resource_type, semester, subject)",
        "CREATE INDEX IF NOT EXISTS idx_academic_updates_kind_id ON academic_updates(kind, id)",
        "CREATE INDEX IF NOT EXISTS idx_student_notifications_recipient_id ON student_notifications(recipient_student_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_issues_status_id ON issues(status, id)",
        "CREATE INDEX IF NOT EXISTS idx_issues_student_id ON issues(student_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_solutions_issue_id ON solutions(issue_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_admin_problem_solutions_student_id ON admin_problem_solutions(student_id, id)",
    ):
        try:
            con.execute(_idx)
        except Exception:
            pass
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Authentication / authorization decorators are deliberately defined BEFORE
# any route that uses them. This fixes the deployed NameError.
# ---------------------------------------------------------------------------
def student_is_online(last_seen, timeout_seconds=300):
    if not last_seen:
        return False
    raw = str(last_seen).strip()
    try:
        if raw.endswith(" IST"):
            seen = datetime.strptime(raw[:-4].strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo("Asia/Kolkata"))
        elif raw.endswith(" UTC"):
            seen = datetime.strptime(raw[:-4].strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        else:
            seen = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - seen.astimezone(timezone.utc)).total_seconds() <= timeout_seconds
    except Exception:
        return False


_AUTHZ_CACHE_LOCK = threading.Lock()
_AUTHZ_CACHE = {}
_AUTHZ_CACHE_TTL = 20.0

def _student_status_cached(sid):
    key = int(sid)
    now_m = time.monotonic()
    with _AUTHZ_CACHE_LOCK:
        item = _AUTHZ_CACHE.get(("student", key))
        if item and item[0] > now_m:
            return item[1]
    con = db()
    try:
        row = con.execute("SELECT id,status FROM students WHERE id=?", (key,)).fetchone()
        status = row["status"] if row else None
    finally:
        con.close()
    with _AUTHZ_CACHE_LOCK:
        _AUTHZ_CACHE[("student", key)] = (now_m + _AUTHZ_CACHE_TTL, status)
    return status

_HEADER_CACHE_TTL = 30.0
def _student_header_updates_cached(sid):
    key=("header_updates",int(sid))
    now_m=time.monotonic()
    with _AUTHZ_CACHE_LOCK:
        item=_AUTHZ_CACHE.get(key)
        if item and item[0] > now_m:
            return item[1]
    con=db()
    try:
        rows=_admin_update_feed(con,int(sid),20)
    finally:
        con.close()
    with _AUTHZ_CACHE_LOCK:
        _AUTHZ_CACHE[key]=(now_m+_HEADER_CACHE_TTL,rows)
    return rows

_AI_SETTINGS_CACHE_TTL = 120.0
def _student_ai_settings_cached():
    key=("ai_settings",0)
    now_m=time.monotonic()
    with _AUTHZ_CACHE_LOCK:
        item=_AUTHZ_CACHE.get(key)
        if item and item[0] > now_m:
            return item[1]
    con=db()
    try:
        enabled=setting(con,"vybe_assistant_enabled","1")=="1"
        raw=setting(con,"vybe_ai_shortcuts","[]") or "[]"
    finally:
        con.close()
    try:
        selected=json.loads(raw)
        if not isinstance(selected,list): selected=[]
    except Exception:
        selected=[]
    value=(enabled,selected)
    with _AUTHZ_CACHE_LOCK:
        _AUTHZ_CACHE[key]=(now_m+_AI_SETTINGS_CACHE_TTL,value)
    return value

def _passkey_count_cached():
    now_m = time.monotonic()
    with _AUTHZ_CACHE_LOCK:
        item = _AUTHZ_CACHE.get(("passkey", 0))
        if item and item[0] > now_m:
            return int(item[1])
    con = db()
    try:
        count = int(con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"])
    finally:
        con.close()
    with _AUTHZ_CACHE_LOCK:
        _AUTHZ_CACHE[("passkey", 0)] = (now_m + _AUTHZ_CACHE_TTL, count)
    return count

def student_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        sid = session.get("student_db_id")
        if not sid:
            return redirect(url_for("login"))
        try:
            status = _student_status_cached(sid)
        except Exception as exc:
            app.logger.error("Student authentication check failed: %s: %s", type(exc).__name__, exc, exc_info=(type(exc), exc, exc.__traceback__))
            session.clear()
            flash("VYBE could not verify your account right now. Please try again.")
            return redirect(url_for("login"))
        if status != "approved":
            session.clear()
            flash("Your student access is not currently active.")
            return redirect(url_for("login"))
        touch_now = time.monotonic()
        last_touch = float(session.get("_student_presence_touch", 0) or 0)
        if touch_now - last_touch >= 60:
            con = None
            try:
                con = db()
                con.execute("UPDATE students SET last_seen=? WHERE id=?", (now(), int(sid)))
                con.commit()
                session["_student_presence_touch"] = touch_now
            except Exception:
                pass
            finally:
                if con is not None:
                    try: con.close()
                    except Exception: pass
        return fn(*args, **kwargs)
    return wrapper


PUBLISHER_PERMISSION_CATALOG = [
    ("announcements", "Announcements", "Publish campus-wide announcements."),
    ("events", "Events", "Create upcoming campus events."),
    ("timetable", "Timetable", "Upload new timetable versions."),
    ("academic_updates", "Academic Updates", "Publish academic notices, results, date sheets and exam updates."),
    ("academic_resources", "Academic Hub Resources", "Add notes, study material, syllabus and previous-year resources."),
]

def publisher_permissions(student_id, con=None):
    """Read publisher permissions safely, including legacy settings."""
    own_con = con is None
    if own_con:
        con = db()
    try:
        sid = int(student_id)
        allowed = {k for k, _, _ in PUBLISHER_PERMISSION_CATALOG}
        try:
            row = con.execute("SELECT value FROM settings WHERE key=?", (f"publisher_permissions_{sid}",)).fetchone()
        except Exception:
            row = None
        if row and row["value"]:
            try:
                data = json.loads(str(row["value"]))
                if isinstance(data, list):
                    return {str(x) for x in data if str(x) in allowed}
            except Exception:
                pass
        try:
            legacy = con.execute("SELECT value FROM settings WHERE key=?", (f"content_manager_{sid}",)).fetchone()
        except Exception:
            legacy = None
        return {"announcements", "events", "timetable"} if legacy and str(legacy["value"]) == "1" else set()
    except Exception:
        app.logger.exception("Could not read publisher permissions for student %s", student_id)
        return set()
    finally:
        if own_con and con is not None:
            try: con.close()
            except Exception: pass


PUBLISHER_ACCESS_PICKER_CSS = """
<style>
.publisher-picker-card,.publisher-controls-card{max-width:900px;margin:0 auto 16px}.publisher-picker-label{display:block;font-size:10px;font-weight:900;letter-spacing:.11em;color:#667887;margin-bottom:8px}.publisher-picker-form select{width:100%;min-height:48px;border:1px solid #d6e0e7;border-radius:13px;background:#fff;color:#17202b;padding:0 13px;font:inherit}.publisher-selected{margin-top:12px;padding:12px 14px;border:1px solid #dce5eb;border-radius:14px;background:#f8fbfd;display:flex;align-items:center;justify-content:space-between;gap:12px}.publisher-selected strong{display:block;font-size:14px}.publisher-selected small{display:block;color:#71808d;font-size:11px;margin-top:3px}.publisher-selected-empty{display:block}.publisher-control-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px}.publisher-control-option{display:flex;align-items:flex-start;gap:10px;padding:13px;border:1px solid #dce5eb;border-radius:14px;background:#fff;cursor:pointer}.publisher-control-option input{margin-top:2px;width:17px;height:17px;accent-color:#2f6fca}.publisher-control-option strong{display:block;font-size:12px}.publisher-control-option small{display:block;margin-top:3px;color:#71808d;font-size:10px;line-height:1.4}.publisher-control-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}@media(max-width:700px){.publisher-picker-card,.publisher-controls-card{margin-bottom:12px}.publisher-control-grid{grid-template-columns:1fr}.publisher-control-actions{display:grid}.publisher-control-actions .btn{width:100%}.publisher-selected{align-items:flex-start;flex-direction:column}.publisher-selected .pill{align-self:flex-start}}
</style>
"""

def publisher_is_active(student_id, con=None):
    """Return whether a student currently has publisher access."""
    own_con = con is None
    if own_con:
        con = db()
    try:
        sid = int(student_id)
        rows = con.execute(
            "SELECT key,value FROM settings WHERE key IN (?,?)",
            (f"content_manager_{sid}", f"publisher_permissions_{sid}"),
        ).fetchall()
        values = {str(r["key"]): str(r["value"] or "").strip() for r in rows}
        flag = values.get(f"content_manager_{sid}", "").lower() in {"1", "true", "yes", "on"}
        if flag:
            return True
        try:
            data = json.loads(values.get(f"publisher_permissions_{sid}", "[]") or "[]")
            allowed = {k for k, _, _ in PUBLISHER_PERMISSION_CATALOG}
            return isinstance(data, list) and any(str(x) in allowed for x in data)
        except Exception:
            return False
    except Exception:
        return False
    finally:
        if own_con and con is not None:
            try:
                con.close()
            except Exception:
                pass


def content_manager_required(fn):
    @wraps(fn)
    @student_required
    def wrapper(*args, **kwargs):
        sid = session.get("student_db_id")
        if not publisher_is_active(sid) or not publisher_permissions(sid):
            flash("You do not have publisher access.")
            return redirect(url_for("dashboard"))
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
            try:
                count = _passkey_count_cached()
            except Exception as exc:
                app.logger.error("Admin passkey check failed: %s: %s", type(exc).__name__, exc, exc_info=(type(exc), exc, exc.__traceback__))
                flash("VYBE could not verify admin security right now. Please try again.")
                return redirect(url_for("admin_login"))
            if count > 0 and not session.get("passkey_verified"):
                return redirect(url_for("admin_verify"))
        return fn(*args, **kwargs)
    return wrapper




def admin_password_hash(con):
    stored = setting(con, "admin_password_hash", "")
    if not stored:
        if not INITIAL_ADMIN_PASSWORD:
            raise RuntimeError("Admin password is not configured. Set VYBE_ADMIN_INITIAL_PASSWORD for a fresh installation.")
        stored = hash_password(INITIAL_ADMIN_PASSWORD)
        set_setting(con, "admin_password_hash", stored)
        con.commit()
    return stored


def webauthn_configured():
    return WEBAUTHN_AVAILABLE and bool(PASSKEY_RP_ID and PASSKEY_ORIGIN)


# ---------------------------------------------------------------------------
# Offline gate: admin login/admin routes remain available while public/student
# routes receive the dedicated offline page.
# ---------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    """Small Render health endpoint that does not depend on student/admin state."""
    try:
        con = db()
        con.execute("SELECT 1").fetchone()
        con.close()
        return jsonify(ok=True, service="VYBE")
    except Exception as exc:
        app.logger.error("VYBE health check failed: %s: %s", type(exc).__name__, exc, exc_info=(type(exc), exc, exc.__traceback__))
        return jsonify(ok=False, service="VYBE", error="database unavailable"), 503


# ---------------------------------------------------------------------------
# Production request protections
# ---------------------------------------------------------------------------
_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_BUCKETS = defaultdict(deque)
_RATE_LIMIT_RULES = {
    ("POST", "/login"): (10, 300),
    ("POST", "/register"): (8, 900),
    ("POST", "/forgot-password"): (5, 900),
    ("GET", "/forgot-password/status"): (30, 300),
    ("POST", "/reset-password"): (8, 900),
    ("POST", "/account/password"): (8, 900),
    ("POST", "/admin"): (6, 300),
    ("POST", "/admin/login-passkey/options"): (12, 300),
    ("POST", "/admin/login-passkey/verify"): (12, 300),
    ("POST", "/passkey/auth/options"): (12, 300),
    ("POST", "/passkey/auth/verify"): (12, 300),
    ("POST", "/passkey/register/options"): (8, 600),
    ("POST", "/passkey/register/verify"): (8, 600),
    ("POST", "/community/chat"): (40, 60),
    ("POST", "/community/problems"): (20, 300),
}

def _client_ip():
    return (request.remote_addr or "unknown")[:64]

def _rate_limited(method, path):
    rule = _RATE_LIMIT_RULES.get((method, path))
    if not rule:
        # A conservative fallback protects every admin state-changing endpoint
        # even if a new route is added later without an explicit rule.
        if method in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith("/admin/"):
            rule = (80, 60)
        else:
            return False
    limit, window = rule
    identity = ""
    if path in {"/login", "/register", "/forgot-password"} and method == "POST":
        identity = request.form.get("student_id", "").strip().lower()[:80]
    key = f"{method}:{path}:{_client_ip()}:{identity}"
    cutoff = time.monotonic() - window
    now_m = time.monotonic()
    with _RATE_LIMIT_LOCK:
        # Bound the in-process limiter so a rotating-IP attack cannot grow the
        # dictionary without limit. Expired buckets are cheap to discard.
        if len(_RATE_LIMIT_BUCKETS) > 10000:
            stale = [k for k, q in _RATE_LIMIT_BUCKETS.items() if not q or q[-1] <= cutoff]
            for k in stale[:5000]:
                _RATE_LIMIT_BUCKETS.pop(k, None)
        q = _RATE_LIMIT_BUCKETS[key]
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now_m)
    return False

def _security_client_ip():
    """Return the client IP as seen through Vercel's trusted proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        candidate = forwarded.split(",", 1)[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    real = request.headers.get("X-Real-IP", "").strip()
    try:
        ipaddress.ip_address(real)
        return real
    except ValueError:
        return (request.remote_addr or "unknown")[:100]

_SECURITY_CACHE_LOCK = threading.Lock()
_SECURITY_DEVICE_CACHE = {}
_SECURITY_CACHE_TTL = 30.0
_SECURITY_DEVICE_COOKIE = "__Host-vybe_device" if _COOKIE_SECURE else "vybe_device"
_SECURITY_DEVICE_MAX_AGE = 60 * 60 * 24 * 365
_SECURITY_LOCK_COOKIE = "__Host-vybe_lock" if _COOKIE_SECURE else "vybe_lock"
_SECURITY_LOCK_MAX_AGE = 60 * 60 * 24


def _security_device_token():
    """Return a stable random browser token, never a hardware fingerprint."""
    token = getattr(g, "vybe_device_token", None)
    if token:
        return token
    token = request.cookies.get(_SECURITY_DEVICE_COOKIE, "").strip()
    if len(token) < 32 or len(token) > 200:
        token = secrets.token_urlsafe(32)
        g.vybe_device_cookie_new = True
    g.vybe_device_token = token
    return token


def _security_device_hash(token=None):
    token = token or _security_device_token()
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _security_cache_set(device_hash, blocked_until):
    with _SECURITY_CACHE_LOCK:
        _SECURITY_DEVICE_CACHE[device_hash] = (time.monotonic() + _SECURITY_CACHE_TTL, float(blocked_until or 0))
        if len(_SECURITY_DEVICE_CACHE) > 10000:
            now_m = time.monotonic()
            stale = [k for k, (expires, _) in _SECURITY_DEVICE_CACHE.items() if expires <= now_m]
            for k in stale[:5000]:
                _SECURITY_DEVICE_CACHE.pop(k, None)


def _security_cache_get(device_hash):
    with _SECURITY_CACHE_LOCK:
        item = _SECURITY_DEVICE_CACHE.get(device_hash)
        if not item:
            return None
        expires, blocked_until = item
        if expires <= time.monotonic():
            _SECURITY_DEVICE_CACHE.pop(device_hash, None)
            return None
        return blocked_until


def _security_block_status(con, device_hash):
    try:
        row = con.execute("SELECT * FROM vybe_security_devices WHERE device_hash=?", (device_hash,)).fetchone()
    except Exception as exc:
        app.logger.error("VYBE security block lookup failed: %s: %s", type(exc).__name__, exc)
        return None
    if not row:
        return None
    until = float(row["blocked_until"] or 0)
    if until > time.time():
        return row
    try:
        con.execute("UPDATE vybe_security_devices SET failed_attempts=0, first_failed_at=0, blocked_until=0, updated_at=? WHERE device_hash=?", (now(), device_hash))
        con.commit()
    except Exception:
        try: con.rollback()
        except Exception: pass
    _security_cache_set(device_hash, 0)
    return None


def _security_block_page(until=0):
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Access temporarily blocked · VYBE</title><style>body{margin:0;background:#020817;color:#eef8ff;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box}.box{width:min(560px,100%);padding:38px;border:1px solid rgba(111,190,230,.2);border-radius:24px;background:linear-gradient(145deg,rgba(9,30,47,.97),rgba(3,14,25,.98));box-shadow:0 25px 80px rgba(0,0,0,.45);text-align:center;box-sizing:border-box}.mark{width:62px;height:62px;border-radius:18px;margin:0 auto 22px;display:grid;place-items:center;background:rgba(255,112,112,.12);border:1px solid rgba(255,112,112,.28);color:#ff9b9b;font-weight:900;font-size:25px}.eyebrow{font-size:11px;font-weight:850;letter-spacing:.14em;color:#8fc9e8}h1{font-size:31px;line-height:1.1;margin:10px 0 14px}p{color:#aac0cf;line-height:1.65;margin:0}.notice{margin-top:22px;padding:15px 16px;border-radius:14px;background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.08);font-size:13px}strong{color:#fff}</style></head><body><main class="box"><div class="mark">!</div><div class="eyebrow">VYBE SECURITY</div><h1>Access temporarily blocked.</h1><p>There were too many unsuccessful login attempts from this browser.</p><div class="notice"><strong>Limit exceeded.</strong><br>For your security, access to VYBE is blocked for 24 hours. Please try again after the block expires.</div><a href="/security/clear-block" style="display:inline-block;margin-top:18px;padding:12px 18px;border-radius:12px;background:#eef8ff;color:#06111b;text-decoration:none;font-weight:800">Try VYBE again</a></main></body></html>"""


def _security_failed_login(con, name, student_id, area):
    """Persist failed attempts by account + VYBE device, never by shared IP alone.

    Security failures must never turn into a generic 500 page. If the security
    tables are temporarily unavailable, log the problem and let the normal
    login error continue rather than breaking authentication.
    """
    device_hash = _security_device_hash()
    ip = _security_client_ip()
    current = time.time()
    name = str(name or "Unknown").strip()[:120]
    student_id = str(student_id or "").strip()[:120]
    area = str(area or "").strip()[:40] or "Student"
    account_key = hashlib.sha256((area.lower() + "|" + student_id.lower()).encode("utf-8")).hexdigest()
    try:
        existing_device = _security_block_status(con, device_hash)
        if existing_device:
            return True, float(existing_device["blocked_until"] or current), int(existing_device["failed_attempts"] or 3)

        row = con.execute(
            "SELECT * FROM vybe_security_attempts WHERE account_key=? AND device_hash=? AND area=?",
            (account_key, device_hash, area),
        ).fetchone()
        if row and float(row["first_failed_at"] or 0) and current - float(row["first_failed_at"]) >= 86400:
            attempts, first = 0, current
        elif row:
            attempts, first = int(row["failed_attempts"] or 0), float(row["first_failed_at"] or current)
        else:
            attempts, first = 0, current
        attempts += 1

        if row:
            con.execute(
                "UPDATE vybe_security_attempts SET failed_attempts=?, first_failed_at=?, updated_at=? WHERE account_key=? AND device_hash=? AND area=?",
                (attempts, first, now(), account_key, device_hash, area),
            )
        else:
            con.execute(
                "INSERT INTO vybe_security_attempts(account_key,device_hash,area,failed_attempts,first_failed_at,updated_at) VALUES(?,?,?,?,?,?)",
                (account_key, device_hash, area, attempts, first, now()),
            )

        blocked_until = current + 86400 if attempts >= 3 else 0
        if blocked_until:
            existing = con.execute(
                "SELECT device_hash FROM vybe_security_devices WHERE device_hash=?", (device_hash,)
            ).fetchone()
            if existing:
                con.execute(
                    "UPDATE vybe_security_devices SET failed_attempts=?, first_failed_at=?, blocked_until=?, last_name=?, last_student_id=?, last_area=?, last_ip=?, updated_at=? WHERE device_hash=?",
                    (attempts, first, blocked_until, name, student_id, area, ip, now(), device_hash),
                )
            else:
                con.execute(
                    "INSERT INTO vybe_security_devices(device_hash,failed_attempts,first_failed_at,blocked_until,last_name,last_student_id,last_area,last_ip,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (device_hash, attempts, first, blocked_until, name, student_id, area, ip, now(), now()),
                )
            con.execute(
                "INSERT INTO vybe_security_alerts(created_at,alert_type,name,student_id,ip_address,area,blocked_until,message) VALUES(?,?,?,?,?,?,?,?)",
                (now_ist(), "login_block", name, student_id, ip, area, blocked_until,
                 f"3 failed {area.lower()} password attempts on one VYBE device; device blocked for 24 hours."),
            )
            _security_cache_set(device_hash, blocked_until)
            g.vybe_security_lock_until = blocked_until
        con.commit()
        return bool(blocked_until), blocked_until, attempts
    except Exception as exc:
        try:
            con.rollback()
        except Exception:
            pass
        app.logger.error("VYBE login-security tracking failed: %s: %s", type(exc).__name__, exc)
        return False, 0, 0


def _security_successful_login(con, area, student_id):
    """Clear the failed counter for this account/device after a valid login."""
    try:
        device_hash = _security_device_hash()
        account_key = hashlib.sha256((str(area).lower() + "|" + str(student_id).lower()).encode("utf-8")).hexdigest()
        con.execute("DELETE FROM vybe_security_attempts WHERE account_key=? AND device_hash=? AND area=?", (account_key, device_hash, area))
        con.commit()
    except Exception:
        try: con.rollback()
        except Exception: pass


def _security_blocked_request_response():
    """Fast block check using a signed 24-hour lock cookie.

    The signed cookie is deliberately checked before Neon so normal page loads
    do not open a database connection just to determine whether a browser is
    blocked. The persistent Neon device record remains the source of truth when
    a login attempt is processed.
    """
    raw_lock = request.cookies.get(_SECURITY_LOCK_COOKIE, "").strip()
    if raw_lock:
        try:
            payload = security_lock_serializer.loads(raw_lock, max_age=_SECURITY_LOCK_MAX_AGE)
            until = float(payload.get("until", 0)) if isinstance(payload, dict) else 0
            device_hash = str(payload.get("device_hash", "")) if isinstance(payload, dict) else ""
            if until > time.time() and len(device_hash) == 64:
                # A lock cookie is the fast path, but an administrator must be
                # able to revoke the lock immediately. Only requests carrying
                # an active lock cookie hit Neon; normal users still avoid this
                # database query entirely.
                con = db()
                try:
                    row = con.execute("SELECT blocked_until FROM vybe_security_devices WHERE device_hash=?", (device_hash,)).fetchone()
                finally:
                    con.close()
                server_until = float(row["blocked_until"] or 0) if row else 0
                if server_until > time.time():
                    return _security_block_page(server_until)
                # The admin removed the lock (or it expired). Clear the stale
                # browser cookie and let this request continue normally.
                response = redirect(request.path)
                response.delete_cookie(_SECURITY_LOCK_COOKIE, path="/")
                return response
            if until > time.time():
                return _security_block_page(until)
        except (BadSignature, SignatureExpired, ValueError, TypeError):
            pass

    token = request.cookies.get(_SECURITY_DEVICE_COOKIE, "").strip()
    if len(token) < 32 or len(token) > 200:
        return None
    device_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    cached = _security_cache_get(device_hash)
    if cached is not None:
        if cached <= time.time():
            _security_cache_set(device_hash, 0)
            return None
        # A warm Vercel instance may still have an old in-memory block after
        # an admin removes it on another instance. Re-check the persistent
        # record before serving the block page so an admin unblock is immediate
        # across Vercel instances. Only devices already known as blocked take
        # this database path; normal visitors still stay on the zero-DB hot path.
        try:
            con = db()
            try:
                row = con.execute(
                    "SELECT blocked_until FROM vybe_security_devices WHERE device_hash=?",
                    (device_hash,),
                ).fetchone()
            finally:
                con.close()
            server_until = float(row["blocked_until"] or 0) if row else 0
            if server_until > time.time():
                _security_cache_set(device_hash, server_until)
                return _security_block_page(server_until)
            _security_cache_set(device_hash, 0)
            return None
        except Exception as exc:
            # If Neon is temporarily unavailable, preserve the existing block
            # rather than accidentally bypassing a security lock. The admin can
            # still remove it once the database is reachable.
            app.logger.warning("VYBE blocked-device verification failed: %s: %s", type(exc).__name__, exc)
            return _security_block_page(cached)
    # No lock cookie and no active blocked-device cache: keep the normal request
    # path free of a Neon lookup.
    return None

@app.route("/security/clear-block")
def security_clear_block():
    """Recover a browser after an administrator has revoked its security block.

    This endpoint never bypasses an active Neon block. It only clears stale
    browser cookies when the persistent device record is no longer blocked.
    """
    token = request.cookies.get(_SECURITY_DEVICE_COOKIE, "").strip()
    device_hash = hashlib.sha256(token.encode("utf-8")).hexdigest() if 32 <= len(token) <= 200 else ""
    if device_hash:
        try:
            con = db()
            row = con.execute(
                "SELECT blocked_until FROM vybe_security_devices WHERE device_hash=?",
                (device_hash,),
            ).fetchone()
            con.close()
            if row and float(row["blocked_until"] or 0) > time.time():
                return _security_block_page(float(row["blocked_until"])), 429, {
                    "Cache-Control": "no-store",
                    "X-Robots-Tag": "noindex, nofollow",
                }
            _security_cache_set(device_hash, 0)
        except Exception as exc:
            app.logger.warning("VYBE security recovery lookup failed: %s: %s", type(exc).__name__, exc)
            return _security_block_page(), 429, {
                "Cache-Control": "no-store",
                "X-Robots-Tag": "noindex, nofollow",
            }

    # Go to the public VYBE entry page, not the dashboard. If the student
    # session is valid, / will immediately route them to the dashboard; if not,
    # it will show the normal VYBE home/login entry page.
    response = redirect(url_for("home"))
    response.delete_cookie(_SECURITY_LOCK_COOKIE, path="/", secure=_COOKIE_SECURE)
    response.delete_cookie(_SECURITY_DEVICE_COOKIE, path="/", secure=_COOKIE_SECURE)
    return response


def _same_origin_unsafe_request():
    """Layered CSRF protection: same-origin plus a per-session token."""
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    origin = request.headers.get("Origin", "").strip()
    if origin:
        try:
            expected = f"{request.scheme}://{request.host}"
            return origin.rstrip("/").lower() == expected.rstrip("/").lower()
        except Exception:
            return False
    referer = request.headers.get("Referer", "").strip()
    if referer:
        try:
            rp = urlparse(referer)
            return rp.scheme == request.scheme and rp.netloc == request.host
        except Exception:
            return False
    # Browser POSTs normally include Origin or Referer. Refuse ambiguous
    # requests rather than silently weakening CSRF protection.
    return False

def _csrf_token_valid():
    expected = session.get("_csrf_token")
    if not expected:
        return False
    supplied = request.headers.get("X-VYBE-CSRF", "").strip() or request.form.get("csrf_token", "").strip()
    return bool(supplied) and secrets.compare_digest(str(expected), str(supplied))


_VYBE_ONLINE_CACHE = {"at": 0.0, "value": True}


@app.after_request
def set_security_device_cookie(response):
    if getattr(g, "vybe_device_cookie_new", False):
        response.set_cookie(
            _SECURITY_DEVICE_COOKIE,
            g.vybe_device_token,
            max_age=_SECURITY_DEVICE_MAX_AGE,
            secure=_COOKIE_SECURE,
            httponly=True,
            samesite="Lax",
            path="/",
        )
    lock_until = getattr(g, "vybe_security_lock_until", 0)
    if lock_until and float(lock_until) > time.time():
        signed = security_lock_serializer.dumps({"until": float(lock_until), "device_hash": _security_device_hash()})
        response.set_cookie(
            _SECURITY_LOCK_COOKIE,
            signed,
            max_age=_SECURITY_LOCK_MAX_AGE,
            expires=datetime.fromtimestamp(float(lock_until), timezone.utc),
            secure=_COOKIE_SECURE,
            httponly=True,
            samesite="Lax",
            path="/",
        )
    return response


@app.before_request
def global_online_gate():
    path = request.path
    if _PRODUCTION and _ALLOWED_HOSTS_RAW:
        host = (request.host or "").split(":", 1)[0].lower().strip(".")
        if host not in _ALLOWED_HOSTS:
            abort(400, description="Unrecognized VYBE host.")
    if path == "/security/clear-block":
        return None
    _security_device_token()
    blocked_response = _security_blocked_request_response()
    if blocked_response:
        # When an admin has revoked a block, the security check returns a real
        # redirect after scheduling deletion of the stale lock cookie. Do not
        # wrap that redirect in HTTP 429: browsers will not follow redirects
        # carrying a 429 status, which would leave the student stuck on the
        # blocked page even though the Neon block was already removed.
        if getattr(blocked_response, "status_code", 200) in {301, 302, 303, 307, 308}:
            return blocked_response
        return blocked_response, 429, {"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"}
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not _same_origin_unsafe_request():
            abort(403, description="Cross-site requests are not allowed.")
        csrf_bootstrap_paths = {
            "/login", "/register", "/forgot-password", "/admin",
            "/admin/login-passkey/options", "/admin/login-passkey/verify",
            "/passkey/register/options", "/passkey/register/verify",
            "/passkey/auth/options", "/passkey/auth/verify",
        }
        if path not in csrf_bootstrap_paths and not _csrf_token_valid():
            abort(403, description="Security verification failed. Refresh the page and try again.")
    if _rate_limited(request.method, path):
        abort(429, description="Too many requests. Please try again shortly.")
    if path.startswith("/admin") or path.startswith("/passkey") or path in ("/offline", "/healthz", "/"):
        return None
    # Cache the global online flag briefly per warm Vercel instance. This avoids
    # an extra database round-trip on every page navigation/API call while still
    # making the admin Online/Offline switch propagate quickly.
    global _VYBE_ONLINE_CACHE
    now_m = time.monotonic()
    if now_m - _VYBE_ONLINE_CACHE["at"] >= 1.5:
        try:
            con = db()
            _VYBE_ONLINE_CACHE["value"] = setting(con, "vybe_online", "1") == "1"
            con.close()
            _VYBE_ONLINE_CACHE["at"] = now_m
        except Exception:
            # Fail open rather than turning a transient database connection issue
            # into a completely unavailable campus site.
            _VYBE_ONLINE_CACHE["value"] = True
            _VYBE_ONLINE_CACHE["at"] = now_m
    if not _VYBE_ONLINE_CACHE["value"]:
        return redirect(url_for("offline"))
    return None



@app.errorhandler(HTTPException)
def handle_http_exception(error):
    code=getattr(error,"code",500) or 500
    if code==404: title="Page not found."; message="The page you are looking for may have moved, been removed, or never existed."; label="404 · NOT FOUND"
    elif code==403: title="Access restricted."; message="You don't have permission to open this VYBE page."; label="403 · FORBIDDEN"
    elif code==405: title="Action not available."; message="That request cannot be used on this VYBE page."; label="405 · METHOD NOT ALLOWED"
    elif code==429: title="Slow down for a moment."; message="VYBE received too many requests at once. Please try again shortly."; label="429 · TOO MANY REQUESTS"
    elif code==503: title="VYBE is unavailable."; message="The service is temporarily unavailable. Please try again in a moment."; label="503 · UNAVAILABLE"
    else: title="Something went wrong."; message="VYBE could not complete that request. Please try again."; label=f"{code} · VYBE ERROR"
    app.logger.warning("VYBE HTTP %s: %s",code,getattr(error,"description",str(error)))
    body=f'''<header class="vybe-top"><a class="vybe-brand" href="/"><span class="vybe-brand-mark"><span>V</span></span><span>VYBE</span></a><a class="vybe-admin-mini" href="/admin">Admin Login</a></header><section class="vybe-status-wrap"><div class="vybe-status-card"><div class="vybe-error-code">{label}</div><div class="vybe-status-mark">V</div><h1>{title}</h1><p>{message}</p><div class="status-actions"><a class="vybe-action primary" href="/">Back to VYBE</a><a class="vybe-action" href="/admin">Admin Login</a></div></div></section>'''
    return _vybe_public_shell(f"{code} · VYBE",body),code

@app.errorhandler(Exception)
def handle_unexpected_exception(error):
    if isinstance(error,HTTPException): return handle_http_exception(error)
    app.logger.error("UNHANDLED VYBE EXCEPTION: %s: %s",type(error).__name__,str(error),exc_info=(type(error),error,error.__traceback__))
    body='''<header class="vybe-top"><a class="vybe-brand" href="/"><span class="vybe-brand-mark"><span>V</span></span><span>VYBE</span></a><a class="vybe-admin-mini" href="/admin">Admin Login</a></header><section class="vybe-status-wrap"><div class="vybe-status-card"><div class="vybe-error-code">500 · SERVER ERROR</div><div class="vybe-status-mark">V</div><h1>Something went wrong.</h1><p>VYBE hit an unexpected application error. Your data was not intentionally changed. Please go back and try again.</p><div class="status-actions"><a class="vybe-action primary" href="/">Back to VYBE</a><a class="vybe-action" href="/admin">Admin Login</a></div></div></section>'''
    return _vybe_public_shell("500 · VYBE",body),500

@app.errorhandler(500)
def handle_internal_server_error(error):
    original=getattr(error,"original_exception",None)
    if original is not None: app.logger.error("VYBE ORIGINAL 500 EXCEPTION: %s: %s",type(original).__name__,str(original),exc_info=(type(original),original,original.__traceback__))
    else: app.logger.error("VYBE 500 response: %s",error,exc_info=(type(error),error,error.__traceback__))
    return handle_unexpected_exception(original or error)

@app.after_request
def security_headers(response):
    # Every successful admin write advances a tiny shared content version.
    # Student browsers use this version for a lightweight soft-sync, so an
    # admin publish/edit/delete becomes visible without a browser refresh.
    if (session.get("admin_authenticated") and request.method in ("POST", "PUT", "PATCH", "DELETE")
            and 200 <= getattr(response, "status_code", 500) < 400):
        try:
            con = db()
            con.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("student_content_version", now()),
            )
            con.commit()
            con.close()
        except Exception:
            try:
                con.close()
            except Exception:
                pass
            app.logger.warning("Could not advance student content version", exc_info=True)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self' data:; connect-src 'self' https://api.openai.com; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'self' https://drive.google.com https://docs.google.com"
    if session.get("student_db_id") or session.get("admin_authenticated"):
        response.headers["Cache-Control"] = "private, no-store, max-age=0"
    elif request.path == "/" and request.method == "GET":
        # The public VYBE landing page is database-free and safe to edge-cache.
        # This lets repeat visits/opening the VYBE link come from the Vercel
        # edge instead of invoking a Python function every time.
        response.headers["Cache-Control"] = "public, max-age=30, s-maxage=120, stale-while-revalidate=300"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


CSS = r"""
/* Student community chat controls */
.community-chat-tools{display:flex;align-items:center;justify-content:flex-end;gap:10px;margin:0 0 10px;min-height:38px}
.community-select-help{font-size:11px;color:#718ba3;margin-right:auto}.community-select-help.is-hidden{display:none}.community-selection-actions{display:none;align-items:center;gap:7px;margin-left:auto}
.community-selection-actions.is-visible{display:flex}
.community-selection-count{font-size:11px;color:#8fa6bd;white-space:nowrap}
.community-delete-toolbar{display:flex;align-items:center;gap:7px}
.community-delete-toolbar button{border:1px solid rgba(255,255,255,.12);border-radius:11px;padding:8px 11px;background:rgba(255,255,255,.045);color:#c7d5e2;cursor:pointer;font:inherit;font-size:11px;font-weight:700}
.community-delete-toolbar .community-delete-selected{color:#ffb7bf;border-color:rgba(255,100,120,.22)}
.community-delete-toolbar .community-delete-selected:hover{background:rgba(255,70,70,.09);border-color:rgba(255,100,120,.40)}
.community-delete-toolbar .community-delete-all{color:#ff9c9c;border-color:rgba(255,100,100,.18)}
.community-delete-toolbar .community-selection-done{color:#c7d5e2}
.community-delete-toolbar button:disabled{opacity:.45;cursor:not-allowed}
.community-delete-toolbar .community-delete-all:hover{background:rgba(255,70,70,.08);color:#ffb4b4}
.community-message{display:flex;align-items:flex-start;gap:8px;transition:background .15s ease,border-color .15s ease,transform .12s ease;user-select:none}.community-message:active{transform:scale(.995)}
.community-message.is-selectable{cursor:pointer}
.community-message.is-selected{border-color:rgba(37,170,242,.48);background:rgba(37,170,242,.075)}
.community-message-content{min-width:0;flex:1}
.community-chat-disabled-note{margin-top:10px;padding:10px 12px;border:1px solid rgba(255,255,255,.07);border-radius:12px;color:#91a9c0;font-size:12px}
.community-chat-keyboard-hint{margin-top:6px;color:#6f879d;font-size:11px;text-align:right}
.community-chat-form textarea{overflow:hidden;line-height:1.45;min-height:46px;max-height:140px;resize:none}
@media(max-width:850px){
  .community-chat-tools{margin-bottom:8px}
  .community-chat-tools{padding:2px 0 7px;min-height:36px}.community-selection-actions{gap:5px}.community-selection-count{font-size:10px}.community-delete-toolbar{gap:5px}.community-delete-toolbar button{min-height:34px;padding:7px 8px;font-size:10px}.community-select-help{font-size:10px}
  .community-chat-keyboard-hint{text-align:center;font-size:10px}
  .community-message-select{flex-basis:20px}
}

/* ===== FRIENDLY CHAT UI — familiar messaging layout ===== */
.community-chat-page-section{padding-top:18px!important}.community-chat-page-section .community-page-top{max-width:1040px!important;margin-bottom:14px!important}.community-chat-page-section .community-page-top h1{font-size:clamp(34px,5vw,56px)!important;margin:7px 0 5px!important}.community-chat-page-section .community-page-top p{font-size:13px!important}
.community-chat-page-card{max-width:1040px!important;padding:0!important;overflow:hidden!important;border-radius:24px!important;background:#f6f8fb!important;border:1px solid #dfe5ea!important;box-shadow:0 24px 70px rgba(20,35,50,.13)!important}
.community-chat-page-card .community-chat-tools{height:58px;margin:0!important;padding:0 18px!important;background:#fff!important;border-bottom:1px solid #e5e9ed!important}.community-chat-page-card .community-select-help{margin:0!important;color:#7a8793!important;font-size:12px!important}.community-chat-page-card .community-selection-actions{display:none!important}.community-chat-window{height:clamp(430px,62vh,680px)!important;max-height:none!important;min-height:430px!important;padding:24px 24px 30px!important;gap:12px!important;background:linear-gradient(180deg,#f7f9fb,#eef2f5)!important}
.community-message{position:relative!important;max-width:min(72%,680px)!important;padding:10px 13px!important;border-radius:17px!important;background:#fff!important;border:1px solid #e0e6eb!important;box-shadow:0 3px 10px rgba(31,45,58,.055)!important;user-select:text!important;cursor:default!important}.community-message.mine{background:#eaf3ff!important;border-color:#d2e3f6!important;border-bottom-right-radius:6px!important}.community-message:not(.mine){border-bottom-left-radius:6px!important}.community-message-content{min-width:0!important}.community-message-head{margin-bottom:3px!important}.community-message-head strong{font-size:12px!important;font-weight:750!important;color:#31506b!important}.community-message.mine .community-message-head strong{color:#285f9e!important}.community-message-text{font-size:14px!important;line-height:1.48!important;color:#1d2a35!important;white-space:pre-wrap!important}.community-message-meta{display:flex;justify-content:flex-end;margin-top:5px;font-size:10px;color:#83909b}.community-message-actions{display:flex;gap:5px;margin-top:7px;opacity:.72}.community-message-action{border:1px solid #dce4ea!important;background:#fff!important;color:#53616d!important;border-radius:9px!important;padding:5px 8px!important;font:inherit!important;font-size:10px!important;font-weight:700!important;cursor:pointer!important;box-shadow:none!important}.community-message-action:hover{background:#f1f6fa!important;color:#245f92!important}.community-message-action.delete{color:#c33c49!important;border-color:#f0d5d8!important}.community-reply-reference{margin:0 0 7px!important;padding:7px 9px!important;background:#f3f7fa!important;border-left:3px solid #5797c9!important;border-radius:8px!important;color:#536674!important}.community-reply-reference strong{color:#326b99!important;font-size:10px!important}.community-reply-reference span{color:#788995!important}.community-reply-bar{margin:0!important;border:0!important;border-top:1px solid #e3e8ed!important;border-left:3px solid #4e8fc2!important;border-radius:0!important;padding:9px 18px!important;background:#fff!important}.community-chat-form{display:grid!important;grid-template-columns:minmax(0,1fr) 48px!important;gap:9px!important;margin:0!important;padding:12px 14px!important;background:#fff!important;border-top:1px solid #e3e8ed!important}.community-chat-form textarea{height:46px!important;min-height:46px!important;padding:12px 15px!important;border-radius:16px!important;background:#f5f7f9!important;color:#1e2a34!important;border:1px solid #dce3e8!important;box-shadow:none!important}.community-chat-form textarea::placeholder{color:#8a97a1!important}.community-send-button{width:46px;height:46px;border:0;border-radius:15px;background:#2f6fca;color:#fff;font-size:18px;font-weight:800;cursor:pointer;box-shadow:0 8px 18px rgba(47,111,202,.22);display:grid;place-items:center}.community-chat-keyboard-hint{display:none!important}
@media (hover:hover){.community-message-actions{opacity:0}.community-message:hover .community-message-actions{opacity:1}}
@media(max-width:850px){.community-chat-page-section{padding:8px 8px 18px!important}.community-chat-page-section .community-page-top{padding:0 3px!important;margin-bottom:9px!important}.community-chat-page-section .community-page-top h1{font-size:29px!important}.community-chat-page-section .community-page-top p{font-size:11px!important}.community-chat-page-card{border-radius:20px!important;height:calc(100dvh - 230px)!important;max-height:700px!important;display:flex!important;flex-direction:column!important}.community-chat-page-card .community-chat-tools{height:48px;padding:0 11px!important}.community-chat-page-card .community-select-help{font-size:10px!important}.community-chat-window{height:auto!important;min-height:0!important;flex:1!important;padding:16px 10px 18px!important;gap:9px!important}.community-message{max-width:88%!important;padding:9px 11px!important;border-radius:15px!important}.community-message-text{font-size:13px!important}.community-message-actions{opacity:1!important;margin-top:6px!important}.community-message-action{padding:5px 8px!important;font-size:10px!important}.community-chat-form{grid-template-columns:minmax(0,1fr) 44px!important;padding:9px 9px calc(9px + env(safe-area-inset-bottom))!important;gap:7px!important}.community-chat-form textarea{height:44px!important;min-height:44px!important;border-radius:15px!important}.community-send-button{width:44px;height:44px;border-radius:14px!important}.community-reply-bar{padding:8px 11px!important}}

:root{--bg:#01040a;--bg2:#020914;--panel:rgba(3,14,27,.86);--line:rgba(28,91,145,.24);--line2:rgba(37,116,181,.48);--text:#eef6ff;--muted:#8fa6bd;--good:#5de6a1;--warn:#ffd166;--bad:#ff6878;--accent:#268fd0;--accent2:#073f6b;--shadow:0 28px 90px rgba(0,0,0,.68)}
*{box-sizing:border-box}html{scroll-behavior:auto}body{margin:0;background:radial-gradient(900px 500px at 50% -180px,rgba(255,255,255,.105),transparent 62%),radial-gradient(700px 500px at 100% 15%,rgba(255,255,255,.035),transparent 65%),var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",sans-serif;min-height:100vh;letter-spacing:-.012em}a{text-decoration:none;color:inherit}.nav{position:sticky;top:0;z-index:50;background:rgba(5,5,5,.72);backdrop-filter:saturate(180%) blur(24px);-webkit-backdrop-filter:saturate(180%) blur(24px);border-bottom:1px solid rgba(255,255,255,.075)}.navin{max-width:1180px;margin:auto;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{font-weight:800;letter-spacing:-.055em;font-size:23px}.brandmark{display:inline-grid;place-items:center;width:31px;height:31px;margin-right:8px;border-radius:9px;background:#f5f5f7;color:#050505;font-size:14px;font-weight:900;box-shadow:0 5px 18px rgba(255,255,255,.08)}.navlinks{display:flex;gap:4px;flex-wrap:wrap}.navlinks a{padding:9px 11px;border-radius:11px;color:#b7b7bd;font-size:13px;transition:.2s ease}.navlinks a:hover{background:rgba(255,255,255,.07);color:#fff}.wrap{max-width:1180px;margin:auto;padding:24px 20px 80px}.hero{min-height:68vh;display:grid;place-items:center;text-align:center;padding:80px 0 50px}.hero h1{font-size:clamp(76px,14vw,155px);line-height:.78;margin:18px 0;letter-spacing:-.1em;background:linear-gradient(180deg,#fff 8%,#d7d7da 45%,#5d5d63 100%);-webkit-background-clip:text;background-clip:text;color:transparent}.hero p{max-width:690px;color:var(--muted);font-size:18px;line-height:1.65;margin:0 auto 28px}.badge,.pill{display:inline-block;border:1px solid var(--line);background:rgba(255,255,255,.045);padding:7px 11px;border-radius:999px;color:#c9c9ce;font-size:12px;backdrop-filter:blur(12px)}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.grid2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.card{background:linear-gradient(145deg,rgba(255,255,255,.075),rgba(255,255,255,.028));border:1px solid var(--line);border-radius:26px;padding:22px;box-shadow:var(--shadow);transition:border-color .16s ease,background .16s ease}.card:hover{transform:translateY(-3px);border-color:var(--line2);background:linear-gradient(145deg,rgba(255,255,255,.09),rgba(255,255,255,.035))}.card h2,.card h3{margin:0 0 9px;letter-spacing:-.035em}.muted{color:var(--muted)}.small{font-size:13px;color:var(--muted)}.btn{display:inline-flex;align-items:center;justify-content:center;border:1px solid transparent;cursor:pointer;padding:11px 16px;border-radius:14px;background:#f5f5f7;color:#080808;font-weight:750;transition:transform .2s ease,opacity .2s ease,background .2s ease;box-shadow:0 8px 24px rgba(0,0,0,.18)}.btn:hover{transform:translateY(-1px)}.btn:active{transform:scale(.98)}.btn:disabled{opacity:.55;cursor:not-allowed;transform:none}.btn.dark{background:rgba(255,255,255,.075);color:#fff;border-color:var(--line);box-shadow:none}.btn.good{background:rgba(45,180,105,.12);color:#9bf2bf;border-color:rgba(98,230,162,.25);box-shadow:none}.btn.danger{background:rgba(255,70,90,.11);color:#ffb5bd;border-color:rgba(255,104,120,.23);box-shadow:none}.btn.accent{background:linear-gradient(180deg,#fff,#d7d7da);color:#080808}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}.section{padding:30px 0}.auth{min-height:80vh;display:grid;place-items:center}.authbox{width:min(470px,100%)}.form{display:grid;gap:13px}.label{font-size:13px;color:#b5b5bb;margin-bottom:5px}input,textarea,select{width:100%;padding:13px 14px;background:rgba(255,255,255,.045);color:#fff;border:1px solid #2a2a2e;border-radius:14px;outline:none;transition:border-color .2s,background .2s,box-shadow .2s}input::placeholder,textarea::placeholder{color:#68686e}input:focus,textarea:focus,select:focus{border-color:#707076;background:rgba(255,255,255,.06);box-shadow:0 0 0 4px rgba(255,255,255,.045)}textarea{min-height:125px;resize:vertical}.flash{padding:13px 15px;border:1px solid #303035;background:rgba(255,255,255,.055);border-radius:15px;margin:10px 0;backdrop-filter:blur(14px)}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid #29292e;vertical-align:top}.tablewrap{overflow:auto}.kpi{font-size:38px;font-weight:850;letter-spacing:-.065em}.footer{padding:50px 0;color:#606066;text-align:center}.empty{text-align:center;padding:45px;color:var(--muted);border:1px dashed #2b2b31;border-radius:20px}.status-good{color:var(--good)}.status-warn{color:var(--warn)}.status-bad{color:var(--bad)}.online{color:var(--good)}.offline{color:var(--bad)}.icon{font-size:30px;margin-bottom:12px}.resource-meta{display:flex;gap:7px;flex-wrap:wrap;margin:10px 0}.danger-zone{border-color:#5a252d}.notice{padding:16px;border-radius:17px;background:rgba(255,255,255,.045);border:1px solid var(--line);line-height:1.55}.chat{display:grid;gap:9px;margin-top:15px}.bubble{padding:13px 15px;border-radius:17px;background:rgba(255,255,255,.045);border:1px solid #24242a}.mine{border-color:#34343b}.offline-page{min-height:78vh;display:grid;place-items:center;text-align:center}.offline-page h1{font-size:clamp(48px,8vw,92px);letter-spacing:-.07em;margin:12px 0} .community-launch{position:relative;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:20px 22px;min-height:92px;overflow:hidden;background:linear-gradient(135deg,rgba(255,255,255,.10),rgba(255,255,255,.035));border:1px solid rgba(255,255,255,.13);border-radius:24px;box-shadow:0 20px 55px rgba(0,0,0,.28);transition:transform .25s ease,border-color .25s ease,background .25s ease}.community-launch:before{content:"";position:absolute;inset:-80px auto auto -50px;width:180px;height:180px;background:rgba(255,255,255,.07);filter:blur(35px);border-radius:50%}.community-launch:hover{transform:translateY(-3px);border-color:rgba(255,255,255,.24);background:linear-gradient(135deg,rgba(255,255,255,.14),rgba(255,255,255,.045))}.student-presence{display:inline-flex;align-items:center;gap:8px}.presence-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex:0 0 8px}.presence-dot.is-online{background:#32d74b;box-shadow:0 0 9px rgba(50,215,75,.55)}.presence-dot.is-offline{background:#ff453a}.community-icon{position:relative;z-index:1;width:50px;height:50px;display:grid;place-items:center;border-radius:16px;background:#f5f5f7;color:#080808;font-size:22px;box-shadow:0 8px 25px rgba(255,255,255,.10)}.community-copy{position:relative;z-index:1;flex:1}.community-copy h3{margin:0 0 4px;font-size:18px}.community-copy p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.community-arrow{position:relative;z-index:1;width:38px;height:38px;border:1px solid var(--line);border-radius:12px;display:grid;place-items:center;color:#fff;background:rgba(255,255,255,.06);font-size:18px}.chat-composer{position:sticky;bottom:14px;padding:14px;border-radius:20px;background:rgba(10,10,12,.78);border:1px solid var(--line);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:0 18px 50px rgba(0,0,0,.35)}
.notice-card{position:relative;overflow:hidden}
.notice-card:after{content:"";position:absolute;inset:auto -40px -70px auto;width:170px;height:170px;background:rgba(255,255,255,.045);filter:blur(25px);border-radius:50%}
.event-date{font-size:30px;font-weight:850;letter-spacing:-.06em}
.feed-list{display:grid;gap:12px}
.feed-item{padding:17px 18px;border:1px solid var(--line);border-radius:19px;background:rgba(255,255,255,.04);transition:.2s ease}
.feed-item:hover{transform:translateY(-2px);border-color:var(--line2)}
.ai-box{background:linear-gradient(145deg,rgba(255,255,255,.10),rgba(255,255,255,.035));border:1px solid rgba(255,255,255,.14);border-radius:28px;padding:24px;box-shadow:var(--shadow)}
.ai-answer{white-space:pre-wrap;line-height:1.7}
.profile-avatar{width:74px;height:74px;border-radius:22px;background:#f5f5f7;color:#080808;display:grid;place-items:center;font-size:28px;font-weight:900;box-shadow:0 12px 30px rgba(255,255,255,.08)}
.stat-row{display:flex;gap:10px;flex-wrap:wrap}
.stat-chip{padding:10px 13px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.045)}
.student-top-tools{display:flex;align-items:center;gap:6px;flex:1;justify-content:flex-end}.top-stat,.top-tool{min-height:38px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.055);display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:7px 9px;color:#eee;font-size:12px;white-space:nowrap}.top-stat{flex-direction:column;line-height:1;min-width:58px}.top-stat small{font-size:8px;color:var(--muted);text-transform:uppercase}.top-search{display:flex;align-items:center;width:190px}.top-search input{height:38px;border-radius:12px 0 0 12px;padding:8px 10px;font-size:12px}.top-search button{height:38px;width:38px;border:1px solid #2a2a2e;border-left:0;border-radius:0 12px 12px 0;background:rgba(255,255,255,.08);color:#fff;cursor:pointer}.page-back,.mobile-back{border:1px solid var(--line);background:rgba(255,255,255,.05);color:#ddd;border-radius:12px;padding:8px 12px;cursor:pointer}.page-back{margin:2px 0 4px}.mobile-back{display:none;width:100%;text-align:left}
.student-home{max-width:900px;margin:0 auto;padding:34px 0 20px}.student-home-head{text-align:left;padding:12px 2px 28px}.student-space-pill{display:inline-flex;align-items:center;padding:9px 15px;border:1px solid rgba(0,174,255,.75);border-radius:999px;color:#5fc9ff;background:rgba(0,151,255,.08);font-size:12px;font-weight:800;letter-spacing:.08em}.student-home-head h1{font-size:clamp(38px,6vw,58px);line-height:1.02;margin:24px 0 10px;letter-spacing:-.06em}.student-home-head p{font-size:18px;color:#a9b9d0;margin:0}.student-home-stats{display:flex;gap:9px;flex-wrap:wrap;margin-top:18px}.student-home-stats span{padding:8px 11px;border-radius:12px;background:rgba(255,255,255,.045);border:1px solid var(--line);color:#cdd7e5;font-size:12px}.student-feature-list{display:grid;gap:14px}.student-feature,.student-wide-link{position:relative;display:flex;align-items:center;gap:18px;min-height:112px;padding:20px 22px;border:1px solid rgba(92,124,157,.28);border-radius:24px;background:linear-gradient(135deg,rgba(19,29,41,.92),rgba(9,14,20,.9));box-shadow:0 18px 50px rgba(0,0,0,.25);transition:.25s ease;overflow:hidden}.student-feature:hover,.student-wide-link:hover{transform:translateY(-2px);border-color:rgba(74,181,255,.5);box-shadow:0 22px 60px rgba(0,0,0,.32)}.student-feature.primary{border-color:rgba(0,190,255,.78);background:linear-gradient(135deg,rgba(14,42,61,.96),rgba(9,16,24,.94));box-shadow:0 0 0 1px rgba(0,180,255,.06),0 20px 65px rgba(0,112,190,.13)}.student-feature-icon{width:58px;height:58px;flex:0 0 58px;display:grid;place-items:center;border-radius:18px;background:linear-gradient(145deg,rgba(60,96,132,.45),rgba(15,27,40,.8));border:1px solid rgba(130,181,225,.22);font-size:27px;box-shadow:inset 0 1px rgba(255,255,255,.08)}.student-feature-copy{min-width:0;flex:1;display:flex;flex-direction:column;gap:5px}.student-feature-copy strong{font-size:21px;letter-spacing:-.035em}.student-feature-copy small,.student-feature-copy em{font-size:14px;color:#a7b8cf;line-height:1.45;font-style:normal}.student-feature-copy em{font-size:12px;color:#70caff}.student-arrow{font-size:37px;color:#8ba6c5;line-height:1}.student-mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.student-mini{display:flex;align-items:center;gap:12px;min-height:78px;padding:12px 16px;border:1px solid rgba(92,124,157,.28);border-radius:22px;background:linear-gradient(135deg,rgba(19,29,41,.92),rgba(9,14,20,.9));transition:.25s ease}.student-mini:hover{transform:translateY(-2px);border-color:rgba(74,181,255,.5)}.student-mini .student-feature-icon{width:48px;height:48px;flex-basis:48px;font-size:21px;border-radius:15px}.student-mini strong{font-size:14px;flex:1}.student-mini>span:last-child{font-size:29px;color:#829ab7}.student-wide-link{margin-top:14px;min-height:84px}.student-wide-link .student-feature-icon{width:50px;height:50px;flex-basis:50px;font-size:23px}.student-wide-link span:nth-child(2){display:flex;flex-direction:column;gap:4px;flex:1}.student-wide-link strong{font-size:17px}.student-wide-link small{color:#a7b8cf}.campus-tools{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:18px 0}.campus-tool{display:flex;align-items:center;gap:13px;padding:16px;border-radius:20px;border:1px solid rgba(92,124,157,.28);background:linear-gradient(135deg,rgba(19,29,41,.92),rgba(9,14,20,.9));transition:.2s ease}.campus-tool:hover{transform:translateY(-2px);border-color:rgba(74,181,255,.5)}.campus-tool-icon{width:46px;height:46px;display:grid;place-items:center;border-radius:15px;background:rgba(52,91,125,.3);font-size:22px}.campus-tool span:nth-child(2){display:flex;flex-direction:column;gap:3px;flex:1}.campus-tool strong{font-size:15px}.campus-tool small{font-size:11px;color:#9eb0c5}.campus-tool b{font-size:26px;color:#819bb9;font-weight:400}.nav-toggle{display:none;width:42px;height:42px;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.06);color:#fff;font-size:20px;cursor:pointer}.mobile-nav{display:none}.mobile-nav a{display:block;padding:12px 14px;border-radius:13px;color:#ddd}.nav{position:relative}.mobile-nav.open{display:grid;gap:4px;position:absolute;right:18px;top:72px;z-index:120;min-width:210px;padding:10px;border:1px solid rgba(58,145,214,.28);border-radius:18px;background:rgba(3,12,22,.97);box-shadow:0 22px 60px rgba(0,0,0,.5);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}.mobile-nav a:hover{background:rgba(255,255,255,.07)}@media(max-width:850px){.timetable-head{padding:8px 0 6px}.timetable-head h1{font-size:34px;letter-spacing:-.045em;margin:14px 0 7px}.timetable-head .muted{font-size:13px;line-height:1.45}.timetable-list{padding:8px 0 18px;display:grid;gap:12px}.timetable-card{padding:14px;border-radius:20px;overflow:hidden}.timetable-card h2{font-size:18px;line-height:1.2;margin:10px 0 5px}.timetable-card .small{font-size:11px}.timetable-preview{width:100%;overflow:hidden;border-radius:14px;margin-top:10px;background:#030a12;border:1px solid rgba(58,145,214,.18)}.timetable-preview img{width:100%!important;height:auto!important;max-height:none!important;object-fit:contain!important;border-radius:14px!important;display:block}.timetable-actions{margin-top:10px;display:flex}.timetable-actions .btn{width:100%;justify-content:center;text-align:center;padding:12px 14px;font-size:13px}.timetable-card .notice{padding:14px}.timetable-card .notice strong{font-size:13px;word-break:break-word}}@media(max-width:850px){.student-bottom-nav a{flex:1;min-width:0}.student-bottom-nav .mobile-menu-nav{order:1}.student-bottom-nav .mobile-home-nav{order:2}.student-bottom-nav .mobile-profile-nav{order:3}.student-bottom-nav .mobile-back-nav{order:4}}\n@media(max-width:850px){.grid,.grid2,.two,.campus-tools{grid-template-columns:1fr}.navin{padding:9px 10px;gap:5px}.navlinks{display:none}.nav-toggle{display:grid;place-items:center;width:40px;height:40px}.brand{font-size:0;flex:0 0 34px}.brandmark{margin:0;width:32px;height:32px}.student-top-tools{gap:4px;overflow:hidden;justify-content:flex-start}.top-stat{min-width:38px;width:38px;padding:5px 2px;font-size:9px}.top-stat small{display:none}.top-tool{width:55px;min-width:55px;padding:6px 2px;font-size:9px}.top-search{width:64px;min-width:64px}.top-search input{font-size:10px;padding:7px}.top-search button{width:30px}.mobile-nav.open{display:grid;gap:4px;padding:10px 14px 14px;border-top:1px solid rgba(255,255,255,.06);background:rgba(5,5,5,.94);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px)}.mobile-back{display:block}.menu-sub{padding-left:28px!important;font-size:12px!important;color:#aaa!important}.wrap{padding:12px}.student-home{padding-top:18px}.student-home-head h1{font-size:39px}.student-home-head p{font-size:15px}.student-feature{min-height:96px;padding:16px}.student-feature-icon{width:52px;height:52px;flex-basis:52px;font-size:24px}.student-feature-copy strong{font-size:18px}.student-feature-copy small{font-size:13px}.student-mini{min-height:72px;padding:10px}.student-mini-grid{grid-template-columns:1fr}.student-wide-link{min-height:78px}.page-back{display:inline-flex}.hero{min-height:0;display:flex;align-items:flex-start;justify-content:center;padding:34px 0 24px}.hero>div{width:100%;display:flex;flex-direction:column;align-items:center}.hero .badge{max-width:100%;text-align:center}.hero h1{font-size:68px;line-height:.9;margin:18px 0 14px}.hero p{max-width:320px;font-size:17px;line-height:1.5;margin:0 auto 24px}.hero .actions{width:100%;max-width:340px;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:0}.hero .actions .btn{width:100%;max-width:none;min-width:0;box-sizing:border-box}.hero .actions .btn:last-child{grid-column:1/-1;justify-self:center;width:calc((100% - 10px)/2)}.card{border-radius:22px}.actions .btn{max-width:100%}}

.admin-header{min-width:0}.admin-navlinks{display:flex;align-items:center;gap:4px;flex:1;min-width:0;overflow-x:auto;scrollbar-width:none;margin-left:12px}.admin-navlinks::-webkit-scrollbar{display:none}.admin-navlinks a{flex:0 0 auto;padding:8px 9px;border-radius:10px;color:#c9d8e7;font-size:11px;white-space:nowrap}.admin-navlinks a:hover{background:rgba(25,101,157,.18);color:#fff}.admin-header .nav-toggle{display:none;flex:0 0 auto}@media(max-width:1050px){.admin-navlinks{gap:2px}.admin-navlinks a{padding:7px 6px;font-size:10px}}@media(max-width:850px){.admin-navlinks{display:none}.admin-header .nav-toggle{display:grid;place-items:center}}

/* VYBE dark-blue visual system + exact student reference chrome */
body{background:radial-gradient(900px 560px at 50% -240px,rgba(13,95,160,.24),transparent 64%),radial-gradient(700px 500px at 100% 15%,rgba(6,67,120,.18),transparent 68%),linear-gradient(180deg,#020713 0%,#020a16 48%,#01060e 100%)}
.nav{background:rgba(2,9,18,.84);border-bottom:1px solid rgba(50,135,205,.18)}
.brandmark{background:linear-gradient(145deg,#1eaaff,#0a568e);color:#fff;box-shadow:0 0 25px rgba(17,146,230,.2)}
.brandtext{background:linear-gradient(180deg,#fff,#b7cce0);-webkit-background-clip:text;background-clip:text;color:transparent}
.navlinks{display:none}.page-back{display:none!important}
.nav-toggle{display:grid;place-items:center;width:42px;height:42px;border:1px solid rgba(58,145,214,.25);border-radius:14px;background:rgba(8,30,52,.72);color:#fff}
.mobile-nav{background:rgba(2,10,19,.96);border-top:1px solid rgba(46,130,200,.16)}
.mobile-nav a:hover{background:rgba(20,93,145,.16);border-color:rgba(58,145,214,.25)}
.btn{background:linear-gradient(180deg,#168bd0,#075384);color:#fff;border-color:rgba(63,163,230,.3);box-shadow:0 8px 24px rgba(0,67,120,.2)}
.btn.accent{background:linear-gradient(180deg,#20adff,#0969a7);color:#fff;border-color:rgba(77,183,247,.55)}
.btn.dark{background:rgba(8,31,51,.8);color:#e9f5ff;border-color:rgba(58,145,214,.25)}
.card{background:linear-gradient(145deg,rgba(10,31,51,.82),rgba(4,14,25,.9));border-color:rgba(58,145,214,.25)}
.card:hover{background:linear-gradient(145deg,rgba(12,40,66,.88),rgba(4,16,28,.94));border-color:rgba(54,169,255,.55)}
input,textarea,select{background:rgba(4,18,31,.82);border-color:rgba(56,127,181,.28)}
input:focus,textarea:focus,select:focus{border-color:#2d9de0;background:rgba(6,25,43,.9);box-shadow:0 0 0 4px rgba(18,139,214,.1)}
.authbox{background:linear-gradient(145deg,rgba(8,30,51,.9),rgba(3,12,22,.96))}
.ai-box{background:linear-gradient(145deg,rgba(9,38,63,.9),rgba(3,15,27,.94));border-color:rgba(54,157,222,.35)}
.feed-item{background:rgba(6,26,44,.62);border-color:rgba(58,145,214,.25)}
.student-header-tools{display:flex;align-items:center;gap:8px;margin-left:auto}
.student-header-icon{width:40px;height:40px;display:grid;place-items:center;border-radius:50%;border:1px solid rgba(68,145,203,.32);background:linear-gradient(145deg,rgba(22,55,82,.9),rgba(7,24,41,.95));color:#dcefff;font-size:19px;position:relative}
.student-header-icon.profile{font-size:18px}.student-header-icon .dot{position:absolute;width:8px;height:8px;border-radius:50%;background:#16aaff;margin:-25px 0 0 23px;box-shadow:0 0 9px rgba(22,170,255,.7)}
.student-control-row{max-width:1180px;margin:0 auto;padding:4px 20px 12px;display:flex;align-items:center;gap:12px}
.student-control{width:52px;height:52px;display:grid;place-items:center;border-radius:17px;border:1px solid rgba(67,139,193,.32);background:linear-gradient(145deg,rgba(17,47,72,.9),rgba(6,22,38,.96));color:#e5f4ff;font-size:24px;box-shadow:inset 0 1px rgba(255,255,255,.06)}
.student-control.active{border-color:#23b0ff;box-shadow:0 0 20px rgba(16,153,231,.13),inset 0 1px rgba(255,255,255,.07)}
.student-control.star{font-size:23px}.student-search{flex:1;display:flex;height:52px;min-width:0}
.student-search input{height:52px;border-radius:17px;padding:0 18px;background:linear-gradient(145deg,rgba(15,39,61,.92),rgba(6,21,36,.96));border-color:rgba(70,143,196,.32);font-size:16px}
.student-menu{width:52px;height:52px;border-radius:17px}
.student-home{max-width:900px;margin:0 auto;padding:22px 0 20px}.student-home-head{text-align:left;padding:12px 2px 28px}
.student-space-pill{display:inline-flex;align-items:center;padding:9px 15px;border:1px solid rgba(24,169,239,.78);border-radius:999px;color:#50c8ff;background:rgba(0,111,180,.1);font-size:12px;font-weight:800;letter-spacing:.08em}
.student-home-head h1{font-size:clamp(38px,6vw,58px);line-height:1.02;margin:24px 0 10px;letter-spacing:-.06em}.student-home-head p{font-size:18px;color:#aac1d7;margin:0}.student-home-stats{display:none}
.student-feature-list{display:grid;gap:14px}.student-feature,.student-wide-link{position:relative;display:flex;align-items:center;gap:18px;min-height:112px;padding:20px 22px;border:1px solid rgba(61,130,178,.34);border-radius:24px;background:linear-gradient(135deg,rgba(11,34,56,.94),rgba(4,15,27,.96));box-shadow:0 18px 50px rgba(0,0,0,.3);transition:.25s ease;overflow:hidden}
.student-feature:hover,.student-wide-link:hover{transform:translateY(-2px);border-color:rgba(45,174,242,.62);box-shadow:0 22px 60px rgba(0,67,120,.22)}
.student-feature.primary{border-color:rgba(24,179,246,.78);background:linear-gradient(135deg,rgba(9,44,70,.98),rgba(4,17,29,.96));box-shadow:0 0 0 1px rgba(0,180,255,.06),0 20px 65px rgba(0,91,153,.18)}
.student-feature-icon{width:58px;height:58px;flex:0 0 58px;display:grid;place-items:center;border-radius:18px;background:linear-gradient(145deg,rgba(37,78,108,.58),rgba(9,27,44,.94));border:1px solid rgba(108,176,220,.26);font-size:27px;box-shadow:inset 0 1px rgba(255,255,255,.08)}
.student-feature-copy{min-width:0;flex:1;display:flex;flex-direction:column;gap:5px}.student-feature-copy strong{font-size:21px;letter-spacing:-.035em}.student-feature-copy small,.student-feature-copy em{font-size:14px;color:#abc0d4;line-height:1.45;font-style:normal}.student-feature-copy em{font-size:12px;color:#63caff}.student-arrow{font-size:37px;color:#9bb9d4;line-height:1}
.student-mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.student-mini{display:flex;align-items:center;gap:12px;min-height:78px;padding:12px 16px;border:1px solid rgba(61,130,178,.34);border-radius:22px;background:linear-gradient(135deg,rgba(11,34,56,.94),rgba(4,15,27,.96));transition:.25s ease}.student-mini .student-feature-icon{width:48px;height:48px;flex-basis:48px;font-size:21px;border-radius:15px}.student-mini strong{font-size:14px;flex:1}.student-mini>span:last-child{font-size:29px;color:#8eacc7}
.student-wide-link{margin-top:14px;min-height:84px}.student-wide-link .student-feature-icon{width:50px;height:50px;flex-basis:50px;font-size:23px}.student-wide-link span:nth-child(2){display:flex;flex-direction:column;gap:4px;flex:1}.student-wide-link strong{font-size:17px}.student-wide-link small{color:#a7bfd5}
.campus-tools{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:18px 0}.campus-tool{display:flex;align-items:center;gap:13px;padding:16px;border-radius:20px;border:1px solid rgba(61,130,178,.34);background:linear-gradient(135deg,rgba(11,34,56,.94),rgba(4,15,27,.96));transition:.2s ease}.campus-tool:hover{transform:translateY(-2px);border-color:rgba(45,174,242,.62)}.campus-tool-icon{width:46px;height:46px;display:grid;place-items:center;border-radius:15px;background:rgba(22,75,111,.42);font-size:22px}.campus-tool span:nth-child(2){display:flex;flex-direction:column;gap:3px;flex:1}.campus-tool strong{font-size:15px}.campus-tool small{font-size:11px;color:#9eb8ce}.campus-tool b{font-size:26px;color:#8eacc7;font-weight:400}
.student-bottom-nav{display:none}.student-bottom-nav a{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;border-radius:15px;color:#91a9c0;font-size:12px;text-decoration:none}.student-bottom-nav a span{font-size:24px;line-height:1}.student-bottom-nav a.active{color:#1aaeff}.student-bottom-spacer{display:none}
.student-top-back{display:inline-flex;align-items:center;gap:8px;margin-right:auto;padding:10px 14px;border:1px solid rgba(67,139,193,.32);border-radius:14px;background:linear-gradient(145deg,rgba(17,47,72,.9),rgba(6,22,38,.96));color:#e5f4ff;text-decoration:none;font-size:14px;font-weight:700;box-shadow:inset 0 1px rgba(255,255,255,.06)}
.student-top-back:hover{border-color:rgba(45,174,242,.62);transform:translateY(-1px)}
@media(max-width:850px){.student-bottom-nav{display:flex;position:fixed;left:50%;bottom:0;transform:translateX(-50%);z-index:90;width:min(900px,100%);height:70px;background:rgba(2,11,20,.94);border-top:1px solid rgba(53,137,199,.28);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);padding:6px 10px calc(6px + env(safe-area-inset-bottom));box-shadow:0 -15px 45px rgba(0,0,0,.35)}.student-bottom-spacer{display:block;height:74px}}
@media(max-width:850px){.grid,.grid2,.two,.campus-tools{grid-template-columns:1fr}.navin{padding:9px 10px;gap:5px}.brand{font-size:23px}.brandmark{width:32px;height:32px}.student-header-tools{gap:5px}.student-header-icon{width:38px;height:38px}.student-control-row{padding:4px 10px 10px;gap:6px}.student-control{width:42px;height:42px;border-radius:14px;font-size:20px}.student-control.star{font-size:19px}.student-menu{width:42px;height:42px}.student-search{height:42px}.student-search input{height:42px;border-radius:14px;font-size:13px;padding:0 13px}.mobile-nav{padding:10px 12px 16px}.wrap{padding:8px 12px 88px}.student-home{padding-top:18px}.student-home-head h1{font-size:39px}.student-home-head p{font-size:15px}.student-feature{min-height:96px;padding:16px}.student-feature-icon{width:52px;height:52px;flex-basis:52px;font-size:24px}.student-feature-copy strong{font-size:18px}.student-feature-copy small{font-size:13px}.student-mini-grid{grid-template-columns:1fr}.student-wide-link{min-height:78px}.hero{padding:55px 0 35px}.hero h1{font-size:74px}.card{border-radius:22px}.actions .btn{max-width:100%}.footer{padding-bottom:95px}}

/* VYBE PREMIUM MIDNIGHT GLASS — visual-only enhancement */
:root{
  --bg:#000308;
  --bg2:#06111f;
  --panel:rgba(2,10,20,.88);
  --line:rgba(83,166,232,.22);
  --line2:rgba(76,184,255,.62);
  --text:#f5f9ff;
  --muted:#91a8c0;
  --accent:#2b8fce;
  --accent2:#063a61;
  --shadow:0 30px 90px rgba(0,0,0,.58);
}
body{
  background:
    radial-gradient(800px 520px at 8% -12%,rgba(22,122,196,.16),transparent 68%),
    radial-gradient(900px 620px at 92% 8%,rgba(20,92,155,.13),transparent 70%),
    radial-gradient(700px 500px at 50% 100%,rgba(8,55,94,.09),transparent 72%),
    linear-gradient(180deg,#01050b 0%,#020914 48%,#01040a 100%);
}
.nav{
  background:rgba(2,8,16,.78);
  border-bottom:1px solid rgba(75,157,220,.16);
  box-shadow:0 12px 45px rgba(0,0,0,.18);
}
.brandmark{
  background:linear-gradient(145deg,#58c6ff 0%,#168bd0 52%,#07517f 100%);
  box-shadow:0 0 28px rgba(34,164,238,.22),inset 0 1px rgba(255,255,255,.25);
}
.brandtext{
  background:linear-gradient(180deg,#ffffff 10%,#d6ecff 48%,#75b8e5 100%);
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.nav-toggle,.student-menu{
  background:linear-gradient(145deg,rgba(17,48,75,.88),rgba(4,17,30,.96));
  border-color:rgba(78,169,229,.28);
  box-shadow:inset 0 1px rgba(255,255,255,.07),0 8px 25px rgba(0,54,95,.16);
}
.nav-toggle:hover,.student-menu:hover{border-color:rgba(84,190,255,.58);box-shadow:0 0 24px rgba(25,151,219,.12),inset 0 1px rgba(255,255,255,.09)}
.mobile-nav.open{
  background:rgba(2,10,20,.94);
  border-color:rgba(77,168,229,.28);
  box-shadow:0 26px 75px rgba(0,0,0,.58),0 0 35px rgba(12,111,173,.09);
}
.mobile-nav a:hover{background:linear-gradient(90deg,rgba(24,123,186,.16),rgba(24,123,186,.04));}
.card,.ai-box{
  background:linear-gradient(145deg,rgba(10,30,50,.82),rgba(3,12,22,.93));
  border-color:rgba(74,155,214,.22);
  box-shadow:0 26px 75px rgba(0,0,0,.42),inset 0 1px rgba(255,255,255,.035);
}
.card:hover{background:linear-gradient(145deg,rgba(12,39,64,.9),rgba(3,14,26,.95));border-color:rgba(75,184,251,.52);box-shadow:0 30px 80px rgba(0,0,0,.48),0 0 32px rgba(12,116,180,.08)}
.btn{
  background:linear-gradient(180deg,#31b8ff 0%,#0c7ab8 100%);
  border-color:rgba(91,195,255,.4);
  box-shadow:0 10px 28px rgba(0,91,145,.23),inset 0 1px rgba(255,255,255,.18);
}
.btn:hover{box-shadow:0 13px 34px rgba(0,104,165,.3),inset 0 1px rgba(255,255,255,.2)}
.btn.accent{background:linear-gradient(180deg,#4ac5ff 0%,#0b78b7 100%);border-color:rgba(107,211,255,.58);box-shadow:0 12px 34px rgba(0,111,174,.26),inset 0 1px rgba(255,255,255,.22)}
.btn.dark{background:linear-gradient(145deg,rgba(15,42,66,.86),rgba(5,20,34,.95));border-color:rgba(74,157,216,.24)}
input,textarea,select{
  background:linear-gradient(145deg,rgba(7,25,42,.88),rgba(3,14,25,.94));
  border-color:rgba(69,139,190,.25);
  box-shadow:inset 0 1px rgba(255,255,255,.025);
}
input:focus,textarea:focus,select:focus{border-color:#32aef0;background:rgba(7,28,48,.95);box-shadow:0 0 0 4px rgba(28,157,224,.1),0 0 28px rgba(18,126,185,.08)}
.badge,.pill,.stat-chip,.top-stat,.top-tool,.page-back,.mobile-back{background:rgba(8,29,48,.66);border-color:rgba(74,157,215,.23);color:#d9edff}
.notice,.feed-item,.bubble{background:rgba(7,27,46,.58);border-color:rgba(72,153,210,.21)}
.feed-item:hover{border-color:rgba(71,181,247,.5);background:rgba(9,34,56,.68)}
.hero h1{background:linear-gradient(180deg,#ffffff 5%,#cfeaff 48%,#4f89b2 100%);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 0 50px rgba(35,157,221,.08)}
.student-header-icon{
  background:linear-gradient(145deg,rgba(19,58,87,.92),rgba(5,22,38,.97));
  border-color:rgba(78,164,221,.3);
  box-shadow:inset 0 1px rgba(255,255,255,.07),0 9px 28px rgba(0,49,83,.18);
}
.student-header-icon:hover{border-color:rgba(76,192,255,.62);box-shadow:0 0 26px rgba(25,157,222,.13)}
.student-control{
  background:linear-gradient(145deg,rgba(18,54,81,.92),rgba(5,21,37,.97));
  border-color:rgba(73,157,213,.28);
  box-shadow:inset 0 1px rgba(255,255,255,.07),0 12px 30px rgba(0,44,76,.16);
}
.student-control.active{border-color:#35baff;box-shadow:0 0 25px rgba(25,165,233,.18),inset 0 1px rgba(255,255,255,.1)}
.student-search input{background:linear-gradient(145deg,rgba(15,43,66,.92),rgba(5,20,35,.98));border-color:rgba(75,158,214,.3);box-shadow:inset 0 1px rgba(255,255,255,.045)}
.student-space-pill{color:#75d4ff;background:linear-gradient(90deg,rgba(0,132,205,.15),rgba(0,75,130,.08));border-color:rgba(60,190,249,.55);box-shadow:0 0 24px rgba(10,133,193,.08)}
.student-home-head h1{background:linear-gradient(180deg,#ffffff 10%,#d9efff 50%,#82b9dc 100%);-webkit-background-clip:text;background-clip:text;color:transparent}
.student-home-head p{color:#9db7cd}
.student-feature,.student-mini,.student-wide-link,.campus-tool{
  background:linear-gradient(145deg,rgba(11,36,59,.9),rgba(3,15,27,.97));
  border-color:rgba(69,143,194,.3);
  box-shadow:0 20px 58px rgba(0,0,0,.3),inset 0 1px rgba(255,255,255,.035);
}
.student-feature:hover,.student-wide-link:hover,.student-mini:hover,.campus-tool:hover{border-color:rgba(69,187,249,.58);box-shadow:0 24px 68px rgba(0,0,0,.35),0 0 30px rgba(11,116,179,.08)}
.student-feature.primary{background:linear-gradient(145deg,rgba(10,52,80,.96),rgba(3,18,31,.98));border-color:rgba(52,190,250,.7);box-shadow:0 0 0 1px rgba(39,181,245,.06),0 24px 70px rgba(0,76,128,.2),inset 0 1px rgba(255,255,255,.07)}
.student-feature-icon{background:linear-gradient(145deg,rgba(40,91,126,.58),rgba(6,26,44,.96));border-color:rgba(105,190,234,.27);box-shadow:inset 0 1px rgba(255,255,255,.1),0 9px 25px rgba(0,50,84,.18)}
.student-feature-copy small,.student-wide-link small,.campus-tool small{color:#a5bfd5}
.student-feature-copy em{color:#68ceff}
.student-arrow,.student-mini>span:last-child,.campus-tool b{color:#8fb7d5}
.campus-tool-icon{background:linear-gradient(145deg,rgba(22,86,126,.46),rgba(5,28,47,.82));border:1px solid rgba(80,162,213,.18)}
.student-top-back{background:linear-gradient(145deg,rgba(18,54,81,.92),rgba(5,21,37,.97));border-color:rgba(73,157,213,.28);box-shadow:inset 0 1px rgba(255,255,255,.07),0 12px 30px rgba(0,44,76,.16)}
.student-top-back:hover{border-color:rgba(69,188,249,.62);box-shadow:0 0 25px rgba(20,151,213,.11)}
.student-bottom-nav{background:rgba(2,9,18,.9);border-top-color:rgba(68,155,213,.25);box-shadow:0 -20px 55px rgba(0,0,0,.45),0 -1px 20px rgba(8,92,143,.07)}
.student-bottom-nav a.active{color:#45c0ff}
.community-launch{background:linear-gradient(135deg,rgba(13,43,68,.86),rgba(4,16,28,.95));border-color:rgba(71,157,213,.25);box-shadow:0 22px 60px rgba(0,0,0,.32),inset 0 1px rgba(255,255,255,.035)}
.community-launch:hover{background:linear-gradient(135deg,rgba(16,53,82,.92),rgba(4,18,31,.97));border-color:rgba(71,184,248,.5)}
.community-icon,.profile-avatar{background:linear-gradient(145deg,#36b9ff,#0a679f);color:#fff;box-shadow:0 10px 30px rgba(0,111,174,.22),inset 0 1px rgba(255,255,255,.22)}
.community-arrow{background:rgba(12,43,68,.7);border-color:rgba(74,159,216,.25)}
.chat-composer{background:rgba(4,17,30,.78);border-color:rgba(72,157,213,.24);box-shadow:0 22px 60px rgba(0,0,0,.42)}
.online{color:#63e6a2}.offline{color:#ff6f7f}
/* VYBE VARIANT B — BLACK + RICH MIDNIGHT BLUE */
:root{
  --bg:#01050A;
  --bg2:#071525;
  --panel:rgba(5,18,33,.94);
  --line:rgba(46,105,157,.28);
  --line2:rgba(55,133,199,.52);
  --text:#EAF4FF;
  --muted:#849BB2;
  --accent:#4B9BE0;
  --accent2:#0C3155;
  --shadow:0 30px 95px rgba(0,0,0,.76);
}
body{
  background:
    radial-gradient(900px 560px at 8% -18%,rgba(14,63,105,.24),transparent 70%),
    radial-gradient(1000px 700px at 94% 5%,rgba(8,52,92,.18),transparent 72%),
    linear-gradient(180deg,#01050A 0%,#030A13 46%,#02060B 100%);
  color:var(--text);
}
.nav{background:rgba(2,8,15,.86);border-bottom-color:rgba(46,105,157,.22)}
.card,.panel,.student-feature,.student-mini,.student-link,.feed-item,.stat-chip,.top-stat,.top-tool{
  background:linear-gradient(145deg,rgba(8,24,42,.94),rgba(3,11,20,.96));
  border-color:var(--line);
  box-shadow:0 20px 60px rgba(0,0,0,.30);
}
.card:hover,.student-feature:hover,.student-mini:hover,.student-link:hover{border-color:var(--line2);box-shadow:0 22px 68px rgba(0,28,58,.24)}
.ai-box{background:linear-gradient(145deg,rgba(10,31,53,.96),rgba(3,12,22,.98));border-color:rgba(67,139,197,.28);box-shadow:0 18px 55px rgba(0,30,65,.20)}
.btn,.button,.student-control.active{
  background:linear-gradient(180deg,#174D79,#0C3155);
  border-color:rgba(75,155,224,.44);
  box-shadow:0 8px 28px rgba(0,45,85,.22);
}
.btn:hover,.button:hover{background:linear-gradient(180deg,#1B5D91,#104067)}
input,textarea,select{background:rgba(2,10,18,.84)!important;border-color:rgba(46,105,157,.30)!important;color:var(--text)!important}
input:focus,textarea:focus,select:focus{border-color:rgba(75,155,224,.62)!important;box-shadow:0 0 0 3px rgba(45,123,186,.14),0 8px 30px rgba(0,31,63,.16)!important}
.student-space-pill{border-color:rgba(55,133,199,.46);color:#9BC8EA;background:rgba(17,67,105,.16)}
.student-feature-icon,.student-control,.student-header-icon{background:linear-gradient(145deg,rgba(14,48,78,.94),rgba(4,16,28,.98));border-color:rgba(46,105,157,.30);box-shadow:0 8px 25px rgba(0,25,50,.18)}
.student-arrow{color:#82B9E5}
.mobile-nav.open{background:rgba(3,13,23,.98);border-color:rgba(46,105,157,.34);box-shadow:0 24px 65px rgba(0,0,0,.58)}
.nav-toggle{background:rgba(6,20,34,.90);border-color:rgba(46,105,157,.30)}
.footer{border-top-color:rgba(46,105,157,.16)}
::selection{background:rgba(75,155,224,.30);color:#F5FAFF}
.password-wrap{position:relative}
.password-toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:40px;height:40px;padding:0!important;display:grid;place-items:center;border-radius:12px;background:rgba(7,24,40,.86)!important;border:1px solid rgba(75,155,224,.20)!important;color:#9fc9e8!important;cursor:pointer;z-index:2;box-shadow:none!important}
.password-toggle:hover{background:rgba(15,47,75,.95)!important;border-color:rgba(75,155,224,.48)!important;color:#dff3ff!important}
.password-toggle .eye-icon{width:19px;height:19px;display:block;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.password-toggle .eye-closed{display:none}
.password-toggle.is-visible .eye-open{display:none}
.password-toggle.is-visible .eye-closed{display:block}
.password-wrap input{padding-right:58px!important}
.password-wrap.password-error input{border-color:#ef4b5f!important;background:rgba(74,10,22,.38)!important;box-shadow:0 0 0 3px rgba(239,75,95,.13),0 8px 28px rgba(120,0,25,.16)!important}
.password-wrap.password-error .password-toggle{border-color:rgba(239,75,95,.42)!important;color:#ff8290!important;background:rgba(70,10,20,.72)!important}
.password-error-note{color:#ff8290;font-size:12px;margin-top:6px}

/* =========================================================
   FINAL MOBILE-ONLY STUDENT NAVIGATION
   Desktop CSS/layout is intentionally not changed.
   ========================================================= */
@media (max-width:850px){
  /* Remove ONLY Menu + Profile from the mobile TOP header.
     Leave the desktop rules completely alone. */
  .nav .student-header-tools .student-header-icon.profile,
  .nav .student-header-tools .student-menu{
    display:none!important;
    visibility:hidden!important;
    pointer-events:none!important;
  }

  /* Keep the header container itself available for any existing
     notification icon; do not hide the whole header-tools block. */
  .nav .student-header-tools{
    display:flex!important;
    align-items:center!important;
    gap:8px!important;
  }

  /* Bottom bar: Menu | Home | Profile.
     Back is added as a fourth item only on subpages. */
  .student-bottom-nav{
    display:flex!important;
    position:fixed!important;
    left:0!important;
    right:0!important;
    bottom:0!important;
    width:100%!important;
    height:70px!important;
    transform:none!important;
    z-index:5000!important;
    box-sizing:border-box!important;
    align-items:stretch!important;
    justify-content:stretch!important;
    padding:6px 8px calc(6px + env(safe-area-inset-bottom))!important;
    gap:4px!important;
  }

  .student-bottom-nav .mobile-menu-nav,
  .student-bottom-nav .mobile-home-nav,
  .student-bottom-nav .mobile-profile-nav,
  .student-bottom-nav .mobile-back-nav{
    order:initial!important;
    flex:1 1 0!important;
    width:0!important;
    max-width:none!important;
    min-width:0!important;
    margin:0!important;
  }
  .student-bottom-nav .mobile-menu-nav{order:1!important}
  .student-bottom-nav .mobile-home-nav{order:2!important}
  .student-bottom-nav .mobile-profile-nav{order:3!important}
  .student-bottom-nav .mobile-back-nav{order:4!important}

  /* The drawer is a real left-edge sidebar, not a floating dialog. */
  #vybeMobileNav.student-mobile-menu{
    display:none!important;
    position:fixed!important;
    left:0!important;
    top:0!important;
    right:auto!important;
    bottom:70px!important;
    width:min(78vw,280px)!important;
    height:auto!important;
    margin:0!important;
    padding:14px!important;
    box-sizing:border-box!important;
    z-index:4999!important;
    overflow-y:auto!important;
    overflow-x:hidden!important;
    flex-direction:column!important;
    gap:10px!important;
    border:0!important;
    border-right:1px solid rgba(70,150,205,.35)!important;
    border-radius:0 18px 0 0!important;
    background:rgba(3,12,22,.98)!important;
    box-shadow:18px 0 45px rgba(0,0,0,.48)!important;
    backdrop-filter:blur(26px)!important;
    -webkit-backdrop-filter:blur(26px)!important;
  }

  #vybeMobileNav.student-mobile-menu.open{
    display:flex!important;
  }

  /* Never show the old desktop/mobile-nav links inside the drawer. */
  #vybeMobileNav.student-mobile-menu > a{
    display:none!important;
  }

  #vybeMobileNav.student-mobile-menu .mobile-menu-head{
    display:none!important;
  }

  /* Show our actual VYBE mobile links. */
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links{
    display:flex!important;
    flex-direction:column!important;
    width:100%!important;
    gap:10px!important;
  }

  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links a{
    display:flex!important;
    align-items:center!important;
    justify-content:flex-start!important;
    width:100%!important;
    min-height:52px!important;
    box-sizing:border-box!important;
    margin:0!important;
    padding:10px 13px!important;
    gap:12px!important;
    border:1px solid rgba(72,145,192,.28)!important;
    border-radius:14px!important;
    background:rgba(10,28,44,.78)!important;
    color:#d9eaf6!important;
    text-decoration:none!important;
    font-size:13px!important;
    font-weight:650!important;
    box-shadow:0 6px 18px rgba(0,0,0,.18)!important;
  }

  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links a:active{
    background:rgba(26,110,165,.42)!important;
    border-color:rgba(73,173,235,.65)!important;
  }

  #vybeMobileNav.student-mobile-menu .student-menu-icon{
    display:grid!important;
    place-items:center!important;
    width:30px!important;
    height:30px!important;
    flex:0 0 30px!important;
    font-size:20px!important;
    line-height:1!important;
    color:#54b9ee!important;
  }

  .student-bottom-spacer{
    height:78px!important;
  }
}


  /* FINAL MOBILE-ONLY MENU ICON — matched to the supplied reference image.
     Desktop navigation is intentionally untouched. */
  @media (max-width:850px){
    .student-bottom-nav button.mobile-menu-nav{
      display:flex!important;
      align-items:center!important;
      justify-content:center!important;
      position:relative!important;
      height:44px!important;
      max-height:44px!important;
      margin:0 auto!important;
      padding:0!important;
      border:1px solid rgba(73,126,164,.34)!important;
      border-radius:14px!important;
      background:#061522!important;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.025), 0 5px 16px rgba(0,0,0,.18)!important;
      color:#fff!important;
      overflow:hidden!important;
    }
    .student-bottom-nav button.mobile-menu-nav .mobile-menu-icon-lines{
      width:24px!important;
      height:18px!important;
      display:flex!important;
      flex-direction:column!important;
      align-items:center!important;
      justify-content:space-between!important;
      flex:0 0 18px!important;
      margin:0!important;
      padding:0!important;
      background:transparent!important;
      border:0!important;
      border-radius:0!important;
      box-shadow:none!important;
      font-size:0!important;
      line-height:0!important;
    }
    .student-bottom-nav button.mobile-menu-nav .mobile-menu-icon-lines i{
      display:block!important;
      width:21px!important;
      height:2px!important;
      flex:0 0 2px!important;
      margin:0!important;
      padding:0!important;
      border:0!important;
      border-radius:2px!important;
      background:#f2f7fb!important;
      box-shadow:0 0 1px rgba(255,255,255,.18)!important;
      transform-origin:center!important;
      transition:transform .18s ease, opacity .18s ease, background .18s ease!important;
    }
    .student-bottom-nav button.mobile-menu-nav[aria-expanded="true"] .mobile-menu-icon-lines i:nth-child(1){
      transform:translateY(8px) rotate(45deg)!important;
      background:#22aef2!important;
    }
    .student-bottom-nav button.mobile-menu-nav[aria-expanded="true"] .mobile-menu-icon-lines i:nth-child(2){
      opacity:0!important;
    }
    .student-bottom-nav button.mobile-menu-nav[aria-expanded="true"] .mobile-menu-icon-lines i:nth-child(3){
      transform:translateY(-8px) rotate(-45deg)!important;
      background:#22aef2!important;
    }
    .student-bottom-nav button.mobile-menu-nav .mobile-menu-label{
      display:none!important;
    }
    .student-bottom-nav button.mobile-menu-nav:active{
      transform:scale(.97)!important;
    }
  }


/* =========================================================
   COMMUNITY PAGE — TWO STUDENT OPTIONS + LIVE CHAT
   Responsive on desktop and mobile without changing desktop nav.
   ========================================================= */
.community-choice-section{padding-top:0}
.community-choice-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;max-width:1000px;margin:0 auto}
.community-choice-card{position:relative;display:flex;align-items:center;gap:16px;min-width:0;padding:20px 22px;border:1px solid rgba(55,133,199,.30);border-radius:24px;background:linear-gradient(145deg,rgba(8,30,51,.96),rgba(3,12,22,.98));box-shadow:0 18px 55px rgba(0,0,0,.30);transition:transform .22s ease,border-color .22s ease,box-shadow .22s ease}
.community-choice-card:hover{transform:translateY(-3px);border-color:rgba(75,155,224,.58);box-shadow:0 24px 65px rgba(0,30,65,.30)}
.community-choice-icon{width:52px;height:52px;flex:0 0 52px;display:grid;place-items:center;border-radius:16px;background:linear-gradient(145deg,rgba(27,91,139,.65),rgba(5,25,43,.98));border:1px solid rgba(75,155,224,.24);font-size:24px}
.community-choice-copy{min-width:0;flex:1;display:flex;flex-direction:column;gap:5px}.community-choice-copy strong{font-size:18px;letter-spacing:-.025em}.community-choice-copy small{font-size:12px;line-height:1.45;color:#9db6cc}.community-choice-arrow{font-size:34px;line-height:1;color:#82b9e5}
.community-section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:14px}.community-section-head h2{margin:9px 0 5px;font-size:clamp(25px,4vw,34px);letter-spacing:-.045em}.community-section-head p{margin:0}
.community-chat-card{border:1px solid rgba(55,133,199,.30);border-radius:26px;background:linear-gradient(145deg,rgba(7,24,42,.96),rgba(2,10,18,.98));padding:16px;box-shadow:0 22px 65px rgba(0,0,0,.34)}
.community-chat-window{display:flex;flex-direction:column;gap:9px;max-height:520px;min-height:180px;overflow-y:auto;padding:4px;scroll-behavior:smooth}
.community-message{max-width:min(78%,720px);align-self:flex-start;padding:11px 14px;border-radius:17px 17px 17px 5px;background:rgba(255,255,255,.045);border:1px solid rgba(55,133,199,.20);word-break:break-word}.community-message.mine{align-self:flex-end;border-radius:17px 17px 5px 17px;background:rgba(15,67,103,.34);border-color:rgba(75,155,224,.28)}
.community-message-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px}.community-message-head strong{font-size:13px;color:#dceeff}.community-message-head span{font-size:10px;color:#718ba3}.community-message-text{font-size:14px;line-height:1.5;color:#edf6ff;white-space:pre-wrap}
.community-reply-bar{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:10px;padding:9px 11px;border-left:3px solid #22aef2;border-radius:10px;background:rgba(34,174,242,.09)}.community-reply-bar>div{min-width:0;display:flex;flex-direction:column;gap:2px}.community-reply-bar strong{font-size:11px;color:#8fd8ff}.community-reply-bar span{font-size:11px;color:#9bb1c5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.community-reply-bar button{border:0;background:transparent;color:#a9bed0;font-size:22px;line-height:1;cursor:pointer;padding:2px 5px}.community-reply-reference{display:flex;flex-direction:column;gap:2px;width:100%;margin:0 0 7px;padding:7px 9px;text-align:left;border:0;border-left:3px solid #2aaef2;border-radius:8px;background:rgba(34,174,242,.08);color:inherit;cursor:pointer}.community-reply-reference strong{font-size:10px;color:#8fd8ff}.community-reply-reference span{font-size:11px;color:#8fa6bd;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.reply-target-flash{box-shadow:0 0 0 2px rgba(34,174,242,.55),0 0 22px rgba(34,174,242,.18)!important}.community-chat-form{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;margin-top:12px}.community-chat-form textarea{min-height:48px;height:48px;resize:none;padding:13px 14px}.community-chat-form .btn{height:48px;white-space:nowrap}
.community-chat-locked{min-height:190px;display:grid;place-items:center;text-align:center;padding:28px 18px}.community-lock-icon{font-size:28px;margin-bottom:6px}.community-chat-locked h3{margin:0 0 7px;font-size:20px}.community-chat-locked p{max-width:520px;margin:0;color:#8fa6bd;line-height:1.55;font-size:13px}
.community-problem-list{display:grid;gap:16px}.community-problem-card{scroll-margin-top:90px}
@media(max-width:850px){
  .community-choice-grid{grid-template-columns:1fr;gap:11px}
  .community-choice-card{padding:15px 16px;border-radius:20px;gap:12px}
  .community-choice-icon{width:46px;height:46px;flex-basis:46px;border-radius:14px;font-size:21px}
  .community-choice-copy strong{font-size:16px}.community-choice-copy small{font-size:11px}
  .community-choice-arrow{font-size:29px}
  .community-section-head{align-items:stretch;flex-direction:column;gap:11px}.community-section-head .btn{width:100%}
  .community-chat-card{padding:10px;border-radius:21px}.community-chat-window{min-height:150px;max-height:430px;padding:3px}
  .community-message{max-width:88%;padding:10px 12px}.community-message-text{font-size:13px}
  .community-chat-form{grid-template-columns:1fr;gap:8px}.community-chat-form textarea{height:48px;min-height:48px}.community-chat-form .btn{width:100%;height:44px}
  .community-chat-locked{min-height:160px;padding:22px 14px}
  .community-problem-card{scroll-margin-top:75px}
}

/* Dedicated community pages */
.community-page-section{padding-top:18px}
.community-page-top{max-width:900px;margin:0 auto 20px}.community-page-top h1{margin:12px 0 8px;font-size:clamp(38px,7vw,64px);letter-spacing:-.065em;line-height:.98}.community-page-top p{margin:0}.community-back-link{display:inline-flex;align-items:center;gap:5px;margin-bottom:18px;color:#9fc8e8;font-size:13px;font-weight:700}.community-back-link:hover{color:#fff}.community-chat-page-card{max-width:1000px;margin:0 auto}.community-page-section>.community-problem-list{max-width:1000px;margin:0 auto}.community-page-section .community-problem-card{border-color:rgba(55,133,199,.30);background:linear-gradient(145deg,rgba(7,24,42,.96),rgba(2,10,18,.98))}.community-page-section .community-problem-card h2{font-size:clamp(21px,3vw,30px)}
@media(max-width:850px){.community-page-section{padding-top:8px}.community-page-top{margin-bottom:14px}.community-page-top h1{font-size:clamp(34px,11vw,48px)}.community-back-link{margin-bottom:14px}.community-chat-page-card{width:100%;margin-left:0;margin-right:0}.community-page-section .community-problem-list{width:100%}}
@media(max-width:600px){
  .community-chat-page-section{padding-left:10px;padding-right:10px;padding-bottom:18px}
  .community-chat-page-section .community-page-top{padding:0;margin-bottom:10px}.community-chat-page-section .community-page-top h1{font-size:28px;margin:5px 0}.community-chat-page-section .community-page-top p{font-size:11px}.community-chat-page-section .community-back-link{margin-bottom:8px}
  .community-chat-page-section .community-chat-page-card{width:100%;max-width:none;margin:0;border-radius:18px;padding:10px;min-height:0;height:calc(100dvh - 245px);max-height:620px;display:flex;flex-direction:column;background:linear-gradient(180deg,rgba(4,15,27,.99),rgba(1,6,12,.99));border:1px solid rgba(55,133,199,.28);overflow:hidden}
  .community-chat-page-section .community-chat-window{flex:1;min-height:0;height:auto;max-height:none;overflow-y:auto;overflow-x:hidden;padding:6px 2px 12px;overscroll-behavior:contain;-webkit-overflow-scrolling:touch;scrollbar-width:thin}
  .community-chat-page-section .community-chat-form{position:relative;bottom:auto;z-index:4;padding-top:7px;background:linear-gradient(180deg,transparent,rgba(1,4,10,.98) 25%);flex:0 0 auto}
  .community-chat-page-section .community-chat-form textarea{border-radius:18px;padding:13px 15px;min-height:48px;background:rgba(6,18,31,.96)}
  .community-chat-page-section .community-chat-keyboard-hint{padding-bottom:2px}
  .community-chat-page-section .community-message{padding:11px 10px;border-radius:15px;margin:0 1px}.community-chat-page-section .community-message-head strong{font-size:12px}.community-chat-page-section .community-message-text{font-size:14px;line-height:1.48}
  .community-chat-page-section .community-selection-actions{flex-wrap:wrap;justify-content:flex-end}
  .community-chat-page-section .community-chat-tools{position:relative;top:auto;z-index:5;padding:3px 0 8px;background:rgba(1,4,10,.92);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);flex:0 0 auto}
}
/* Hide the mobile student bottom buttons while the keyboard/composer is active. */
@media(max-width:850px){
  body.vybe-chat-composing .student-bottom-nav,
  body.vybe-chat-composing .student-bottom-spacer{display:none!important}
}
/* Clean student home */
.clean-home{max-width:980px;padding-top:28px}.clean-home-head{padding-bottom:30px}.clean-home-head h1{margin-top:20px}.clean-home-head p{font-size:16px}.home-section-label{font-size:11px;font-weight:800;letter-spacing:.14em;color:#6f9fc2;margin:0 0 11px}.home-action-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.home-action{display:flex;align-items:center;gap:14px;min-height:106px;padding:18px;border:1px solid rgba(61,130,178,.30);border-radius:22px;background:linear-gradient(145deg,rgba(10,32,52,.82),rgba(3,14,25,.92));transition:transform .22s ease,border-color .22s ease,background .22s ease}.home-action:hover{transform:translateY(-2px);border-color:rgba(45,174,242,.58);background:linear-gradient(145deg,rgba(12,40,64,.9),rgba(3,15,27,.95))}.home-action-primary{border-color:rgba(25,174,242,.58);background:linear-gradient(145deg,rgba(8,43,69,.9),rgba(3,16,28,.95))}.home-action-icon{width:48px;height:48px;flex:0 0 48px;display:grid;place-items:center;border-radius:15px;background:rgba(27,89,130,.32);border:1px solid rgba(105,183,227,.22);font-size:22px}.home-action>span:nth-child(2){min-width:0;flex:1;display:flex;flex-direction:column;gap:4px}.home-action strong{font-size:16px;letter-spacing:-.02em}.home-action small{font-size:12px;line-height:1.4;color:#98b1c8}.home-action>b{font-size:27px;color:#7899b5;font-weight:400}.home-updates-head{display:flex;align-items:end;justify-content:space-between;margin-top:30px;margin-bottom:11px}.home-updates-head p{margin:0;color:#829ab1;font-size:12px}.home-updates-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.home-update-panel{padding:15px;border:1px solid rgba(61,130,178,.26);border-radius:22px;background:rgba(5,20,34,.62)}.home-panel-title{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:1px 2px 10px;color:#dcecf8;font-size:14px;font-weight:750}.home-panel-title a{color:#59bdf3;font-size:11px;font-weight:700}.home-update{display:flex;align-items:center;gap:10px;padding:11px 9px;border-radius:15px;border:1px solid transparent;transition:.2s ease}.home-update:hover{background:rgba(31,105,151,.12);border-color:rgba(61,130,178,.22)}.home-update-icon{width:34px;height:34px;display:grid;place-items:center;flex:0 0 34px;border-radius:11px;background:rgba(27,89,130,.24);font-size:15px}.home-update>span:nth-child(2){min-width:0;flex:1;display:flex;flex-direction:column;gap:3px}.home-update strong{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.home-update small{font-size:10px;color:#8099b0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.home-update>b{font-size:20px;color:#6887a1;font-weight:400}.home-empty{padding:16px 9px;color:#70889e;font-size:11px}
@media(max-width:850px){.clean-home{padding-top:18px}.clean-home-head{padding-bottom:25px}.clean-home-head h1{font-size:38px;margin-top:18px}.clean-home-head p{font-size:14px;line-height:1.5}.home-action-grid{grid-template-columns:1fr;gap:10px}.home-action{min-height:88px;padding:14px 15px;border-radius:19px}.home-action-icon{width:44px;height:44px;flex-basis:44px;font-size:20px}.home-action strong{font-size:16px}.home-action small{font-size:12px}.home-updates-head{margin-top:26px}.home-updates-head p{font-size:11px}.home-updates-grid{grid-template-columns:1fr;gap:10px}.home-update-panel{border-radius:19px;padding:13px}.home-section-label{font-size:10px}}




/* ===== VYBE Academic Hub theme ===== */
:root{--vybe-black:#050708;--vybe-ink:#0b1014;--vybe-panel:#0f1519;--vybe-panel-2:#141c21;--vybe-line:#26323a;--vybe-white:#f5f7f8;--vybe-grey:#93a1aa;--vybe-blue:#2587d9;--vybe-blue-soft:#16364e;--vybe-green:#8fdf2e;--vybe-green-deep:#2f8f2f}
body{background:var(--vybe-black)!important;color:var(--vybe-white)!important}
.nav{background:rgba(5,7,8,.96)!important;border-color:var(--vybe-line)!important}
.card,.academic-app-card{background:var(--vybe-panel)!important;border-color:var(--vybe-line)!important}
.btn.accent,.academic-btn{background:var(--vybe-blue)!important;color:#fff!important;border-color:var(--vybe-blue)!important}
.btn.good{background:var(--vybe-green-deep)!important;color:#fff!important}
.badge,.academic-kicker{color:var(--vybe-green)!important}
.muted{color:var(--vybe-grey)!important}.pill{border-radius:7px!important;background:#10202b!important;border-color:#2b4c61!important;color:#b8d7ea!important}.brandmark{background:var(--vybe-green)!important;color:#071008!important}.nav a{color:#dce5ea!important}.nav a:hover{color:#8fdfff!important}
input,select,textarea{background:#0b1115!important;color:var(--vybe-white)!important;border-color:#2b3942!important}
input::placeholder,textarea::placeholder{color:#72818b!important}
.academic-hero{padding:58px 0 36px;text-align:center}.academic-hero h1{max-width:880px;margin:14px auto 12px;font-size:clamp(38px,6vw,68px);line-height:1.02;letter-spacing:-.045em}.academic-lead{max-width:760px;margin:0 auto 26px;color:#a9b4bb;font-size:17px;line-height:1.7}.academic-kicker{font-size:12px;font-weight:800;letter-spacing:.14em}
.academic-search{max-width:760px;margin:24px auto;display:grid;grid-template-columns:1fr auto;background:#fff;border:1px solid #dce2e5;border-radius:16px;padding:5px;box-shadow:0 12px 40px rgba(0,0,0,.24)}.academic-search input{background:#fff!important;color:#101418!important;border:0!important;min-height:52px;padding:0 16px!important}.academic-search button,.academic-filter-form button{border:0;background:#0a0d0f;color:#fff;padding:0 22px;min-height:48px;border-radius:12px;font-weight:800;cursor:pointer}
.academic-quick-grid{max-width:980px;margin:auto;display:grid;grid-template-columns:repeat(6,1fr);gap:10px}.academic-quick{display:flex;flex-direction:column;align-items:flex-start;gap:6px;text-align:left;padding:16px;border:1px solid var(--vybe-line);background:#0d1317;color:#fff;text-decoration:none;border-radius:14px;min-height:105px;transition:border-color .18s,transform .18s}.academic-quick:hover{border-color:#3b83b8;transform:translateY(-2px)}.academic-quick-green{border-color:rgba(143,223,46,.42)}.academic-icon{width:32px;height:32px;display:grid;place-items:center;border:1px solid #35505f;background:#102331;color:#7ec8ff;border-radius:9px;font-size:12px;font-weight:900}.academic-quick-green .academic-icon{background:#162514;border-color:#476e28;color:var(--vybe-green)}.academic-quick strong{font-size:14px}.academic-quick small{color:#7e8b94;font-size:11px}
.academic-section-heading{display:flex;justify-content:space-between;align-items:end;gap:16px;margin-bottom:16px}.academic-section-heading h2{margin:7px 0 0;font-size:30px;letter-spacing:-.03em}.academic-outline{display:inline-flex;align-items:center;justify-content:center;padding:10px 14px;border:1px solid #33414a;border-radius:10px;color:#d7e0e5;text-decoration:none;font-weight:750;background:#0d1317}
.academic-tool-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.academic-tool{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:14px;padding:18px;border:1px solid var(--vybe-line);background:#0d1317;color:#fff;text-decoration:none;border-radius:14px}.academic-tool:hover{border-color:#3375a3}.academic-tool-mark{width:42px;height:42px;display:grid;place-items:center;border-radius:10px;background:#102a3c;color:#70c5ff;border:1px solid #24516e;font-size:12px;font-weight:900}.academic-tool:nth-child(4n) .academic-tool-mark{background:#172614;color:var(--vybe-green);border-color:#3f6129}.academic-tool p{margin:4px 0 0;color:#8d9aa3;font-size:13px;line-height:1.5}.academic-arrow{color:#6f7e87;font-size:20px}
.academic-filter-panel{border:1px solid var(--vybe-line);background:#0d1317;padding:14px;border-radius:14px;margin-bottom:16px}.academic-filter-form{display:grid;grid-template-columns:2fr repeat(4,1fr) auto auto;gap:8px}.academic-filter-form input,.academic-filter-form select{min-width:0}.academic-filter-form button{background:var(--vybe-blue);min-height:44px}.academic-reset{display:grid;place-items:center;padding:0 12px;color:#aeb9c0;text-decoration:none;border:1px solid #34424a;border-radius:10px}
.academic-resource-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.academic-resource-card{background:#0d1317;border:1px solid var(--vybe-line);border-radius:14px;padding:18px;display:flex;flex-direction:column;min-height:215px}.academic-card-top{display:flex;justify-content:space-between;gap:10px}.academic-tag{display:inline-flex;align-items:center;padding:5px 8px;border-radius:7px;background:#132638;color:#82cfff;border:1px solid #254761;font-size:10px;font-weight:800;letter-spacing:.04em}.academic-semester{font-size:11px;color:#8d9aa3}.academic-resource-card h3{margin:16px 0 6px;font-size:18px}.academic-resource-card p{color:#89969f;font-size:13px;line-height:1.55}.academic-subline{color:#c1cbd1!important}.academic-card-action{margin-top:auto}.academic-meta{font-size:12px;color:#73818a}
.academic-update-list{display:grid;gap:10px}.academic-update-card{border:1px solid var(--vybe-line);background:#0d1317;border-radius:14px;padding:18px}.academic-update-card:hover{border-color:#31566d}.academic-update-large{padding:22px}.academic-update-line{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.academic-update-category{font-size:10px;font-weight:900;letter-spacing:.09em;color:var(--vybe-green)}.academic-update-kind{font-size:11px;color:#7f8d96}.academic-update-card h3,.academic-update-card h2{margin:10px 0 7px}.academic-update-card p{color:#8e9ba3;line-height:1.6;margin:0}.academic-update-foot{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-top:16px;font-size:11px;color:#6f7e87}.academic-link{color:#6fc1ff;text-decoration:none;font-weight:800}.academic-empty{border:1px dashed #35444d;border-radius:14px;padding:28px;text-align:center;color:#829099}.academic-detail{max-width:900px;margin:auto;border:1px solid var(--vybe-line);background:#0d1317;border-radius:18px;padding:30px}.academic-detail h1{font-size:clamp(34px,5vw,54px);letter-spacing:-.04em;margin:12px 0}.academic-detail-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:24px 0}.academic-detail-grid div{border:1px solid #26353e;background:#0a1014;padding:14px;border-radius:10px}.academic-detail-grid span{display:block;color:#687780;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}.academic-detail-grid strong{font-size:13px}
.academic-app-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.academic-app-card{padding:24px;border:1px solid var(--vybe-line);border-radius:16px}.academic-app-card h2{margin:12px 0 8px}.academic-app-card p{color:#8e9ba3;line-height:1.6}.sgpa-rows{display:grid;gap:8px;margin:18px 0}.sgpa-row{display:grid;grid-template-columns:1fr 1fr auto;gap:8px}.sgpa-row button{border:1px solid #3a464e;background:#0a0f12;color:#aab5bc;border-radius:9px;cursor:pointer}.sgpa-result{margin-top:14px;padding:14px;border:1px solid #2d3e49;background:#0a1116;color:#8fdfff;border-radius:10px;font-weight:800}.academic-shortcuts{display:grid;gap:8px}.academic-shortcuts a{padding:12px;border:1px solid #29363e;border-radius:10px;color:#dbe3e7;text-decoration:none;background:#0b1115}.academic-shortcuts a:hover{border-color:#3375a3}
@media(max-width:1050px){.academic-quick-grid{grid-template-columns:repeat(3,1fr)}.academic-filter-form{grid-template-columns:1fr 1fr 1fr}.academic-resource-grid{grid-template-columns:repeat(2,1fr)}.academic-app-grid{grid-template-columns:1fr}}
@media(max-width:700px){.academic-hero{padding-top:34px}.academic-hero h1{font-size:40px}.academic-lead{font-size:14px}.academic-search{grid-template-columns:1fr}.academic-search button{min-height:46px}.academic-quick-grid{grid-template-columns:repeat(2,1fr)}.academic-tool-grid,.academic-resource-grid{grid-template-columns:1fr}.academic-filter-form{grid-template-columns:1fr}.academic-filter-form button,.academic-reset{min-height:44px}.academic-detail-grid{grid-template-columns:1fr 1fr}.academic-update-foot{align-items:flex-start;flex-direction:column}.sgpa-row{grid-template-columns:1fr 1fr}.sgpa-row button{grid-column:1/-1;min-height:38px}}

/* VYBE academic-portal visual layer */
:root{--vybe-ui-bg:#fbfbf8;--vybe-ui-surface:#fff;--vybe-ui-muted:#69727e;--vybe-ui-text:#101624;--vybe-ui-line:#e1e6df;--vybe-ui-green:#79bd32;--vybe-ui-green-soft:#eaf7dc;--vybe-ui-blue:#356fc4;--vybe-ui-blue-soft:#e8f0ff;--vybe-ui-shadow:0 10px 35px rgba(20,30,20,.055)}
html{background:var(--vybe-ui-bg)}
body{background:var(--vybe-ui-bg)!important;color:var(--vybe-ui-text)!important}
.nav{background:rgba(255,255,255,.96)!important;border-bottom:1px solid var(--vybe-ui-line)!important;box-shadow:0 4px 18px rgba(20,30,20,.035)!important;backdrop-filter:blur(14px)}
.navin{max-width:1400px!important}.brand{color:var(--vybe-ui-text)!important}.brandmark{background:var(--vybe-ui-green)!important;color:#081006!important;box-shadow:none!important}.brandtext{background:none!important;color:var(--vybe-ui-text)!important;-webkit-text-fill-color:var(--vybe-ui-text)!important}
.nav-toggle,.student-menu{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:none!important}.mobile-nav{background:#fff!important;border-color:var(--vybe-ui-line)!important;box-shadow:0 18px 45px rgba(20,30,20,.12)!important}.mobile-nav a{color:#39424e!important}.mobile-nav a:hover{background:#f3f7ef!important;border-color:#dfe8d7!important}.wrap{max-width:1400px!important}.footer{background:#fff!important;color:#737b85!important;border-top:1px solid var(--vybe-ui-line)!important}
.btn,.button{background:#101624!important;color:#fff!important;border:1px solid #101624!important;box-shadow:none!important;border-radius:11px!important}.btn.accent{background:var(--vybe-ui-green)!important;color:#081006!important;border-color:var(--vybe-ui-green)!important}.btn.dark{background:#fff!important;color:#27303a!important;border:1px solid var(--vybe-ui-line)!important}.btn.good{background:var(--vybe-ui-green-soft)!important;color:#3f7417!important;border-color:#cfe8b8!important}.btn.danger{background:#fff0f0!important;color:#b32626!important;border-color:#f0caca!important}.btn:hover,.button:hover{transform:translateY(-1px)!important;box-shadow:0 7px 20px rgba(20,30,20,.08)!important}
.card,.panel,.student-feature,.student-mini,.student-link,.feed-item,.stat-chip,.top-stat,.top-tool{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important}.card:hover,.student-feature:hover,.student-mini:hover,.student-link:hover{border-color:#cdd9c5!important;box-shadow:0 15px 38px rgba(20,30,20,.08)!important}.muted,.small,.student-feature-copy small,.student-wide-link small,.campus-tool small{color:var(--vybe-ui-muted)!important}.badge,.pill{background:var(--vybe-ui-green-soft)!important;color:#4d861b!important;border-color:#d5e9c4!important}.notice{background:#fff!important;border-color:var(--vybe-ui-line)!important;color:var(--vybe-ui-text)!important}
input,textarea,select{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid #dce2da!important;border-radius:10px!important}input::placeholder,textarea::placeholder{color:#929aa4!important}input:focus,textarea:focus,select:focus{border-color:#8fc65b!important;background:#fff!important;box-shadow:0 0 0 3px rgba(121,189,50,.13)!important}table{background:#fff!important;color:var(--vybe-ui-text)!important}th{background:#f4f7f3!important;color:#4d5661!important;border-color:var(--vybe-ui-line)!important}td{border-color:var(--vybe-ui-line)!important}
.student-header-icon,.student-control,.student-top-back{background:#fff!important;color:#27303a!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:none!important}.student-control.active{background:#101624!important;color:#fff!important;border-color:#101624!important;box-shadow:none!important}.student-search input{background:#fff!important;border:1px solid var(--vybe-ui-line)!important;color:var(--vybe-ui-text)!important;box-shadow:none!important}.student-home{max-width:1120px!important}.student-space-pill{background:var(--vybe-ui-green-soft)!important;color:#4d861b!important;border-color:#d5e9c4!important}.student-home-head h1{background:none!important;color:var(--vybe-ui-text)!important;-webkit-text-fill-color:var(--vybe-ui-text)!important;text-shadow:none!important}.student-home-head p{color:var(--vybe-ui-muted)!important}.home-section-label{color:#5f8f25!important}
.home-action-grid{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px!important}.home-action{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid var(--vybe-ui-line)!important;border-radius:17px!important;box-shadow:var(--vybe-ui-shadow)!important}.home-action:hover{border-color:#c9d9bd!important;background:#fff!important}.home-action-primary{border-color:#bcd99f!important;background:linear-gradient(135deg,#fff,#f4faed)!important}.home-action-icon{background:var(--vybe-ui-blue-soft)!important;border-color:#d6e2fb!important;color:var(--vybe-ui-blue)!important}.home-update-panel{background:#fff!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important}.home-update{border-color:#edf0eb!important;color:var(--vybe-ui-text)!important}.home-update-icon{background:var(--vybe-ui-green-soft)!important;border-color:#d7e9c7!important}.home-panel-title a{color:var(--vybe-ui-blue)!important}
.academic-hero{padding:70px 0 42px!important;text-align:center!important;background:linear-gradient(180deg,#fff 0,#f5f9f1 100%)!important;border-bottom:1px solid var(--vybe-ui-line);border-radius:0 0 26px 26px}.academic-kicker{color:#5c8d23!important}.academic-hero h1{color:var(--vybe-ui-text)!important;background:none!important;-webkit-text-fill-color:var(--vybe-ui-text)!important;text-shadow:none!important}.academic-lead{color:var(--vybe-ui-muted)!important}.academic-search{background:#fff!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:0 12px 34px rgba(20,30,20,.08)!important;border-radius:14px!important}.academic-search input{border:0!important;border-radius:9px!important}.academic-search button,.academic-filter-form button{background:#101624!important;color:#fff!important;border-radius:10px!important}.academic-quick-grid{display:grid!important;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px!important}.academic-quick{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important;border-radius:14px!important}.academic-quick:hover{border-color:#c8d8bc!important;background:#fff!important}.academic-quick-green{background:#f5faef!important;border-color:#cfe4bb!important}.academic-icon{background:var(--vybe-ui-blue-soft)!important;color:var(--vybe-ui-blue)!important;border-color:#d4e0f6!important}.academic-quick-green .academic-icon{background:var(--vybe-ui-green-soft)!important;color:#4d861b!important;border-color:#d5e9c4!important}
.academic-tools-section{background:#f4f7f3!important}.academic-section-heading h2{color:var(--vybe-ui-text)!important}.academic-tool-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important}.academic-tool{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important;border-radius:16px!important}.academic-tool:hover{border-color:#c9d9bd!important}.academic-tool-mark{background:var(--vybe-ui-blue-soft)!important;color:var(--vybe-ui-blue)!important;border-color:#d4e0f6!important}.academic-tool:nth-child(4n) .academic-tool-mark{background:var(--vybe-ui-green-soft)!important;color:#4d861b!important;border-color:#d5e9c4!important}.academic-tool p{color:var(--vybe-ui-muted)!important}.academic-arrow{color:#87919d!important}.academic-filter-panel{background:#fff!important;border-color:var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important}.academic-filter-form input,.academic-filter-form select{background:#fff!important;color:var(--vybe-ui-text)!important}.academic-reset{color:#5e6874!important;border-color:var(--vybe-ui-line)!important}.academic-resource-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important}.academic-resource-card,.academic-update-card,.academic-detail,.academic-app-card{background:#fff!important;color:var(--vybe-ui-text)!important;border-color:var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important;border-radius:16px!important}.academic-tag{background:var(--vybe-ui-blue-soft)!important;color:var(--vybe-ui-blue)!important;border-color:#d4e0f6!important}.academic-semester,.academic-meta{color:#78818c!important}.academic-resource-card p,.academic-update-card p,.academic-app-card p{color:var(--vybe-ui-muted)!important}.academic-link{color:var(--vybe-ui-blue)!important}.academic-update-category{color:#5c8d23!important}.academic-empty{background:#fff!important;border-color:#d6ddd2!important;color:#7a838d!important}.sgpa-result{background:var(--vybe-ui-green-soft)!important;border-color:#d5e9c4!important;color:#4d861b!important}.academic-shortcuts a{background:#fff!important;color:var(--vybe-ui-text)!important;border-color:var(--vybe-ui-line)!important}
.hero{background:linear-gradient(180deg,#fff 0,#f5f9f1 100%)!important;color:var(--vybe-ui-text)!important;border-bottom:1px solid var(--vybe-ui-line)!important}.hero h1{color:var(--vybe-ui-text)!important;background:none!important;-webkit-text-fill-color:var(--vybe-ui-text)!important;text-shadow:none!important}.hero p{color:var(--vybe-ui-muted)!important}.authbox{background:#fff!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:0 18px 55px rgba(20,30,20,.08)!important}
.community-choice-card,.community-chat-card,.community-page-section .community-problem-card{background:#fff!important;color:var(--vybe-ui-text)!important;border-color:var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important}.community-choice-copy strong,.community-message-head strong{color:var(--vybe-ui-text)!important}.community-choice-copy small,.community-message-head span,.community-message-text,.community-problem-card p{color:var(--vybe-ui-muted)!important}.community-choice-icon{background:var(--vybe-ui-blue-soft)!important;color:var(--vybe-ui-blue)!important;border-color:#d4e0f6!important}.community-choice-arrow{color:var(--vybe-ui-blue)!important}.community-message{background:#f7f9f6!important;border-color:#e0e5de!important;color:var(--vybe-ui-text)!important}.community-message.mine{background:#edf5ff!important;border-color:#d5e3f6!important}.community-message-text{color:var(--vybe-ui-text)!important}.community-reply-bar,.community-reply-reference{background:#f2f7ed!important;border-color:#d8e9ca!important;color:var(--vybe-ui-text)!important}.community-chat-form textarea{background:#fff!important}
@media(max-width:1050px){.academic-quick-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important}.academic-tool-grid,.academic-resource-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}.home-action-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}}
@media(max-width:700px){.academic-hero{padding-top:42px!important}.academic-quick-grid,.academic-tool-grid,.academic-resource-grid{grid-template-columns:1fr!important}.home-action-grid{grid-template-columns:1fr!important}.student-control-row{padding-left:12px!important;padding-right:12px!important}}

/* ===== ADMIN CONTROL CENTER v2 ===== */
.admin-home-page{max-width:1180px!important;margin:0 auto!important;padding:46px 0 90px!important}.admin-home-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:30px;margin-bottom:28px}.admin-home-kicker,.admin-page-kicker{display:inline-flex;align-items:center;padding:7px 11px;border-radius:10px;background:#edf4ff;border:1px solid #d7e5f8;color:#2f6fca;font-size:10px;font-weight:800;letter-spacing:.12em}.admin-home-hero h1{font-size:clamp(42px,5.2vw,66px);line-height:.98;letter-spacing:-.055em;margin:16px 0 12px;color:#17202b}.admin-home-hero h1 em{font-style:normal;color:#2f6fca}.admin-home-hero p{max-width:650px;color:#687482;font-size:16px;line-height:1.6;margin:0}.admin-home-status{display:flex;align-items:center;gap:12px;min-width:240px;padding:15px 16px;border:1px solid #dfe5ea;background:#fff;border-radius:18px;box-shadow:0 10px 28px rgba(31,48,66,.06)}.admin-home-status>span{width:10px;height:10px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 5px #edf8e6}.admin-home-status.offline>span{background:#d9534f;box-shadow:0 0 0 5px #fff0f0}.admin-home-status div{display:grid;gap:2px;flex:1}.admin-home-status strong{font-size:13px}.admin-home-status small{font-size:10px;color:#7b8794}.admin-home-status a{font-size:11px;font-weight:800;color:#2f6fca}.admin-home-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:0 0 42px}.admin-home-stats div{background:#fff;border:1px solid #e0e6eb;border-radius:16px;padding:15px 16px;box-shadow:0 7px 20px rgba(31,48,66,.045)}.admin-home-stats b{display:block;font-size:24px;letter-spacing:-.04em}.admin-home-stats span{display:block;margin-top:3px;color:#74808d;font-size:10px;text-transform:uppercase;letter-spacing:.07em;font-weight:800}.admin-home-section-title{display:flex;justify-content:space-between;align-items:end;margin-bottom:16px}.admin-home-section-title>div span,.admin-list-head>div span{font-size:10px;letter-spacing:.12em;font-weight:800;color:#7a8794}.admin-home-section-title h2,.admin-list-head h2{font-size:24px;letter-spacing:-.035em;margin:5px 0 0}.admin-home-section-title small{color:#7b8794;font-size:11px}.admin-home-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.admin-home-card{position:relative;display:flex;flex-direction:column;min-height:225px;padding:19px;border:1px solid #dfe5ea;border-radius:22px;background:#fff;color:#17202b;box-shadow:0 9px 28px rgba(31,48,66,.055);overflow:hidden;transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}.admin-home-card:before{content:"";position:absolute;inset:0 auto auto 0;width:100%;height:3px;background:#2f6fca}.admin-home-card-green:before{background:#68b82e}.admin-home-card-purple:before{background:#8068d9}.admin-home-card-orange:before{background:#e39a3a}.admin-home-card:hover{transform:translateY(-4px);border-color:#cdd9e3;box-shadow:0 18px 40px rgba(31,48,66,.11)}.admin-home-card-top{display:flex;justify-content:space-between;align-items:center;color:#83909c;font-size:10px;font-weight:800;letter-spacing:.06em}.admin-home-number{color:#2f6fca}.admin-home-count{background:#f6f8fa;border-radius:999px;padding:5px 8px}.admin-home-icon{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;margin:24px 0 14px;background:#edf4ff;color:#2f6fca;font-size:14px;font-weight:900}.admin-home-card-green .admin-home-icon{background:#edf8e6;color:#68a92e}.admin-home-card-purple .admin-home-icon{background:#f0edff;color:#725ed1}.admin-home-card-orange .admin-home-icon{background:#fff4e5;color:#cf8120}.admin-home-card h2{font-size:20px;letter-spacing:-.035em;margin:0 0 7px}.admin-home-card p{font-size:12px;line-height:1.5;color:#6d7986;margin:0}.admin-home-open{margin-top:auto;padding-top:17px;font-size:11px;font-weight:800;color:#2f6fca;display:flex;justify-content:space-between}.admin-home-open b{font-size:18px;line-height:10px}.admin-home-bottom{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:15px}.admin-home-bottom a{display:flex;align-items:center;gap:12px;padding:14px 15px;border:1px solid #dfe5ea;background:#fff;border-radius:17px;color:#17202b;box-shadow:0 7px 20px rgba(31,48,66,.04)}.admin-home-bottom a>span{width:35px;height:35px;border-radius:11px;display:grid;place-items:center;background:#f1f5f8;color:#2f6fca;font-weight:800}.admin-home-bottom div{flex:1;display:grid;gap:2px}.admin-home-bottom b{font-size:12px}.admin-home-bottom small{font-size:10px;color:#7a8794;line-height:1.4}.admin-home-bottom strong{font-size:18px;color:#8b97a3}.admin-content-page{max-width:1180px!important;margin:0 auto!important;padding:38px 0 90px!important}.admin-page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:25px;margin-bottom:25px}.admin-page-head h1{font-size:clamp(38px,5vw,58px);line-height:1;letter-spacing:-.05em;margin:13px 0 8px}.admin-page-head p{max-width:700px;color:#687482;line-height:1.55;margin:0}.admin-back{display:inline-block;color:#2f6fca;font-size:12px;font-weight:800;margin-bottom:13px}.admin-secondary-btn{display:inline-flex;padding:10px 13px;border:1px solid #d8e2eb;border-radius:12px;background:#fff;color:#2f6fca;font-size:11px;font-weight:800}.admin-editor-grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(280px,.55fr);gap:16px;margin-bottom:18px}.admin-editor-card,.admin-editor-side{border:1px solid #dfe5ea!important;box-shadow:0 10px 28px rgba(31,48,66,.055)!important}.admin-editor-card h2,.admin-editor-side h2{margin-top:7px}.admin-editor-label{font-size:10px;font-weight:800;letter-spacing:.11em;color:#7c8995}.admin-editor-side{display:flex;flex-direction:column;justify-content:center;min-height:320px}.admin-side-icon{width:48px;height:48px;border-radius:15px;background:#edf4ff;color:#2f6fca;display:grid;place-items:center;font-weight:900;font-size:22px}.admin-editor-side p{color:#6f7b88;line-height:1.6;font-size:13px}.admin-side-rule{height:1px;background:#e4e9ed;margin:14px 0}.admin-editor-side b{font-size:13px;color:#2f6fca}.admin-list-card{background:#fff;border:1px solid #dfe5ea;border-radius:22px;overflow:hidden;box-shadow:0 10px 28px rgba(31,48,66,.055)}.admin-list-head{display:flex;justify-content:space-between;align-items:flex-end;padding:19px 20px;border-bottom:1px solid #e5e9ed}.admin-list-head small{color:#7b8794;font-size:10px}.admin-list-row{display:flex;align-items:center;gap:16px;justify-content:space-between;padding:14px 20px;border-bottom:1px solid #edf0f2}.admin-list-row:last-child{border-bottom:0}.admin-list-row>div{display:grid;gap:4px;min-width:0}.admin-list-row strong{font-size:13px}.admin-list-row small{font-size:10px;color:#7b8794}.admin-empty{padding:30px 20px;color:#7b8794;text-align:center}.admin-table-card{overflow:auto}.admin-table-card table{min-width:820px}.admin-navlinks .admin-nav-logout{color:#d05b5b!important}.admin-navlinks .admin-nav-logout:hover{background:#fff1f1!important;color:#b94343!important}@media(max-width:1050px){.admin-home-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.admin-content-page,.admin-home-page{padding-left:16px!important;padding-right:16px!important}}@media(max-width:850px){.admin-home-hero{align-items:flex-start;flex-direction:column}.admin-home-status{width:100%;box-sizing:border-box}.admin-home-stats{grid-template-columns:repeat(3,1fr)}.admin-editor-grid{grid-template-columns:1fr}.admin-page-head{align-items:flex-start;flex-direction:column}.admin-secondary-btn{width:100%;justify-content:center;box-sizing:border-box}.admin-home-bottom{grid-template-columns:1fr}.admin-navlinks{display:none!important}.admin-header .nav-toggle{display:grid!important;place-items:center!important}}@media(max-width:560px){.admin-home-page{padding-top:28px!important}.admin-home-hero h1{font-size:42px}.admin-home-hero p{font-size:14px}.admin-home-stats{grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:30px}.admin-home-stats div{padding:13px}.admin-home-grid{grid-template-columns:1fr;gap:11px}.admin-home-card{min-height:190px;border-radius:20px;padding:17px}.admin-home-icon{margin-top:19px}.admin-home-card h2{font-size:19px}.admin-home-card p{font-size:12px}.admin-home-section-title{align-items:flex-start;flex-direction:column;gap:5px}.admin-page-head h1{font-size:39px}.admin-list-head{align-items:flex-start;flex-direction:column;gap:5px}.admin-list-row{align-items:flex-start}.admin-list-row .btn{flex:0 0 auto}.admin-editor-side{min-height:0}.admin-table-card{border-radius:18px}.admin-table-card table{font-size:11px}}
/* ===== VYBE friendly UI polish ===== */
:root{--vybe-ui-blue:#2f6fca;--vybe-ui-blue-dark:#245aa8;--vybe-ui-blue-soft:#edf4ff;--vybe-ui-green:#68b82e;--vybe-ui-green-soft:#edf8e6;--vybe-ui-text:#17202b;--vybe-ui-muted:#687482;--vybe-ui-line:#dfe5ea;--vybe-ui-surface:#ffffff;--vybe-ui-shadow:0 8px 24px rgba(31,48,66,.07)}
body{background:#f6f8fa!important;color:var(--vybe-ui-text)!important}
.nav{background:rgba(255,255,255,.97)!important;border-bottom:1px solid #e2e7ec!important;box-shadow:0 3px 14px rgba(28,43,58,.05)!important}
.brandmark{background:var(--vybe-ui-blue)!important;color:#fff!important;border-radius:9px!important}.brandtext{color:var(--vybe-ui-text)!important}
.navlinks a,.nav a{color:#465260!important}.navlinks a:hover,.nav a:hover{background:#f0f5fb!important;color:var(--vybe-ui-blue)!important}
.wrap{max-width:1320px!important}
.card,.panel,.student-feature,.student-mini,.student-link,.feed-item,.stat-chip,.top-stat,.top-tool,.academic-resource-card,.academic-update-card,.academic-detail,.academic-app-card{background:#fff!important;border:1px solid var(--vybe-ui-line)!important;box-shadow:var(--vybe-ui-shadow)!important;border-radius:16px!important}
.card:hover,.student-feature:hover,.student-mini:hover,.student-link:hover{border-color:#cbd8e5!important;box-shadow:0 12px 30px rgba(31,48,66,.09)!important}
/* Consistent, easy-to-read buttons */
.btn,.button,.academic-btn,.academic-search button,.academic-filter-form button{min-height:42px!important;padding:10px 17px!important;border-radius:9px!important;font-size:14px!important;font-weight:700!important;letter-spacing:-.005em!important;transition:background .16s ease,border-color .16s ease,color .16s ease,transform .16s ease,box-shadow .16s ease!important}
.btn,.button{background:#26323e!important;color:#fff!important;border:1px solid #26323e!important;box-shadow:0 2px 5px rgba(20,35,50,.08)!important}
.btn.accent,.academic-btn{background:var(--vybe-ui-blue)!important;color:#fff!important;border-color:var(--vybe-ui-blue)!important}
.btn.accent:hover,.academic-btn:hover{background:var(--vybe-ui-blue-dark)!important;border-color:var(--vybe-ui-blue-dark)!important}
.btn.dark{background:#fff!important;color:#34404d!important;border-color:#cfd8e0!important;box-shadow:none!important}
.btn.dark:hover{background:#f5f8fb!important;border-color:#b9c7d4!important}
.btn.good{background:var(--vybe-ui-green-soft)!important;color:#3f7819!important;border-color:#cce5b9!important;box-shadow:none!important}
.btn.good:hover{background:#e2f3d4!important}
.btn.danger{background:#fff4f4!important;color:#b32929!important;border-color:#efcaca!important;box-shadow:none!important}
.btn.danger:hover{background:#ffe9e9!important;border-color:#e8b6b6!important}
.btn:hover,.button:hover{transform:translateY(-1px)!important;box-shadow:0 5px 14px rgba(31,48,66,.10)!important}
.btn:active,.button:active{transform:translateY(0)!important;box-shadow:none!important}
.btn:focus-visible,.button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid rgba(47,111,202,.18)!important;outline-offset:2px!important}
.actions{gap:8px!important}
input,textarea,select{background:#fff!important;color:var(--vybe-ui-text)!important;border:1px solid #d6dee5!important;border-radius:9px!important;box-shadow:none!important}
input:focus,textarea:focus,select:focus{border-color:#75a2d9!important;box-shadow:0 0 0 3px rgba(47,111,202,.10)!important}
.badge{background:var(--vybe-ui-blue-soft)!important;color:#3566a7!important;border-color:#d5e3f6!important;border-radius:7px!important}
.pill{background:#f3f6f8!important;color:#586572!important;border:1px solid #dce3e8!important;border-radius:7px!important}
.muted,.small{color:var(--vybe-ui-muted)!important}
/* Friendlier student home cards */
.home-action{background:#fff!important;border-color:#dfe5ea!important;border-radius:15px!important;box-shadow:var(--vybe-ui-shadow)!important}
.home-action:hover{border-color:#c8d8e8!important;background:#fff!important}
.home-action-primary{background:#f5f9ff!important;border-color:#c9dbf1!important}
.home-action-icon{background:var(--vybe-ui-blue-soft)!important;border-color:#d5e3f5!important;color:var(--vybe-ui-blue)!important;border-radius:11px!important}
.home-update-panel{background:#fff!important;border-color:#dfe5ea!important}
.home-update-icon{background:var(--vybe-ui-green-soft)!important;border-color:#d5e9c7!important}
/* Academic search and navigation controls */
.academic-search{border-radius:11px!important;border-color:#dce3e9!important;box-shadow:0 8px 25px rgba(31,48,66,.07)!important}
.academic-search button,.academic-filter-form button{background:var(--vybe-ui-blue)!important;color:#fff!important;border-color:var(--vybe-ui-blue)!important}
.academic-search button:hover,.academic-filter-form button:hover{background:var(--vybe-ui-blue-dark)!important}
.academic-outline,.academic-reset{border-radius:9px!important;background:#fff!important;color:#465463!important;border-color:#d3dce4!important}
.academic-outline:hover,.academic-reset:hover{background:#f4f7fa!important;border-color:#bccbd8!important}
.academic-quick,.academic-tool{border-radius:13px!important;background:#fff!important;border-color:#dfe5ea!important}
.academic-quick:hover,.academic-tool:hover{border-color:#c7d7e7!important;box-shadow:0 8px 20px rgba(31,48,66,.06)!important}
.academic-quick-green{background:#f7fbf3!important;border-color:#d5e8c7!important}
.academic-icon{background:var(--vybe-ui-blue-soft)!important;color:var(--vybe-ui-blue)!important;border-color:#d5e3f5!important;border-radius:8px!important}
.academic-quick-green .academic-icon{background:var(--vybe-ui-green-soft)!important;color:#4f8b20!important;border-color:#d5e8c7!important}
.academic-tag{background:var(--vybe-ui-blue-soft)!important;color:#3566a7!important;border-color:#d5e3f6!important;border-radius:6px!important}
.academic-link{color:var(--vybe-ui-blue)!important;font-weight:700!important}
/* Mobile: keep buttons comfortably tappable */
@media(max-width:700px){.btn,.button,.academic-btn,.academic-search button,.academic-filter-form button{min-height:44px!important;padding:10px 15px!important}.actions .btn{flex:0 0 auto}.home-action{border-radius:13px!important}.academic-quick,.academic-tool{border-radius:12px!important}}
/* ===== VYBE soft blue-white-green background ===== */
html{background:#f2f7f8!important}
body{
  background:
    radial-gradient(circle at 8% 8%, rgba(83,154,220,.16), transparent 30%),
    radial-gradient(circle at 92% 16%, rgba(111,190,76,.12), transparent 28%),
    radial-gradient(circle at 50% 100%, rgba(73,151,211,.10), transparent 34%),
    linear-gradient(135deg,#f4f8fb 0%,#f7faf8 48%,#f1f8f3 100%)!important;
  color:var(--vybe-ui-text)!important;
}
.nav{background:rgba(255,255,255,.90)!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important}
main,.main,.wrap{position:relative}
.section{position:relative}
.academic-hero{background:linear-gradient(180deg,rgba(255,255,255,.40),rgba(236,246,251,.20))!important;border-radius:24px}
.card,.panel,.student-feature,.student-mini,.student-link,.feed-item,.stat-chip,.top-stat,.top-tool,.academic-resource-card,.academic-update-card,.academic-detail,.academic-app-card{background:rgba(255,255,255,.90)!important}
.home-action,.home-update-panel,.academic-quick,.academic-tool,.academic-filter-panel{background:rgba(255,255,255,.88)!important}
.home-action-primary{background:linear-gradient(135deg,rgba(238,246,255,.96),rgba(242,250,246,.96))!important}
.academic-quick-green{background:linear-gradient(135deg,#f5fbf0,#f4f9ff)!important}


/* ===== VYBE LIVE UI / PAGE PERSONALITY ===== */
.page-shell{min-height:calc(100vh - 150px)}
/* Each major page gets a subtle identity tint without changing the overall VYBE palette. */
.page-academics .section:first-child,.page-papers .section:first-child{background:linear-gradient(135deg,rgba(232,243,255,.70),rgba(239,250,241,.55));border:1px solid rgba(83,137,199,.13);border-radius:24px;padding:28px}
.page-community .section:first-child,.page-chat .section:first-child{background:linear-gradient(135deg,rgba(236,250,238,.72),rgba(235,246,255,.55));border:1px solid rgba(96,164,91,.13);border-radius:24px;padding:28px}
.page-issues .section:first-child,.page-help-desk .section:first-child{background:linear-gradient(135deg,rgba(236,246,255,.72),rgba(244,250,239,.58));border:1px solid rgba(70,132,194,.13);border-radius:24px;padding:28px}
.page-events .section:first-child,.page-updates .section:first-child{background:linear-gradient(135deg,rgba(239,250,232,.72),rgba(236,246,255,.52));border:1px solid rgba(100,166,70,.13);border-radius:24px;padding:28px}
.page-profile .section:first-child,.page-security .section:first-child{background:linear-gradient(135deg,rgba(236,246,255,.72),rgba(248,250,243,.58));border:1px solid rgba(70,132,194,.12);border-radius:24px;padding:28px}
/* Search bar feels alive: animated caret/glow and a soft rotating suggestion. */
.student-search,.academic-search{position:relative}
.student-search:focus-within,.academic-search:focus-within{box-shadow:0 0 0 4px rgba(47,111,202,.08),0 12px 30px rgba(47,111,202,.08)!important}
.student-search input,.academic-search input{transition:border-color .2s ease,box-shadow .2s ease,background .2s ease!important}
.student-search input::placeholder,.academic-search input::placeholder{transition:opacity .22s ease!important}
.vybe-live-caret{display:inline-block;width:2px;height:16px;background:#4f91d6;vertical-align:-3px;margin-left:3px;border-radius:2px;animation:vybeCaret 1s steps(1,end) infinite}
@keyframes vybeCaret{50%{opacity:0}}
/* Better compact controls: real words, not single-letter placeholders. */
.student-control{min-width:76px!important;height:42px!important;padding:0 13px!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:7px!important;border-radius:11px!important;font-weight:750!important;font-size:12px!important;letter-spacing:.01em!important}
.student-control .control-symbol{display:inline-flex;align-items:center;justify-content:center;line-height:1}
.student-control.active .control-symbol{font-weight:800}
.student-header-icon.profile,.student-menu{min-width:78px!important;padding:0 13px!important;border-radius:10px!important;font-size:12px!important;font-weight:750!important;letter-spacing:.01em!important}
.student-menu{cursor:pointer!important}
/* Desktop menu is a single dropdown. The mobile drawer is completely hidden on desktop until opened. */
@media(min-width:851px){
  #vybeMobileNav.student-mobile-menu{display:none!important;position:absolute!important;top:72px!important;right:18px!important;left:auto!important;width:260px!important;height:auto!important;padding:10px!important;z-index:6000!important;border-radius:16px!important;background:rgba(255,255,255,.98)!important;border:1px solid #dfe5ea!important;box-shadow:0 18px 45px rgba(31,48,66,.14)!important;backdrop-filter:blur(18px)!important}
  #vybeMobileNav.student-mobile-menu.open{display:flex!important;flex-direction:column!important;gap:5px!important}
  #vybeMobileNav.student-mobile-menu > a{display:flex!important;align-items:center!important;padding:11px 12px!important;border-radius:10px!important;text-decoration:none!important;color:#33404d!important;font-weight:650!important}
  #vybeMobileNav.student-mobile-menu > a:hover{background:#eef5ff!important;color:#2f6fca!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-head,.mobile-only-menu-links{display:none!important}
}
/* Mobile keeps the existing bottom navigation. */
@media(max-width:850px){
  .student-header-icon.profile,.student-menu{min-width:0!important}
  .student-control{min-width:0!important;font-size:11px!important;padding:0 8px!important}
  .student-control-row{gap:7px!important}
  .student-search{flex:1 1 auto!important}
  .page-shell{padding-bottom:12px}
}
/* Make small action buttons visually distinct instead of looking like one generic rectangle. */
.actions .btn,.card .btn,.form .btn{white-space:nowrap}
.btn:not(.accent):not(.danger):not(.good):not(.dark){background:#26323e!important}
.btn.good{font-weight:800!important}.btn.danger{font-weight:800!important}

/* ===== VYBE HOME / SIMPLE NAV / LIVE FOOTER ===== */
.home-live-hero{position:relative;display:grid;grid-template-columns:minmax(0,1.35fr) 300px;align-items:center;min-height:390px;padding:48px 52px;margin:8px 0 34px;overflow:hidden;border:1px solid #dce8f0;border-radius:30px;background:linear-gradient(135deg,#ffffff 0%,#f1f8ff 58%,#f2faef 100%);box-shadow:0 24px 70px rgba(42,75,105,.10)}
.home-live-copy{position:relative;z-index:2}.home-live-copy h1{font-size:clamp(42px,6vw,76px);line-height:.96;letter-spacing:-.065em;margin:16px 0 12px;color:#101827}.home-live-copy p{max-width:620px;color:#667484;font-size:17px;line-height:1.6;margin:0}.home-hero-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}.home-hero-actions .btn{min-height:46px}
.home-live-glow{position:absolute;border-radius:50%;filter:blur(3px);pointer-events:none}.home-live-glow-one{width:280px;height:280px;right:140px;top:-100px;background:rgba(48,115,202,.13);}.home-live-glow-two{width:230px;height:230px;right:-50px;bottom:-80px;background:rgba(82,164,62,.12);}.home-live-orbit{position:relative;width:250px;height:250px;margin:auto;border-radius:50%;border:1px solid rgba(47,111,202,.18);background:radial-gradient(circle,#fff 0 20%,rgba(255,255,255,.72) 21% 42%,rgba(47,111,202,.06) 43% 100%);box-shadow:0 20px 55px rgba(47,111,202,.12);}.home-live-orbit:before,.home-live-orbit:after{content:"";position:absolute;inset:26px;border:1px solid rgba(76,139,203,.13);border-radius:50%}.home-live-orbit:after{inset:52px;border-color:rgba(81,159,73,.16)}.orbit-core{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);display:grid;place-items:center;width:76px;height:76px;border-radius:22px;background:#101827;color:#fff;font-size:31px;font-weight:900;box-shadow:0 16px 35px rgba(16,24,39,.20)}.orbit-dot{position:absolute;width:12px;height:12px;border-radius:50%;z-index:2}.orbit-dot-a{top:29px;right:61px;background:#3279ce;box-shadow:0 0 0 7px rgba(50,121,206,.10)}.orbit-dot-b{bottom:45px;left:38px;background:#62a74d;box-shadow:0 0 0 7px rgba(98,167,77,.10)}

.home-action-grid.live-home-grid{grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.live-home-grid .home-action{min-height:154px;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:13px;padding:18px;border-radius:21px;background:#fff;border:1px solid #dfe7ed;box-shadow:0 10px 28px rgba(39,62,82,.055);transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}.live-home-grid .home-action:hover{transform:translateY(-4px);border-color:#bdd6e8;box-shadow:0 18px 38px rgba(39,83,119,.10)}.live-home-grid .home-action b{font-size:11px;color:#4c82bb;text-transform:uppercase;letter-spacing:.06em}.live-home-grid .home-action-icon{display:grid;place-items:center;width:44px;height:44px;border-radius:14px;background:#eef5ff;color:#2f6fca;font-size:13px;font-weight:850}.live-home-grid .home-action:nth-child(2n) .home-action-icon{background:#f0f8ec;color:#5b8f35}.live-home-grid .home-action:nth-child(3n) .home-action-icon{background:#f3f5f7;color:#43515f}.live-home-grid .home-action-primary{background:linear-gradient(145deg,#f4f9ff,#fff)!important;border-color:#cfe0ef!important}.live-home-grid .home-action span:nth-child(2){min-width:0}.live-home-grid .home-action strong{display:block;font-size:15px;color:#172130;margin-bottom:4px}.live-home-grid .home-action small{display:block;color:#748292;line-height:1.4}
.home-updates-head{display:flex;justify-content:space-between;align-items:end;gap:18px;margin:40px 0 14px}.home-updates-head p{margin:4px 0 0;color:#7a8794}.home-live-status{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #d7e8d0;border-radius:999px;background:#f4faef;color:#56833a;font-size:11px;font-weight:800;letter-spacing:.05em}.home-live-status span{width:7px;height:7px;border-radius:50%;background:#57a53f;box-shadow:0 0 0 5px rgba(87,165,63,.10);}
.vybe-footer{margin-top:40px!important;background:#f8fafb!important;border-top:1px solid #dfe7ed!important;text-align:left!important;color:#66717e!important}.footer-inner{max-width:1400px;margin:auto;padding:26px 20px;display:flex;align-items:center;gap:28px;justify-content:space-between}.footer-brand{display:flex;flex-direction:column;gap:4px}.footer-brand strong{font-size:18px;color:#182230}.footer-brand span,.footer-copy{font-size:12px;color:#7b8792}.footer-links{display:flex;gap:6px;flex-wrap:wrap;justify-content:center}.footer-links a{padding:9px 12px;border:1px solid #dce4ea;border-radius:10px;background:#fff;color:#42505d;font-size:12px;font-weight:700;transition:.2s ease}.footer-links a:hover{border-color:#b9d3e8;background:#eef6ff;color:#2f6fca}.footer-copy{text-align:right}
@media(max-width:1000px){.home-live-hero{grid-template-columns:1fr 220px;padding:38px}.home-live-orbit{width:200px;height:200px}.home-action-grid.live-home-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:850px){.home-live-hero{display:block;min-height:0;padding:30px 22px;border-radius:24px}.home-live-copy h1{font-size:43px}.home-live-copy p{font-size:15px}.home-live-orbit{width:145px;height:145px;margin:28px 0 0 auto}.orbit-core{width:52px;height:52px;border-radius:16px;font-size:22px}.home-live-orbit:before{inset:18px}.home-live-orbit:after{inset:35px}.orbit-dot-a{top:18px;right:35px}.orbit-dot-b{bottom:27px;left:22px}.home-action-grid.live-home-grid{grid-template-columns:1fr;gap:10px}.live-home-grid .home-action{min-height:94px;grid-template-columns:auto 1fr auto}.home-updates-head{align-items:start}.footer-inner{padding:22px 14px 100px;display:grid;gap:15px}.footer-links{justify-content:flex-start}.footer-copy{text-align:left}.footer-links a{flex:1 1 auto;text-align:center}.home-hero-actions .btn{flex:1 1 180px}.student-control-row{overflow-x:auto;scrollbar-width:none}.student-control-row::-webkit-scrollbar{display:none}.student-control{flex:0 0 auto!important}.student-search{min-width:180px!important}}
/* ===== FLOATING VYBE ASSISTANT ===== */
.vybe-assistant-fab{position:fixed;right:24px;bottom:24px;z-index:7000;display:flex;align-items:center;gap:9px;border:1px solid #b9d6ed;background:#101827;color:#fff;border-radius:16px;padding:12px 16px;min-height:48px;box-shadow:0 16px 40px rgba(16,24,39,.20);font-weight:800;font-size:13px;cursor:pointer;transition:transform .2s ease,box-shadow .2s ease,background .2s ease}
.vybe-assistant-fab:hover{transform:translateY(-3px);box-shadow:0 20px 46px rgba(16,24,39,.25);background:#172238}
.vybe-assistant-fab .fab-mark{display:grid;place-items:center;width:27px;height:27px;border-radius:9px;background:#eaf3ff;color:#2f6fca;font-size:11px;font-weight:900}
.vybe-assistant-panel{position:fixed;right:24px;bottom:84px;width:min(390px,calc(100vw - 32px));z-index:6999;background:rgba(8,15,25,.97);background-image:linear-gradient(145deg,rgba(19,34,53,.98),rgba(7,13,22,.97));border:1px solid rgba(104,142,178,.38);border-radius:22px;box-shadow:0 26px 72px rgba(0,0,0,.46),0 6px 22px rgba(9,18,31,.34),inset 0 1px rgba(255,255,255,.07);backdrop-filter:blur(24px) saturate(135%);-webkit-backdrop-filter:blur(24px) saturate(135%);overflow:hidden;opacity:0;transform:translateY(12px) scale(.98);pointer-events:none;transition:opacity .2s ease,transform .2s ease;color:#f4f7fb}
.vybe-assistant-panel.open{opacity:1;transform:none;pointer-events:auto}
.vybe-assistant-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 17px;border-bottom:1px solid rgba(105,139,171,.24);background:linear-gradient(135deg,rgba(29,50,76,.92),rgba(13,29,42,.88))}
.vybe-assistant-head strong{font-size:15px;color:#ffffff}.vybe-assistant-head small{display:block;margin-top:2px;color:#9fb2c5;font-size:11px}.vybe-assistant-close{border:1px solid rgba(120,150,180,.34);background:rgba(255,255,255,.07);color:#e4edf5;width:34px;height:34px;border-radius:10px;font-size:18px;cursor:pointer}
.vybe-assistant-body{padding:15px}.vybe-assistant-suggestions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:13px}.vybe-assistant-suggestion{display:flex;align-items:center;justify-content:flex-start;min-height:42px;padding:9px 11px;border:1px solid rgba(105,139,170,.28);border-radius:11px;background:rgba(255,255,255,.055);color:#e8eef5;text-decoration:none;font-size:12px;font-weight:750;transition:.18s ease}.vybe-assistant-suggestion:hover{background:rgba(47,111,202,.20);border-color:rgba(104,160,216,.48);color:#ffffff;transform:translateY(-1px)}
.vybe-assistant-form{display:flex;gap:8px;align-items:stretch}.vybe-assistant-form input{min-width:0;flex:1;height:44px;border:1px solid #d5e0e7;border-radius:11px;padding:0 12px;background:#fff;color:#1e2935;outline:none}.vybe-assistant-form input:focus{border-color:#77aeda;box-shadow:0 0 0 4px rgba(47,111,202,.08)}.vybe-assistant-form button{height:44px;padding:0 14px;border:0;border-radius:11px;background:#101827;color:#fff;font-weight:800;cursor:pointer}.vybe-assistant-note{font-size:10px;color:#87929d;margin:10px 2px 0;line-height:1.4}
@media(max-width:850px){.vybe-assistant-fab{right:14px;bottom:82px;border-radius:14px;padding:10px 13px;min-height:45px}.vybe-assistant-panel{right:10px;bottom:136px;width:calc(100vw - 20px);border-radius:20px}.vybe-assistant-suggestions{grid-template-columns:1fr 1fr}.vybe-assistant-form input{font-size:14px}}




/* ===== FINAL MENU PANEL — MATCH ASK VYBE DARK BLUE GLASS ===== */
#vybeMobileNav.student-mobile-menu{
  background:linear-gradient(145deg,rgba(19,34,53,.98),rgba(7,13,22,.97))!important;
  background-color:#0b1625!important;
  color:#f4f7fb!important;
  border:1px solid rgba(104,142,178,.38)!important;
  box-shadow:0 26px 72px rgba(0,0,0,.46),0 6px 22px rgba(9,18,31,.34),inset 0 1px rgba(255,255,255,.07)!important;
  backdrop-filter:blur(24px) saturate(135%)!important;
  -webkit-backdrop-filter:blur(24px) saturate(135%)!important;
}
#vybeMobileNav.student-mobile-menu .mobile-menu-head{
  border-bottom:1px solid rgba(105,139,171,.24)!important;
  background:linear-gradient(135deg,rgba(29,50,76,.92),rgba(13,29,42,.88))!important;
}
#vybeMobileNav.student-mobile-menu .mobile-menu-title{
  color:#fff!important;
}
#vybeMobileNav.student-mobile-menu .mobile-menu-close{
  background:rgba(255,255,255,.07)!important;
  border:1px solid rgba(120,150,180,.34)!important;
  color:#e4edf5!important;
}
#vybeMobileNav.student-mobile-menu > a,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a{
  background:rgba(255,255,255,.055)!important;
  border:1px solid rgba(105,139,170,.28)!important;
  color:#e8eef5!important;
  box-shadow:none!important;
}
#vybeMobileNav.student-mobile-menu > a:hover,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a:hover,
#vybeMobileNav.student-mobile-menu > a:focus-visible,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a:focus-visible,
#vybeMobileNav.student-mobile-menu > a:active,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a:active{
  background:rgba(47,111,202,.20)!important;
  border-color:rgba(104,160,216,.48)!important;
  color:#fff!important;
}
@media(max-width:850px){
  #vybeMobileNav.student-mobile-menu{
    background:linear-gradient(145deg,rgba(19,34,53,.98),rgba(7,13,22,.97))!important;
    border:1px solid rgba(104,142,178,.38)!important;
    box-shadow:0 26px 72px rgba(0,0,0,.46),0 6px 22px rgba(9,18,31,.34),inset 0 1px rgba(255,255,255,.07)!important;
    backdrop-filter:blur(24px) saturate(135%)!important;
    -webkit-backdrop-filter:blur(24px) saturate(135%)!important;
  }
  #vybeMobileNav.student-mobile-menu .mobile-menu-title{color:#fff!important}
  #vybeMobileNav.student-mobile-menu > a,
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links a{
    background:rgba(255,255,255,.055)!important;
    border:1px solid rgba(105,139,170,.28)!important;
    color:#e8eef5!important;
  }
}
/* ===== VYBE COMPACT HEADER / NO FOOTER ===== */
.student-nav-compact{max-width:1280px!important;min-height:58px!important;padding:7px 18px!important;gap:16px!important}
.student-nav-compact .student-brand-compact{font-size:20px!important;min-width:76px!important}
.student-desktop-links{display:flex;align-items:center;gap:4px;flex:0 1 auto}
.student-desktop-links a{padding:9px 11px;border-radius:10px;color:#aebdca;font-size:13px;font-weight:700;white-space:nowrap;transition:.18s ease}
.student-desktop-links a:hover{background:rgba(40,133,191,.12);color:#fff}
.student-header-back{display:inline-flex;align-items:center;gap:7px;color:#dcefff;font-weight:750;font-size:13px;text-decoration:none;min-width:76px}
.student-header-back:hover{color:#4cc2ff}
.student-header-tools{margin-left:auto!important;display:flex!important;align-items:center!important}
.student-header-tools .profile{display:none!important}
.student-control-row{max-width:1280px!important;margin:0 auto!important;padding:0 18px 8px!important;border:0!important;background:transparent!important}
.student-control-row .student-search{max-width:420px!important;margin-left:auto!important;height:38px!important}
.student-control-row .student-search input{height:38px!important;border-radius:11px!important;font-size:13px!important}
.vybe-footer,.footer{display:none!important}
@media(max-width:850px){
  .navin.student-nav-compact{min-height:54px!important;padding:7px 10px!important;justify-content:space-between!important}
  .student-brand-compact{font-size:19px!important}
  .student-desktop-links{display:none!important}
  .student-nav-compact .student-header-tools{display:flex!important;margin-left:auto!important}
  .student-header-back{min-width:0!important;font-size:13px!important;padding:7px 4px!important}
  .student-control-row{padding:0 10px 7px!important}
  .student-control-row .student-search{max-width:none!important;width:100%!important;height:38px!important}
  .student-control-row .student-search input{height:38px!important}
  .student-bottom-spacer{display:block!important;height:74px!important}
}
@media(min-width:851px){
  .student-mobile-menu{top:58px!important;right:18px!important;left:auto!important;width:230px!important;border-radius:16px!important}
  .student-mobile-menu.open{display:flex!important}
  .student-bottom-nav{display:none!important}
}


/* ===== VYBE REFERENCE HEADER / CLEAN MOBILE NAV ===== */
.student-nav-compact{
  max-width:1400px!important;
  min-height:64px!important;
  padding:8px 30px!important;
  gap:28px!important;
  background:#fff!important;
  color:#172033!important;
}
.nav:has(.student-nav-compact){
  background:#fff!important;
  border-bottom:1px solid #e8ece7!important;
  box-shadow:0 5px 20px rgba(30,45,55,.045)!important;
}
.student-brand-compact{display:flex!important;align-items:center!important;gap:11px!important;min-width:150px!important;text-decoration:none!important}
.student-brand-compact .brandmark{width:46px!important;height:46px!important;border-radius:15px!important;background:linear-gradient(145deg,#163b69,#07111f)!important;color:#fff!important;box-shadow:0 10px 24px rgba(7,17,31,.16)!important;display:grid!important;place-items:center!important;font-weight:900!important;font-size:22px!important}
.student-brand-compact .brandtext{background:none!important;color:#172033!important;-webkit-text-fill-color:#172033!important;font-size:22px!important;font-weight:900!important;letter-spacing:-.04em!important}
.student-desktop-links{flex:1!important;justify-content:center!important;gap:4px!important}
.student-desktop-links a{padding:11px 15px!important;border-radius:9px!important;color:#172033!important;font-size:14px!important;font-weight:700!important}
.student-desktop-links a:hover{background:#f2f7ed!important;color:#172033!important}
.student-header-tools{gap:8px!important}
.student-header-updates{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:40px!important;padding:0 13px!important;border-radius:10px!important;color:#172033!important;text-decoration:none!important;font-size:14px!important;font-weight:700!important}
.student-header-updates:hover{background:#f2f7ed!important}
.student-menu{height:40px!important;min-width:68px!important;background:#172033!important;color:#fff!important;border:0!important;border-radius:10px!important;box-shadow:none!important}
.student-menu:hover{background:#263246!important;border-color:transparent!important;box-shadow:none!important}
.student-control-row{max-width:1400px!important;padding:0 30px 10px!important;background:#fff!important}
.student-control-row .student-search{max-width:460px!important;margin-left:auto!important}
.student-search input{background:#f7f9f7!important;border-color:#e0e6df!important;color:#172033!important;box-shadow:none!important}
.student-search input:focus{background:#fff!important;border-color:#a8c987!important;box-shadow:0 0 0 4px rgba(155,234,43,.12)!important}
.student-header-back{color:#172033!important;background:#f5f7f4!important;border:1px solid #e0e6df!important;border-radius:10px!important;padding:9px 13px!important;min-width:auto!important}
.student-header-back:hover{color:#172033!important;background:#edf5e8!important}
.student-header-back + .student-desktop-links{justify-content:center!important}
/* Desktop menu contains names only, never alphabet markers. */
#vybeMobileNav.student-mobile-menu > a{font-size:13px!important;color:#25313e!important}
#vybeMobileNav.student-mobile-menu > a:hover{background:#f1f7eb!important;color:#4e7f25!important}
#vybeMobileNav.student-mobile-menu .student-menu-icon{display:none!important}
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a{font-size:13px!important}
/* Phone: the bottom navigation is the same clean navigation language as Home. */
@media(max-width:850px){
  .student-nav-compact{min-height:58px!important;padding:7px 12px!important;gap:8px!important}
  .student-brand-compact{min-width:auto!important;gap:8px!important}
  .student-brand-compact .brandmark{width:38px!important;height:38px!important;border-radius:12px!important;background:linear-gradient(145deg,#163b69,#07111f)!important;color:#fff!important;box-shadow:0 8px 20px rgba(7,17,31,.15)!important;font-size:19px!important}
  .student-brand-compact .brandtext{font-size:19px!important}
  .student-header-tools{gap:6px!important}
  .student-header-updates{display:none!important}
  .student-menu{height:38px!important;min-width:62px!important;font-size:12px!important}
  .student-control-row{padding:5px 12px 8px!important;background:#fff!important}
  .student-control-row .student-search{width:100%!important;max-width:none!important}
  .student-bottom-nav{
    display:flex!important;align-items:stretch!important;justify-content:space-around!important;
    height:68px!important;padding:7px 12px calc(7px + env(safe-area-inset-bottom))!important;
    background:rgba(255,255,255,.97)!important;border-top:1px solid #e1e7df!important;
    box-shadow:0 -8px 25px rgba(30,50,40,.08)!important;backdrop-filter:blur(18px)!important;
  }
  .student-bottom-nav a,.student-bottom-nav button.mobile-menu-nav{
    flex:1!important;display:flex!important;align-items:center!important;justify-content:center!important;
    min-width:0!important;height:48px!important;margin:0 4px!important;border-radius:12px!important;
    color:#5d6874!important;background:transparent!important;border:0!important;text-decoration:none!important;
    font-size:12px!important;font-weight:750!important;box-shadow:none!important;
  }
  .student-bottom-nav a.active{background:#f0f7ea!important;color:#4e7f25!important}
  .student-bottom-nav a:hover,.student-bottom-nav button.mobile-menu-nav:hover{background:#f5f7f5!important;color:#172033!important}
  .student-bottom-nav .mobile-menu-label{display:block!important;font-size:12px!important;color:inherit!important}
  .student-bottom-nav .mobile-menu-icon-lines{display:none!important}
  .student-bottom-spacer{height:78px!important}
  /* Remove the old letter-style markers from mobile menu links. */
  #vybeMobileNav.student-mobile-menu .student-menu-icon{display:none!important}
  #vybeMobileNav.student-mobile-menu a{display:flex!important;align-items:center!important;gap:0!important}
}

/* ===== FINAL STUDENT NAV + SEARCH SUGGESTIONS ===== */
.student-nav-compact .student-desktop-links{display:flex!important;align-items:center!important;justify-content:center!important;flex:1 1 auto!important;gap:2px!important}
.student-nav-compact .student-desktop-links a{display:inline-flex!important;align-items:center!important;justify-content:center!important;padding:10px 13px!important;color:#172033!important;background:transparent!important;border:0!important;text-decoration:none!important;white-space:nowrap!important}
.student-nav-compact .student-desktop-links a:hover{background:#f2f7ed!important;color:#172033!important}
.student-header-tools{flex:0 0 auto!important}
.student-control-row{position:relative!important;display:flex!important;justify-content:center!important;max-width:1400px!important;padding:0 30px 10px!important;background:#fff!important}
.student-control-row .student-search{position:relative!important;width:min(460px,100%)!important;max-width:460px!important;margin:0!important}
.student-search input{width:100%!important;box-sizing:border-box!important}
.vybe-search-suggestions{position:absolute!important;left:0!important;right:0!important;top:calc(100% + 7px)!important;z-index:6500!important;display:none!important;padding:7px!important;background:#fff!important;border:1px solid #dfe7df!important;border-radius:13px!important;box-shadow:0 18px 40px rgba(31,48,66,.14)!important}
.vybe-search-suggestions.open{display:block!important}
.vybe-search-suggestion{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important;width:100%!important;box-sizing:border-box!important;padding:10px 11px!important;border:0!important;border-radius:9px!important;background:#fff!important;color:#25313e!important;text-decoration:none!important;font-size:12px!important;font-weight:700!important;text-align:left!important}
.vybe-search-suggestion:hover,.vybe-search-suggestion:focus{background:#f1f7eb!important;color:#4e7f25!important;outline:none!important}
.vybe-search-suggestion span:last-child{color:#89949d!important;font-weight:600!important;font-size:10px!important}
@media(max-width:850px){
  .student-nav-compact{min-height:58px!important;padding:7px 10px!important;gap:6px!important}
  .student-brand-compact .brandmark{width:38px!important;height:38px!important}
  .student-brand-compact .brandtext{font-size:19px!important}
  .student-header-tools{gap:5px!important}
  .student-header-updates{display:inline-flex!important;height:36px!important;padding:0 10px!important;font-size:12px!important;background:#f2f7ed!important;color:#315a19!important;border:1px solid #d7e9c9!important}
  .student-menu{height:36px!important;min-width:58px!important;background:#172033!important;color:#fff!important;border:0!important;border-radius:10px!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;visibility:visible!important;opacity:1!important}
  .student-control-row{display:flex!important;justify-content:center!important;padding:5px 10px 8px!important;background:#fff!important}
  .student-control-row .student-search{width:100%!important;max-width:none!important;margin:0!important}
  .student-search input{height:40px!important}
  .vybe-search-suggestions{top:calc(100% + 6px)!important;max-height:310px!important;overflow:auto!important}
  .student-bottom-nav button.mobile-menu-nav{background:#172033!important;color:#fff!important;border:1px solid #172033!important;box-shadow:0 7px 18px rgba(23,32,51,.18)!important;visibility:visible!important;opacity:1!important}
  .student-bottom-nav button.mobile-menu-nav:hover,.student-bottom-nav button.mobile-menu-nav:focus{background:#263246!important;color:#fff!important}
  .student-bottom-nav button.mobile-menu-nav .mobile-menu-label{display:block!important;color:#fff!important;font-size:12px!important;font-weight:800!important}
  .student-bottom-nav button.mobile-menu-nav .mobile-menu-icon-lines{display:none!important}
  #vybeMobileNav.student-mobile-menu{display:none!important;position:fixed!important;left:8px!important;right:auto!important;top:64px!important;width:46vw!important;max-width:230px!important;height:auto!important;max-height:calc(100vh - 84px)!important;overflow:auto!important;padding:8px!important;z-index:10000!important;border-radius:14px!important;background:rgba(255,255,255,.99)!important;border:1px solid #dfe7df!important;box-shadow:0 18px 45px rgba(31,48,66,.18)!important;backdrop-filter:blur(18px)!important}
  #vybeMobileNav.student-mobile-menu.open{display:flex!important;flex-direction:column!important;gap:4px!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-head{display:flex!important;align-items:center!important;justify-content:space-between!important;padding:5px 6px 8px!important;border-bottom:1px solid #edf0ec!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-title{font-size:12px!important;font-weight:850!important;color:#172033!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-close{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:27px!important;height:27px!important;border:1px solid #dce5dc!important;border-radius:8px!important;background:#f4f7f3!important;color:#172033!important}
  #vybeMobileNav.student-mobile-menu > a,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a{min-height:35px!important;padding:7px 8px!important;border-radius:8px!important;background:#fff!important;border:0!important;color:#26323e!important;font-size:10.5px!important;font-weight:700!important;white-space:normal!important;line-height:1.2!important}
  #vybeMobileNav.student-mobile-menu > a:hover,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a:hover{background:#f1f7eb!important;color:#4e7f25!important}
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links{display:flex!important;flex-direction:column!important;gap:4px!important}
  #vybeMobileNav.student-mobile-menu .student-menu-icon{display:none!important}
}
@media(min-width:851px){#vybeMobileNav.student-mobile-menu{left:auto!important;right:18px!important;width:260px!important}}


/* ===== FINAL PHONE LAYOUT POLISH ===== */
@media(max-width:850px){
  html,body{width:100%;max-width:100%;overflow-x:hidden!important}
  .nav{width:100%!important;position:relative!important;z-index:5000!important}
  .navin.student-nav-compact{
    width:100%!important;box-sizing:border-box!important;
    min-height:54px!important;padding:7px 12px!important;
    display:flex!important;align-items:center!important;gap:8px!important;
  }
  .student-brand-compact{display:flex!important;align-items:center!important;min-width:0!important;flex:1 1 auto!important;gap:8px!important;overflow:hidden!important}
  .student-brand-compact .brandmark{width:36px!important;height:36px!important;flex:0 0 36px!important;border-radius:11px!important}
  .student-brand-compact .brandtext{font-size:18px!important;white-space:nowrap!important}
  /* Phone header: logo + Updates only. Menu lives exclusively in the bottom bar. */
  .student-header-tools{margin-left:auto!important;flex:0 0 auto!important;gap:0!important}
  .student-header-tools .student-menu{display:none!important}
  .student-header-updates{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:35px!important;padding:0 11px!important;border-radius:9px!important;background:#172033!important;color:#fff!important;border:0!important;font-size:12px!important;font-weight:800!important;white-space:nowrap!important}
  .student-header-back{display:inline-flex!important;align-items:center!important;justify-content:center!important;flex:0 0 auto!important;padding:7px 8px!important;margin-right:1px!important;border-radius:9px!important;font-size:12px!important}
  /* Keep the search directly below the header and make it full-width on every page. */
  .student-control-row{width:100%!important;box-sizing:border-box!important;padding:6px 12px 9px!important;display:flex!important;justify-content:center!important;background:#fff!important}
  .student-control-row .student-search{width:100%!important;max-width:none!important;margin:0!important}
  .student-search input{width:100%!important;height:42px!important;box-sizing:border-box!important;border-radius:11px!important;font-size:13px!important}
  .vybe-search-suggestions{left:0!important;right:0!important;top:calc(100% + 6px)!important;max-height:52vh!important;overflow:auto!important;border-radius:12px!important}
  .vybe-search-suggestion{min-height:42px!important;padding:10px 11px!important;font-size:12px!important}
  .vybe-search-suggestion span:last-child{font-size:10px!important}

  /* One clean bottom navigation: Menu / Home / Profile. */
  .student-bottom-nav{
    position:fixed!important;left:0!important;right:0!important;bottom:0!important;transform:none!important;
    width:100%!important;max-width:none!important;height:68px!important;box-sizing:border-box!important;
    display:flex!important;align-items:center!important;justify-content:stretch!important;
    padding:7px 10px calc(7px + env(safe-area-inset-bottom))!important;
    gap:7px!important;background:rgba(255,255,255,.98)!important;
    border-top:1px solid #dfe7df!important;box-shadow:0 -10px 28px rgba(31,48,66,.10)!important;
    z-index:9000!important;overflow:visible!important;
  }
  .student-bottom-nav a,.student-bottom-nav button.mobile-menu-nav{
    flex:1 1 0!important;width:0!important;min-width:0!important;height:48px!important;
    margin:0!important;padding:0 5px!important;box-sizing:border-box!important;
    display:flex!important;align-items:center!important;justify-content:center!important;
    border-radius:12px!important;font-size:12px!important;font-weight:800!important;
  }
  .student-bottom-nav a{color:#5d6874!important;background:transparent!important;border:0!important;text-decoration:none!important}
  .student-bottom-nav a.active{background:#eef6e8!important;color:#4e7f25!important}
  .student-bottom-nav button.mobile-menu-nav{background:#172033!important;color:#fff!important;border:1px solid #172033!important;box-shadow:0 6px 16px rgba(23,32,51,.16)!important;visibility:visible!important;opacity:1!important}
  .student-bottom-nav button.mobile-menu-nav .mobile-menu-label{display:block!important;color:#fff!important;font-size:12px!important;font-weight:850!important}
  .student-bottom-nav button.mobile-menu-nav .mobile-menu-icon-lines{display:none!important}
  .student-bottom-spacer{display:block!important;height:78px!important}

  /* Phone drawer: left side, clearly separated from the page, under half the screen. */
  #vybeMobileNav.student-mobile-menu{
    display:none!important;position:fixed!important;left:8px!important;right:auto!important;top:60px!important;
    width:44vw!important;max-width:220px!important;min-width:170px!important;
    max-height:calc(100vh - 82px)!important;overflow:auto!important;
    padding:8px!important;box-sizing:border-box!important;z-index:10000!important;
    border-radius:14px!important;background:rgba(255,255,255,.99)!important;
    border:1px solid #dfe7df!important;box-shadow:0 18px 45px rgba(31,48,66,.18)!important;
  }
  #vybeMobileNav.student-mobile-menu.open{display:flex!important;flex-direction:column!important;gap:4px!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-head{display:flex!important;align-items:center!important;justify-content:space-between!important;padding:5px 6px 8px!important;border-bottom:1px solid #edf0ec!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-title{font-size:12px!important;font-weight:850!important;color:#172033!important}
  #vybeMobileNav.student-mobile-menu .mobile-menu-close{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:27px!important;height:27px!important;border:1px solid #dce5dc!important;border-radius:8px!important;background:#f4f7f3!important;color:#172033!important}
  #vybeMobileNav.student-mobile-menu > a,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a{min-height:36px!important;padding:8px 9px!important;border-radius:9px!important;background:#fff!important;border:0!important;color:#26323e!important;font-size:11px!important;font-weight:750!important;line-height:1.2!important;text-decoration:none!important}
  #vybeMobileNav.student-mobile-menu > a:hover,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links a:hover{background:#f1f7eb!important;color:#4e7f25!important}
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links{display:flex!important;flex-direction:column!important;gap:4px!important}
  #vybeMobileNav.student-mobile-menu .student-menu-icon{display:none!important}

  /* Prevent wide cards/tables/forms from breaking the phone viewport. */
  .wrap,.page-shell,.clean-home,.academic-hero,.academic-detail,.community-chat-page-section,.community-page-section{width:100%!important;max-width:100%!important;box-sizing:border-box!important}
  .wrap{padding-left:12px!important;padding-right:12px!important}
  img,video,iframe,table{max-width:100%!important}
  .card,.panel,.academic-detail,.academic-update-card,.academic-resource-card,.home-update-panel{box-sizing:border-box!important;max-width:100%!important}
  input,select,textarea,button{max-width:100%!important;box-sizing:border-box!important}
}



/* ===== FINAL PHONE LOGIN — PHONE FIT ===== */
@media (max-width:850px){
  html,body{width:100%!important;max-width:100%!important;overflow-x:hidden!important}
  body{min-height:100svh!important}
  .nav{width:100%!important;box-sizing:border-box!important}
  .navin{width:100%!important;box-sizing:border-box!important;padding:10px 12px!important}
  .auth{
    min-height:calc(100svh - 62px)!important;width:100%!important;
    display:flex!important;align-items:flex-start!important;justify-content:center!important;
    padding:18px 12px 28px!important;box-sizing:border-box!important;
  }
  .authbox{
    width:100%!important;max-width:430px!important;min-width:0!important;
    margin:0!important;padding:20px 16px!important;box-sizing:border-box!important;
    border-radius:20px!important;overflow:hidden!important;
  }
  .authbox .badge{max-width:100%!important;box-sizing:border-box!important;font-size:10px!important;white-space:nowrap!important}
  .authbox h1{font-size:28px!important;line-height:1.08!important;letter-spacing:-.04em!important;margin:11px 0 8px!important}
  .authbox>p.muted{font-size:13px!important;line-height:1.45!important;margin:0 0 16px!important}
  .authbox .form{display:grid!important;width:100%!important;min-width:0!important;gap:12px!important}
  .authbox .form>div{width:100%!important;min-width:0!important}
  .authbox .label{font-size:12px!important;margin-bottom:5px!important}
  .authbox input,.authbox select,.authbox textarea{
    display:block!important;width:100%!important;min-width:0!important;max-width:100%!important;
    height:46px!important;padding:0 13px!important;box-sizing:border-box!important;
    border-radius:12px!important;font-size:14px!important;
  }
  .authbox .password-wrap{position:relative!important;width:100%!important;min-width:0!important;box-sizing:border-box!important}
  .authbox .password-wrap input{padding-right:48px!important}
  .authbox .password-toggle{right:7px!important;top:50%!important;transform:translateY(-50%)!important;width:36px!important;height:36px!important}
  .authbox .btn{
    width:100%!important;max-width:100%!important;min-height:46px!important;height:auto!important;
    box-sizing:border-box!important;padding:11px 14px!important;border-radius:12px!important;
    font-size:13px!important;white-space:normal!important;
  }
  .authbox .actions{display:grid!important;grid-template-columns:minmax(0,1fr)!important;width:100%!important;gap:9px!important;margin-top:13px!important}
  .authbox .actions .btn{width:100%!important}
  .authbox .small{font-size:11px!important;line-height:1.45!important;text-align:center!important;margin:13px 0 0!important}
  .authbox .flash,.authbox+.flash{max-width:100%!important;box-sizing:border-box!important;overflow-wrap:anywhere!important}
  .authbox a{overflow-wrap:anywhere!important}
}

@media (max-width:380px){
  .navin{padding:9px 10px!important}
  .brandtext{font-size:20px!important}
  .brandmark{width:30px!important;height:30px!important}
  .auth{padding:12px 8px 22px!important}
  .authbox{padding:17px 13px!important;border-radius:17px!important}
  .authbox h1{font-size:25px!important}
  .authbox>p.muted{font-size:12px!important}
  .authbox input,.authbox select,.authbox textarea{height:44px!important;font-size:13px!important}
}


/* ===== VYBE BUTTON SYSTEM — DESKTOP + PHONE ===== */
button,
input[type="submit"],
input[type="button"]{
  font:inherit;
  -webkit-tap-highlight-color:transparent;
  touch-action:manipulation;
}
.btn,.button,.academic-btn,.academic-search button,.academic-filter-form button{
  position:relative!important;
  overflow:hidden!important;
  min-height:44px!important;
  min-width:44px!important;
  padding:10px 17px!important;
  border-radius:12px!important;
  font-size:14px!important;
  font-weight:800!important;
  line-height:1.15!important;
  letter-spacing:-.01em!important;
  text-decoration:none!important;
  cursor:pointer!important;
  user-select:none!important;
  -webkit-user-select:none!important;
  -webkit-tap-highlight-color:transparent!important;
  touch-action:manipulation!important;
  transition:transform .18s ease,box-shadow .18s ease,background .18s ease,border-color .18s ease,color .18s ease,filter .18s ease!important;
}
.btn::after,.button::after,.academic-btn::after{
  content:"";
  position:absolute!important;
  top:0!important;
  left:-130%!important;
  width:55%!important;
  height:100%!important;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.22),transparent)!important;
  transform:skewX(-18deg)!important;
  transition:left .45s ease!important;
  pointer-events:none!important;
}
.btn:hover::after,.button:hover::after,.academic-btn:hover::after{left:145%!important}
.btn:hover,.button:hover,.academic-btn:hover,.academic-search button:hover,.academic-filter-form button:hover{
  transform:translateY(-2px)!important;
  filter:none!important;
}
.btn:active,.button:active,.academic-btn:active,.academic-search button:active,.academic-filter-form button:active{
  transform:translateY(0) scale(.985)!important;
  transition-duration:.06s!important;
}
.btn:focus-visible,.button:focus-visible,.academic-btn:focus-visible,
.academic-search button:focus-visible,.academic-filter-form button:focus-visible,
.nav-toggle:focus-visible,.mobile-menu-close:focus-visible,.vybe-assistant-fab:focus-visible{
  outline:3px solid rgba(47,111,202,.22)!important;
  outline-offset:2px!important;
}
.btn[disabled],.button[disabled],button:disabled,input[type="submit"]:disabled{
  opacity:.55!important;
  cursor:not-allowed!important;
  transform:none!important;
  box-shadow:none!important;
}
.btn.accent,.academic-btn{
  background:linear-gradient(135deg,#3479d1,#245eae)!important;
  color:#fff!important;
  border-color:#2f6fca!important;
  box-shadow:0 7px 18px rgba(47,111,202,.18)!important;
}
.btn.accent:hover,.academic-btn:hover{box-shadow:0 11px 25px rgba(47,111,202,.25)!important}
.btn.dark{
  background:linear-gradient(180deg,#fff,#f5f8fb)!important;
  color:#34404d!important;
  border:1px solid #cfd8e0!important;
  box-shadow:0 3px 10px rgba(31,48,66,.07)!important;
}
.btn.dark:hover{background:#fff!important;border-color:#b8c8d7!important;box-shadow:0 8px 18px rgba(31,48,66,.10)!important}
.btn.good{box-shadow:0 4px 12px rgba(80,140,35,.08)!important}
.btn.danger{box-shadow:0 4px 12px rgba(180,40,40,.07)!important}
.actions{align-items:center!important}
.actions .btn{flex:0 0 auto!important}
.nav-toggle{
  min-width:44px!important;min-height:44px!important;padding:9px 13px!important;
  border:1px solid #d5dde5!important;border-radius:12px!important;
  background:#fff!important;color:#17202b!important;font-weight:800!important;
  cursor:pointer!important;touch-action:manipulation!important;
  box-shadow:0 3px 10px rgba(31,48,66,.06)!important;
  transition:transform .18s ease,box-shadow .18s ease,background .18s ease!important;
}
.nav-toggle:hover{transform:translateY(-1px)!important;background:#f6f9fc!important;box-shadow:0 7px 16px rgba(31,48,66,.10)!important}
.nav-toggle:active{transform:scale(.97)!important}
.mobile-menu-close{
  min-height:38px!important;padding:7px 12px!important;border:1px solid #d5dde5!important;
  border-radius:10px!important;background:#fff!important;color:#34404d!important;
  cursor:pointer!important;font-weight:750!important;touch-action:manipulation!important;
}
.vybe-assistant-fab,.vybe-assistant-close{cursor:pointer!important;touch-action:manipulation!important}

@media(max-width:850px){
  .btn,.button,.academic-btn,.academic-search button,.academic-filter-form button{
    min-height:45px!important;
    padding:10px 14px!important;
    border-radius:12px!important;
    font-size:13px!important;
  }
  .actions{width:100%!important;gap:9px!important}
  .actions .btn{max-width:100%!important}
  .home-hero-actions{width:100%!important;gap:9px!important}
  .home-hero-actions .btn{min-height:46px!important;flex:1 1 160px!important}
  .nav-toggle{min-width:46px!important;min-height:46px!important;border-radius:13px!important}
  .mobile-menu-close{min-height:40px!important}
}
@media(max-width:380px){
  .btn,.button,.academic-btn,.academic-search button,.academic-filter-form button{min-height:44px!important;padding:9px 12px!important;font-size:12px!important}
  .home-hero-actions .btn{flex:1 1 100%!important;width:100%!important}
}


/* ===== VYBE CARD ACTION SYSTEM — DESKTOP + PHONE ===== */
/* Every interactive card remains a real link/button; this layer only improves
   hit-area, feedback, focus states and mobile touch behavior. */
a.home-action,
a.academic-quick,
a.academic-tool,
a.community-choice-card,
a.student-feature,
a.student-mini,
a.student-wide-link,
a.campus-tool,
a.card,
a.student-link,
a.academic-resource-card,
a.academic-update-card{
  position:relative!important;
  pointer-events:auto!important;
  cursor:pointer!important;
  -webkit-tap-highlight-color:transparent!important;
  touch-action:manipulation!important;
  text-decoration:none!important;
  overflow:hidden!important;
  isolation:isolate!important;
}

/* Subtle premium shine without blocking clicks. */
a.home-action::after,
a.academic-quick::after,
a.academic-tool::after,
a.community-choice-card::after,
a.student-feature::after,
a.student-mini::after,
a.student-wide-link::after,
a.campus-tool::after,
a.card::after{
  content:"";
  position:absolute!important;
  inset:0 auto 0 -120%!important;
  width:48%!important;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.34),transparent)!important;
  transform:skewX(-18deg)!important;
  transition:left .5s ease!important;
  pointer-events:none!important;
  z-index:0!important;
}

a.home-action:hover::after,
a.academic-quick:hover::after,
a.academic-tool:hover::after,
a.community-choice-card:hover::after,
a.student-feature:hover::after,
a.student-mini:hover::after,
a.student-wide-link:hover::after,
a.campus-tool:hover::after,
a.card:hover::after{left:145%!important}

/* Keep the card contents above the visual shine. */
a.home-action > *,
a.academic-quick > *,
a.academic-tool > *,
a.community-choice-card > *,
a.student-feature > *,
a.student-mini > *,
a.student-wide-link > *,
a.campus-tool > *,
a.card > *{position:relative;z-index:1}

a.home-action,
a.academic-quick,
a.academic-tool,
a.community-choice-card,
a.student-feature,
a.student-mini,
a.student-wide-link,
a.campus-tool,
a.card{
  transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease,background-color .18s ease!important;
}

a.home-action:hover,
a.academic-quick:hover,
a.academic-tool:hover,
a.community-choice-card:hover,
a.student-feature:hover,
a.student-mini:hover,
a.student-wide-link:hover,
a.campus-tool:hover,
a.card:hover{
  transform:translateY(-3px)!important;
  box-shadow:0 14px 32px rgba(31,48,66,.12)!important;
}

a.home-action:active,
a.academic-quick:active,
a.academic-tool:active,
a.community-choice-card:active,
a.student-feature:active,
a.student-mini:active,
a.student-wide-link:active,
a.campus-tool:active,
a.card:active{
  transform:translateY(-1px) scale(.992)!important;
  transition-duration:.06s!important;
}

a.home-action:focus-visible,
a.academic-quick:focus-visible,
a.academic-tool:focus-visible,
a.community-choice-card:focus-visible,
a.student-feature:focus-visible,
a.student-mini:focus-visible,
a.student-wide-link:focus-visible,
a.campus-tool:focus-visible,
a.card:focus-visible{
  outline:3px solid rgba(47,111,202,.22)!important;
  outline-offset:3px!important;
}

/* Make the action label/arrow feel like a real button. */
.home-action b,
.community-choice-arrow,
.academic-arrow,
.student-arrow{
  transition:transform .18s ease,color .18s ease!important;
}
a.home-action:hover b,
a.community-choice-card:hover .community-choice-arrow,
a.academic-tool:hover .academic-arrow,
a.student-feature:hover .student-arrow,
a.student-mini:hover > span:last-child,
a.student-wide-link:hover .student-arrow{
  transform:translateX(3px)!important;
}

/* Cards that contain an actual button/form control: keep the control clickable. */
a.home-action button,
a.academic-quick button,
a.academic-tool button,
a.community-choice-card button,
a.student-feature button,
a.student-mini button,
a.student-wide-link button,
a.campus-tool button,
a.card button,
a.card input,
a.card select,
a.card textarea{
  position:relative!important;
  z-index:5!important;
  pointer-events:auto!important;
}

@media(max-width:850px){
  a.home-action,
  a.academic-quick,
  a.academic-tool,
  a.community-choice-card,
  a.student-feature,
  a.student-mini,
  a.student-wide-link,
  a.campus-tool,
  a.card{
    min-width:0!important;
    max-width:100%!important;
    -webkit-user-select:none!important;
    user-select:none!important;
  }
  a.home-action:hover,
  a.academic-quick:hover,
  a.academic-tool:hover,
  a.community-choice-card:hover,
  a.student-feature:hover,
  a.student-mini:hover,
  a.student-wide-link:hover,
  a.campus-tool:hover,
  a.card:hover{transform:translateY(-1px)!important}
}

@media(hover:none){
  a.home-action:hover::after,
  a.academic-quick:hover::after,
  a.academic-tool:hover::after,
  a.community-choice-card:hover::after,
  a.student-feature:hover::after,
  a.student-mini:hover::after,
  a.student-wide-link:hover::after,
  a.campus-tool:hover::after,
  a.card:hover::after{left:-120%!important}
}


/* ===== VYBE DASHBOARD QUICK-ACCESS CARDS — PREMIUM REDESIGN ===== */
.home-action-grid.live-home-grid{
  grid-template-columns:repeat(4,minmax(0,1fr))!important;
  gap:16px!important;
  margin-top:2px!important;
}
.live-home-grid .home-action{
  position:relative!important;
  isolation:isolate!important;
  min-height:176px!important;
  padding:22px 20px 20px!important;
  display:flex!important;
  flex-direction:column!important;
  align-items:flex-start!important;
  justify-content:space-between!important;
  gap:16px!important;
  overflow:hidden!important;
  border-radius:22px!important;
  border:1px solid #dce5ec!important;
  background:linear-gradient(145deg,#ffffff 0%,#fbfdff 72%,#f5f9fc 100%)!important;
  box-shadow:0 8px 24px rgba(32,55,76,.055),0 1px 2px rgba(32,55,76,.04)!important;
  transition:transform .24s cubic-bezier(.2,.8,.2,1),box-shadow .24s ease,border-color .24s ease,background .24s ease!important;
}
.live-home-grid .home-action::before{
  content:"";
  position:absolute!important;
  z-index:-1!important;
  top:0!important;
  left:0!important;
  right:0!important;
  height:4px!important;
  background:#2f6fca!important;
  opacity:.95!important;
}
.live-home-grid .home-action::after{
  content:"";
  position:absolute!important;
  z-index:-1!important;
  width:130px!important;
  height:130px!important;
  right:-58px!important;
  bottom:-62px!important;
  border-radius:50%!important;
  background:rgba(47,111,202,.055)!important;
  filter:blur(2px)!important;
  transform:none!important;
  left:auto!important;
  inset:auto -58px -62px auto!important;
  transition:transform .3s ease,opacity .3s ease!important;
}
.live-home-grid .home-action:hover{
  transform:translateY(-5px)!important;
  border-color:#c7d9e8!important;
  background:linear-gradient(145deg,#ffffff 0%,#ffffff 62%,#f3f8fd 100%)!important;
  box-shadow:0 18px 38px rgba(31,69,99,.105),0 3px 7px rgba(31,69,99,.05)!important;
}
.live-home-grid .home-action:hover::after{
  transform:scale(1.28)!important;
  opacity:.9!important;
}
.live-home-grid .home-action:active{
  transform:translateY(-1px) scale(.988)!important;
}
.live-home-grid .home-action > span:nth-child(2){
  display:flex!important;
  flex-direction:column!important;
  align-items:flex-start!important;
  gap:5px!important;
  width:100%!important;
  min-width:0!important;
  flex:1!important;
}
.live-home-grid .home-action-icon{
  width:52px!important;
  height:52px!important;
  flex:0 0 52px!important;
  display:grid!important;
  place-items:center!important;
  border-radius:16px!important;
  background:#eef5ff!important;
  border:1px solid #d7e5f7!important;
  color:#2f6fca!important;
  font-size:14px!important;
  font-weight:900!important;
  letter-spacing:-.02em!important;
  box-shadow:inset 0 1px rgba(255,255,255,.95),0 6px 15px rgba(47,111,202,.07)!important;
  transition:transform .24s ease,box-shadow .24s ease!important;
}
.live-home-grid .home-action:hover .home-action-icon{
  transform:translateY(-2px) scale(1.035)!important;
  box-shadow:inset 0 1px rgba(255,255,255,.95),0 9px 19px rgba(47,111,202,.12)!important;
}
.live-home-grid .home-action strong{
  display:block!important;
  width:100%!important;
  margin:0!important;
  color:#17202b!important;
  font-size:16px!important;
  line-height:1.2!important;
  letter-spacing:-.025em!important;
  font-weight:800!important;
}
.live-home-grid .home-action small{
  display:block!important;
  width:100%!important;
  max-width:230px!important;
  color:#718091!important;
  font-size:12px!important;
  line-height:1.5!important;
}
.live-home-grid .home-action b{
  align-self:flex-end!important;
  display:inline-flex!important;
  align-items:center!important;
  justify-content:center!important;
  min-height:28px!important;
  padding:0 10px!important;
  border-radius:999px!important;
  background:#f4f7fa!important;
  border:1px solid #e1e7ec!important;
  color:#4d79aa!important;
  font-size:10px!important;
  line-height:1!important;
  text-transform:uppercase!important;
  letter-spacing:.08em!important;
  font-weight:850!important;
  transition:transform .2s ease,background .2s ease,border-color .2s ease,color .2s ease!important;
}
.live-home-grid .home-action:hover b{
  transform:translateX(3px)!important;
  background:#eef5ff!important;
  border-color:#d4e3f4!important;
  color:#2f6fca!important;
}
/* Distinct but restrained accent identities. */
.live-home-grid .home-action:nth-child(1)::before{background:linear-gradient(90deg,#2f6fca,#67a2ea)!important}
.live-home-grid .home-action:nth-child(2)::before{background:linear-gradient(90deg,#67a72d,#9bd25f)!important}
.live-home-grid .home-action:nth-child(3)::before{background:linear-gradient(90deg,#6377d8,#91a0ec)!important}
.live-home-grid .home-action:nth-child(4)::before{background:linear-gradient(90deg,#279c91,#61cfc2)!important}
.live-home-grid .home-action:nth-child(5)::before{background:linear-gradient(90deg,#e08a35,#f0b768)!important}
.live-home-grid .home-action:nth-child(6)::before{background:linear-gradient(90deg,#7a68c9,#a89be7)!important}
.live-home-grid .home-action:nth-child(7)::before{background:linear-gradient(90deg,#d65d7d,#ec91a8)!important}
.live-home-grid .home-action:nth-child(2) .home-action-icon{background:#f0f8e9!important;border-color:#d9e9ca!important;color:#5d902f!important}
.live-home-grid .home-action:nth-child(3) .home-action-icon{background:#f0f3ff!important;border-color:#dce2fa!important;color:#6274ce!important}
.live-home-grid .home-action:nth-child(4) .home-action-icon{background:#edf9f7!important;border-color:#d5ece8!important;color:#278c83!important}
.live-home-grid .home-action:nth-child(5) .home-action-icon{background:#fff5e9!important;border-color:#f2dfc7!important;color:#c8782c!important}
.live-home-grid .home-action:nth-child(6) .home-action-icon{background:#f4f1ff!important;border-color:#e3ddf7!important;color:#7562c2!important}
.live-home-grid .home-action:nth-child(7) .home-action-icon{background:#fff0f4!important;border-color:#f1d9e0!important;color:#c75372!important}
.live-home-grid .home-action-primary{
  background:linear-gradient(145deg,#f5faff 0%,#ffffff 68%,#f1f7ff 100%)!important;
  border-color:#cbddec!important;
  box-shadow:0 10px 28px rgba(47,111,202,.09),0 1px 2px rgba(32,55,76,.04)!important;
}
.live-home-grid .home-action-primary .home-action-icon{
  background:linear-gradient(145deg,#eaf3ff,#f3f8ff)!important;
}

@media(max-width:1050px){
  .home-action-grid.live-home-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
}
@media(max-width:700px){
  .home-action-grid.live-home-grid{grid-template-columns:1fr!important;gap:11px!important}
  .live-home-grid .home-action{
    min-height:112px!important;
    padding:16px!important;
    flex-direction:row!important;
    align-items:center!important;
    gap:13px!important;
    border-radius:19px!important;
  }
  .live-home-grid .home-action-icon{width:46px!important;height:46px!important;flex-basis:46px!important;border-radius:14px!important;font-size:13px!important}
  .live-home-grid .home-action > span:nth-child(2){gap:4px!important}
  .live-home-grid .home-action strong{font-size:15px!important}
  .live-home-grid .home-action small{font-size:11.5px!important;line-height:1.42!important;max-width:none!important}
  .live-home-grid .home-action b{flex:0 0 auto!important;min-height:27px!important;padding:0 9px!important;font-size:9px!important}
}
@media(max-width:380px){
  .live-home-grid .home-action{padding:14px!important;gap:11px!important;min-height:105px!important}
  .live-home-grid .home-action-icon{width:43px!important;height:43px!important;flex-basis:43px!important}
  .live-home-grid .home-action strong{font-size:14px!important}
  .live-home-grid .home-action small{font-size:11px!important}
  .live-home-grid .home-action b{padding:0 8px!important}
}



/* ===== ADMIN CONTROL CENTER REDESIGN ===== */
.admin-dashboard-page,.admin-manage-page{max-width:1180px!important;margin:0 auto!important;padding:56px 0 90px!important}
.admin-dashboard-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:28px;margin-bottom:28px}.admin-eyebrow{border:1px solid #d7e4f4!important;background:rgba(255,255,255,.74)!important;color:#2f6fca!important}.admin-dashboard-hero h1,.admin-manage-title h1{margin:14px 0 8px!important;font-size:clamp(38px,5vw,58px)!important;line-height:1.03!important;letter-spacing:-.045em!important;color:#17202b!important}.admin-dashboard-subtitle,.admin-manage-title p{margin:0!important;color:#687482!important;font-size:16px!important;max-width:650px!important;line-height:1.6!important}
.admin-status-pill{display:flex;align-items:center;gap:9px;padding:11px 15px;border:1px solid #dfe5ea;border-radius:999px;background:rgba(255,255,255,.88);font-size:13px;font-weight:800;white-space:nowrap;box-shadow:0 8px 22px rgba(31,48,66,.06)}.admin-status-pill span{width:8px;height:8px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 4px #edf8e6}.admin-status-pill.is-offline span{background:#df5c5c;box-shadow:0 0 0 4px #fff0f0}
.admin-stat-strip{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:0 0 42px;padding:7px;border:1px solid #e1e7eb;border-radius:18px;background:rgba(255,255,255,.78);box-shadow:0 10px 28px rgba(31,48,66,.05)}.admin-stat-strip div{padding:14px 16px;border-radius:13px;background:#fff}.admin-stat-strip strong{display:block;font-size:24px;line-height:1.05;color:#17202b}.admin-stat-strip span{display:block;margin-top:5px;color:#7a8794;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.06em}
.admin-section-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:15px}.admin-section-heading span,.admin-tool-section-head span{font-size:11px;font-weight:900;letter-spacing:.12em;color:#8a97a4}.admin-section-heading h2{margin:4px 0 0;font-size:25px;color:#17202b}.admin-open-all{font-size:13px;font-weight:800;color:#2f6fca;text-decoration:none;padding:10px 13px;border-radius:11px;background:#edf4ff;border:1px solid #d8e6fa}
.admin-main-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-bottom:34px}.admin-control-card{position:relative;display:flex;align-items:center;gap:17px;min-height:132px;padding:21px 22px;border:1px solid #dfe5ea;border-radius:22px;background:rgba(255,255,255,.94);text-decoration:none;color:#17202b;box-shadow:0 12px 30px rgba(31,48,66,.055);overflow:hidden;transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}.admin-control-card:after{content:"";position:absolute;right:-35px;top:-45px;width:125px;height:125px;border-radius:50%;background:rgba(47,111,202,.06)}.admin-control-card:hover{transform:translateY(-3px);box-shadow:0 18px 38px rgba(31,48,66,.10);border-color:#cdd8e2}.admin-card-icon{position:relative;z-index:1;flex:0 0 52px;width:52px;height:52px;border-radius:16px;display:grid;place-items:center;font-size:12px;font-weight:900;background:#edf4ff;color:#2f6fca}.admin-card-green .admin-card-icon{background:#edf8e6;color:#579c24}.admin-card-orange .admin-card-icon{background:#fff3e5;color:#c8751b}.admin-card-purple .admin-card-icon{background:#f1edff;color:#7056bf}.admin-card-dark .admin-card-icon{background:#e9eef4;color:#334250}.admin-card-slate .admin-card-icon{background:#eef1f4;color:#5c6875}.admin-card-copy{position:relative;z-index:1;min-width:0;flex:1}.admin-card-label{display:block;font-size:10px;font-weight:900;letter-spacing:.12em;color:#84919d}.admin-card-copy h3{margin:4px 0 5px;font-size:20px}.admin-card-copy p{margin:0;color:#6d7b88;font-size:13px;line-height:1.45}.admin-card-arrow{position:relative;z-index:1;font-size:20px;color:#8794a0}.admin-control-card:hover .admin-card-arrow{transform:translateX(4px);color:#2f6fca}
.admin-quick-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.admin-quick-card{display:flex;align-items:center;gap:13px;padding:15px 17px;border:1px solid #dfe5ea;border-radius:16px;background:#fff;text-decoration:none;color:#17202b;box-shadow:0 8px 22px rgba(31,48,66,.045)}.admin-quick-card>div{min-width:0;flex:1}.admin-quick-card b{display:block;font-size:14px}.admin-quick-card small{display:block;color:#778592;margin-top:3px;line-height:1.35}.admin-quick-card>span:last-child{font-size:18px;color:#8b98a4}.admin-quick-dot{width:10px;height:10px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 5px #edf8e6;flex:0 0 auto}.admin-quick-dot.red{background:#df5c5c;box-shadow:0 0 0 5px #fff0f0}.admin-quick-icon{width:32px;height:32px;border-radius:10px;background:#edf4ff;color:#2f6fca;display:grid;place-items:center;font-weight:900;flex:0 0 auto}
.admin-inner-top{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-bottom:16px}.admin-back{font-size:13px;font-weight:800;color:#2f6fca;text-decoration:none}.admin-manage-title{margin-bottom:35px}.admin-tool-section{scroll-margin-top:90px;margin-top:30px;padding-top:28px;border-top:1px solid #e1e7eb}.admin-tool-section:first-of-type{border-top:0;padding-top:0}.admin-tool-section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:13px}.admin-tool-section-head h2{margin:4px 0 0;font-size:24px;color:#17202b}.admin-tool-section-head>b{font-size:12px;color:#7b8894;background:#fff;border:1px solid #dfe5ea;border-radius:999px;padding:7px 10px;white-space:nowrap}.admin-tool-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.admin-tool{position:relative;display:flex;flex-direction:column;gap:4px;min-height:94px;padding:16px 42px 15px 16px;border:1px solid #dfe5ea;border-radius:15px;background:#fff;text-decoration:none;box-shadow:0 6px 18px rgba(31,48,66,.035);transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease}.admin-tool:hover{transform:translateY(-2px);border-color:#cbd7e1;box-shadow:0 12px 24px rgba(31,48,66,.07)}.admin-tool-name{font-size:14px;font-weight:850;color:#17202b}.admin-tool-desc{font-size:12px;line-height:1.4;color:#7a8793}.admin-tool-arrow{position:absolute;right:14px;top:50%;transform:translateY(-50%);font-size:18px;color:#9aa5ae}.admin-tool:hover .admin-tool-arrow{color:#2f6fca}
@media(max-width:850px){.admin-dashboard-page,.admin-manage-page{padding:38px 16px 80px!important}.admin-dashboard-hero{align-items:flex-start;flex-direction:column}.admin-status-pill{margin-top:2px}.admin-stat-strip{grid-template-columns:repeat(3,1fr)}.admin-main-grid{grid-template-columns:1fr}.admin-tool-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.admin-dashboard-hero h1,.admin-manage-title h1{font-size:38px!important}.admin-dashboard-subtitle,.admin-manage-title p{font-size:14px!important}.admin-stat-strip{grid-template-columns:repeat(2,1fr);gap:6px;padding:6px;margin-bottom:30px}.admin-stat-strip div{padding:12px}.admin-stat-strip strong{font-size:21px}.admin-stat-strip span{font-size:9px}.admin-section-heading{align-items:flex-start;flex-direction:column;gap:10px}.admin-open-all{width:100%;text-align:center}.admin-control-card{min-height:118px;padding:17px;border-radius:18px;gap:13px}.admin-card-icon{flex-basis:45px;width:45px;height:45px;border-radius:13px}.admin-card-copy h3{font-size:18px}.admin-card-copy p{font-size:12px}.admin-quick-row{grid-template-columns:1fr}.admin-tool-section-head{align-items:flex-start;flex-direction:column;gap:8px}.admin-tool-grid{grid-template-columns:1fr}.admin-tool{min-height:82px}.admin-inner-top{align-items:flex-start;flex-direction:column-reverse}.admin-eyebrow{font-size:11px}}

"""



def _admin_update_feed(con, student_id, limit=18):
    """Return unread header updates with bounded, set-based database work."""
    try:
        existing_view = con.execute(
            "SELECT 1 FROM student_update_views WHERE student_id=? LIMIT 1", (student_id,)
        ).fetchone()
        if not existing_view:
            baseline_time = now()
            specs = (
                ("academic", "academic_updates", False),
                ("resource", "resources", False),
                ("timetable", "timetables", False),
                ("announcement", "announcements", False),
                ("event", "events", False),
                ("admin_solution", "admin_problem_solutions", True),
            )
            for typ, table, student_only in specs:
                if student_only:
                    sql = (
                        "INSERT INTO student_update_views(student_id,item_type,item_id,viewed_at) "
                        "SELECT ?, ?, id, ? FROM admin_problem_solutions WHERE student_id=?"
                    )
                    params = (student_id, typ, baseline_time, student_id)
                else:
                    sql = (
                        "INSERT INTO student_update_views(student_id,item_type,item_id,viewed_at) "
                        f"SELECT ?, ?, id, ? FROM {table}"
                    )
                    params = (student_id, typ, baseline_time)
                try:
                    if con.is_pg:
                        sql += " ON CONFLICT(student_id,item_type,item_id) DO NOTHING"
                    else:
                        sql = sql.replace("INSERT INTO", "INSERT OR IGNORE INTO", 1)
                    con.execute(sql, params)
                except Exception:
                    pass
            con.commit()
            return []
    except Exception:
        pass

    sources = [
        ("academic", "SELECT id,title,description,created_at FROM academic_updates WHERE kind IN ('Result','Date Sheet','Exam Notice','Admit Card') ORDER BY id DESC LIMIT 50", "Academic update"),
        ("resource", "SELECT id,title,description,created_at FROM resources ORDER BY id DESC LIMIT 50", "Study resource"),
        ("timetable", "SELECT id,title,original_name,created_at FROM timetables ORDER BY id DESC LIMIT 50", "Timetable"),
        ("announcement", "SELECT id,title,message,created_at FROM announcements ORDER BY id DESC LIMIT 50", "Announcement"),
        ("event", "SELECT id,title,description,created_at FROM events ORDER BY id DESC LIMIT 50", "Campus event"),
        ("admin_solution", "SELECT aps.id,i.title,aps.solution_text AS description,aps.created_at FROM admin_problem_solutions aps JOIN issues i ON i.id=aps.issue_id WHERE aps.student_id=? ORDER BY aps.id DESC LIMIT 50", "Admin solution"),
    ]
    items=[]
    for typ,sql,label in sources:
        try:
            rows=con.execute(sql,(student_id,)).fetchall() if typ=="admin_solution" else con.execute(sql).fetchall()
        except Exception:
            rows=[]
        for r in rows:
            keys=r.keys()
            detail=str(r["description"] or "")[:120] if "description" in keys else ""
            if not detail:
                try: detail=str(r["message"] or r["original_name"] or "")[:120]
                except Exception: detail=""
            rid=int(r["id"])
            target={
                "academic":f"/updates#academic-update-{rid}",
                "resource":f"/resource/{rid}",
                "timetable":f"/timetable-file/{rid}",
                "announcement":"/announcements",
                "event":"/events",
                "admin_solution":f"/student-admin-solution/{rid}",
            }[typ]
            items.append({"type":typ,"id":rid,"title":str(r["title"] or "Untitled"),"detail":detail,"created_at":str(r["created_at"] or ""),"label":label,"url":target})

    # Check all candidate IDs in batches rather than issuing a SELECT per item.
    seen_by_type={}
    for typ in {x["type"] for x in items}:
        ids=[x["id"] for x in items if x["type"]==typ]
        if not ids: continue
        placeholders=",".join("?" for _ in ids)
        try:
            rows=con.execute(
                f"SELECT item_id FROM student_update_views WHERE student_id=? AND item_type=? AND item_id IN ({placeholders})",
                (student_id,typ,*ids),
            ).fetchall()
            seen_by_type[typ]={int(r["item_id"]) for r in rows}
        except Exception:
            seen_by_type[typ]=set(ids)
    unread=[x for x in items if x["id"] not in seen_by_type.get(x["type"],set())]
    unread.sort(key=lambda x:x["created_at"],reverse=True)
    return unread[:limit]






def _mark_admin_update_seen(student_id,item_type,item_id):
    con=db()
    try:
        if con.is_pg: con.execute("INSERT INTO student_update_views(student_id,item_type,item_id,viewed_at) VALUES(?,?,?,?) ON CONFLICT(student_id,item_type,item_id) DO NOTHING",(student_id,item_type,int(item_id),now()))
        else: con.execute("INSERT OR IGNORE INTO student_update_views(student_id,item_type,item_id,viewed_at) VALUES(?,?,?,?)",(student_id,item_type,int(item_id),now()))
        con.commit()
    finally: con.close()


def _mark_all_page_items_seen(con,student_id,item_type,table):
    try:
        for r in con.execute(f"SELECT id FROM {table}").fetchall():
            rid=int(r["id"])
            if con.is_pg: con.execute("INSERT INTO student_update_views(student_id,item_type,item_id,viewed_at) VALUES(?,?,?,?) ON CONFLICT(student_id,item_type,item_id) DO NOTHING",(student_id,item_type,rid,now()))
            else: con.execute("INSERT OR IGNORE INTO student_update_views(student_id,item_type,item_id,viewed_at) VALUES(?,?,?,?)",(student_id,item_type,rid,now()))
    except Exception: pass


@app.route("/student/header-notifications/read", methods=["POST"])
@student_required
def student_header_notifications_read():
    """Mark only the updates currently shown by the bell as seen."""
    sid=int(session["student_db_id"])
    con=db()
    try:
        items=_admin_update_feed(con,sid,20)
        for x in items:
            if con.is_pg:
                con.execute(
                    "INSERT INTO student_update_views(student_id,item_type,item_id,viewed_at) VALUES(?,?,?,?) ON CONFLICT(student_id,item_type,item_id) DO NOTHING",
                    (sid,x["type"],int(x["id"]),now()),
                )
            else:
                con.execute(
                    "INSERT OR IGNORE INTO student_update_views(student_id,item_type,item_id,viewed_at) VALUES(?,?,?,?)",
                    (sid,x["type"],int(x["id"]),now()),
                )
        con.commit()
        with _AUTHZ_CACHE_LOCK:
            _AUTHZ_CACHE.pop(("header_updates",sid),None)
        return jsonify(ok=True,seen=len(items))
    except Exception:
        try: con.rollback()
        except Exception: pass
        return jsonify(ok=False),200
    finally:
        con.close()


@app.route("/student-update-seen/<item_type>/<int:item_id>", methods=["POST"])
@student_required
def student_update_seen(item_type,item_id):
    targets={"academic":"/updates","resource":"/academics","timetable":"/timetable","announcement":"/announcements","event":"/events","admin_solution":"/issues"}
    if item_type not in targets: abort(404)
    _mark_admin_update_seen(session["student_db_id"],item_type,item_id)
    target=request.form.get("next","").strip()
    if not target.startswith("/") or target.startswith("//") or "\n" in target or "\r" in target: target=targets[item_type]
    return redirect(target)


@app.route("/student-admin-solution/<int:sid>")
@student_required
def student_admin_solution(sid):
    con=db()
    row=con.execute(
        "SELECT aps.id,aps.solution_text,aps.admin_label,aps.created_at,i.title AS issue_title,i.category,i.description,i.status "
        "FROM admin_problem_solutions aps JOIN issues i ON i.id=aps.issue_id "
        "WHERE aps.id=? AND aps.student_id=?",
        (sid,session["student_db_id"]),
    ).fetchone()
    con.close()
    if not row: abort(404)
    _mark_admin_update_seen(session["student_db_id"],"admin_solution",sid)
    body=f"""<section class=\"section admin-solution-student-page\"><div class=\"admin-solution-student-card\"><span class=\"badge\">ADMIN SOLUTION</span><h1>{esc(row["issue_title"])}</h1><p class=\"muted\">Your campus problem · {esc(row["created_at"])}</p><div class=\"admin-solution-problem\"><strong>Your reported problem</strong><p>{esc(row["description"])}</p></div><div class=\"admin-solution-message\"><div class=\"admin-solution-message-head\"><span>{esc(row["admin_label"])}</span><small>{esc(row["created_at"])}</small></div><p>{esc(row["solution_text"])}</p></div><div class=\"actions\"><a class=\"btn dark\" href=\"/issues\">Back to Help Desk</a></div></div></section>"""
    return layout("Admin Solution",body)


@app.route("/admin/problem/<int:iid>/solution", methods=["POST"])
@admin_required
def admin_problem_solution(iid):
    solution_text=request.form.get("solution_text","").strip()[:3000]
    if not solution_text:
        flash("Please enter a solution before sending it.")
        return redirect(url_for("admin_problems")+f"#problem-{iid}")
    con=db()
    try:
        issue=con.execute("SELECT id,student_id,title FROM issues WHERE id=?",(iid,)).fetchone()
        if not issue:
            con.close(); flash("That student problem no longer exists.")
            return redirect(url_for("admin_problems"))
        con.execute(
            "INSERT INTO admin_problem_solutions(issue_id,student_id,solution_text,admin_label,created_at) VALUES(?,?,?,?,?)",
            (iid,issue["student_id"],solution_text,"VYBE Admin",now()),
        )
        con.execute("UPDATE issues SET status=? WHERE id=?",("Resolved",iid))
        con.commit()
        con.close()
        flash(f"Admin solution sent to {issue['title']}. The student will see it in the alert button.")
    except Exception:
        try: con.rollback()
        except Exception: pass
        con.close()
        app.logger.exception("Admin solution failed for issue %s",iid)
        flash("We couldn't send the admin solution right now.")
    return redirect(url_for("admin_problems")+f"#problem-{iid}")


@app.route("/admin/problem/<int:iid>/solution/<int:sid>/delete", methods=["POST"])
@admin_required
def delete_admin_problem_solution(iid,sid):
    con=db()
    con.execute("DELETE FROM admin_problem_solutions WHERE id=? AND issue_id=?",(sid,iid))
    con.commit(); con.close()
    flash("Admin solution deleted.")
    return redirect(url_for("admin_problems")+f"#problem-{iid}")


@app.route("/admin/problem/<int:iid>/solution/<int:sid>/resend", methods=["POST"])
@admin_required
def resend_admin_problem_solution(iid,sid):
    con=db()
    row=con.execute("SELECT id FROM admin_problem_solutions WHERE id=? AND issue_id=?",(sid,iid)).fetchone()
    if not row:
        con.close(); flash("That admin solution no longer exists.")
        return redirect(url_for("admin_problems")+f"#problem-{iid}")
    con.execute("DELETE FROM student_update_views WHERE item_type=? AND item_id=?",("admin_solution",sid))
    con.commit(); con.close()
    flash("Admin solution marked as new again for the student.")
    return redirect(url_for("admin_problems")+f"#problem-{iid}")


@app.route("/admin/problem/<int:iid>/solution", methods=["GET"])
@admin_required
def admin_problem_solution_get(iid):
    return redirect(url_for("admin_problems")+f"#problem-{iid}")



ADMIN_PASSWORD_ALERT_CSS = r"""
.admin-password-alert-wrap{position:relative;display:inline-flex;align-items:center}
.admin-password-alert{position:relative;display:inline-flex;align-items:center;gap:7px;min-height:38px;padding:8px 11px;border-radius:12px;background:#172033;color:#fff;border:1px solid rgba(255,255,255,.10);text-decoration:none;font-size:11px;font-weight:850;box-shadow:0 8px 20px rgba(23,32,51,.14);transition:.18s ease}
.admin-password-alert:hover{transform:translateY(-1px);background:#0f1727;color:#fff;box-shadow:0 12px 26px rgba(23,32,51,.20)}
.admin-password-alert-icon{width:18px;height:18px;display:grid;place-items:center;font-size:14px}
.admin-password-alert-count{min-width:18px;height:18px;padding:0 5px;border-radius:999px;display:grid;place-items:center;background:#ef4b5f;color:#fff;font-size:10px;font-weight:950;box-shadow:0 0 0 3px rgba(239,75,95,.13)}
.admin-password-alert.is-clear .admin-password-alert-count{display:none}
@media(max-width:800px){.admin-password-alert{min-width:38px;width:38px;height:38px;padding:0;justify-content:center}.admin-password-alert-label{display:none}}
"""
AUTH_PAGE_CSS = r"""
body:has(.vybe-auth-page) .nav{display:none!important}
body:has(.vybe-auth-page){background:radial-gradient(700px 420px at 12% 12%,rgba(47,111,202,.12),transparent 62%),radial-gradient(650px 430px at 88% 82%,rgba(104,184,46,.10),transparent 62%),linear-gradient(145deg,#f8fbfe,#f3f7fa 52%,#f7faf4)!important;min-height:100vh!important}
body:has(.vybe-auth-page) .flash{display:none!important}
.vybe-auth-page{min-height:100svh;display:grid;place-items:center;padding:32px 22px 38px!important;position:relative;overflow:hidden;box-sizing:border-box}
.vybe-auth-page::before,.vybe-auth-page::after{content:"";position:fixed;pointer-events:none;border-radius:50%;filter:blur(2px);opacity:.7;animation:vybeAuthFloat 8s ease-in-out infinite}.vybe-auth-page::before{width:320px;height:320px;left:-150px;top:-100px;background:radial-gradient(circle,rgba(47,111,202,.15),transparent 68%)}.vybe-auth-page::after{width:360px;height:360px;right:-160px;bottom:-150px;background:radial-gradient(circle,rgba(104,184,46,.13),transparent 68%);animation-delay:-3s}
.vybe-auth-page .authbox{width:min(500px,100%)!important;max-width:500px!important;position:relative;z-index:2;padding:34px 34px 26px!important;border-radius:30px!important;background:rgba(255,255,255,.92)!important;color:#17202b!important;border:1px solid rgba(255,255,255,.98)!important;box-shadow:0 28px 90px rgba(31,48,66,.13),0 3px 12px rgba(31,48,66,.04)!important;backdrop-filter:blur(24px) saturate(135%);-webkit-backdrop-filter:blur(24px) saturate(135%);overflow:visible!important;animation:vybeAuthIn .65s cubic-bezier(.16,1,.3,1) both}
.vybe-auth-logo{position:absolute;right:24px;top:24px;width:52px;height:52px;border-radius:16px;display:grid;place-items:center;background:#172033;color:#fff;font-size:22px;font-weight:950;letter-spacing:-.08em;box-shadow:0 12px 28px rgba(23,32,51,.18),inset 0 1px rgba(255,255,255,.18);transition:transform .2s ease,box-shadow .2s ease}.vybe-auth-logo:hover{transform:translateY(-2px) rotate(-2deg);box-shadow:0 16px 34px rgba(23,32,51,.22)}
.vybe-auth-page .authbox h1{color:#17202b!important;font-size:clamp(34px,6vw,48px)!important;letter-spacing:-.06em!important;margin:12px 72px 10px 0!important}.vybe-auth-page .authbox>p.muted{color:#6c7885!important;line-height:1.55!important;max-width:410px!important}.vybe-auth-page .badge{background:#edf4ff!important;color:#2f6fca!important;border-color:#dce9f7!important;font-weight:850!important}.vybe-auth-page .label{color:#667382!important;font-weight:750!important}
.vybe-auth-page input,.vybe-auth-page select,.vybe-auth-page textarea{background:#fff!important;color:#17202b!important;border:1px solid #dce4ea!important;box-shadow:inset 0 1px 2px rgba(30,45,60,.02)!important}.vybe-auth-page input::placeholder{color:#9aa5af!important}.vybe-auth-page input:focus,.vybe-auth-page textarea:focus,.vybe-auth-page select:focus{border-color:#2f6fca!important;background:#fff!important;box-shadow:0 0 0 4px rgba(47,111,202,.10)!important}.vybe-auth-page .btn.accent,.vybe-auth-page .btn.dark{background:#172033!important;color:#fff!important;border-color:#172033!important;box-shadow:0 12px 25px rgba(23,32,51,.16)!important}.vybe-auth-page .small{color:#7a8793!important}.vybe-auth-page .small a{color:#2f6fca!important;font-weight:800!important}
.vybe-auth-back-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:22px;padding-top:18px;border-top:1px solid #e8edf1}.vybe-auth-back{display:inline-flex!important;align-items:center;justify-content:center;gap:8px;min-height:42px;padding:9px 15px!important;border-radius:12px!important;background:#172033!important;color:#fff!important;border:1px solid #172033!important;font-size:12px!important;font-weight:850!important;box-shadow:0 9px 22px rgba(23,32,51,.14)!important;transition:transform .18s ease,box-shadow .18s ease,background .18s ease!important}.vybe-auth-back:hover{transform:translateY(-2px);box-shadow:0 13px 28px rgba(23,32,51,.18)!important;background:#0f1727!important}.vybe-auth-hint{font-size:11px;color:#8a96a2;line-height:1.4;text-align:right}
.vybe-auth-page .authbox>.card{background:#f8fafc!important;color:#17202b!important;border:1px solid #e2e8ed!important;box-shadow:none!important;border-radius:18px!important}.vybe-auth-page .authbox>.card h2{color:#17202b!important}.vybe-auth-page .authbox>.card p,.vybe-auth-page .authbox>.card .small{color:#71808e!important}
@keyframes vybeAuthIn{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:none}}@keyframes vybeAuthFloat{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(0,14px,0)}}
@media(max-width:600px){.vybe-auth-page{padding:16px 12px 22px!important}.vybe-auth-page .authbox{padding:26px 18px 20px!important;border-radius:23px!important}.vybe-auth-logo{width:46px;height:46px;right:17px;top:17px;border-radius:14px;font-size:19px}.vybe-auth-page .authbox h1{font-size:31px!important;margin-right:58px!important}.vybe-auth-page .authbox>p.muted{font-size:13px!important}.vybe-auth-back-row{align-items:stretch;flex-direction:column-reverse}.vybe-auth-back{width:100%!important}.vybe-auth-hint{text-align:center}.vybe-auth-page .authbox>.card{padding:15px!important}}
@media(max-width:380px){.vybe-auth-page{padding:10px 8px 16px!important}.vybe-auth-page .authbox{padding:22px 14px 17px!important;border-radius:20px!important}.vybe-auth-logo{width:42px;height:42px;right:14px;top:14px}.vybe-auth-page .authbox h1{font-size:28px!important;margin-top:8px!important}}
"""

ADMIN_PROBLEM_ALERT_CSS = r"""
.admin-problem-alert-wrap{position:relative;display:inline-flex;align-items:center}
.admin-problem-alert{position:relative;width:40px;height:38px;display:inline-flex;align-items:center;justify-content:center;border:1px solid rgba(255,255,255,.10);border-radius:12px;background:#172033;color:#fff;text-decoration:none;box-shadow:0 8px 20px rgba(23,32,51,.14);transition:.18s ease;cursor:pointer}
.admin-problem-alert:hover{transform:translateY(-1px);background:#202b43;box-shadow:0 12px 26px rgba(23,32,51,.20)}
.admin-problem-alert svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.admin-problem-alert-count{position:absolute;top:-6px;right:-6px;min-width:19px;height:19px;padding:0 5px;display:inline-flex;align-items:center;justify-content:center;border-radius:999px;background:#ef4d52;color:#fff;border:2px solid #fff;font-size:9px;font-weight:950;box-shadow:0 4px 10px rgba(239,77,82,.28)}
.admin-problem-alert-panel{position:absolute;top:calc(100% + 10px);right:0;width:min(420px,calc(100vw - 28px));background:rgba(255,255,255,.985);border:1px solid #dfe5ea;border-radius:19px;box-shadow:0 24px 60px rgba(20,37,55,.20);overflow:hidden;z-index:3000}
.admin-problem-alert-panel[hidden]{display:none}
.admin-problem-alert-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:17px;border-bottom:1px solid #edf0f3}
.admin-problem-alert-head strong{display:block;color:#17202b;font-size:14px}.admin-problem-alert-head small{display:block;margin-top:4px;color:#7b8793;font-size:10px}
.admin-problem-alert-head>span{padding:6px 9px;border-radius:999px;background:#fff1f1;color:#c44d55;font-size:10px;font-weight:900}
.admin-problem-alert-list{max-height:390px;overflow:auto;padding:8px}
.admin-problem-alert-item{display:flex;gap:10px;align-items:flex-start;padding:12px 10px;border-radius:13px;color:#17202b;text-decoration:none;transition:.15s ease}
.admin-problem-alert-item:hover{background:#f4f8fc;transform:translateX(2px)}
.admin-problem-alert-dot{width:30px;height:30px;flex:0 0 30px;display:grid;place-items:center;border-radius:9px;background:#fff1f1;color:#c44d55;font-size:13px;font-weight:950}
.admin-problem-alert-copy{min-width:0;flex:1}.admin-problem-alert-copy strong{display:block;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.admin-problem-alert-copy small{display:block;margin-top:3px;color:#7b8793;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.admin-problem-alert-copy p{margin:5px 0 0;color:#687482;font-size:10px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.admin-problem-alert-arrow{font-size:19px;line-height:1;color:#a2adb8;margin-top:5px}.admin-problem-alert-empty{padding:28px 15px;text-align:center;color:#7b8793;font-size:12px}
.admin-problem-alert-all{display:block;padding:13px 15px;border-top:1px solid #edf0f3;background:#fbfcfd;color:#2f6fca;font-size:11px;font-weight:900;text-align:center;text-decoration:none}
@media(max-width:800px){.admin-problem-alert{width:38px;height:38px}.admin-problem-alert-panel{position:fixed;top:61px;right:10px;width:min(420px,calc(100vw - 20px));max-height:calc(100vh - 82px);border-radius:18px}.admin-problem-alert-list{max-height:calc(100vh - 180px)}}
"""

_ADMIN_HEADER_CACHE_TTL = 20.0
def _admin_header_alerts_cached():
    key=("admin_header_alerts", 0)
    now_m=time.monotonic()
    with _AUTHZ_CACHE_LOCK:
        item=_AUTHZ_CACHE.get(key)
        if item and item[0] > now_m:
            return item[1]
    con=None
    try:
        con=db()
        pending=int(con.execute("SELECT COUNT(*) AS c FROM password_reset_requests WHERE status='pending'").fetchone()["c"])
        problems=con.execute(
            "SELECT i.id,i.title,i.description,i.category,i.status,i.created_at,s.name,s.student_id "
            "FROM issues i JOIN students s ON s.id=i.student_id "
            "WHERE i.status NOT IN ('Resolved','Closed') ORDER BY i.id DESC LIMIT 8"
        ).fetchall()
        value=(pending,problems)
    except Exception:
        value=(0,[])
    finally:
        if con is not None:
            try: con.close()
            except Exception: pass
    with _AUTHZ_CACHE_LOCK:
        _AUTHZ_CACHE[key]=(now_m+_ADMIN_HEADER_CACHE_TTL,value)
    return value


def layout(title, body, admin=False):
    student = bool(session.get("student_db_id")) and not admin
    if admin:
        links = '<a href="/admin/panel">Dashboard</a><a href="/admin/settings">Settings</a><a href="/admin/analytics">Analytics</a><a href="/admin/assistant">VYBE AI Settings</a><a class="admin-nav-logout" href="/admin/logout">Logout</a>'
        brand = '<a class="brand" href="/admin/panel"><span class="brandmark">V</span><span class="brandtext">VYBE</span></a>'
        _admin_pending_password, _admin_problem_rows = _admin_header_alerts_cached()
        _admin_alert_count = f'<span class="admin-password-alert-count">{_admin_pending_password}</span>' if _admin_pending_password else ''
        _admin_alert_class = '' if _admin_pending_password else ' is-clear'
        admin_alert = f"""<div class="admin-password-alert-wrap"><a class="admin-password-alert{_admin_alert_class}" href="/admin/password-requests" title="Password access requests"><span class="admin-password-alert-icon" aria-hidden="true">🔐</span><span class="admin-password-alert-label">Password Access</span>{_admin_alert_count}</a></div>"""
        _problem_count = len(_admin_problem_rows)
        _problem_badge = f'<span class="admin-problem-alert-count">{_problem_count if _problem_count < 100 else "99+"}</span>' if _problem_count else ''
        _problem_items = ''.join(
            f'<a class="admin-problem-alert-item" href="/admin/problems#problem-{int(x["id"])}"><span class="admin-problem-alert-dot">!</span><span class="admin-problem-alert-copy"><strong>{esc(x["title"])}</strong><small>{esc(x["name"])} · {esc(x["category"])} · {esc(x["created_at"])}</small><p>{esc(x["description"])}</p></span><span class="admin-problem-alert-arrow">›</span></a>'
            for x in _admin_problem_rows
        ) or '<div class="admin-problem-alert-empty">No active student problems.</div>'
        admin_problem_alert = f"""<div class="admin-problem-alert-wrap"><button class="admin-problem-alert" id="vybeAdminProblemBell" type="button" aria-label="Reported student problems" aria-expanded="false" aria-controls="vybeAdminProblemPanel"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"></path><path d="M10 21h4"></path></svg>{_problem_badge}</button><div class="admin-problem-alert-panel" id="vybeAdminProblemPanel" hidden><div class="admin-problem-alert-head"><div><strong>Reported Problems</strong><small>Student reports needing admin attention</small></div><span id="vybeAdminProblemCount">{_problem_count} open</span></div><div class="admin-problem-alert-list" id="vybeAdminProblemList">{_problem_items}</div><a class="admin-problem-alert-all" href="/admin/problems">Open Problems &amp; Solutions →</a></div></div>"""
        header = f'<div class="navin admin-header">{brand}<nav class="admin-navlinks" aria-label="Admin navigation">{links}</nav><div class="admin-header-actions">{admin_problem_alert}{admin_alert}<button class="nav-toggle admin-menu-toggle" id="vybeNavToggle" type="button" aria-label="Open admin menu" aria-expanded="false">☰</button></div></div>'
        bottom_nav = ""
    elif student:
        # Keep the desktop student navigation exactly as it was.
        links = '<a href="/dashboard">Home</a><a href="/academics">Academics</a><a href="/updates">Updates</a><a href="/community">Community</a><a href="/issues">Help Desk</a><a href="/events">Events</a><a href="/search">Search</a><a href="/profile">Profile</a><a href="/logout">Logout</a>'
        # Mobile gets its own drawer links so desktop navigation is never changed.
        mobile_links = '<a href="/dashboard"><span>Home</span></a><a href="/academics"><span>Academics</span></a><a href="/updates"><span>Updates</span></a><a href="/apps"><span>Study Apps</span></a><a href="/papers"><span>Previous Papers</span></a><a href="/issues"><span>Help Desk</span></a><a href="/community"><span>Community</span></a><a href="/chat"><span>Chat</span></a><a href="/search"><span>Search</span></a><a href="/announcements"><span>Announcements</span></a><a href="/events"><span>Events</span></a><a href="/profile"><span>Profile</span></a><a href="/logout"><span>Logout</span></a>'
        brand = '<a class="brand" href="/dashboard"><span class="brandmark">V</span><span class="brandtext">VYBE</span></a>'
        student_on_subpage = request.path.rstrip("/") != "/dashboard"
        mobile_back = '<a class="mobile-back-nav" href="javascript:history.back()" aria-label="Go back"><span>←</span>Back</a>' if student_on_subpage else ''
        header_lead = '<a class="brand student-brand-compact" href="/dashboard"><span class="brandmark">V</span><span class="brandtext">VYBE</span></a>' + ('<a class="student-header-back" href="javascript:history.back()" aria-label="Go back">Back</a>' if student_on_subpage else '')
        try:
            _header_updates=_student_header_updates_cached(session["student_db_id"])
        except Exception: _header_updates=[]
        _unread_count=sum(1 for x in _header_updates if x.get("unread", True))
        _alert_items=[]
        for x in _header_updates:
            # Bell entries are informational only. They deliberately contain no
            # link/button target, so the bell never acts as a shortcut menu.
            detail = x.get("detail", "")
            _alert_items.append(
                f'<div class="vybe-header-alert-item is-new">'
                f'<span class="vybe-alert-type">{esc(x["label"][:1])}</span>'
                f'<span class="vybe-alert-copy"><strong>{esc(x["title"])}</strong>'
                f'<small>{esc(x["label"])} · {esc(x["created_at"])}</small>'
                f'{("<p>" + esc(detail) + "</p>") if detail else ""}</span>'
                f'<span class="vybe-alert-open">NEW</span></div>'
            )
        _alert_panel=''.join(_alert_items) or '<div class="vybe-header-alert-empty">No new updates.</div>'
        _count_badge=f'<span class="vybe-alert-count">{_unread_count}</span>' if _unread_count else ''
        header=f'''<div class="navin student-nav-compact">{header_lead}<nav class="student-desktop-links" aria-label="Student navigation"><a href="/dashboard">Home</a><a href="/academics">Academics</a><a href="/community">Community</a><a href="/issues">Help Desk</a><a href="/events">Events</a></nav><div class="student-header-tools"><a class="student-header-updates" href="/updates">Updates</a><div class="vybe-header-alert-wrap"><button class="vybe-header-alert" id="vybeHeaderAlertButton" type="button" aria-label="Show new VYBE updates" aria-expanded="false" aria-controls="vybeHeaderAlertPanel"><span class="vybe-header-alert-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"></path><path d="M10 21h4"></path></svg></span><span class="vybe-header-alert-label">New</span>{_count_badge}</button><div class="vybe-header-alert-panel" id="vybeHeaderAlertPanel" hidden><div class="vybe-header-alert-head"><div><strong>New updates</strong><small>What has arrived since you last checked</small></div><span id="vybeHeaderAlertCount">{_unread_count}</span></div><div class="vybe-header-alert-list">{_alert_panel}</div></div></div><button class="nav-toggle student-menu" id="vybeNavToggle" type="button" aria-label="Open menu" aria-expanded="false">Menu</button></div></div>

<div class="student-control-row"><form id="vybeStudentSearchForm" class="student-search" action="/search" method="get" autocomplete="off"><input name="q" placeholder="Search campus" aria-label="Search campus" autocomplete="off"><div id="vybeStudentSearchSuggestions" class="vybe-search-suggestions mobile-direct-suggestions" role="listbox"><a class="vybe-search-suggestion" role="option" href="/academic-hub/study-material"><span>Study Material</span><span>Academics</span></a><a class="vybe-search-suggestion" role="option" href="/academic-hub/notes"><span>Notes</span><span>Study Notes</span></a><a class="vybe-search-suggestion" role="option" href="/timetable"><span>Timetable</span><span>Campus timetable</span></a><a class="vybe-search-suggestion" role="option" href="/papers"><span>Previous Papers</span><span>PYQ Papers</span></a><a class="vybe-search-suggestion" role="option" href="/updates?kind=Admit%20Card"><span>Admit Card</span><span>Exam updates</span></a><a class="vybe-search-suggestion" role="option" href="/updates"><span>Results &amp; Updates</span><span>Latest updates</span></a></div></form></div>'''
        bottom_nav = f'''<nav id="vybeStudentBottomNav" class="student-bottom-nav" aria-label="Student navigation"><button id="vybeBottomMenuButton" class="mobile-menu-nav" type="button" aria-label="Open menu" aria-expanded="false" onclick="return window.vybeToggleStudentMenu(event)"><span class="vybe-nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><path d="M4 7h16M4 12h16M4 17h16"></path></svg></span><span class="mobile-menu-label">Menu</span></button><a class="mobile-home-nav active" href="/dashboard"><span class="vybe-nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><path d="M3.5 10.5 12 3.8l8.5 6.7V20a1 1 0 0 1-1 1h-5v-6h-5v6h-5a1 1 0 0 1-1-1z"></path></svg></span><span class="mobile-menu-label">Home</span></a><a class="mobile-profile-nav" href="/profile"><span class="vybe-nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><circle cx="12" cy="8" r="3.5"></circle><path d="M5 20c.8-3.5 3.1-5.2 7-5.2s6.2 1.7 7 5.2"></path></svg></span><span class="mobile-menu-label">Profile</span></a></nav><div class="student-bottom-spacer"></div>'''
        # Academic library pages have their own single clean search bar; remove the global campus search there.
        if request.path == "/academics" or request.path.startswith("/academic-hub/"):
            header=re.sub(r'<div class="student-control-row">.*?</form></div>', '', header, count=1, flags=re.S)


    else:
        links = '<a href="/login">Student Login</a><a href="/register">Register</a><a href="/admin">Admin Login</a>'
        brand = '<a class="brand" href="/"><span class="brandmark">V</span><span class="brandtext">VYBE</span></a>'
        header = f'<div class="navin">{brand}<button class="nav-toggle" id="vybeNavToggle" type="button" aria-label="Open menu" aria-expanded="false">☰</button></div>'
        bottom_nav = ""
    _flash_items = session.pop("_flashes", [])
    _flash_html = []
    for _item in _flash_items:
        # Flask stores flashed messages as (category, message). Render only the
        # human message so internal tuple data can never leak into the UI.
        if isinstance(_item, (tuple, list)) and len(_item) >= 2:
            _message = _item[1]
        else:
            _message = _item
        _flash_html.append(f'<div class="flash">{esc(_message)}</div>')
    flashes = "".join(_flash_html)
    assistant_widget = ""
    if student:
        try:
            _ai_enabled, _ai_selected = _student_ai_settings_cached()
        except Exception:
            _ai_enabled = True
            _ai_selected = ["study_material", "admit_card", "date_sheets", "previous_papers", "timetable", "updates"]
        _ai_catalog = {
            "study_material": ("Study Material", "/academic-hub/study-material"),
            "admit_card": ("Admit Card", "/academic-hub/admit-card"),
            "date_sheets": ("Date Sheets", "/updates?category=Examination"),
            "previous_papers": ("Previous Papers", "/papers"),
            "timetable": ("Timetable", "/timetable"),
            "updates": ("Results & Updates", "/updates"),
            "notes": ("Notes", "/academic-hub/notes"),
            "syllabus": ("Syllabus", "/academic-hub/syllabus"),
            "assignments": ("Assessments", "/academic-hub/assessment"),
            "helpdesk": ("Help Desk", "/issues"),
            "announcements": ("Announcements", "/announcements"),
            "events": ("Events", "/events"),
            "community": ("Community", "/community"),
            "profile": ("My Profile", "/profile"),
        }
        if _ai_enabled and not request.path.startswith("/academic-hub/") and request.path != "/academics":
            _ai_links = "".join(f'<a class="vybe-assistant-suggestion" href="{url}">{esc(label)}</a>' for key,(label,url) in _ai_catalog.items() if key in _ai_selected)
            if not _ai_links:
                _ai_links = '<div class="vybe-assistant-empty">No shortcuts have been enabled by the admin.</div>'
            assistant_widget = f"""<button class="vybe-assistant-fab" id="vybeAssistantFab" type="button" aria-expanded="false" aria-controls="vybeAssistantPanel"><span class="fab-mark">AI</span><span>Ask VYBE</span></button><section class="vybe-assistant-panel" id="vybeAssistantPanel" aria-label="VYBE Assistant"><div class="vybe-assistant-head"><div><strong>VYBE Assistant</strong><small>Quick campus shortcuts</small></div></div><div class="vybe-assistant-body"><div class="vybe-assistant-suggestions">{_ai_links}</div></div></section>"""
    # This is injected inside layout()'s single <style> block. Keep it as raw CSS.
    # Wrapping it in <style> here would prematurely close the outer style tag and
    # cause the following mobile CSS to be rendered as visible text in the page.
    performance_css = r"""
/* ===== VYBE PERFORMANCE LAYER ===== */
html{scroll-behavior:auto!important}
body{background-attachment:scroll!important}
*,*::before,*::after{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.nav,.mobile-nav,.student-bottom-nav,.vybe-assistant-panel,.vybe-assistant-fab,.chat-composer,.flash,.badge,.pill{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}
.card,.admin-control-card,.admin-tool,.home-action,.home-update-panel,.home-update{animation:none!important}
.card{transition:border-color .14s ease,background .14s ease!important}
/* Students / Access has two renderers: table on desktop, cards on phones. */
.admin-students-mobile{display:none!important}
.admin-students-desktop{display:block!important}
.admin-students-page .admin-student-card{display:block!important;padding:15px!important;border:1px solid #dfe5ea!important;border-radius:17px!important;background:#fff!important;box-shadow:0 4px 12px rgba(31,48,66,.045)!important;min-width:0!important;box-sizing:border-box!important}
.admin-students-page .admin-student-card-head{display:flex!important;align-items:flex-start!important;justify-content:space-between!important;gap:10px!important;min-width:0!important}
.admin-students-page .admin-student-person{display:flex!important;align-items:center!important;gap:9px!important;min-width:0!important;flex:1!important}
.admin-students-page .admin-student-person>div{min-width:0!important}
.admin-students-page .admin-student-person strong{display:block!important;font-size:14px!important;line-height:1.25!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
.admin-students-page .admin-student-person small{display:block!important;margin-top:3px!important;color:#718090!important;font-size:10px!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
.admin-students-page .admin-student-meta{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:8px!important;margin:13px 0!important}
.admin-students-page .admin-student-meta>div{padding:9px 10px!important;border:1px solid #edf0f3!important;border-radius:11px!important;background:#f8fafc!important;min-width:0!important}
.admin-students-page .admin-student-meta small{display:block!important;color:#7b8792!important;font-size:8px!important;text-transform:uppercase!important;letter-spacing:.06em!important}
.admin-students-page .admin-student-meta strong{display:block!important;color:#17202b!important;font-size:11px!important;margin-top:3px!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
.admin-students-page .admin-student-card-actions{display:grid!important;gap:7px!important}
@media(max-width:850px){
@media(max-width:850px){
  *,*::before,*::after{animation:none!important}
  html,body{width:100%!important;max-width:100%!important;overflow-x:hidden!important}
  body{background:#f4f8fb!important}
  .card,.btn,.home-action,.home-update-panel,.home-update,.admin-control-card,.admin-tool,.settings-tile,.publisher-student-card,.ah-key,.ah-choice{transition:none!important;animation:none!important}
  .page-home .home-live-glow,.page-home .home-live-orbit{display:none!important}
  .page-home .home-updates-grid{display:grid!important;grid-template-columns:1fr!important;gap:12px!important;width:100%!important;max-width:100%!important;overflow:visible!important}
  .page-home .home-update-panel{width:100%!important;min-width:0!important;max-width:100%!important;box-sizing:border-box!important;overflow:hidden!important;padding:12px!important;border-radius:18px!important;box-shadow:0 2px 8px rgba(20,30,20,.045)!important}
  .page-home .home-update{display:grid!important;grid-template-columns:34px minmax(0,1fr) 14px!important;align-items:center!important;width:100%!important;min-width:0!important;max-width:100%!important;box-sizing:border-box!important;padding:10px 8px!important;gap:9px!important}
  .page-home .home-update>span:nth-child(2){min-width:0!important;max-width:100%!important;overflow:hidden!important}
  .page-home .home-update strong,.page-home .home-update small{display:block!important;max-width:100%!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
  .page-home .home-update>b{font-size:18px!important}
  .student-feature,.student-mini,.student-link,.home-action{box-shadow:0 3px 10px rgba(20,30,20,.04)!important}
  .admin-students-desktop{display:none!important}
  .admin-students-mobile{display:grid!important;gap:10px!important}
  .admin-students-page .admin-student-card-actions{display:grid!important;grid-template-columns:1fr!important;gap:7px!important}
  .admin-students-page .admin-student-card-actions .btn{width:100%!important;min-height:42px!important}
  .admin-students-page .admin-student-meta{grid-template-columns:1fr 1fr!important}
  .admin-students-page .admin-student-meta>div:last-child{grid-column:1 / -1}
  .admin-students-page .admin-student-card{padding:14px!important;border-radius:16px!important}
  .admin-student-card,.settings-tile,.publisher-student-card,.ah-key,.ah-choice{content-visibility:auto;contain-intrinsic-size:72px}
}
@media(min-width:851px){
  .card,.home-action,.home-update-panel,.admin-control-card,.admin-tool,.settings-tile,.publisher-student-card{animation:none!important}
}
"""
    admin_problem_alert_runtime = r"""
<script>
(function(){
  const bell=document.getElementById('vybeAdminProblemBell');
  const panel=document.getElementById('vybeAdminProblemPanel');
  if(!bell||!panel)return;
  function closePanel(){panel.hidden=true;bell.setAttribute('aria-expanded','false');}
  bell.addEventListener('click',function(e){e.stopPropagation();const open=panel.hidden;panel.hidden=!open;bell.setAttribute('aria-expanded',open?'true':'false');});
  panel.addEventListener('click',function(e){e.stopPropagation();});
  document.addEventListener('click',function(e){if(!panel.hidden&&!e.target.closest('.admin-problem-alert-wrap'))closePanel();});
  document.addEventListener('keydown',function(e){if(e.key==='Escape')closePanel();});
})();
</script>
"""
    mobile_runtime_css = r'''
/* ===== VYBE AI SETTINGS ===== */
.ai-settings-page{max-width:1120px!important;margin:0 auto!important;padding-bottom:80px}.ai-settings-head{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin-bottom:24px}.ai-settings-head h1{margin:8px 0 8px;font-size:clamp(34px,5vw,56px);letter-spacing:-.045em}.ai-settings-head p{max-width:700px;color:#687482;font-size:15px;line-height:1.65;margin:0}.ai-live-status{min-width:130px;padding:15px 17px;border:1px solid #dfe5ea;border-radius:18px;background:#fff;box-shadow:0 12px 30px rgba(31,48,66,.07);display:grid;grid-template-columns:auto 1fr;column-gap:9px;align-items:center}.ai-live-status small{grid-column:2;color:#7b8792;font-size:11px;margin-top:2px}.ai-status-dot{width:10px;height:10px;border-radius:50%;grid-row:1 / span 2;background:#9aa4ad;box-shadow:0 0 0 5px #f0f2f4}.ai-live-status.is-on .ai-status-dot{background:#68b82e;box-shadow:0 0 0 5px #edf8e6}.ai-live-status.is-off .ai-status-dot{background:#d65a5a;box-shadow:0 0 0 5px #faecec}.ai-control-card{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:24px;border:1px solid #dfe5ea;border-radius:22px;background:#fff;box-shadow:0 14px 36px rgba(31,48,66,.07);margin-bottom:18px}.ai-control-label{display:block;font-size:10px;font-weight:900;letter-spacing:.14em;color:#2f6fca;margin-bottom:7px}.ai-control-card h2,.ai-shortcuts-head h2{margin:0 0 6px;font-size:22px;letter-spacing:-.025em}.ai-control-card p,.ai-shortcuts-head p{margin:0;color:#687482;line-height:1.55;font-size:13px}.ai-toggle-button{display:inline-flex;align-items:center;gap:10px;border-radius:14px;padding:11px 14px;font:inherit;font-size:12px;font-weight:850;cursor:pointer;white-space:nowrap}.ai-toggle-button.on{background:#fff0f0;color:#a83232;border:1px solid #f1d1d1}.ai-toggle-button.off{background:#edf8e6;color:#3c7f1a;border:1px solid #d6edc8}.ai-toggle-track{width:39px;height:22px;border-radius:99px;background:#a9b1b9;padding:3px;display:flex;align-items:center}.ai-toggle-track span{width:16px;height:16px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.2);transition:transform .18s ease}.ai-toggle-button.on .ai-toggle-track{background:#d85d5d}.ai-toggle-button.on .ai-toggle-track span{transform:translateX(17px)}.ai-toggle-button.off .ai-toggle-track{background:#68b82e}.ai-shortcuts-section{padding:24px;border:1px solid #dfe5ea;border-radius:22px;background:#fff;box-shadow:0 14px 36px rgba(31,48,66,.07)}.ai-shortcuts-head{display:flex;justify-content:space-between;gap:18px;align-items:flex-end;margin-bottom:18px}.ai-selected-count{background:#f4f7fa;border:1px solid #e1e7ec;border-radius:999px;padding:7px 11px;font-size:11px;color:#687482;white-space:nowrap}.ai-selected-count b{color:#17202b}.ai-shortcut-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.ai-shortcut-card{position:relative;display:flex;align-items:center;gap:11px;padding:14px 15px;border:1px solid #e0e6eb;border-radius:15px;background:#fbfcfd;cursor:pointer;transition:transform .16s ease,border-color .16s ease,background .16s ease,box-shadow .16s ease}.ai-shortcut-card:hover{transform:translateY(-2px);border-color:#b9d2ec;background:#fff;box-shadow:0 8px 22px rgba(47,111,202,.08)}.ai-shortcut-card input{position:absolute;opacity:0;pointer-events:none}.ai-shortcut-check{width:22px;height:22px;flex:0 0 22px;border-radius:7px;border:1.5px solid #cbd5de;background:#fff;color:transparent;display:grid;place-items:center;font-size:13px;font-weight:900}.ai-shortcut-card:has(input:checked){border-color:#9fc3e8;background:#f3f8ff;box-shadow:0 7px 20px rgba(47,111,202,.08)}.ai-shortcut-card:has(input:checked) .ai-shortcut-check{background:#2f6fca;border-color:#2f6fca;color:#fff}.ai-shortcut-copy{min-width:0;display:flex;flex-direction:column;gap:3px;flex:1}.ai-shortcut-copy strong{font-size:13px;color:#17202b}.ai-shortcut-copy small{font-size:11px;color:#75818c;line-height:1.35}.ai-shortcut-arrow{font-size:20px;color:#a2adb7}.ai-save-row{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:18px;padding-top:17px;border-top:1px solid #e7ebef}.ai-save-row span{font-size:11px;color:#7b8792}.vybe-assistant-empty{grid-column:1/-1;padding:18px;border:1px dashed rgba(159,182,205,.35);border-radius:13px;color:#a9bbcc;text-align:center;font-size:12px}
@media(max-width:760px){.ai-settings-head{display:block}.ai-live-status{margin-top:16px;width:max-content}.ai-control-card{display:block}.ai-toggle-button{margin-top:18px;width:100%;justify-content:center}.ai-shortcuts-head{display:block}.ai-selected-count{display:inline-block;margin-top:10px}.ai-shortcut-grid{grid-template-columns:1fr}.ai-save-row{display:block}.ai-save-row .btn{width:100%;margin-top:12px}}

/* ===== HEADER ADMIN ALERTS ===== */
.vybe-header-alert-wrap{position:relative;display:inline-flex;align-items:center}.vybe-header-alert{position:relative;height:38px;display:inline-flex;align-items:center;gap:8px;padding:0 11px;border:1px solid rgba(255,255,255,.10);border-radius:12px;background:#172033;color:#fff;cursor:pointer;font:inherit;font-size:11px;font-weight:850;box-shadow:0 8px 22px rgba(23,32,51,.16)}.vybe-header-alert-icon{width:22px;height:22px;display:grid;place-items:center;border-radius:7px;background:rgba(255,255,255,.12);color:#fff}.vybe-header-alert-icon svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.vybe-alert-count{position:absolute;top:-6px;right:-6px;min-width:19px;height:19px;padding:0 5px;display:inline-flex;align-items:center;justify-content:center;border-radius:999px;background:#ef4d52;color:#fff;border:2px solid #fff;font-size:9px;font-weight:950}.vybe-header-alert-panel{position:absolute;top:calc(100% + 10px);right:0;width:min(410px,calc(100vw - 28px));background:#fff;border:1px solid #dfe5ea;border-radius:16px;box-shadow:0 18px 44px rgba(20,37,55,.18);overflow:hidden;z-index:3000}.vybe-header-alert-panel[hidden]{display:none}.vybe-header-alert-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 15px;border-bottom:1px solid #edf0f3}.vybe-header-alert-head strong{display:block;color:#17202b;font-size:14px}.vybe-header-alert-head small{display:block;margin-top:3px;color:#7b8793;font-size:10px}.vybe-header-alert-head>span{padding:5px 8px;border-radius:999px;background:#edf5ff;color:#2f6fca;font-size:10px;font-weight:900}.vybe-header-alert-list{max-height:360px;overflow:auto;padding:7px}.vybe-header-alert-item{width:100%;display:flex;align-items:flex-start;gap:10px;padding:11px 10px;border-radius:11px;color:#17202b;background:#f8fbff;border:0;text-align:left;box-sizing:border-box}.vybe-header-alert-item + .vybe-header-alert-item{margin-top:4px}.vybe-alert-type{width:28px;height:28px;flex:0 0 28px;display:grid;place-items:center;border-radius:8px;background:#eaf7df;color:#4d8f21;font-size:10px;font-weight:950;text-transform:uppercase}.vybe-alert-copy{min-width:0;flex:1}.vybe-alert-copy strong{display:block;font-size:12px;line-height:1.3}.vybe-alert-copy small{display:block;margin-top:3px;color:#84909c;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.vybe-alert-copy p{margin:5px 0 0;color:#687482;font-size:10px;line-height:1.4;white-space:normal}.vybe-alert-open{flex:0 0 auto;padding:4px 6px;border-radius:6px;background:#eaf7df;color:#4d8f21;font-size:8px;font-weight:950;letter-spacing:.3px}.vybe-header-alert-empty{padding:24px 15px;text-align:center;color:#7b8793;font-size:12px}@media(max-width:850px){.vybe-header-alert-label{display:none}.vybe-header-alert{width:39px;height:36px;padding:0;justify-content:center;border-radius:10px}.vybe-header-alert-icon{width:22px;height:22px}.vybe-header-alert-panel{position:fixed;top:61px;right:10px;width:min(410px,calc(100vw - 20px));max-height:calc(100vh - 82px);border-radius:16px}.vybe-header-alert-list{max-height:calc(100vh - 160px)}}

/* ===== SINGLE MOBILE STUDENT SHELL ===== */
@media (max-width:850px){
  #vybeStudentBottomNav{
    position:fixed!important;left:0!important;right:0!important;bottom:0!important;
    width:100vw!important;height:68px!important;min-height:68px!important;
    display:grid!important;grid-template-columns:repeat(3,1fr)!important;
    gap:6px!important;margin:0!important;padding:6px 10px!important;
    padding-bottom:calc(6px + env(safe-area-inset-bottom))!important;
    box-sizing:border-box!important;background:#172033!important;
    border-top:1px solid #2d3b4d!important;box-shadow:0 -8px 24px rgba(0,0,0,.20)!important;
    z-index:2147483000!important;transform:none!important;
  }
  #vybeStudentBottomNav > #vybeBottomMenuButton,
  #vybeStudentBottomNav > .mobile-home-nav,
  #vybeStudentBottomNav > .mobile-profile-nav{
    width:100%!important;min-width:0!important;height:50px!important;
    margin:0!important;padding:0!important;box-sizing:border-box!important;
    display:flex!important;align-items:center!important;justify-content:center!important;
    border:1px solid #435166!important;border-radius:10px!important;
    background:#263246!important;color:#fff!important;
    text-decoration:none!important;font-size:13px!important;font-weight:800!important;
    line-height:1!important;visibility:visible!important;opacity:1!important;
    position:relative!important;left:auto!important;right:auto!important;top:auto!important;
    transform:none!important;order:initial!important;
  }
  #vybeStudentBottomNav > #vybeBottomMenuButton{background:#101827!important;border-color:#536176!important;cursor:pointer!important}
  #vybeStudentBottomNav > .mobile-home-nav.active{background:#33445a!important;border-color:#64758a!important}
  #vybeStudentBottomNav > .mobile-profile-nav{background:#263246!important}
  #vybeStudentBottomNav .mobile-menu-label{display:block!important;color:#fff!important;font-size:13px!important;font-weight:800!important}
  #vybeStudentBottomNav .mobile-menu-icon-lines{display:none!important}
  #vybeStudentBottomNav + .student-bottom-spacer{display:block!important;height:76px!important}

  #vybeStudentSearchForm{
    position:relative!important;display:block!important;width:100%!important;
    max-width:none!important;margin:0!important;overflow:visible!important;
    z-index:2147482000!important;
  }
  #vybeStudentSearchForm input{width:100%!important;box-sizing:border-box!important}
  #vybeStudentSearchSuggestions{
    position:absolute!important;left:0!important;right:0!important;top:calc(100% + 6px)!important;
    display:none!important;z-index:2147483640!important;
    background:#fff!important;color:#263542!important;
    border:1px solid #cbd6df!important;border-radius:12px!important;padding:6px!important;
    box-shadow:0 18px 40px rgba(15,30,45,.25)!important;box-sizing:border-box!important;
  }
  #vybeStudentSearchForm:focus-within #vybeStudentSearchSuggestions,
  #vybeStudentSearchSuggestions.open{display:block!important}
  #vybeStudentSearchSuggestions .vybe-search-suggestion{
    display:flex!important;width:100%!important;min-height:42px!important;
    align-items:center!important;justify-content:space-between!important;
    box-sizing:border-box!important;padding:9px 11px!important;margin:0!important;
    background:#fff!important;color:#263542!important;border:0!important;border-radius:8px!important;
    text-decoration:none!important;font-size:12px!important;font-weight:800!important;
  }
  #vybeStudentSearchSuggestions .vybe-search-suggestion:hover,
  #vybeStudentSearchSuggestions .vybe-search-suggestion:focus{background:#eef4f8!important;color:#1f5f8e!important}

  .nav:has(.student-nav-compact){z-index:2147482000!important;overflow:visible!important}
  .nav:has(.student-nav-compact) .student-control-row{position:relative!important;z-index:2147482001!important;overflow:visible!important}
  body{padding-bottom:84px!important;overflow-x:hidden!important}
}
/* ===== FINAL ASK VYBE PANEL — DARK ON EVERY PAGE ===== */
.vybe-assistant-panel{
  background:rgba(8,15,25,.97)!important;
  background-image:linear-gradient(145deg,rgba(19,34,53,.98),rgba(7,13,22,.97))!important;
  border:1px solid rgba(104,142,178,.38)!important;
  box-shadow:0 26px 72px rgba(0,0,0,.46),0 6px 22px rgba(9,18,31,.34),inset 0 1px rgba(255,255,255,.07)!important;
  color:#f4f7fb!important;
  backdrop-filter:blur(24px) saturate(135%)!important;
  -webkit-backdrop-filter:blur(24px) saturate(135%)!important;
}
.vybe-assistant-panel .vybe-assistant-head{
  background:linear-gradient(135deg,rgba(29,50,76,.92),rgba(13,29,42,.88))!important;
  border-bottom:1px solid rgba(105,139,171,.24)!important;
}
.vybe-assistant-panel .vybe-assistant-head strong{color:#fff!important}
.vybe-assistant-panel .vybe-assistant-head small{color:#9fb2c5!important}
.vybe-assistant-panel .vybe-assistant-close{
  background:rgba(255,255,255,.07)!important;
  color:#e4edf5!important;
  border-color:rgba(120,150,180,.34)!important;
}
.vybe-assistant-panel .vybe-assistant-suggestion{
  background:rgba(255,255,255,.055)!important;
  color:#e8eef5!important;
  border-color:rgba(105,139,170,.28)!important;
}
.vybe-assistant-panel .vybe-assistant-suggestion:hover{
  background:rgba(47,111,202,.20)!important;
  color:#fff!important;
  border-color:rgba(104,160,216,.48)!important;
}
@media(max-width:850px){
  .vybe-assistant-panel{
    right:10px!important;left:10px!important;bottom:136px!important;width:calc(100vw - 20px)!important;
    border-radius:20px!important;
    background:rgba(8,15,25,.97)!important;
    background-image:linear-gradient(145deg,rgba(19,34,53,.98),rgba(7,13,22,.97))!important;
  }
}

'''
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#020817"><meta name="vybe-csrf-token" content="{esc(session.get("_csrf_token", ""))}"><title>{esc(title)} · VYBE</title><style>{CSS}{AUTH_PAGE_CSS}{ADMIN_PASSWORD_ALERT_CSS if admin else ""}{ADMIN_PROBLEM_ALERT_CSS if admin else ""}{mobile_runtime_css}{performance_css}
  /* ===== PHONE HEADER + BOTTOM NAV FINAL FIX ===== */
  @media(max-width:850px){{
    html,body{{width:100%!important;max-width:100%!important;overflow-x:hidden!important}}
    body{{padding-bottom:76px!important;box-sizing:border-box!important}}
    body:has(.student-nav-compact){{padding-top:112px!important}}
    .nav:has(.student-nav-compact){{position:fixed!important;top:0!important;left:0!important;right:0!important;width:100%!important;z-index:5000!important;background:rgba(255,255,255,.98)!important;border-bottom:1px solid #dfe7df!important;box-shadow:0 4px 18px rgba(20,35,28,.08)!important;backdrop-filter:blur(14px)!important;-webkit-backdrop-filter:blur(14px)!important}}
    .nav:has(.student-nav-compact) .navin{{width:100%!important;box-sizing:border-box!important}}
    .nav:has(.student-nav-compact) .student-control-row{{width:100%!important;box-sizing:border-box!important}}
    .student-nav-compact .student-brand-compact{{display:flex!important;visibility:visible!important;opacity:1!important}}
    .student-nav-compact .student-header-back{{display:none!important}}
    .student-nav-compact .student-desktop-links{{display:none!important}}
    .student-nav-compact .student-header-tools{{display:flex!important;margin-left:auto!important}}
    .student-nav-compact .student-header-tools .student-menu{{display:none!important}}
    .student-control-row{{display:block!important}}
    .student-control-row .student-search{{display:block!important}}
    .student-search input{{display:block!important}}
    .student-search-suggestions,.search-suggestions,.search-dropdown{{z-index:6000!important}}
    #vybeMobileNav.student-mobile-menu{{position:fixed!important;z-index:7000!important;top:108px!important;left:8px!important;right:auto!important;width:44vw!important;max-width:205px!important;min-width:160px!important}}
    .student-bottom-nav{{position:fixed!important;left:0!important;right:0!important;bottom:0!important;z-index:5000!important;width:100%!important;margin:0!important}}
    .student-bottom-spacer{{display:none!important}}
    .vybe-assistant-fab{{bottom:86px!important}}
    .vybe-assistant-panel{{bottom:140px!important;max-width:calc(100vw - 24px)!important}}
    .wrap{{width:100%!important;max-width:100%!important;box-sizing:border-box!important;overflow-x:hidden!important}}
    .vybe-footer,.footer{{display:none!important}}
  }}

  /* ===== FINAL MOBILE VYBE HEADER / MENU CLEANUP ===== */
  @media(max-width:850px){{
    .student-nav-compact{{display:flex!important;align-items:center!important;gap:8px!important;width:100%!important;min-height:54px!important;padding:8px 12px!important;box-sizing:border-box!important}}
    .student-nav-compact .student-brand-compact{{display:flex!important;align-items:center!important;gap:7px!important;flex:0 0 auto!important;min-width:max-content!important}}
    .student-nav-compact .student-brand-compact .brandtext{{font-size:16px!important;font-weight:850!important}}
    .student-nav-compact .student-brand-compact .brandmark{{width:29px!important;height:29px!important;display:inline-flex!important;align-items:center!important;justify-content:center!important}}
    .student-desktop-links,.student-header-back{{display:none!important}}
    .student-header-tools{{display:flex!important;align-items:center!important;margin-left:auto!important;flex:0 0 auto!important}}
    .student-header-tools .student-menu{{display:none!important}}
    .student-header-updates{{display:inline-flex!important;height:34px!important;padding:0 10px!important;border-radius:9px!important;background:#315f24!important;color:#fff!important;border:1px solid #315f24!important;font-size:11px!important;font-weight:850!important;white-space:nowrap!important}}
    .student-control-row{{display:block!important;width:100%!important;padding:6px 12px 10px!important;box-sizing:border-box!important}}
    .student-control-row .student-search{{width:100%!important;max-width:none!important;margin:0!important}}
    .student-search{{position:relative!important}}
    .student-search input{{width:100%!important;height:42px!important;padding:0 14px!important;border-radius:11px!important;font-size:13px!important;box-sizing:border-box!important}}
    .student-search:focus-within input{{border-color:#5f8f3b!important;box-shadow:0 0 0 3px rgba(95,143,59,.12)!important}}
    /* Only one set of menu entries. */
    #vybeMobileNav.student-mobile-menu > a{{display:flex!important}}
    #vybeMobileNav.student-mobile-menu .mobile-only-menu-links{{display:none!important}}
    #vybeMobileNav.student-mobile-menu{{left:8px!important;right:auto!important;top:62px!important;width:44vw!important;max-width:205px!important;min-width:160px!important;height:auto!important;max-height:calc(100vh - 145px)!important;overflow-y:auto!important;box-sizing:border-box!important;padding:8px!important;border-radius:14px!important;background:#fff!important;border:1px solid #dbe5d9!important;box-shadow:0 18px 42px rgba(25,42,33,.22)!important}}
    #vybeMobileNav.student-mobile-menu.open{{display:flex!important;flex-direction:column!important;gap:3px!important}}
    #vybeMobileNav.student-mobile-menu .mobile-menu-head{{display:flex!important}}
    #vybeMobileNav.student-mobile-menu > a{{min-height:34px!important;padding:7px 9px!important;border-radius:8px!important;background:#fff!important;color:#24302a!important;font-size:11px!important;font-weight:750!important;line-height:1.2!important;text-decoration:none!important}}
    #vybeMobileNav.student-mobile-menu > a:hover,#vybeMobileNav.student-mobile-menu > a:focus{{background:#edf6e8!important;color:#315f24!important}}
    #vybeMobileNav.student-mobile-menu .mobile-menu-close{{display:inline-flex!important}}
    .student-bottom-nav{{display:grid!important;grid-template-columns:1fr 1fr 1fr!important;align-items:stretch!important;gap:6px!important;height:auto!important;min-height:58px!important;padding:6px 10px calc(6px + env(safe-area-inset-bottom))!important;box-sizing:border-box!important;background:rgba(255,255,255,.98)!important;border-top:1px solid #dfe8df!important;box-shadow:0 -8px 24px rgba(25,42,33,.08)!important}}
    .student-bottom-nav a,.student-bottom-nav button.mobile-menu-nav{{width:100%!important;min-width:0!important;height:46px!important;display:flex!important;align-items:center!important;justify-content:center!important;border-radius:10px!important;box-sizing:border-box!important}}
    .student-bottom-nav button.mobile-menu-nav{{background:#172033!important;color:#fff!important;border:1px solid #172033!important;visibility:visible!important;opacity:1!important;font-size:12px!important;font-weight:850!important}}
    .student-bottom-nav button.mobile-menu-nav .mobile-menu-label{{display:block!important;color:#fff!important}}
    .student-bottom-nav .mobile-menu-icon-lines{{display:none!important}}
    .student-bottom-nav a{{font-size:12px!important;font-weight:750!important}}
    .student-bottom-spacer{{height:72px!important}}
  }}
  @media(min-width:851px){{
    .student-control-row .student-search{{margin-left:auto!important;margin-right:auto!important}}
  }}
  /* ===== MOBILE NAV FINAL, SIMPLE AND DETERMINISTIC ===== */
  @media(max-width:850px){{
    .nav:has(.student-nav-compact){{position:fixed!important;top:0!important;left:0!important;right:0!important;width:100%!important;height:108px!important;padding:0!important;margin:0!important;z-index:10000!important;background:#fff!important;border-bottom:1px solid #dfe4e8!important;box-shadow:0 3px 14px rgba(20,32,44,.10)!important;backdrop-filter:none!important}}
    .nav:has(.student-nav-compact) .student-nav-compact{{height:54px!important;min-height:54px!important;padding:7px 12px!important;display:flex!important;align-items:center!important;gap:7px!important}}
    .student-nav-compact .student-brand-compact{{display:flex!important;align-items:center!important;gap:6px!important;flex:0 0 auto!important}}
    .student-nav-compact .student-brand-compact .brandmark{{width:28px!important;height:28px!important}}
    .student-nav-compact .student-brand-compact .brandtext{{font-size:16px!important;font-weight:850!important}}
    .student-nav-compact .student-header-back{{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:30px!important;padding:0 8px!important;margin-left:2px!important;border:1px solid #cfd8df!important;border-radius:8px!important;background:#fff!important;color:#263542!important;font-size:11px!important;font-weight:800!important;text-decoration:none!important}}
    .student-nav-compact .student-desktop-links{{display:none!important}}
    .student-nav-compact .student-header-tools{{display:flex!important;align-items:center!important;margin-left:auto!important}}
    .student-nav-compact .student-header-updates{{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:32px!important;padding:0 10px!important;background:#fff!important;color:#263542!important;border:1px solid #cfd8df!important;border-radius:8px!important;font-size:11px!important;font-weight:800!important;box-shadow:none!important}}
    .student-nav-compact .student-menu{{display:none!important}}
    .nav:has(.student-nav-compact) .student-control-row{{display:block!important;height:54px!important;width:100%!important;padding:6px 12px 8px!important;box-sizing:border-box!important}}
    .student-control-row .student-search{{display:block!important;position:relative!important;width:100%!important;height:40px!important;margin:0!important}}
    .student-search input{{display:block!important;width:100%!important;height:40px!important;padding:0 13px!important;background:#f7fafc!important;border:1px solid #cfd8df!important;border-radius:10px!important;color:#1d2a35!important;font-size:13px!important;outline:none!important;box-sizing:border-box!important}}
    .student-search input:focus{{background:#fff!important;border-color:#6a8294!important;box-shadow:0 0 0 3px rgba(73,103,126,.10)!important}}
    .mobile-direct-suggestions{{display:none!important;position:absolute!important;left:0!important;right:0!important;top:44px!important;z-index:50000!important;background:#fff!important;border:1px solid #cbd5dc!important;border-radius:10px!important;padding:5px!important;box-shadow:0 16px 34px rgba(20,32,44,.20)!important;box-sizing:border-box!important}}
    .student-search:focus-within .mobile-direct-suggestions,.mobile-direct-suggestions.open{{display:block!important}}
    .vybe-search-suggestions.open{{display:block!important}}
    .mobile-direct-suggestions .vybe-search-suggestion{{display:flex!important;min-height:38px!important;align-items:center!important;justify-content:space-between!important;padding:7px 9px!important;border-radius:7px!important;text-decoration:none!important;background:#fff!important;color:#263542!important;font-size:11px!important;font-weight:750!important}}
    .mobile-direct-suggestions .vybe-search-suggestion span:last-child{{font-size:9px!important;color:#84909a!important}}
    .mobile-direct-suggestions .vybe-search-suggestion:hover{{background:#f1f5f7!important}}
    #vybeMobileNav.student-mobile-menu{{position:fixed!important;top:60px!important;left:8px!important;right:auto!important;width:210px!important;max-width:calc(100vw - 32px)!important;min-width:0!important;max-height:calc(100vh - 135px)!important;overflow-y:auto!important;z-index:30000!important;background:#fff!important;border:1px solid #d5dde2!important;border-radius:11px!important;padding:7px!important;box-shadow:0 16px 38px rgba(20,32,44,.20)!important}}
    #vybeMobileNav.student-mobile-menu.open{{display:flex!important;flex-direction:column!important;gap:2px!important}}
    #vybeMobileNav.student-mobile-menu > a{{display:flex!important;align-items:center!important;min-height:36px!important;padding:7px 9px!important;background:#fff!important;border:0!important;border-radius:7px!important;color:#263542!important;font-size:11px!important;font-weight:750!important;text-decoration:none!important}}
    #vybeMobileNav.student-mobile-menu > a:hover{{background:#f1f5f7!important}}
    .student-bottom-nav{{position:fixed!important;left:0!important;right:0!important;bottom:0!important;width:100%!important;height:64px!important;min-height:64px!important;display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:0!important;margin:0!important;padding:6px 8px calc(6px + env(safe-area-inset-bottom))!important;background:linear-gradient(135deg,#ffffff 0%,#f1f8ff 58%,#f2faef 100%)!important;border-top:1px solid #dce8f0!important;box-shadow:0 -8px 24px rgba(42,75,105,.10)!important;z-index:10000!important;box-sizing:border-box!important}}
    .student-bottom-nav > *{{width:100%!important;height:48px!important;min-width:0!important;margin:0!important;padding:0!important;display:flex!important;align-items:center!important;justify-content:center!important;box-sizing:border-box!important;border:1px solid #dfe7ed!important;border-radius:10px!important;background:rgba(255,255,255,.88)!important;color:#172130!important;text-decoration:none!important;font-size:12px!important;font-weight:800!important;line-height:1!important;visibility:visible!important;opacity:1!important;box-shadow:0 4px 12px rgba(39,62,82,.06)!important}}
    .student-bottom-nav .mobile-home-nav.active{{background:#eef5ff!important;color:#2f6fca!important;border-color:#cfe0ef!important}}
    .student-bottom-nav .mobile-profile-nav{{background:#f0f8ec!important;color:#5b8f35!important;border-color:#d7e8ca!important}}
    .student-bottom-nav button.mobile-menu-nav{{display:flex!important;visibility:visible!important;opacity:1!important;background:#f3f5f7!important;color:#43515f!important;border-color:#dfe7ed!important;box-shadow:none!important}}
    .student-bottom-nav .mobile-menu-label{{display:block!important;color:inherit!important}}
    .student-bottom-nav .mobile-menu-icon-lines{{display:none!important}}
    .student-bottom-spacer{{display:block!important;height:64px!important}}
    body:has(.student-nav-compact){{padding-top:112px!important;padding-bottom:70px!important}} body:not(:has(.student-nav-compact)){{padding-top:0!important;padding-bottom:0!important}}
    .vybe-footer,.footer{{display:none!important}}
    .vybe-assistant-fab{{bottom:76px!important}}
    .vybe-assistant-panel{{bottom:130px!important}}
  }}

/* ===== FINAL NAV / FOOTER COLORS ===== */
.student-bottom-nav{{
  background:linear-gradient(180deg,#ffffff 0%,#eef7ff 55%,#dceeff 100%)!important;
  background-image:linear-gradient(180deg,#ffffff 0%,#eef7ff 55%,#dceeff 100%)!important;
  border-top:1px solid #b9d4ea!important;
  box-shadow:0 -8px 22px rgba(38,75,105,.12)!important;
}}
.student-bottom-nav > .mobile-menu-nav,
.student-bottom-nav > .mobile-home-nav,
.student-bottom-nav > .mobile-profile-nav{{
  width:100%!important;
  min-width:0!important;
  max-width:none!important;
  height:46px!important;
  margin:0!important;
  padding:4px 8px!important;
  display:flex!important;
  flex-direction:column!important;
  align-items:center!important;
  justify-content:center!important;
  gap:3px!important;
  border:1px solid rgba(91,143,190,.32)!important;
  border-radius:12px!important;
  background:linear-gradient(145deg,rgba(24,39,57,.96),rgba(9,17,28,.98))!important;
  color:#b9cbe0!important;
  box-sizing:border-box!important;
  text-decoration:none!important;
  box-shadow:inset 0 1px rgba(255,255,255,.055),0 8px 20px rgba(0,0,0,.22)!important;
  cursor:pointer!important;
  font:inherit!important;
}}
.student-bottom-nav .vybe-nav-icon{{
  width:19px!important;
  height:19px!important;
  display:grid!important;
  place-items:center!important;
  flex:0 0 19px!important;
}}
.student-bottom-nav .vybe-nav-icon svg{{
  width:19px!important;
  height:19px!important;
  display:block!important;
  fill:none!important;
  stroke:currentColor!important;
  stroke-width:1.8!important;
  stroke-linecap:round!important;
  stroke-linejoin:round!important;
}}
.student-bottom-nav .mobile-menu-label{{
  display:block!important;
  color:inherit!important;
  font-size:10px!important;
  font-weight:800!important;
  line-height:1!important;
  letter-spacing:.01em!important;
}}
.student-bottom-nav > .mobile-home-nav.active{{
  background:linear-gradient(145deg,rgba(20,77,112,.98),rgba(9,39,62,.98))!important;
  color:#69c9ff!important;
  border-color:rgba(66,190,255,.55)!important;
  box-shadow:inset 0 1px rgba(255,255,255,.08),0 8px 24px rgba(0,126,210,.18)!important;
}}
.student-bottom-nav > .mobile-menu-nav:hover,
.student-bottom-nav > .mobile-profile-nav:hover,
.student-bottom-nav > .mobile-menu-nav:focus-visible,
.student-bottom-nav > .mobile-profile-nav:focus-visible{{
  background:linear-gradient(145deg,rgba(30,49,70,.98),rgba(10,20,32,.98))!important;
  color:#e7f5ff!important;
  border-color:rgba(93,169,224,.5)!important;
}}
.student-bottom-nav > .mobile-home-nav:hover,
.student-bottom-nav > .mobile-home-nav:focus-visible{{
  color:#7bd2ff!important;
  border-color:rgba(66,190,255,.65)!important;
}}
.student-bottom-nav > .mobile-menu-nav:active,
.student-bottom-nav > .mobile-home-nav:active,
.student-bottom-nav > .mobile-profile-nav:active{{
  transform:translateY(1px)!important;
}}
.student-bottom-nav button.mobile-menu-nav .mobile-menu-icon-lines{{
  display:none!important;
}}
/* Every desktop navigation/menu item gets its own visible border. */
.student-desktop-links > a,
.navlinks > a,
.admin-navlinks > a{{
  border:1px solid #b8bdc3!important;
  background:#ffffff!important;
  color:#17191c!important;
  border-radius:8px!important;
  box-shadow:none!important;
}}
.student-desktop-links > a:hover,
.navlinks > a:hover,
.admin-navlinks > a:hover{{
  background:#f0f7fc!important;
  border-color:#8fbce0!important;
  color:#000000!important;
}}
/* Each item in the phone menu has its own box. */
#vybeMobileNav.student-mobile-menu > a,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a{{
  display:flex!important;
  align-items:center!important;
  width:calc(100% - 16px)!important;
  min-height:40px!important;
  margin:4px 8px!important;
  padding:0 12px!important;
  border:1px solid #b8bdc3!important;
  border-radius:8px!important;
  background:#ffffff!important;
  color:#17191c!important;
  box-sizing:border-box!important;
  text-decoration:none!important;
}}
#vybeMobileNav.student-mobile-menu > a:hover,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:hover{{
  background:#f0f1f2!important;
  border-color:#777d83!important;
}}


/* ===== GLOBAL PHONE SHELL — HOMEPAGE STYLE, ALL STUDENT PAGES ===== */
@media (max-width:850px){{
  html,body{{
    width:100%!important;
    max-width:100%!important;
    overflow-x:hidden!important;
  }}

  /* Leave room for the floating navigation on every student page. */
  body:has(.student-nav-compact){{
    padding-bottom:88px!important;
  }}
  body:has(.student-nav-compact) .page-shell{{
    padding-bottom:18px!important;
  }}

  /* Floating glass Menu / Home / Profile bar — same on every page. */
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav{{
    position:fixed!important;
    left:8px!important;
    right:8px!important;
    bottom:8px!important;
    width:auto!important;
    height:58px!important;
    min-height:58px!important;
    padding:5px!important;
    margin:0!important;
    display:grid!important;
    grid-template-columns:repeat(3,minmax(0,1fr))!important;
    gap:5px!important;
    box-sizing:border-box!important;
    background:rgba(255,255,255,.70)!important;
    background-image:linear-gradient(110deg,rgba(255,255,255,.82),rgba(248,251,255,.66) 52%,rgba(247,252,242,.72))!important;
    border:1px solid rgba(255,255,255,.96)!important;
    border-radius:17px!important;
    box-shadow:0 10px 30px rgba(28,49,69,.16),0 2px 8px rgba(28,49,69,.07),inset 0 1px rgba(255,255,255,1)!important;
    backdrop-filter:blur(22px) saturate(150%)!important;
    -webkit-backdrop-filter:blur(22px) saturate(150%)!important;
    z-index:2147483000!important;
  }}

  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > #vybeBottomMenuButton,
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-home-nav,
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-profile-nav{{
    width:100%!important;
    height:46px!important;
    min-width:0!important;
    min-height:46px!important;
    max-width:none!important;
    margin:0!important;
    padding:0 4px!important;
    display:flex!important;
    flex-direction:column!important;
    align-items:center!important;
    justify-content:center!important;
    gap:2px!important;
    box-sizing:border-box!important;
    border-radius:12px!important;
    text-decoration:none!important;
    font-size:10px!important;
    font-weight:800!important;
    line-height:1!important;
    letter-spacing:0!important;
    cursor:pointer!important;
    -webkit-tap-highlight-color:transparent!important;
    transition:transform .15s ease,background .15s ease,border-color .15s ease,box-shadow .15s ease!important;
  }}

  /* Menu: dark active-looking button exactly like the reference. */
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > #vybeBottomMenuButton{{
    background:linear-gradient(145deg,#172033,#24334a)!important;
    color:#fff!important;
    border:1px solid rgba(67,83,105,.92)!important;
    box-shadow:0 5px 13px rgba(23,32,51,.18),inset 0 1px rgba(255,255,255,.08)!important;
  }}

  /* Home: white glass + VYBE blue. */
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-home-nav{{
    background:rgba(255,255,255,.70)!important;
    color:#2f6fca!important;
    border:1px solid rgba(202,220,237,.86)!important;
    box-shadow:inset 0 1px rgba(255,255,255,.95)!important;
  }}
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-home-nav.active{{
    background:linear-gradient(145deg,rgba(255,255,255,.90),rgba(239,247,255,.82))!important;
    color:#2f6fca!important;
    border-color:rgba(178,207,232,.92)!important;
    box-shadow:0 3px 10px rgba(47,111,202,.08),inset 0 1px rgba(255,255,255,1)!important;
  }}

  /* Profile: white glass + VYBE green. */
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-profile-nav{{
    background:linear-gradient(145deg,rgba(255,255,255,.90),rgba(242,249,236,.82))!important;
    color:#60913d!important;
    border:1px solid rgba(198,220,180,.92)!important;
    box-shadow:inset 0 1px rgba(255,255,255,1)!important;
  }}

  body:has(.student-nav-compact) #vybeStudentBottomNav .vybe-nav-icon{{
    width:18px!important;
    height:18px!important;
    display:grid!important;
    place-items:center!important;
    flex:0 0 18px!important;
  }}
  body:has(.student-nav-compact) #vybeStudentBottomNav .vybe-nav-icon svg{{
    width:18px!important;
    height:18px!important;
    fill:none!important;
    stroke:currentColor!important;
    stroke-width:1.75!important;
    stroke-linecap:round!important;
    stroke-linejoin:round!important;
  }}
  body:has(.student-nav-compact) #vybeStudentBottomNav .mobile-menu-label{{
    display:block!important;
    color:inherit!important;
    font-size:10px!important;
    font-weight:800!important;
    line-height:1!important;
  }}

  body:has(.student-nav-compact) #vybeStudentBottomNav > *:active{{
    transform:scale(.97)!important;
  }}

  /* Same floating AI / Ask VYBE control on EVERY student page. */
  body:has(.student-nav-compact) .vybe-assistant-fab{{
    position:fixed!important;
    right:12px!important;
    bottom:74px!important;
    min-height:38px!important;
    height:38px!important;
    padding:4px 9px 4px 5px!important;
    display:flex!important;
    align-items:center!important;
    gap:6px!important;
    border-radius:14px!important;
    background:rgba(255,255,255,.76)!important;
    background-image:linear-gradient(110deg,rgba(255,255,255,.88),rgba(244,249,255,.76))!important;
    color:#263646!important;
    border:1px solid rgba(255,255,255,.98)!important;
    box-shadow:0 9px 24px rgba(28,49,69,.15),inset 0 1px rgba(255,255,255,1)!important;
    backdrop-filter:blur(20px) saturate(150%)!important;
    -webkit-backdrop-filter:blur(20px) saturate(150%)!important;
    font-size:11px!important;
    font-weight:850!important;
    z-index:2147482990!important;
  }}
  body:has(.student-nav-compact) .vybe-assistant-fab .fab-mark{{
    width:27px!important;
    height:27px!important;
    min-width:27px!important;
    border-radius:9px!important;
    display:grid!important;
    place-items:center!important;
    background:linear-gradient(145deg,#eef7ff,#dfeeff)!important;
    color:#2f6fca!important;
    border:1px solid #cfe1f2!important;
    box-shadow:inset 0 1px rgba(255,255,255,.95)!important;
    font-size:10px!important;
    font-weight:950!important;
  }}
  body:has(.student-nav-compact) .vybe-assistant-fab:active{{
    transform:scale(.96)!important;
  }}

  /* Assistant panel — dark desktop-matched design on phone too. */
  body:has(.student-nav-compact) .vybe-assistant-panel{{
    right:10px!important;
    left:10px!important;
    bottom:122px!important;
    width:auto!important;
    max-width:none!important;
    border-radius:20px!important;
    background:rgba(8,15,25,.98)!important;
    background-image:linear-gradient(145deg,rgba(19,34,53,.98),rgba(7,13,22,.98))!important;
    border:1px solid rgba(104,142,178,.42)!important;
    box-shadow:0 24px 60px rgba(0,0,0,.48),0 8px 24px rgba(9,18,31,.36),inset 0 1px rgba(255,255,255,.07)!important;
    backdrop-filter:blur(24px) saturate(135%)!important;
    -webkit-backdrop-filter:blur(24px) saturate(135%)!important;
    color:#f4f7fb!important;
    overflow:hidden!important;
  }}
  body:has(.student-nav-compact) .vybe-assistant-head{{
    background:linear-gradient(135deg,rgba(29,50,76,.96),rgba(13,29,42,.94))!important;
    border-bottom:1px solid rgba(105,139,171,.25)!important;
  }}
  body:has(.student-nav-compact) .vybe-assistant-head strong{{color:#fff!important}}
  body:has(.student-nav-compact) .vybe-assistant-head small{{color:#9fb2c5!important}}
  body:has(.student-nav-compact) .vybe-assistant-close{{background:rgba(255,255,255,.07)!important;color:#e4edf5!important;border-color:rgba(120,150,180,.34)!important}}
  body:has(.student-nav-compact) .vybe-assistant-body{{background:transparent!important;color:#f4f7fb!important}}
  body:has(.student-nav-compact) .vybe-assistant-suggestion{{background:rgba(255,255,255,.055)!important;color:#e8eef5!important;border-color:rgba(105,139,170,.28)!important}}
  body:has(.student-nav-compact) .vybe-assistant-suggestion:hover{{background:rgba(47,111,202,.20)!important;color:#fff!important;border-color:rgba(104,160,216,.48)!important}}
  body:has(.student-nav-compact) .vybe-assistant-suggestion{{
    background:rgba(248,251,253,.78)!important;
    border:1px solid #e1e9ef!important;
    color:#263646!important;
  }}
  body:has(.student-nav-compact) .vybe-assistant-suggestion:hover{{
    background:#eef6ff!important;
    border-color:#cfe1f2!important;
    color:#2f6fca!important;
  }}

  /* Keep the page content above the floating bar. */
  body:has(.student-nav-compact) #vybeStudentBottomNav + .student-bottom-spacer{{
    display:block!important;
    height:0!important;
  }}
}}

@media (max-width:380px){{
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav{{
    left:6px!important;
    right:6px!important;
    bottom:6px!important;
    height:56px!important;
    min-height:56px!important;
    border-radius:16px!important;
  }}
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > #vybeBottomMenuButton,
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-home-nav,
  body:has(.student-nav-compact) #vybeStudentBottomNav.student-bottom-nav > .mobile-profile-nav{{
    height:44px!important;
    min-height:44px!important;
    border-radius:11px!important;
  }}
  body:has(.student-nav-compact) .vybe-assistant-fab{{
    right:9px!important;
    bottom:70px!important;
  }}
}}


/* ===== ADMIN PHONE MENU — CLEAN DRAWER ===== */
.admin-header-actions{{display:flex!important;align-items:center!important;gap:8px!important;flex:0 0 auto!important}}
.admin-menu-toggle{{display:none!important}}
@media(max-width:850px){{
  .admin-header{{min-height:58px!important;padding:8px 12px!important;display:flex!important;align-items:center!important}}
  .admin-header .brand{{display:flex!important;align-items:center!important;gap:8px!important;flex:1 1 auto!important;min-width:0!important;font-size:18px!important}}
  .admin-header .brandmark{{width:34px!important;height:34px!important;flex:0 0 34px!important;margin:0!important}}
  .admin-header .brandtext{{display:inline!important;font-size:18px!important;letter-spacing:-.04em!important}}
  .admin-header-actions{{margin-left:auto!important}}
  .admin-menu-toggle{{display:grid!important;place-items:center!important;width:42px!important;height:42px!important;min-width:42px!important;min-height:42px!important;padding:0!important;border:1px solid rgba(88,151,205,.35)!important;border-radius:13px!important;background:linear-gradient(145deg,#14263a,#091522)!important;color:#fff!important;font-size:19px!important;font-weight:900!important;line-height:1!important;box-shadow:0 8px 22px rgba(4,17,29,.20)!important}}
  .admin-menu-toggle:hover{{background:linear-gradient(145deg,#1a3550,#0b1928)!important;border-color:rgba(103,181,239,.55)!important}}
  .admin-mobile-menu{{display:none!important;position:fixed!important;top:68px!important;right:12px!important;left:12px!important;width:auto!important;max-width:390px!important;margin-left:auto!important;z-index:9999!important;padding:10px!important;border:1px solid rgba(104,157,202,.25)!important;border-radius:22px!important;background:linear-gradient(180deg,rgba(13,25,39,.98),rgba(6,13,22,.98))!important;box-shadow:0 28px 70px rgba(0,0,0,.42),0 0 0 1px rgba(255,255,255,.025) inset!important;backdrop-filter:blur(24px)!important;-webkit-backdrop-filter:blur(24px)!important;overflow:hidden!important;transform-origin:top right!important}}
  .admin-mobile-menu.open{{display:grid!important;gap:5px!important;animation:adminMenuIn .18s ease both!important}}
  .admin-mobile-menu::before{{content:"";display:block;position:absolute;top:0;right:22px;width:80px;height:1px;background:linear-gradient(90deg,transparent,rgba(89,179,239,.7),transparent)!important}}
  .admin-mobile-menu-head{{display:flex!important;flex-direction:column!important;gap:2px!important;padding:12px 12px 11px!important;margin-bottom:3px!important;border-bottom:1px solid rgba(255,255,255,.08)!important}}
  .admin-mobile-menu-kicker{{font-size:9px!important;letter-spacing:.16em!important;color:#6eb7eb!important;font-weight:900!important}}
  .admin-mobile-menu-head strong{{font-size:16px!important;color:#fff!important;letter-spacing:-.02em!important}}
  .admin-mobile-menu > a{{display:flex!important;align-items:center!important;min-height:48px!important;padding:0 13px!important;border:1px solid rgba(125,159,188,.15)!important;border-radius:14px!important;background:rgba(255,255,255,.045)!important;color:#eaf1f7!important;text-decoration:none!important;font-size:13px!important;font-weight:750!important;box-sizing:border-box!important}}
  .admin-mobile-menu > a::after{{content:"›";margin-left:auto;color:#7fa7c6;font-size:20px;font-weight:400}}
  .admin-mobile-menu > a:hover,.admin-mobile-menu > a:active{{background:rgba(48,119,171,.18)!important;border-color:rgba(87,166,220,.34)!important;color:#fff!important}}
  .admin-mobile-menu > a.admin-nav-logout{{color:#ffb7b7!important;background:rgba(185,66,66,.08)!important;border-color:rgba(208,91,91,.20)!important}}
  .admin-mobile-menu > a.admin-nav-logout::after{{color:#e17d7d!important}}
}}
@keyframes adminMenuIn{{from{{opacity:0;transform:translateY(-8px) scale(.98)}}to{{opacity:1;transform:none}}}}
@media(max-width:380px){{
  .admin-header{{padding-left:9px!important;padding-right:9px!important}}
  .admin-mobile-menu{{top:64px!important;left:9px!important;right:9px!important;border-radius:19px!important}}
  .admin-mobile-menu > a{{min-height:45px!important;font-size:12px!important}}
}}

/* ===== ADMIN SETTINGS / PUBLISHER CONTROL CENTER ===== */
.settings-hub,.settings-detail,.publisher-access-page{{max-width:1120px!important;margin:0 auto!important}}
.settings-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:22px}}
.settings-tile{{display:flex;align-items:center;gap:16px;min-width:0;padding:22px;border:1px solid #dfe5ea;border-radius:22px;background:rgba(255,255,255,.92);box-shadow:0 10px 28px rgba(31,48,66,.07);text-decoration:none;color:#17202b;transition:.2s ease}}
.settings-tile:hover{{transform:translateY(-3px);border-color:#c5d8e9;box-shadow:0 18px 36px rgba(31,48,66,.11)}}
.settings-icon{{width:48px;height:48px;flex:0 0 48px;display:grid;place-items:center;border-radius:15px;background:#edf4ff;font-size:21px}}
.settings-tile div{{min-width:0;flex:1}}.settings-tile b{{display:block;font-size:17px}}.settings-tile small{{display:block;margin-top:5px;color:#718090;font-size:12px;line-height:1.45}}.settings-tile>strong{{font-size:22px;color:#8a97a3}}.settings-state{{font-size:10px;font-weight:900;letter-spacing:.08em;padding:7px 9px;border-radius:999px;background:#edf4ff;color:#2f6fca;white-space:nowrap}}.settings-state.off{{background:#fff1f1;color:#c45b61}}.settings-footer-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:16px}}.settings-mini{{text-decoration:none;color:#17202b;display:block}}.settings-mini small{{display:block;color:#718090;margin:6px 0 12px}}.settings-mini span{{font-size:12px;color:#2f6fca;font-weight:800}}
.settings-detail-grid{{display:grid;grid-template-columns:1.25fr .75fr;gap:18px;margin-top:20px}}.settings-editor,.settings-preview{{border-radius:24px!important}}.settings-editor-icon{{width:52px;height:52px;display:grid;place-items:center;border-radius:16px;background:#edf8e6;font-size:23px;margin-bottom:12px}}.settings-check{{display:flex!important;gap:12px;align-items:flex-start;padding:13px;border:1px solid #e1e7ec;border-radius:15px;background:#f8fafb}}.settings-check input{{width:18px!important;flex:0 0 18px;margin-top:2px}}.settings-check b,.settings-check small{{display:block}}.settings-check small{{margin-top:4px;color:#718090}}.preview-row{{display:flex;justify-content:space-between;gap:12px;padding:14px 0;border-bottom:1px solid #e7ebef;font-size:13px}}.preview-row b{{color:#2f6fca}}.publisher-access-note{{min-width:150px;text-align:center;padding:18px!important;display:flex!important;flex-direction:column!important;align-items:center!important;justify-content:center!important;gap:4px!important;line-height:1.2!important}}.publisher-access-note strong{{display:block;font-size:34px}}.publisher-access-note small{{color:#718090}}.publisher-on{{background:#edf8e6!important;color:#57952a!important}}.publisher-page .publisher-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin-top:20px}}.publisher-page .publisher-permission-summary{{min-width:210px;padding:16px!important}}.publisher-page .publisher-permission-summary strong{{display:block}}.publisher-page .publisher-permission-summary small{{display:block;color:#718090;margin-top:5px;line-height:1.45}}.publisher-page .publisher-grid .card{{border-radius:22px}}
@media(max-width:800px){{.settings-grid,.settings-footer-grid,.settings-detail-grid,.publisher-page .publisher-grid{{grid-template-columns:1fr}}.settings-tile{{padding:17px}}.settings-tile small{{font-size:11px}}.publisher-access-note{{width:max-content}}.publisher-page .admin-page-head{{flex-direction:column}}.settings-detail .admin-page-head{{display:block}}}}
@media(max-width:520px){{.settings-icon{{width:42px;height:42px;flex-basis:42px;border-radius:13px}}.settings-tile{{gap:11px;padding:15px;border-radius:18px}}.settings-tile b{{font-size:15px}}.settings-tile>strong{{font-size:18px}}.settings-state{{font-size:8px;padding:6px 7px}}.settings-detail-grid{{gap:12px}}}}

/* ===== FINAL VYBE MENU PANEL — DARK BLUE, LIGHTWEIGHT, ALL DEVICES ===== */
#vybeMobileNav.student-mobile-menu{{
  background:linear-gradient(145deg,#142a43 0%,#0b1b2d 58%,#071321 100%)!important;
  border:1px solid rgba(116,171,214,.34)!important;
  box-shadow:0 22px 55px rgba(4,12,22,.42),inset 0 1px rgba(255,255,255,.055)!important;
  color:#eef7ff!important;
  backdrop-filter:none!important;-webkit-backdrop-filter:none!important;
  isolation:isolate!important;
}}
#vybeMobileNav.student-mobile-menu.open{{display:flex!important}}
#vybeMobileNav.student-mobile-menu .mobile-menu-head{{background:transparent!important;border-bottom:1px solid rgba(145,190,220,.16)!important;color:#fff!important}}
#vybeMobileNav.student-mobile-menu .mobile-menu-title{{color:#fff!important}}
#vybeMobileNav.student-mobile-menu .mobile-menu-close{{background:rgba(255,255,255,.07)!important;border:1px solid rgba(150,195,225,.20)!important;color:#eaf6ff!important}}
#vybeMobileNav.student-mobile-menu > a,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a{{display:flex!important;align-items:center!important;background:rgba(255,255,255,.055)!important;color:#edf7ff!important;border:1px solid rgba(112,174,216,.20)!important;box-shadow:none!important;text-decoration:none!important}}
#vybeMobileNav.student-mobile-menu > a:hover,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:hover,#vybeMobileNav.student-mobile-menu > a:focus-visible,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:focus-visible,#vybeMobileNav.student-mobile-menu > a:active,#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:active{{background:#1b4c73!important;border-color:rgba(94,190,241,.55)!important;color:#fff!important}}
#vybeMobileNav.student-mobile-menu .student-menu-icon{{color:#66c8f5!important}}
@media(min-width:851px){{#vybeMobileNav.student-mobile-menu{{top:72px!important;right:18px!important;left:auto!important;width:280px!important;padding:12px!important;border-radius:18px!important}}#vybeMobileNav.student-mobile-menu > a{{min-height:44px!important;padding:10px 12px!important;margin:0 0 5px!important;border-radius:11px!important;font-size:12px!important}}#vybeMobileNav.student-mobile-menu > a:last-child{{margin-bottom:0!important}}}}
@media(max-width:850px){{#vybeMobileNav.student-mobile-menu{{top:60px!important;left:8px!important;right:auto!important;width:min(78vw,280px)!important;max-width:280px!important;min-width:0!important;max-height:calc(100vh - 135px)!important;padding:12px!important;border-radius:18px!important}}#vybeMobileNav.student-mobile-menu > a{{min-height:46px!important;padding:9px 12px!important;margin:0 0 7px!important;border-radius:12px!important;font-size:12px!important}}#vybeMobileNav.student-mobile-menu > a:last-child{{margin-bottom:0!important}}}}

/* ===== FINAL SCROLL PERFORMANCE OVERRIDES ===== */
html{{scroll-behavior:auto!important}}
body{{background-attachment:scroll!important}}
body:has(.student-nav-compact){{background:linear-gradient(135deg,#f4f8fb 0%,#f7faf8 48%,#f1f8f3 100%)!important}}
.nav:has(.student-nav-compact),
.nav:has(.admin-header),
.mobile-nav.open,
.admin-mobile-menu,
.vybe-assistant-panel,
.vybe-status-card,
.chat-composer{{backdrop-filter:none!important;-webkit-backdrop-filter:none!important}}

/* No continuous paint work on the student experience. */
.home-live-glow,
.home-live-orbit,
.home-live-status span,
.student-home [class*="orbit"],
.student-home [class*="glow"]{{animation:none!important}}
.home-live-glow{{filter:none!important}}

/* Keep cards visually clean without large soft shadows while scrolling. */
.student-feature,.student-mini,.student-link,.home-action,.home-update-panel,.ah-key,.ah-choice,.ah-result{{box-shadow:0 3px 10px rgba(20,30,20,.045)!important}}
.student-feature:hover,.student-mini:hover,.student-link:hover,.home-action:hover,.ah-key:hover,.ah-choice:hover,.ah-result:hover{{transform:none!important;box-shadow:0 3px 10px rgba(20,30,20,.045)!important}}

@media(max-width:850px){{
  body{{background:#f4f8fb!important;background-attachment:scroll!important}}
  .nav:has(.student-nav-compact){{background:#fff!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;box-shadow:0 2px 8px rgba(20,35,28,.06)!important}}
  .student-bottom-nav{{backdrop-filter:none!important;-webkit-backdrop-filter:none!important;box-shadow:0 -2px 9px rgba(20,35,28,.055)!important}}
  .mobile-nav.open{{backdrop-filter:none!important;-webkit-backdrop-filter:none!important;box-shadow:0 8px 24px rgba(20,35,28,.10)!important}}
  .home-live-glow{{display:none!important}}
  .home-live-orbit{{animation:none!important;box-shadow:none!important}}
  .live-home-grid .home-action{{box-shadow:0 2px 8px rgba(20,30,20,.04)!important}}
}}
@media(prefers-reduced-motion:reduce){{*,*::before,*::after{{animation:none!important;transition:none!important;scroll-behavior:auto!important}}}}

/* FINAL MOBILE FIT: keep dashboard updates contained and lightweight. */
.compact-home-updates{{display:grid!important;grid-template-columns:1fr 1fr!important;gap:12px!important;align-items:start!important;width:100%!important;max-width:100%!important}}
.compact-home-updates .home-update-panel{{width:100%!important;min-width:0!important;max-width:100%!important;box-sizing:border-box!important;overflow:hidden!important}}
.compact-home-updates .home-update-list{{display:grid!important;gap:4px!important;min-width:0!important}}
.compact-home-updates .home-update{{width:100%!important;min-width:0!important;max-width:100%!important;box-sizing:border-box!important;overflow:hidden!important}}
.compact-home-updates .home-update > span:nth-child(2){{min-width:0!important;overflow:hidden!important}}
.compact-home-updates .home-update strong,.compact-home-updates .home-update small{{max-width:100%!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}}
@media(max-width:850px){{
  .compact-home-updates{{grid-template-columns:1fr!important;gap:10px!important}}
  .compact-home-updates .home-update-panel{{padding:10px!important;border-radius:16px!important}}
  .compact-home-updates .home-panel-title{{margin:0 1px 6px!important;font-size:12px!important}}
  .compact-home-updates .home-update{{display:grid!important;grid-template-columns:30px minmax(0,1fr) 12px!important;gap:8px!important;padding:8px 6px!important;border-radius:11px!important;align-items:center!important}}
  .compact-home-updates .home-update-icon{{width:30px!important;height:30px!important;flex:0 0 30px!important;border-radius:9px!important}}
  .compact-home-updates .home-update strong{{font-size:11px!important;line-height:1.25!important}}
  .compact-home-updates .home-update small{{font-size:9px!important;line-height:1.25!important}}
  .compact-home-updates .home-update>b{{font-size:16px!important}}
}}

</style>{ADMIN_DESKTOP_POLISH_CSS if admin else ""}</head><body>
<div class="nav">{header}</div><div class="mobile-nav {"student-mobile-menu" if student else "admin-mobile-menu"}" id="vybeMobileNav">{('<div class="mobile-menu-head"><span class="mobile-menu-title">Menu</span></div>'+mobile_links) if student else ('<div class="admin-mobile-menu-head"><span class="admin-mobile-menu-kicker">VYBE ADMIN</span><strong>Control center</strong></div>'+links)}<div class="mobile-only-menu-links"></div></div>
<main class="wrap page-shell page-{re.sub(r"[^a-z0-9]+", "-", request.path.strip("/").lower()) or "home"}">{flashes}{body}</main>{bottom_nav}{assistant_widget}{admin_problem_alert_runtime}
<script>(function(){{
const toggle=document.getElementById("vybeNavToggle");
const menu=document.getElementById("vybeMobileNav");
const bottomMenu=document.querySelector(".mobile-menu-nav");

function setMenu(open){{
  if(!menu)return;
  const isOpen=!!open;
  menu.classList.toggle("open",isOpen);
  if(toggle){{
    toggle.setAttribute("aria-expanded",isOpen?"true":"false");
    const isAdminMenu=menu && menu.classList.contains("admin-mobile-menu");
    toggle.textContent=isAdminMenu?"☰":(isOpen?"Close":"Menu");
  }}
  if(bottomMenu){{
    bottomMenu.setAttribute("aria-expanded",isOpen?"true":"false");
    const icon=bottomMenu.querySelector(".mobile-menu-icon-lines");
    if(icon) icon.classList.toggle("is-open",isOpen);
  }}
}}


/* Live search suggestions: no external service, no fake data, just helpful UI prompts. */
(function(){{
  const fields=document.querySelectorAll('.student-search input, .academic-search input, input[name="q"]');
  const suggestions=[
    'Search notes, papers, subjects...',
    'Search announcements and events...',
    'Search timetable and campus help...',
    'Search study material and PDFs...',
    'Search your VYBE campus...'
  ];
  fields.forEach(function(input){{
    if(input.dataset.vybeSuggestReady==='1') return;
    input.dataset.vybeSuggestReady='1';
    input.placeholder=input.placeholder||suggestions[0];
  }});
}})();

/* Header search: direct campus destinations. */
(function(){{
  const forms=document.querySelectorAll('.student-search');
  const items=[
    {{label:'Study Material',hint:'Academics',url:'/academic-hub/study-material'}},
    {{label:'Notes',hint:'Study Notes',url:'/academic-hub/notes'}},
    {{label:'Timetable',hint:'Campus timetable',url:'/timetable'}},
    {{label:'Previous Papers',hint:'PYQ Papers',url:'/papers'}},
    {{label:'Admit Card',hint:'Exam updates',url:'/updates?kind=Admit%20Card'}},
    {{label:'Results & Updates',hint:'Latest updates',url:'/updates'}}
  ];
  forms.forEach(function(form){{
    const input=form.querySelector('input[name="q"]');
    if(!input || form.dataset.vybeSuggestionReady==='1') return;
    form.dataset.vybeSuggestionReady='1';
    let box=form.querySelector('.mobile-direct-suggestions');
    if(!box){{
      box=document.createElement('div');
      box.className='vybe-search-suggestions';
      box.setAttribute('role','listbox');
      box.innerHTML=items.map(function(item){{
        return '<a class="vybe-search-suggestion" role="option" href="'+item.url+'"><span>'+item.label+'</span><span>'+item.hint+'</span></a>';
      }}).join('');
      form.appendChild(box);
    }}
    function openSuggestions(){{ box.classList.add('open'); }}
    function closeSuggestions(){{ setTimeout(function(){{ if(!form.contains(document.activeElement)) box.classList.remove('open'); }},220); }}
    input.addEventListener('focus',openSuggestions);
    input.addEventListener('click',openSuggestions);
    input.addEventListener('input',function(){{ openSuggestions(); }});
    input.addEventListener('blur',closeSuggestions);
  }});
}})();

window.vybeToggleStudentMenu=function(e){{
  if(e){{e.preventDefault();e.stopPropagation();}}
  if(!menu)return;
  setMenu(!menu.classList.contains("open"));
}};

if(toggle&&menu){{
  toggle.addEventListener("click",function(e){{
    e.preventDefault();
    e.stopPropagation();
    setMenu(!menu.classList.contains("open"));
  }});
}}

if(menu){{
  menu.addEventListener("click",function(e){{
    const link=e.target.closest("a");
    const close=e.target.closest(".mobile-menu-close");
    if(close){{
      e.preventDefault();
      e.stopPropagation();
      setMenu(false);
      return;
    }}
    if(link){{
      setMenu(false);
      return;
    }}
    e.stopPropagation();
  }});
}}

document.addEventListener("click",function(e){{
  if(!menu||!menu.classList.contains("open"))return;
  if(menu.contains(e.target))return;
  if(toggle&&toggle.contains(e.target))return;
  if(bottomMenu&&bottomMenu.contains(e.target))return;
  setMenu(false);
}});

document.addEventListener("keydown",function(e){{
  if(e.key==="Escape")setMenu(false);
}});

/* VYBE navigation: use normal browser navigation.
   Do not prefetch every hovered/touched link; that created duplicate requests and
   made mobile navigation feel slower, especially on Vercel. External links are
   intentionally left untouched so they open directly through their href/target. */
(function(){{
  if(window.__vybeLinkWarmupDisabled)return;
  window.__vybeLinkWarmupDisabled=true;
}})();

document.querySelectorAll(".toggle-password").forEach(function(btn){{
  btn.addEventListener("click",function(){{
    const el=document.getElementById(btn.dataset.target);
    if(!el)return;
    const show=el.type==="password";
    el.type=show?"text":"password";
    btn.classList.toggle("is-visible",show);
    btn.setAttribute("aria-label",show?"Hide password":"Show password");
    btn.setAttribute("title",show?"Hide password":"Show password");
  }});
}});

document.querySelectorAll(".password-error input").forEach(function(el){{
  el.addEventListener("input",function(){{
    const wrap=el.closest(".password-wrap");
    if(wrap)wrap.classList.remove("password-error");
  }});
}});

const assistantFab=document.getElementById("vybeAssistantFab");
const assistantPanel=document.getElementById("vybeAssistantPanel");
const assistantClose=document.getElementById("vybeAssistantClose");
function setAssistant(open){{
  if(!assistantPanel)return;
  assistantPanel.classList.toggle("open",!!open);
  if(assistantFab)assistantFab.setAttribute("aria-expanded",open?"true":"false");
  if(open){{
    const input=assistantPanel.querySelector('input[name="question"]');
    if(input)setTimeout(function(){{input.focus();}},120);
  }}
}}
if(assistantFab)assistantFab.addEventListener("click",function(e){{e.preventDefault();e.stopPropagation();setAssistant(!assistantPanel.classList.contains("open"));}});
if(assistantClose)assistantClose.addEventListener("click",function(e){{e.preventDefault();setAssistant(false);}});
if(assistantPanel)assistantPanel.addEventListener("click",function(e){{e.stopPropagation();}});
document.addEventListener("click",function(e){{if(assistantPanel&&assistantPanel.classList.contains("open")&&!assistantPanel.contains(e.target)&&e.target!==assistantFab)setAssistant(false);}});
document.addEventListener("keydown",function(e){{if(e.key==="Escape")setAssistant(false);}});
}})();(function(){{const b=document.getElementById("vybeHeaderAlertButton"),p=document.getElementById("vybeHeaderAlertPanel");if(!b||!p)return;let marked=false;function closePanel(){{p.hidden=true;b.setAttribute("aria-expanded","false");}}b.addEventListener("click",function(e){{e.preventDefault();e.stopPropagation();const opening=p.hidden;p.hidden=!opening;b.setAttribute("aria-expanded",opening?"true":"false");if(opening&&!marked){{marked=true;fetch('/student/header-notifications/read',{{method:'POST',credentials:'same-origin',headers:{{'Accept':'application/json'}}}}).then(function(){{const badge=b.querySelector('.vybe-alert-count');if(badge)badge.remove();const count=document.getElementById('vybeHeaderAlertCount');if(count)count.textContent='0';}}).catch(function(){{}});}}}});p.addEventListener("click",function(e){{e.stopPropagation();}});document.addEventListener("click",function(e){{if(!p.hidden&&!e.target.closest('.vybe-header-alert-wrap'))closePanel();}});document.addEventListener("keydown",function(e){{if(e.key==='Escape')closePanel();}});}})();(function(){{const m=document.querySelector('meta[name="vybe-csrf-token"]');const t=m&&m.content;if(!t)return;document.querySelectorAll('form').forEach(function(f){{const method=(f.getAttribute('method')||'get').toLowerCase();if(!['post','put','patch','delete'].includes(method))return;if(!f.querySelector('input[name="csrf_token"]')){{const i=document.createElement('input');i.type='hidden';i.name='csrf_token';i.value=t;f.appendChild(i);}}}});const originalFetch=window.fetch;if(originalFetch&&!window.__vybeCsrfFetchWrapped){{window.__vybeCsrfFetchWrapped=true;window.fetch=function(input,init){{init=init||{{}};const u=typeof input==='string'?input:(input&&input.url)||'';const same=!u||u.startsWith('/')||u.startsWith(location.origin);const method=String(init.method||((typeof input!=='string'&&input&&input.method)||'GET')).toUpperCase();if(same&&['POST','PUT','PATCH','DELETE'].includes(method)){{const h=new Headers(init.headers||{{}});if(!h.has('X-VYBE-CSRF'))h.set('X-VYBE-CSRF',t);init.headers=h;}}return originalFetch.call(this,input,init);}};}}}})();(function(){{
  // Seamless student-side sync: admin changes are detected quickly and the
  // current page content is replaced in-place, without a browser refresh.
  // Chat pages keep their own realtime polling so an admin content sync never
  // interrupts an active conversation.
  if(!document.body.classList.contains('vybe-student-page') && !document.querySelector('.student-nav-compact')) return;
  if(!document.querySelector('main.page-updates, main.page-announcements, main.page-events, main.page-timetable, main.page-community, main.page-issues')) return;
  if(window.__vybeContentSyncStarted)return;
  window.__vybeContentSyncStarted=true;
  let lastVersion=null;
  let syncing=false;
  let scrolling=false;
  let scrollTimer=0;
  const syncable=()=>!document.querySelector('.community-chat, #communityChatWindow, .chat-window');
  window.addEventListener('scroll',function(){{
    scrolling=true;
    clearTimeout(scrollTimer);
    scrollTimer=setTimeout(function(){{scrolling=false;}},700);
  }},{{passive:true}});
  async function check(){{
    if(syncing || scrolling || !syncable() || document.visibilityState!=='visible')return;
    try{{
      const r=await fetch('/student/content-version',{{credentials:'same-origin',cache:'no-store',headers:{{Accept:'application/json'}}}});
      if(!r.ok)return;
      const d=await r.json();
      const v=String(d.version||'0');
      if(lastVersion===null){{lastVersion=v;return;}}
      if(v===lastVersion)return;
      lastVersion=v;
      if(document.querySelector('input:focus, textarea:focus, select:focus, [contenteditable="true"]:focus'))return;
      syncing=true;
      const y=window.scrollY;
      const page=await fetch(location.pathname+location.search,{{credentials:'same-origin',cache:'no-store',headers:{{Accept:'text/html','X-VYBE-Silent-Sync':'1'}}}});
      if(!page.ok){{syncing=false;return;}}
      const html=await page.text();
      const doc=new DOMParser().parseFromString(html,'text/html');
      const fresh=doc.querySelector('main.page-shell');
      const current=document.querySelector('main.page-shell');
      if(fresh&&current){{
        current.replaceChildren(...Array.from(fresh.childNodes).map(function(n){{return document.importNode(n,true);}}));
        current.className=fresh.className;
        document.title=doc.title;
        window.scrollTo(0,y);
      }}
    }}catch(_){{}}
    syncing=false;
  }}
  setInterval(function(){{ if(document.visibilityState==='visible' && !scrolling) check(); }},180000);
}})();</script></body></html>'''


# ---------------------------------------------------------------------------
# VYBE public entry / maintenance / error screens
# ---------------------------------------------------------------------------

def _vybe_public_shell(title, body):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#07111f"><title>{title} · VYBE</title><style>
*{{box-sizing:border-box}}html,body{{margin:0;min-height:100%;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",sans-serif;background:#f6f8fb;color:#17202b}}body{{overflow-x:hidden}}a{{color:inherit;text-decoration:none}}
.vybe-public{{min-height:100vh;position:relative;overflow:hidden;background:radial-gradient(circle at 50% 0%,rgba(47,111,202,.13),transparent 34%),linear-gradient(180deg,#fbfdff 0%,#f4f7fa 100%)}}.vybe-public::before{{content:"";position:absolute;width:620px;height:620px;border-radius:50%;left:50%;top:-340px;transform:translateX(-50%);background:radial-gradient(circle,rgba(47,111,202,.15),rgba(104,184,46,.035) 45%,transparent 70%);filter:blur(8px);pointer-events:none}}
.vybe-top{{position:relative;z-index:10;display:flex;align-items:center;justify-content:space-between;max-width:1180px;margin:auto;padding:24px 24px 0}}.vybe-brand{{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:-.04em;font-size:20px}}.vybe-brand-mark{{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;color:#fff;background:linear-gradient(145deg,#163b69,#07111f);box-shadow:0 12px 30px rgba(7,17,31,.18);position:relative;overflow:hidden}}.vybe-brand-mark span{{position:relative;z-index:1}}.vybe-brand-mark::after{{content:"";position:absolute;inset:-20%;background:linear-gradient(115deg,transparent 35%,rgba(255,255,255,.3),transparent 65%);animation:shine 3.8s linear infinite}}.vybe-admin-mini{{padding:10px 14px;border:1px solid rgba(7,17,31,.1);background:rgba(255,255,255,.72);backdrop-filter:blur(16px);border-radius:13px;font-size:13px;font-weight:700;box-shadow:0 8px 24px rgba(18,36,56,.06);transition:.22s ease}}.vybe-admin-mini:hover{{transform:translateY(-2px)}}
.vybe-hero{{position:relative;z-index:2;max-width:1080px;margin:0 auto;padding:78px 24px 34px;text-align:center}}.vybe-logo-orbit{{width:164px;height:164px;margin:0 auto 30px;position:relative;display:grid;place-items:center;animation:float 5s ease-in-out infinite}}.vybe-logo-orbit::before,.vybe-logo-orbit::after{{content:"";position:absolute;border-radius:50%;inset:0;border:1px solid rgba(47,111,202,.15);animation:orbit 8s linear infinite}}.vybe-logo-orbit::after{{inset:14px;border-color:rgba(104,184,46,.16);animation-direction:reverse;animation-duration:11s}}.vybe-logo-core{{width:100px;height:100px;border-radius:30px;display:grid;place-items:center;color:#fff;font-size:47px;font-weight:900;letter-spacing:-.09em;background:linear-gradient(145deg,#1c4c83 0%,#07111f 78%);box-shadow:0 25px 60px rgba(7,17,31,.22),inset 0 1px 0 rgba(255,255,255,.2);position:relative;overflow:hidden;animation:logoIn .95s cubic-bezier(.16,1,.3,1) both}}.vybe-logo-core::before{{content:"";position:absolute;width:55%;height:150%;top:-25%;left:-80%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);transform:rotate(20deg);animation:logoSweep 3.5s ease-in-out .8s infinite}}.vybe-logo-core span{{position:relative;z-index:1}}
.vybe-kicker{{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.76);border:1px solid rgba(23,32,43,.08);box-shadow:0 8px 25px rgba(18,36,56,.05);font-size:12px;font-weight:800;color:#506071;animation:rise .8s .1s both}}.vybe-kicker i{{width:7px;height:7px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 5px rgba(104,184,46,.12);animation:pulse 2s infinite}}
.vybe-hero h1{{font-size:clamp(58px,10vw,104px);line-height:.9;margin:22px 0 15px;letter-spacing:-.075em;font-weight:900;color:#101923;animation:rise .8s .18s both}}.vybe-hero h1 em{{font-style:normal;background:linear-gradient(100deg,#163b69,#2f6fca 48%,#68b82e);-webkit-background-clip:text;background-clip:text;color:transparent}}.vybe-hero p{{max-width:650px;margin:0 auto;color:#647180;font-size:clamp(16px,2vw,20px);line-height:1.6;animation:rise .8s .26s both}}
.vybe-actions{{display:flex;justify-content:center;gap:11px;flex-wrap:wrap;margin:30px 0 0;animation:rise .8s .34s both}}.vybe-action{{min-width:145px;padding:13px 18px;border-radius:15px;font-weight:800;font-size:14px;border:1px solid rgba(23,32,43,.1);background:rgba(255,255,255,.78);box-shadow:0 12px 30px rgba(18,36,56,.06);transition:.22s ease;backdrop-filter:blur(14px)}}.vybe-action:hover{{transform:translateY(-3px);box-shadow:0 18px 38px rgba(18,36,56,.1)}}.vybe-action.primary{{background:#07111f;color:#fff;border-color:#07111f;box-shadow:0 15px 35px rgba(7,17,31,.18)}}.vybe-action.green{{background:#edf8e6;color:#315f18;border-color:#d7edc8}}
.vybe-fake-row{{display:flex;justify-content:center;gap:9px;flex-wrap:wrap;margin:34px auto 0;animation:rise .8s .43s both}}.vybe-fake{{font-size:11px;font-weight:800;color:#758292;padding:8px 11px;border-radius:999px;background:rgba(255,255,255,.58);border:1px solid rgba(23,32,43,.07);box-shadow:0 7px 20px rgba(18,36,56,.04);user-select:none;cursor:default}}.vybe-fake::before{{content:"";display:inline-block;width:5px;height:5px;border-radius:50%;margin:0 7px 1px 0;background:#2f6fca;opacity:.7}}
.vybe-showcase{{max-width:1020px;margin:30px auto 0;padding:0 24px 62px;display:grid;grid-template-columns:repeat(3,1fr);gap:14px;position:relative;z-index:2}}.vybe-show-card{{min-height:130px;padding:21px;border-radius:24px;background:rgba(255,255,255,.68);border:1px solid rgba(23,32,43,.075);box-shadow:0 18px 50px rgba(18,36,56,.06);backdrop-filter:blur(18px);text-align:left;transition:.25s ease;animation:cardIn .8s both}}.vybe-show-card:nth-child(2){{animation-delay:.08s}}.vybe-show-card:nth-child(3){{animation-delay:.16s}}.vybe-show-card:hover{{transform:translateY(-5px)}}.vybe-show-icon{{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:#edf3fb;color:#2f6fca;font-weight:900;margin-bottom:15px}}.vybe-show-card:nth-child(2) .vybe-show-icon{{background:#edf8e6;color:#5a9e29}}.vybe-show-card:nth-child(3) .vybe-show-icon{{background:#f0eefb;color:#6657b4}}.vybe-show-card h3{{margin:0 0 6px;font-size:16px}}.vybe-show-card p{{margin:0;color:#71808e;font-size:13px;line-height:1.5}}.vybe-footer{{position:relative;z-index:2;text-align:center;padding:0 20px 28px;color:#8a96a3;font-size:11px}}
.vybe-status-wrap{{min-height:calc(100vh - 100px);display:grid;place-items:center;padding:40px 20px;position:relative;z-index:2}}.vybe-status-card{{width:min(620px,100%);text-align:center;padding:42px 34px;border-radius:30px;background:rgba(255,255,255,.76);border:1px solid rgba(23,32,43,.09);box-shadow:0 25px 80px rgba(18,36,56,.1);backdrop-filter:blur(22px);animation:rise .75s both}}.vybe-status-mark{{width:88px;height:88px;margin:0 auto 22px;border-radius:27px;display:grid;place-items:center;background:#07111f;color:#fff;font-size:35px;font-weight:900;box-shadow:0 20px 50px rgba(7,17,31,.2);animation:float 4s ease-in-out infinite}}.vybe-status-card .badge{{display:inline-block;font-size:11px;font-weight:900;letter-spacing:.08em;color:#5f6d7c;padding:7px 10px;border-radius:999px;background:#eef2f6}}.vybe-status-card h1{{font-size:clamp(38px,8vw,66px);letter-spacing:-.06em;margin:14px 0 10px;color:#101923}}.vybe-status-card p{{max-width:480px;margin:0 auto;color:#6d7a88;line-height:1.65;font-size:15px}}.status-actions{{display:flex;justify-content:center;gap:10px;margin-top:25px}}.vybe-error-code{{font-size:12px;font-weight:900;letter-spacing:.12em;color:#2f6fca;margin-bottom:8px}}
@keyframes rise{{from{{opacity:0;transform:translateY(22px)}}to{{opacity:1;transform:none}}}}@keyframes cardIn{{from{{opacity:0;transform:translateY(28px) scale(.98)}}to{{opacity:1;transform:none}}}}@keyframes logoIn{{from{{opacity:0;transform:scale(.55) rotate(-10deg)}}to{{opacity:1;transform:none}}}}@keyframes logoSweep{{0%,30%{{left:-80%}}65%,100%{{left:125%}}}}@keyframes shine{{0%,45%{{transform:translateX(-130%)}}75%,100%{{transform:translateX(130%)}}}}@keyframes orbit{{to{{transform:rotate(360deg)}}}}@keyframes float{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-8px)}}}}@keyframes pulse{{0%,100%{{transform:scale(1);opacity:.8}}50%{{transform:scale(1.35);opacity:1}}}}
@media (max-width:700px){{.vybe-top{{padding:17px 16px 0}}.vybe-brand{{font-size:18px}}.vybe-brand-mark{{width:35px;height:35px;border-radius:11px}}.vybe-admin-mini{{font-size:12px;padding:9px 11px}}.vybe-hero{{padding:57px 18px 22px}}.vybe-logo-orbit{{width:132px;height:132px;margin-bottom:25px}}.vybe-logo-core{{width:82px;height:82px;border-radius:25px;font-size:39px}}.vybe-hero h1{{font-size:65px;margin-top:18px}}.vybe-hero p{{font-size:15px;max-width:350px}}.vybe-actions{{display:grid;grid-template-columns:1fr;max-width:340px;margin-left:auto;margin-right:auto}}.vybe-action{{width:100%;padding:13px 16px}}.vybe-fake-row{{margin-top:27px;gap:7px}}.vybe-fake{{font-size:10px;padding:7px 9px}}.vybe-showcase{{grid-template-columns:1fr;padding:0 18px 40px;margin-top:22px}}.vybe-show-card{{min-height:auto;padding:18px;border-radius:20px}}.vybe-status-wrap{{min-height:calc(100vh - 78px);padding:26px 16px}}.vybe-status-card{{padding:32px 20px;border-radius:25px}}.vybe-status-card h1{{font-size:46px}}.vybe-status-card p{{font-size:14px}}.status-actions{{display:grid;grid-template-columns:1fr;max-width:280px;margin:23px auto 0}}}}@media (prefers-reduced-motion:reduce){{*,*::before,*::after{{animation-duration:.001ms!important;animation-iteration-count:1!important;transition:none!important}}}}
</style></head><body><main class="vybe-public">{body}</main></body></html>'''

@app.route("/offline")
def offline():
    body='''<header class="vybe-top"><a class="vybe-brand" href="/offline"><span class="vybe-brand-mark"><span>V</span></span><span>VYBE</span></a><a class="vybe-admin-mini" href="/admin">Admin Login</a></header><section class="vybe-status-wrap"><div class="vybe-status-card"><div class="vybe-status-mark">V</div><span class="badge">VYBE STATUS</span><h1>We'll be right back.</h1><p>VYBE is temporarily offline while the campus system is being updated or maintained. Student access is paused for now.</p><div class="status-actions"><a class="vybe-action primary" href="/admin">Admin Login</a></div></div></section>'''
    return _vybe_public_shell("Offline",body)

@app.route("/")
def home():
    if session.get("student_db_id"):
        return redirect(url_for("dashboard"))
    if session.get("admin_authenticated"):
        return redirect(url_for("admin_panel"))
    body='''<header class="vybe-top"><a class="vybe-brand" href="/"><span class="vybe-brand-mark"><span>V</span></span><span>VYBE</span></a><a class="vybe-admin-mini" href="/admin">Admin Login</a></header><section class="vybe-hero"><div class="vybe-logo-orbit"><div class="vybe-logo-core"><span>V</span></div></div><div class="vybe-kicker"><i></i> Student-powered campus space</div><h1>Welcome to <em>VYBE.</em></h1><p>Your Campus. Your Community. Your Space. A focused digital home for academics, campus support and student community.</p><div class="vybe-actions"><a class="vybe-action primary" href="/login">Enter VYBE →</a><a class="vybe-action green" href="/register">Request Access</a><a class="vybe-action" href="/contact-terms" target="_blank" rel="noopener">Contact / Terms</a><a class="vybe-action" href="/admin">Admin Login</a></div><div class="vybe-fake-row" aria-hidden="true"><span class="vybe-fake">Academics</span><span class="vybe-fake">Campus</span><span class="vybe-fake">Community</span><span class="vybe-fake">Updates</span><span class="vybe-fake">Resources</span><span class="vybe-fake">Help Desk</span></div></section><section class="vybe-showcase"><article class="vybe-show-card"><div class="vybe-show-icon" aria-hidden="true">▦</div><h3>Academics</h3><p>Study resources, updates and useful campus learning material.</p></article><article class="vybe-show-card"><div class="vybe-show-icon" aria-hidden="true">◉</div><h3>Campus</h3><p>One simple place for campus information and support.</p></article><article class="vybe-show-card"><div class="vybe-show-icon">✦</div><h3>Community</h3><p>A student space built around useful conversations and solutions.</p></article></section><footer class="vybe-footer">VYBE · Your Campus. Your Community. Your Space.</footer>'''
    return _vybe_public_shell("Welcome",body)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        sid = request.form.get("student_id", "").strip()[:80]
        password = request.form.get("password", "")
        if len(name) < 2 or len(sid) < 2 or len(password) < 10:
            flash("Enter a valid name, unique Student ID and a password of at least 10 characters.")
            return redirect(url_for("register"))
        con = db()
        try:
            password_hash_value = hash_password(password)
            con.execute(
                "INSERT INTO students(name,student_id,password_hash,status,created_at,last_seen) VALUES(?,?,?,?,?,?)",
                (name, sid, password_hash_value, "pending", now(), None),
            )
            con.commit()
            flash("Registration submitted. Your account is pending admin approval.")
        except Exception:
            con.rollback()
            flash("That Student ID is already registered, or could not be saved.")
        finally:
            con.close()
        return redirect(url_for("login"))
    body = '''<div class="auth vybe-auth-page"><div class="card authbox"><a class="vybe-auth-logo" href="/" aria-label="VYBE home">V</a><div class="badge">NEW STUDENT</div><h1>Request access.</h1><p class="muted">Create your student account with your name, unique Student ID and personal password.</p><form class="form" method="post"><div><div class="label">Full name</div><input name="name" required maxlength="80" autocomplete="name" placeholder="Your full name"></div><div><div class="label">Student ID</div><input name="student_id" required maxlength="80" autocomplete="username" placeholder="Your unique Student ID"></div><div><div class="label">Personal password</div><div class="password-wrap"><input id="registerPassword" type="password" name="password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="Create your password"><button type="button" class="password-toggle toggle-password" data-target="registerPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><button class="btn accent" type="submit">Request access →</button></form><p class="small">Already approved? <a href="/login" style="text-decoration:underline">Student login</a></p><div class="vybe-auth-back-row"><a class="vybe-auth-back" href="/">← Back</a><span class="vybe-auth-hint">Your request is reviewed by the VYBE admin.</span></div></div></div>'''
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
        row = con.execute("SELECT id,name,status,password_hash FROM students WHERE student_id=?", (sid,)).fetchone()
        if not row:
            blocked, until, _ = _security_failed_login(con, "Unknown student", sid, "Student")
            con.close()
            if blocked: return _security_block_page(until), 429, {"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"}
            session["student_login_password_error"] = True; flash("Student ID or password is incorrect."); return redirect(url_for("login"))
        if row["status"] == "pending":
            con.close(); flash("Your registration is still pending admin approval."); return redirect(url_for("login"))
        if row["status"] == "blocked":
            con.close(); flash("Your student access is currently blocked."); return redirect(url_for("login"))
        if not check_password(password, row["password_hash"]):
            blocked, until, _ = _security_failed_login(con, row["name"], sid, "Student")
            con.close()
            if blocked: return _security_block_page(until), 429, {"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"}
            session["student_login_password_error"] = True; flash("Student ID or password is incorrect."); return redirect(url_for("login"))
        _security_successful_login(con, "Student", sid)
        stamp = now()
        con.execute("UPDATE students SET last_login=?, last_seen=? WHERE id=?", (stamp, stamp, row["id"])); con.commit(); con.close()
        session.clear(); session.permanent = True; session["student_db_id"] = row["id"]; session["_csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))
    password_error = bool(session.pop("student_login_password_error", False))
    body = f'''<div class="auth vybe-auth-page"><div class="card authbox"><a class="vybe-auth-logo" href="/" aria-label="VYBE home">V</a><div class="badge">STUDENT LOGIN</div><h1>Welcome back.</h1><p class="muted">Sign in with your Student ID and personal password.</p><form class="form" method="post"><div><div class="label">Student ID</div><input name="student_id" required maxlength="80" autocomplete="username" placeholder="Your Student ID"></div><div><div class="label">Password</div><div class="password-wrap{" password-error" if password_error else ""}"><input id="loginPassword" type="password" name="password" required autocomplete="current-password" placeholder="Your password"><button type="button" class="password-toggle toggle-password" data-target="loginPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6 9.5-6 9.5-6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><button class="btn accent" type="submit">Enter VYBE →</button></form><div class="actions"><a class="btn dark" href="/forgot-password">Forgot password?</a></div><p class="small">New student? <a href="/register" style="text-decoration:underline">Request access</a></p><div class="vybe-auth-back-row"><a class="vybe-auth-back" href="/">← Back</a><span class="vybe-auth-hint">Secure campus access for approved students.</span></div></div></div>'''
    return layout("Student Login", body)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Student password-change request flow.

    The password request itself is the source of truth for the admin panel.
    Optional admin notifications are created only AFTER the request has been
    committed, so a notification/WhatsApp/schema problem can never prevent the
    password request from reaching the admin.
    """
    if request.method == "POST":
        sid = request.form.get("student_id", "").strip()[:80]
        name = request.form.get("name", "").strip()[:80]
        if not sid or not name:
            flash("Enter your full name and Student ID.")
            return redirect(url_for("forgot_password"))

        con = db()
        request_id = None
        student = None
        try:
            # Always make sure the actual source-of-truth table exists before
            # doing anything else. This also repairs older Render databases.
            _ensure_password_reset_schema(con)
            con.commit()

            student = con.execute(
                "SELECT id,name,student_id,status FROM students WHERE student_id=?",
                (sid,),
            ).fetchone()

            if not student or student["name"].strip().lower() != name.lower() or str(student["status"]).lower() != "approved":
                # Keep the response generic so account status/existence is not
                # disclosed to an unauthenticated requester. Password recovery
                # is available only to approved student accounts.
                flash("If the account is eligible, the password-change request has been sent to the admin.")
                return redirect(url_for("forgot_password"))

            # Do not create duplicate active requests. If an approved request
            # exists, the same recovery session can continue to reset the password.
            existing = con.execute(
                "SELECT id,status FROM password_reset_requests "
                "WHERE student_id=? AND status IN ('pending','approved') "
                "ORDER BY id DESC LIMIT 1",
                (student["id"],),
            ).fetchone()

            if existing:
                request_id = int(existing["id"])
                session["password_reset_request_id"] = request_id
                if existing["status"] == "approved":
                    flash("Your password-change request is already approved. You can continue to set a new password.")
                else:
                    flash("Your password-change request is already waiting for admin approval.")
                return redirect(url_for("forgot_password"))

            # IMPORTANT: only the password_reset_requests table is written in
            # this transaction. Nothing optional can roll it back.
            con.execute(
                "INSERT INTO password_reset_requests(student_id,status,requested_at) VALUES(?,?,?)",
                (student["id"], "pending", now()),
            )
            request_row = con.execute(
                "SELECT id FROM password_reset_requests "
                "WHERE student_id=? AND status='pending' "
                "ORDER BY id DESC LIMIT 1",
                (student["id"],),
            ).fetchone()
            if not request_row:
                raise RuntimeError("Password reset request was not created")

            request_id = int(request_row["id"])
            con.commit()

        except Exception as exc:
            try:
                con.rollback()
            except Exception:
                pass
            app.logger.exception("PASSWORD RESET REQUEST FAILED: %s", exc)
            flash("We couldn't send the password-change request right now. Please try again in a moment.")
            return redirect(url_for("forgot_password"))
        finally:
            con.close()

        # Store the committed request ID in the student's session.
        session["password_reset_request_id"] = request_id

        # Create the admin alert only AFTER the request is safely committed.
        # This is best-effort and can never cancel the request.
        if student is not None:
            try:
                create_admin_notification(
                    "password_reset",
                    "Password change request",
                    f"{student['name']} ({student['student_id']}) requested access to change their VYBE password.",
                    student_id=student["id"],
                )
            except Exception as exc:
                app.logger.warning("Password reset admin notification failed: %s", exc)

        flash("Request sent successfully. The admin can now see it in Password Access.")
        return redirect(url_for("forgot_password"))

    request_id = session.get("password_reset_request_id")
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
        if row["status"] == "approved" and row["expires_at"]:
            try:
                exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) >= exp:
                    con.execute("UPDATE password_reset_requests SET status='expired' WHERE id=? AND status='approved'", (int(request_id),))
                    con.commit()
                    return jsonify({"status": "expired"})
            except Exception:
                pass
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
        if not row or row["status"] != "approved" or row["student_status"] != "approved":
            flash("Your password-change request has not been approved yet or is no longer active.")
            return redirect(url_for("forgot_password"))
        if row["expires_at"]:
            try:
                exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) >= exp:
                    con.execute("UPDATE password_reset_requests SET status='expired' WHERE id=? AND status='approved'", (row["id"],))
                    con.commit()
                    flash("The password-change approval has expired. Please request access again.")
                    return redirect(url_for("forgot_password"))
            except Exception:
                pass
        if request.method == "POST":
            posted_request_id = request.form.get("request_id", "").strip()
            new_password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if posted_request_id != str(request_id):
                flash("This password-change session is invalid. Please start again.")
                return redirect(url_for("forgot_password"))
            if len(new_password) < 10 or new_password != confirm:
                flash("New passwords must match and be at least 10 characters.")
                return redirect(url_for("forgot_password"))
            con.execute("UPDATE students SET password_hash=? WHERE id=?", (hash_password(new_password), row["student_id"]))
            con.execute("UPDATE password_reset_requests SET status='used', used_at=? WHERE id=?", (now(), row["id"]))
            con.commit()
            session.pop("password_reset_request_id", None)
            flash("Password changed successfully. You can now log in with your new password.")
            return redirect(url_for("login"))
    finally:
        con.close()
    body = """<div class="auth vybe-auth-page"><div class="card authbox"><a class="vybe-auth-logo" href="/" aria-label="VYBE home">V</a><div class="badge">APPROVED RESET</div><h1>Set a new password.</h1><p class="muted">Admin has approved your password-change request. Create your new password below. Your existing password is never visible to the admin.</p><form class="form" method="post"><input type="hidden" name="request_id" value="{rid}"><div><div class="label">New password</div><div class="password-wrap"><input id="resetPassword" type="password" name="password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="New password"><button type="button" class="password-toggle toggle-password" data-target="resetPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><div><div class="label">Confirm new password</div><div class="password-wrap"><input id="resetConfirmPassword" type="password" name="confirm_password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="Confirm new password"><button type="button" class="password-toggle toggle-password" data-target="resetConfirmPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><button class="btn accent" type="submit">Change password</button></form><div class="vybe-auth-back-row"><a class="vybe-auth-back" href="/forgot-password">← Password recovery</a><span class="vybe-auth-hint">Secure password change · admin approved</span></div></div></div>""".format(rid=int(request_id))
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
        if len(new_password) < 10 or new_password != confirm:
            con.close(); flash("New passwords must match and be at least 10 characters."); return redirect(url_for("account_password"))
        con.execute("UPDATE students SET password_hash=? WHERE id=?", (hash_password(new_password), session["student_db_id"]))
        con.commit(); con.close(); flash("Password changed successfully."); return redirect(url_for("dashboard"))
    con.close()
    body='''<div class="auth"><div class="card authbox"><div class="badge">ACCOUNT SECURITY</div><h1>Change password.</h1><p class="muted">Because you are signed in, enter your current password to authorize the change.</p><form class="form" method="post"><div><div class="label">Current password</div><div class="password-wrap"><input id="currentPassword" type="password" name="current_password" required autocomplete="current-password" placeholder="Current password"><button type="button" class="password-toggle toggle-password" data-target="currentPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><div><div class="label">New password</div><div class="password-wrap"><input id="changePassword" type="password" name="new_password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="New password"><button type="button" class="password-toggle toggle-password" data-target="changePassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><div><div class="label">Confirm new password</div><div class="password-wrap"><input id="changeConfirmPassword" type="password" name="confirm_password" required minlength="10" maxlength="128" autocomplete="new-password" placeholder="Confirm new password"><button type="button" class="password-toggle toggle-password" data-target="changeConfirmPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div></div><button class="btn accent" type="submit">Update password →</button></form></div></div>'''
    return layout("Change Password", body)


@app.route("/admin/logout")
def admin_logout():
    # Admin logout is deliberately separate from the student session.
    session.pop("admin_authenticated", None)
    session.pop("passkey_verified", None)
    session.pop("admin_login_area", None)
    session.pop("admin_login_name", None)
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("home"))


def _active_announcements(con, limit=6):
    current=now()
    return con.execute(
        "SELECT * FROM announcements WHERE (publish_at IS NULL OR publish_at='' OR publish_at<=?) AND (expires_at IS NULL OR expires_at='' OR expires_at>?) ORDER BY CASE WHEN priority='High' THEN 0 WHEN priority='Important' THEN 1 ELSE 2 END, id DESC LIMIT ?",
        (current,current,limit)
    ).fetchall()


def _upcoming_events(con, limit=6):
    from zoneinfo import ZoneInfo
    today=datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d")
    return con.execute(
        "SELECT * FROM events WHERE (publish_at IS NULL OR publish_at='' OR publish_at<=?) AND event_date>=? ORDER BY event_date ASC, event_time ASC, id ASC LIMIT ?",
        (now(),today,limit)
    ).fetchall()


def _latest_timetables(con, limit=20):
    return con.execute("SELECT id,title,original_name,created_at,drive_file_id,drive_web_url FROM timetables ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def _decode_pdf_literal(value):
    value=value.replace(b"\\n",b"\n").replace(b"\\r",b"\r").replace(b"\\t",b"\t")
    value=value.replace(b"\\(",b"(").replace(b"\\)",b")").replace(b"\\\\",b"\\")
    def repl(m):
        try: return bytes([int(m.group(1),8)])
        except Exception: return b""
    value=re.sub(rb"\\([0-7]{1,3})",repl,value)
    return value.decode("utf-8","ignore") or value.decode("latin-1","ignore")


def _extract_pdf_text(file_data,max_chars=50000):
    if not file_data or not file_data.startswith(b"%PDF"): return ""
    try:
        import fitz
        doc=fitz.open(stream=file_data,filetype="pdf")
        text="\n".join(page.get_text("text") for page in doc)
        doc.close()
        if text.strip(): return _clean_extracted_text(text,max_chars)
    except Exception: pass
    try:
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(file_data))
        text="\n".join((page.extract_text() or "") for page in reader.pages)
        if text.strip(): return _clean_extracted_text(text,max_chars)
    except Exception: pass
    chunks=[]
    try:
        for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream",file_data,re.S):
            raw=match.group(1); header=file_data[max(0,match.start()-1600):match.start()]
            if b"/FlateDecode" in header:
                try: raw=zlib.decompress(raw)
                except Exception: continue
            text=raw.decode("latin-1","ignore")
            for block in re.findall(r"BT(.*?)ET",text,re.S):
                strings=[_decode_pdf_literal(x[1:-1].encode("latin-1","ignore")) for x in re.findall(r"\((?:\\.|[^\\)])*\)",block)]
                for arr in re.findall(r"\[(.*?)\]\s*TJ",block,re.S):
                    strings += [_decode_pdf_literal(x[1:-1].encode("latin-1","ignore")) for x in re.findall(r"\((?:\\.|[^\\)])*\)",arr)]
                if strings: chunks.append(" ".join(x for x in strings if x.strip()))
                if sum(map(len,chunks))>=max_chars: break
            if sum(map(len,chunks))>=max_chars: break
    except Exception: return ""
    return _clean_extracted_text(" ".join(chunks),max_chars)


def _clean_extracted_text(value, max_chars=50000):
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", value or "")
    value = re.sub(r"\s+", " ", value).strip()
    return value[:max_chars]


def _extract_zip_xml_text(file_data,suffix,max_chars=50000):
    """Extract text from modern Office/OpenDocument ZIP containers."""
    if not file_data or suffix not in (".docx",".pptx",".xlsx",".odt",".odp",".zip"):
        return ""
    try:
        with zipfile.ZipFile(io.BytesIO(file_data)) as z:
            infos=z.infolist()
            if len(infos) > 500:
                return ""
            names=[i.filename for i in infos]
            if suffix==".docx":
                targets=[n for n in names if n.startswith("word/") and n.endswith(".xml")]
            elif suffix==".pptx":
                targets=[n for n in names if re.match(r"ppt/slides/slide\d+\.xml$",n)]
            elif suffix==".xlsx":
                targets=[n for n in names if (n.startswith("xl/sharedStrings") and n.endswith(".xml")) or re.match(r"xl/worksheets/sheet\d+\.xml$",n)]
            elif suffix in (".odt",".odp"):
                targets=["content.xml"] if "content.xml" in names else []
            else:
                targets=[n for n in names if not n.endswith("/") and n.lower().endswith((".txt",".csv",".md",".html",".htm",".xml",".json"))]
            parts=[]
            total_uncompressed=0
            for name in targets[:500]:
                try:
                    info=z.getinfo(name)
                    if info.file_size > 2 * 1024 * 1024 or total_uncompressed + info.file_size > 8 * 1024 * 1024:
                        continue
                    raw=z.read(name)
                    total_uncompressed += len(raw)
                    if name.lower().endswith((".txt",".csv",".md",".html",".htm",".json")):
                        parts.append(raw.decode("utf-8","ignore"))
                    else:
                        root=ET.fromstring(raw)
                        vals=[t.text for t in root.iter() if t.text and t.text.strip()]
                        if vals: parts.append(" ".join(vals))
                except Exception:
                    pass
                if sum(len(x) for x in parts)>=max_chars: break
            return _clean_extracted_text("\n".join(parts),max_chars)
    except Exception:
        return ""


def _extract_legacy_binary_text(file_data,max_chars=50000):
    """Best-effort text extraction for legacy .doc/.ppt files."""
    chunks=[]
    try:
        decoded=file_data.decode("utf-16le","ignore")
        chunks.extend(re.findall(r'[A-Za-z0-9][A-Za-z0-9 ,.;:!?()/"\'&@#%+\\\-_=]{3,}',decoded))
    except Exception:
        pass
    try:
        decoded=file_data.decode("latin-1","ignore")
        chunks.extend(re.findall(r'[A-Za-z][A-Za-z0-9 ,.;:!?()/"\'&@#%+\\\-_=]{4,}',decoded))
    except Exception:
        pass
    out=[]; seen=set()
    for x in chunks:
        x=re.sub(r"\s+"," ",x).strip()
        if len(x)<4 or x.lower() in seen: continue
        seen.add(x.lower()); out.append(x)
    return _clean_extracted_text(" ".join(out),max_chars)


def _extract_doc_text(file_data,suffix,max_chars=50000):
    if not file_data: return ""
    suffix=(suffix or "").lower()
    if suffix==".pdf": return _extract_pdf_text(file_data,max_chars)
    if suffix in (".png",".jpg",".jpeg",".webp"): return _extract_image_text(file_data,max_chars)
    if suffix in (".docx",".pptx",".xlsx",".odt",".odp",".zip"): return _extract_zip_xml_text(file_data,suffix,max_chars)
    if suffix in (".txt",".csv",".md",".rtf",".json",".xml",".html",".htm",".log",".yaml",".yml"):
        return _clean_extracted_text(file_data.decode("utf-8","ignore"),max_chars)
    if suffix in (".doc",".ppt"):
        return _extract_legacy_binary_text(file_data,max_chars)
    return ""



def _timetable_text(file_data,suffix,browser_text=""):
    browser_text=re.sub(r"\s+"," ",browser_text or "").strip()[:50000]
    return browser_text or _extract_doc_text(file_data,suffix,50000)


def _resource_ocr_script(form_id,file_id,text_id,status_id):
    return rf'''<script src="https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js"></script>
<script>(function(){{const form=document.getElementById({form_id!r}),file=document.getElementById({file_id!r}),hidden=document.getElementById({text_id!r}),status=document.getElementById({status_id!r});if(!form||!file||!hidden)return;form.addEventListener('submit',async function(e){{const f=file.files&&file.files[0];if(!f)return;const ext=(f.name.split('.').pop()||'').toLowerCase();if(!['png','jpg','jpeg','webp'].includes(ext)||hidden.value.trim())return;e.preventDefault();if(status)status.textContent='Reading file for Ask VYBE… please wait.';try{{const result=await Tesseract.recognize(f,'eng',{{logger:function(m){{if(status&&m.status)status.textContent='Reading file… '+Math.round((m.progress||0)*100)+'%';}}}});hidden.value=(result.data.text||'').trim().slice(0,50000);if(status)status.textContent=hidden.value?'File text captured for Ask VYBE.':'No readable text found; the file was still uploaded.';form.submit();}}catch(err){{if(status)status.textContent='Could not read image text; the file will still be uploaded.';form.submit();}}}});}})();</script>'''


def _timetable_ocr_script(form_id,file_id,text_id,status_id):
    return _resource_ocr_script(form_id,file_id,text_id,status_id)

def _assistant_query_tokens(question):
    q = re.sub(r"\s+", " ", (question or "").lower()).strip()
    # Common words which do not help locate a fact in a college document.
    stop = {
        "what","when","where","which","who","why","how","does","did","are","the",
        "and","for","from","with","about","please","tell","show","give","can","you",
        "our","this","that","have","has","into","there","their","your","student","students",
        "vybe","assistant","tell","me","is","of","to","in","on","a","an","do","i","my"
    }
    aliases = {
        "bsc":"b.sc", "bachelor":"b.sc", "computer":"computer", "cs":"computer science",
        "sem":"semester", "sem1":"semester 1", "semester1":"semester 1", "sem2":"semester 2", "semester2":"semester 2",
        "eligibility":"eligibility", "eligible":"eligibility", "qualification":"eligibility",
        "fee":"fees", "fees":"fees", "admission":"admission", "apply":"admission",
        "teacher":"faculty", "teachers":"faculty", "professor":"faculty", "prof":"faculty",
        "sir":"faculty", "mam":"faculty", "maam":"faculty", "instructor":"faculty",
    }
    raw = re.findall(r"[a-z0-9.]+", q)
    expanded=[]
    for w in raw:
        if w in stop: continue
        w=aliases.get(w,w)
        for part in re.findall(r"[a-z0-9]+", w):
            if len(part)>=2 and part not in stop:
                expanded.append(part)
    # Preserve useful multi-word phrases as well as individual terms.
    phrases=[]
    for phrase in ("semester 1","semester 2","semester 3","semester 4","semester 5","semester 6","semester 7","semester 8",
                   "computer science","minor in entrepreneurship","object oriented programming using python",
                   "admission link","online admission","class 12","class xii"):
        if phrase in q: phrases.append(phrase)
    return q, list(dict.fromkeys(expanded))[:24], phrases


def _assistant_knowledge_rows(con, question, limit=8):
    """Rank knowledge by exact phrases, title/heading matches and term coverage."""
    q,tokens,phrases = _assistant_query_tokens(question)
    rows=con.execute("SELECT id,title,description,original_name,content,source_type,created_at,updated_at FROM assistant_knowledge ORDER BY id DESC LIMIT 100").fetchall()
    scored=[]
    for r in rows:
        title=(r["title"] or "").lower()
        desc=(r["description"] or "").lower()
        name=(r["original_name"] or "").lower()
        content=(r["content"] or "").lower()
        hay=title+" "+desc+" "+name+" "+content
        score=0
        for phrase in phrases:
            if phrase in hay: score += 18
        for t in tokens:
            if re.search(r"\b"+re.escape(t)+r"\b", title): score += 10
            elif re.search(r"\b"+re.escape(t)+r"\b", desc): score += 5
            elif re.search(r"\b"+re.escape(t)+r"\b", hay): score += 2
        if not tokens and r["source_type"]=="note": score=1
        if score: scored.append((score,int(r["id"]),r))
    scored.sort(key=lambda x:(x[0],x[1]), reverse=True)
    return [x[2] for x in scored[:limit]]


def _assistant_make_chunks(content):
    """Split a source into heading-aware chunks instead of isolated sentences."""
    text=re.sub(r"\r\n?", "\n", content or "").strip()
    if not text: return []
    lines=text.split("\n")
    chunks=[]; heading=[]; buf=[]
    heading_re=re.compile(r"^(?:#{1,6}\s+|(?:I|II|III|IV)\s+Year\b|Semester\s+[1-8]\b|[A-Z][A-Za-z0-9 &(),.'’:/\-]{2,80}:\s*$)", re.I)
    def flush():
        nonlocal buf
        if buf:
            body="\n".join(buf).strip()
            if len(body)>=25: chunks.append((" > ".join(heading[-3:]),body))
            buf=[]
    for line in lines:
        clean=line.strip()
        if not clean:
            if buf: flush()
            continue
        if heading_re.match(clean) and len(clean)<130:
            flush()
            h=re.sub(r"^#+\s*", "", clean).strip()
            if h.endswith(":"): h=h[:-1]
            heading.append(h)
            heading=heading[-4:]
            continue
        buf.append(clean)
        if len(" ".join(buf))>=1200: flush()
    flush()
    # Also make short line-level units available for timetable/OCR style sources.
    if len(chunks)<4:
        units=[]
        for line in lines:
            line=re.sub(r"\s+"," ",line).strip(" -•\t")
            if len(line)>=20: units.append(("",line))
        chunks.extend(units[:300])
    return chunks


def _clean_answer_text(text, limit=500):
    text=re.sub(r"\[[^\]]*\]", "", text or "")
    text=re.sub(r"\s+", " ", text).strip(" -•\t")
    return text[:limit].rstrip(" .")


def _question_intent(q):
    q=re.sub(r"\s+", " ", (q or "").lower()).strip()
    if any(x in q for x in ("eligibility", "eligible", "qualification", "qualify", "criteria", "requirements to apply")):
        return "eligibility"
    if any(x in q for x in ("admission link", "apply link", "application link", "where do i apply", "how do i apply", "admission website")):
        return "admission"
    m=re.search(r"(?:semester|sem)\s*[- ]?([1-8])\b", q)
    if m and any(x in q for x in ("subject", "subjects", "course", "courses", "paper", "papers", "study", "syllabus")):
        return "semester_subjects_"+m.group(1)
    if any(x in q for x in ("subjects in semester", "courses in semester", "what do i study in semester", "semester subjects")):
        return "semester_subjects"
    if any(x in q for x in ("who teaches", "teacher", "teachers", "faculty", "professor", "instructor")):
        return "faculty"
    if any(x in q for x in ("fee", "fees", "tuition", "cost of admission")):
        return "fees"
    if any(x in q for x in ("duration", "how many years", "years is", "course length")):
        return "duration"
    if any(x in q for x in ("degree", "course name", "program name", "programme name")):
        return "course_name"
    return "general"


def _find_source_passages(rows, question, max_chunks=30):
    q,tokens,phrases=_assistant_query_tokens(question)
    candidates=[]
    for r in rows:
        content=(r["content"] or "").strip()
        if not content: continue
        title=(r["title"] or r["original_name"] or "VYBE knowledge")
        for heading,unit in _assistant_make_chunks(content):
            low=(heading+" "+unit).lower()
            score=0
            matched=0
            for phrase in phrases:
                if phrase in low: score += 24
            for t in tokens:
                if re.search(r"\b"+re.escape(t)+r"\b", low):
                    matched += 1; score += 5
            if q and q in low: score += 40
            if tokens and matched:
                score += int(30*matched/max(1,len(tokens)))
            if score:
                candidates.append((score,matched,int(r["id"]),title,heading,unit))
    candidates.sort(key=lambda x:(x[0],x[1],x[2]), reverse=True)
    return candidates[:max_chunks]


def _assistant_knowledge_answer(con, question):
    """Answer the question, not the document.

    The assistant intentionally returns a tiny fact/list extracted from the
    strongest source section. It does not echo long source passages.
    """
    q=re.sub(r"\s+", " ", (question or "").lower()).strip()
    if not q: return ""

    # Do not guess when the question depends on missing conversation context.
    # For example, "what is his name?" has no identifiable person in the
    # question/source, so returning the first name found in a document is wrong.
    vague_referent = re.search(r"\b(his|her|their|this|that|he|she|they)\b", q)
    bare_name_question = bool(re.search(r"\b(what is|what's|tell me)\s+(his|her|their)\s+name\b", q))
    if bare_name_question or (vague_referent and len(re.findall(r"[a-z0-9]+", q)) <= 8):
        return "I need the person or subject you mean. Please mention their name, role, or the message you are referring to."

    rows=_assistant_knowledge_rows(con, question, limit=20)
    if not rows: return ""
    intent=_question_intent(q)
    candidates=_find_source_passages(rows, question, 60)
    if not candidates: return ""

    # Semester subject questions: collect the actual course rows from the
    # requested semester instead of returning prospectus prose.
    if intent.startswith("semester_subjects"):
        sem=intent.split("_")[-1] if intent[-1].isdigit() else None
        hits=[]
        for _,_,_,_,heading,unit in candidates:
            low=(heading+" "+unit).lower()
            if sem and not re.search(r"(?:semester|sem)\s*[- ]?"+sem+r"\b", low):
                continue
            for line in re.split(r"\n|(?<=\.)\s+(?=[A-Z])", unit):
                line=_clean_answer_text(line, 260)
                if not line: continue
                if re.search(r"\b(?:DSC|GE|AEC|SEC|VAC|DSE)\b", line, re.I) or "credits" in line.lower():
                    if line not in hits: hits.append(line)
        if hits:
            return " Semester "+sem+" subjects:\n"+"\n".join("• "+x for x in hits[:10])

    if intent=="eligibility":
        hits=[]
        for score,_,_,_,heading,unit in candidates:
            if "eligib" not in (heading+" "+unit).lower(): continue
            # Prefer the sentence(s) containing eligibility/subject requirements.
            for sent in re.split(r"(?<=[.!?])\s+|\n", unit):
                sent=_clean_answer_text(sent, 420)
                if sent and ("eligib" in sent.lower() or "mathematics" in sent.lower() or "recognized board" in sent.lower()):
                    if sent not in hits: hits.append(sent)
        if hits:
            return " Eligibility:\n"+"\n".join("• "+x for x in hits[:2])

    if intent=="admission":
        for _,_,_,_,_,unit in candidates:
            urls=re.findall(r"https?://[^\s)]+", unit)
            if urls:
                return " Admission link: "+urls[0].rstrip(".,")
        for _,_,_,_,_,unit in candidates:
            if "admission" in unit.lower():
                sent=next((_clean_answer_text(x,350) for x in re.split(r"\n|(?<=[.!?])\s+",unit) if "admission" in x.lower()),"")
                if sent: return " Admission: "+sent

    if intent=="faculty":
        hits=[]
        for _,_,_,_,_,unit in candidates:
            for line in unit.splitlines():
                line=_clean_answer_text(line,220)
                if line and re.search(r"\b(?:Ms|Mr|Dr|Prof|Professor)\.?\s+[A-Z]", line):
                    if line not in hits: hits.append(line)
        if hits:
            return "‍ Faculty:\n"+"\n".join("• "+x for x in hits[:8])

    if intent=="duration":
        for _,_,_,_,_,unit in candidates:
            for sent in re.split(r"\n|(?<=[.!?])\s+",unit):
                if re.search(r"\b(?:four|4)\s*(?:years|year)\b",sent,re.I):
                    return "WAIT Duration: "+_clean_answer_text(sent,250)+"."

    # General questions: only answer when there is strong evidence that the
    # selected passage actually addresses the question. Otherwise say that the
    # source does not contain a supported answer instead of returning an
    # unrelated sentence.
    best=candidates[0]
    if best[0] < 12 or best[1] < 1:
        return "I couldn't find a specific answer to that in the VYBE knowledge."
    unit=best[5]
    sentences=[_clean_answer_text(x,360) for x in re.split(r"\n|(?<=[.!?])\s+",unit)]
    sentences=[x for x in sentences if x]
    if sentences:
        # Choose the sentence with the most question-term coverage.
        _,tokens,_=_assistant_query_tokens(question)
        scored=[]
        for sent in sentences:
            low=sent.lower(); cov=sum(bool(re.search(r"\b"+re.escape(t)+r"\b",low)) for t in tokens)
            scored.append((cov,-len(sent),sent))
        scored.sort(reverse=True)
        return " "+scored[0][2]+("." if not scored[0][2].endswith(('.', '?', '!')) else "")
    return ""


def _ai_extract_text(data):
    """Extract plain answer text from common OpenAI-compatible API responses."""
    if not isinstance(data, dict):
        return ""

    # OpenAI Responses API commonly exposes output_text.
    text = data.get("output_text")
    if isinstance(text, str) and text.strip():
        return text.strip()

    # Responses API fallback: output -> message -> content -> output_text/text.
    parts = []
    for item in data.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue
            value = content.get("text")
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, dict) and isinstance(value.get("value"), str):
                parts.append(value["value"])
    if parts:
        return "\n".join(parts).strip()

    # Chat Completions-compatible fallback.
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        choice = choices[0] or {}
        message = choice.get("message") or {}
        content = message.get("content")
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            if parts:
                return "\n".join(parts).strip()
    return ""


def _build_ai_vybe_context(con, question):
    """Build compact VYBE-specific context for the external AI."""
    blocks = []

    # Uploaded Assistant knowledge is the primary source for college facts.
    try:
        rows = _assistant_knowledge_rows(con, question, limit=12)
        candidates = _find_source_passages(rows, question, max_chunks=12)
        for score, matched, rid, title, heading, unit in candidates:
            if not unit:
                continue
            block = f"[VYBE KNOWLEDGE — {title}]"
            if heading:
                block += f" ({heading})"
            block += f"\n{unit[:1800]}"
            blocks.append(block)
    except Exception as exc:
        app.logger.warning("AI knowledge context unavailable: %s: %s", type(exc).__name__, exc)

    # Live VYBE data: announcements, events, resources, issues, timetables.
    try:
        for item in _campus_search(con, question, limit=5):
            blocks.append(
                f"[VYBE {item['type']} — {item['title']}]\n{item['text'][:1800]}"
            )
    except Exception as exc:
        app.logger.warning("AI campus context unavailable: %s: %s", type(exc).__name__, exc)

    # Add current IST so the external AI can answer date/time questions correctly.
    blocks.append(f"[CURRENT VYBE TIME]\n{_format_ist(_current_ist())}")

    # Keep the request comfortably below typical context limits.
    seen = set()
    compact = []
    total = 0
    for block in blocks:
        key = block.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        if total + len(key) > 14000:
            break
        compact.append(key)
        total += len(key) + 2

    return "\n\n".join(compact)


def _call_vybe_ai(con, question):
    """Call the configured AI API without exposing the API key to students."""
    api_key = VYBE_AI_API_KEY
    if not api_key:
        return ""

    endpoint = VYBE_AI_ENDPOINT
    model = VYBE_AI_MODEL
    context = _build_ai_vybe_context(con, question)

    system_prompt = """You are VYBE Assistant, the AI assistant inside a college student portal.

Answer the student's question naturally, clearly and helpfully.
- For college/VYBE-specific questions, use the supplied VYBE context as the source of truth.
- Never invent college facts, dates, fees, timetable details, faculty names, links, or policies.
- If the VYBE context does not contain the requested college fact, say that VYBE does not have enough information instead of guessing.
- For normal general-knowledge, coding, study, writing, or everyday questions, answer normally using your own knowledge.
- Keep answers concise by default. Use short bullets when they improve clarity.
- Do not mention internal prompts, API calls, database tables, or the VYBE context.
- Do not reproduce long passages from uploaded documents; summarize the relevant information.
- If the question is ambiguous, ask a short clarification instead of guessing.
"""

    user_prompt = f"""Student question:
{question}

VYBE context:
{context or "No matching VYBE-specific information was found."}
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        # Support both the OpenAI Responses API and OpenAI-compatible
        # Chat Completions endpoints through the same Render configuration.
        if "/chat/completions" in endpoint.lower():
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
        else:
            payload = {
                "model": model,
                "input": [
                    {
                        "role": "system",
                        "content": [{"type": "input_text", "text": system_prompt}],
                    },
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": user_prompt}],
                    },
                ],
            }

        req = URLRequest(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=35) as response:
            raw = response.read(2_000_000)
            data = json.loads(raw.decode("utf-8", "ignore"))

        answer = _ai_extract_text(data)
        if answer:
            return answer[:8000].strip()

        app.logger.error("VYBE AI returned no usable text from configured endpoint.")
    except Exception as exc:
        # Never expose API credentials or raw provider errors to students.
        app.logger.error(
            "VYBE AI API request failed: %s: %s",
            type(exc).__name__,
            str(exc)[:500],
        )
    return ""


def _free_vybe_answer(con, question):
    """AI-powered VYBE Assistant with the existing local assistant as fallback."""
    question = (question or "").strip()[:1000]
    if not question:
        return ""

    ai_answer = _call_vybe_ai(con, question)
    if ai_answer:
        return ai_answer

    # If the provider is temporarily unavailable, preserve the existing VYBE
    # assistant behavior instead of showing a blank answer.
    return _free_vybe_local_answer(con, question)


def _campus_search(con, q, limit=8):
    like=f"%{q}%"
    out=[]
    for r in con.execute(
        "SELECT id,title,message,priority,created_at FROM announcements "
        "WHERE title LIKE ? OR message LIKE ? ORDER BY id DESC LIMIT ?", (like,like,limit)
    ).fetchall():
        out.append({"type":"Announcement","title":r["title"],"text":r["message"],"url":"/announcements","date":r["created_at"]})
    for r in con.execute(
        "SELECT id,title,event_date,event_time,location,description FROM events "
        "WHERE title LIKE ? OR description LIKE ? OR location LIKE ? ORDER BY event_date ASC LIMIT ?",
        (like,like,like,limit)
    ).fetchall():
        out.append({"type":"Event","title":r["title"],"text":f'{r["event_date"]} {r["event_time"]} · {r["location"]} · {r["description"]}',"url":"/events","date":r["event_date"]})
    for r in con.execute(
        "SELECT id,title,description,status,created_at FROM issues "
        "WHERE title LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ?", (like,like,limit)
    ).fetchall():
        out.append({"type":"Community","title":r["title"],"text":f'{r["status"]} · {r["description"]}',"url":"/community#problem-"+str(r["id"]),"date":r["created_at"]})
    for r in con.execute(
        "SELECT id,title,original_name,assistant_text,created_at FROM timetables WHERE title LIKE ? OR original_name LIKE ? OR assistant_text LIKE ? ORDER BY id DESC LIMIT ?",
        (like,like,like,limit)
    ).fetchall():
        out.append({"type":"Timetable","title":r["title"],"text":(r["assistant_text"] or r["original_name"])[:1500],"url":"/timetable","date":r["created_at"]})
    for r in con.execute(
        "SELECT id,title,course,semester,subject,description,assistant_text FROM resources "
        "WHERE title LIKE ? OR course LIKE ? OR subject LIKE ? OR description LIKE ? OR assistant_text LIKE ? ORDER BY id DESC LIMIT ?",
        (like,like,like,like,like,limit)
    ).fetchall():
        content=(r["assistant_text"] or "").strip()
        meta=f'{r["course"]} · {r["semester"]} · {r["subject"]} · {r["description"]}'
        out.append({"type":"Resource","title":r["title"],"text":(meta + ((" · "+content) if content else ""))[:3000],"url":"/academics?q="+q,"date":""})
    return out[:limit*4]




def _current_ist():
    from zoneinfo import ZoneInfo
    return datetime.now(ZoneInfo("Asia/Kolkata"))


def _format_ist(dt):
    return dt.strftime("%A, %d %B %Y at %I:%M %p IST")


def _free_vybe_local_answer(con, question):
    """Free, deterministic VYBE assistant: no external AI/API is required."""
    q = re.sub(r"\s+", " ", question.lower()).strip()
    ist = _current_ist()
    timetable_words = ("timetable", "time table", "class schedule", "class timing", "period", "lecture", "which class", "which room", "what class", "class at", "class tomorrow", "teacher", "teachers", "faculty", "professor", "prof", "instructor", "who teaches", "teacher name", "faculty name")

    if any(x in q for x in timetable_words):
        rows=con.execute("SELECT id,title,original_name,file_data,assistant_text,created_at FROM timetables ORDER BY id DESC LIMIT 8").fetchall()
        if not rows: return " No timetable has been uploaded to VYBE yet."
        terms=[w for w in re.findall(r"[a-z0-9]+",q) if len(w)>2 and w not in {"timetable","table","class","schedule","what","which","room","timing","period","lecture","tomorrow","today"}]
        matches=[]
        for r in rows:
            if not (r["assistant_text"] or "").strip() and r["file_data"]:
                extracted=_extract_doc_text(bytes(r["file_data"]),Path(r["original_name"] or "").suffix.lower(),50000)
                if extracted:
                    try: con.execute("UPDATE timetables SET assistant_text=? WHERE id=?",(extracted,r["id"])); r["assistant_text"]=extracted
                    except Exception: pass
            hay=(r["title"]+" "+(r["assistant_text"] or "")).lower()
            if not terms or all(t in hay for t in terms[:4]): matches.append(r)
        matches=matches or rows[:3]
        teacher_intent=any(x in q for x in ("teacher","teachers","faculty","professor","prof","instructor","who teaches","teacher name","faculty name","sir","mam","ma'am"))
        lines=[" Timetable information from VYBE:", "[[TIMETABLE_IDS:" + ",".join(str(int(r["id"])) for r in matches[:3]) + "]]" ]
        for r in matches[:3]:
            text=(r["assistant_text"] or "").strip()
            if teacher_intent and text:
                teacher_lines=[]
                for line in re.split(r"[\n|]+",text):
                    if re.search(r"\b(teacher|faculty|professor|prof|instructor|sir|mam|ma'am)\b",line,re.I): teacher_lines.append(line.strip())
                if teacher_lines: text="\n".join(teacher_lines[:12])
            lines.append(f"• {r['title']}: {text[:2200] if text else 'The timetable file is available in Timetable, but no readable text was extracted from this upload.'}")
        try: con.commit()
        except Exception: pass
        return "\n".join(lines)

    if any(x in q for x in ("what time", "current time", "time now", "time is it", "what's the time", "whats the time")):
        return f" The current VYBE time is {_format_ist(ist)}."
    if any(x in q for x in ("today's date", "todays date", "current date", "what date", "what day is it", "today date")):
        return f" Today is {_format_ist(ist)}."

    if any(x in q for x in ("announcement", "announcements", "latest update", "new update", "new updates", "campus update", "campus news", "what's new", "whats new")):
        rows = _active_announcements(con, 8)
        if not rows:
            return " There are no active campus announcements right now."
        lines = [" Latest VYBE announcements:"]
        for r in rows[:5]:
            lines.append(f"• {r['title']} — {r['message']}")
        return "\n".join(lines)

    if any(x in q for x in ("event", "events", "happening", "schedule", "program", "programs", "this week", "upcoming")):
        rows = _upcoming_events(con, 8)
        if not rows:
            return " There are no upcoming events listed in VYBE right now."
        lines = [" Upcoming VYBE events:"]
        for r in rows[:5]:
            lines.append(f"• {r['title']} — {r['event_date']} · {r['event_time'] or 'Time TBA'} · {r['location'] or 'Location TBA'}")
        return "\n".join(lines)

    knowledge_answer=_assistant_knowledge_answer(con,question)
    if knowledge_answer:
        return knowledge_answer

    resource_words = ("note", "notes", "pyq", "pyqs", "assignment", "assignments", "study material", "syllabus", "file", "files", "resource", "resources", "document", "documents", "pdf", "word", "ppt", "slide", "where is", "where are", "find", "read", "contains", "written")
    if any(x in q for x in resource_words):
        search_terms=[w for w in re.findall(r"[a-z0-9]+",q) if len(w)>2 and w not in {"where","what","are","the","for","from","find","file","files","notes","note","resource","resources","please","show","give","me","read","written","contains","document","documents","pdf","word","ppt","slide"}]
        rows=[]
        if search_terms:
            clauses=[]; params=[]
            for t in search_terms[:6]:
                like=f"%{t}%"; clauses.append("(title LIKE ? OR course LIKE ? OR semester LIKE ? OR subject LIKE ? OR description LIKE ? OR assistant_text LIKE ?)"); params.extend([like]*6)
            rows=con.execute("SELECT id,title,resource_type,course,semester,subject,description,file_name,original_name,file_data,assistant_text FROM resources WHERE "+" AND ".join(clauses)+" ORDER BY id DESC LIMIT 8",params).fetchall()
        if not rows:
            rows=con.execute("SELECT id,title,resource_type,course,semester,subject,description,file_name,original_name,file_data,assistant_text FROM resources ORDER BY id DESC LIMIT 8").fetchall()
        if not rows:
            drive=setting(con,"google_drive_url",DRIVE_URL)
            return f" I couldn't find a VYBE resource yet. Check Academics or the shared Google Drive: {drive}"
        lines=[" I found these VYBE files/resources:"]
        for r in rows[:5]:
            content=(r["assistant_text"] or "").strip()
            if not content and r["file_data"]:
                extracted=_extract_doc_text(bytes(r["file_data"]),Path(r["original_name"] or r["file_name"] or "").suffix.lower(),50000)
                if extracted:
                    content=extracted
                    try: con.execute("UPDATE resources SET assistant_text=? WHERE id=?",(content,r["id"]))
                    except Exception: pass
            if content:
                snippet=content[:1800]; low=content.lower()
                for t in search_terms[:6]:
                    pos=low.find(t)
                    if pos>=0:
                        snippet=content[max(0,pos-220):min(len(content),pos+1100)]; break
                lines.append(f"• {r['title']} ({r['resource_type']}) — {snippet}")
            else:
                lines.append(f"• {r['title']} ({r['resource_type']}) — uploaded as {r['original_name'] or r['file_name'] or 'resource'}, but no readable text was extracted yet.")
        return "\n".join(lines)

    results = _campus_search(con, question, 8)
    if results:
        return " I found this in VYBE:\n" + "\n".join(f"• {x['title']} — {x['text']}" for x in results[:5])
    return "I couldn't find a verified answer in VYBE's campus data yet. Ask the admin to upload the relevant timetable/resource or add the information to VYBE."

@app.route("/chat")
@student_required
def chat_alias():
    # Keep the legacy /chat URL, but open the Community chooser first.
    return redirect(url_for("community"))


@app.route("/student/notifications", methods=["GET"])
@student_required
def student_notifications():
    con = db()
    try:
        my_id = session["student_db_id"]
        try:
            rows = con.execute(
                "SELECT sn.id, sn.reply_message_id, sn.title, sn.message, sn.created_at, sn.read_at, s.name AS sender_name "
                "FROM student_notifications sn LEFT JOIN students s ON s.id=sn.sender_student_id "
                "WHERE sn.recipient_student_id=? ORDER BY sn.id DESC LIMIT 20",
                (my_id,),
            ).fetchall()
        except Exception:
            # Notification storage is optional. Keep the bell empty if an older
            # deployment has not completed the migration yet.
            try: con.rollback()
            except Exception: pass
            return jsonify({"unread": 0, "notifications": []})
        unread = sum(1 for r in rows if not r["read_at"])
        return jsonify({"unread": unread, "notifications": [{
            "id": int(r["id"]),
            "reply_message_id": int(r["reply_message_id"]) if r["reply_message_id"] else None,
            "title": r["title"],
            "message": r["message"],
            "created_at": r["created_at"],
            "read": bool(r["read_at"]),
            "sender_name": r["sender_name"] or "Student",
        } for r in rows]})
    finally:
        con.close()


@app.route("/student/notifications/read", methods=["POST"])
@student_required
def student_notifications_read():
    con = db()
    try:
        my_id = session["student_db_id"]
        nid = request.form.get("notification_id", "").strip()
        if nid:
            try:
                con.execute("UPDATE student_notifications SET read_at=? WHERE id=? AND recipient_student_id=?", (now(), int(nid), my_id))
            except (TypeError, ValueError):
                pass
        else:
            con.execute("UPDATE student_notifications SET read_at=? WHERE recipient_student_id=? AND read_at IS NULL", (now(), my_id))
        con.commit()
        return jsonify({"ok": True})
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        # Notifications are optional; a missing/older notification table must
        # never break the student's chat or navigation.
        return jsonify({"ok": False})
    finally:
        con.close()


@app.route("/announcements")
@student_required
def announcements():
    con=db(); rows=_active_announcements(con,30); _mark_all_page_items_seen(con,session["student_db_id"],"announcement","announcements"); con.commit(); con.close()
    cards=""
    for r in rows:
        badge=" "+esc(r["priority"]) if r["priority"] in ("High","Important") else " Announcement"
        cards += f'''<div class="card notice-card"><div class="badge">{badge}</div><h2>{esc(r["title"])}</h2><p class="muted" style="white-space:pre-wrap">{esc(r["message"])}</p><div class="small">{esc(r["created_at"])}</div></div>'''
    body=f'''<section class="section"><div class="badge">CAMPUS UPDATES</div><h1>Announcements.</h1><p class="muted">Important campus information, in one place.</p></section><section class="section" style="display:grid;gap:14px">{cards or '<div class="empty">No active announcements.</div>'}</section>'''
    return layout("Announcements",body)


@app.route("/events")
@student_required
def events():
    con=db(); rows=_upcoming_events(con,30); _mark_all_page_items_seen(con,session["student_db_id"],"event","events"); con.commit(); con.close()
    cards=""
    for r in rows:
        cards += f'''<div class="card"><div class="badge"> EVENT</div><div class="event-date">{esc(r["event_date"])}</div><h2>{esc(r["title"])}</h2><p class="small"> {esc(r["event_time"] or "Time TBA")} ·  {esc(r["location"] or "Location TBA")}</p>{(f'<p><a class="btn" href="{esc(r["location_url"])}" target="_blank" rel="noopener">Open location in Google Maps ↗</a></p>' if r["location_url"] else "")}<p class="muted" style="white-space:pre-wrap">{esc(r["description"])}</p></div>'''
    body=f'''<section class="section"><div class="badge">CAMPUS EVENTS</div><h1>What's happening.</h1><p class="muted">Upcoming events and activities around campus.</p></section><section class="section grid">{cards or '<div class="empty">No upcoming events.</div>'}</section>'''
    return layout("Events",body)


TIMETABLE_PAGE_CSS = """<style>
.page-timetable .timetable-head{max-width:1180px;margin:0 auto;padding:30px 0 18px}.page-timetable .timetable-head .badge{background:#edf4ff;color:#2f6fca;border-color:#d7e4f7}.page-timetable .timetable-head h1{font-size:clamp(38px,5vw,62px);line-height:1;letter-spacing:-.055em;margin:15px 0 9px;color:#17202b}.page-timetable .timetable-head .muted{max-width:700px;font-size:14px;line-height:1.6}.page-timetable .timetable-list{max-width:1180px;margin:0 auto;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.page-timetable .timetable-card{position:relative;display:flex;flex-direction:column;min-width:0;padding:0;border:1px solid #dfe5ea;border-radius:24px;background:#fff;overflow:hidden;text-decoration:none;color:#17202b;box-shadow:0 10px 30px rgba(31,48,66,.065);transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease}.page-timetable .timetable-card:hover{transform:translateY(-5px);border-color:#bfd5ec;box-shadow:0 20px 44px rgba(31,48,66,.12)}.page-timetable .timetable-card:focus-visible{outline:3px solid rgba(47,111,202,.22);outline-offset:3px}.page-timetable .timetable-card-head{display:flex;align-items:flex-start;gap:14px;padding:19px 20px 14px}.page-timetable .timetable-icon{width:46px;height:46px;flex:0 0 46px;display:grid;place-items:center;border-radius:15px;background:linear-gradient(145deg,#e9f2ff,#f2f8ff);border:1px solid #d5e5f7;color:#2f6fca;font-weight:900;font-size:17px}.page-timetable .timetable-title-wrap{min-width:0;flex:1}.page-timetable .timetable-title-wrap h2{margin:6px 0 4px;font-size:20px;line-height:1.2;letter-spacing:-.025em;color:#17202b}.page-timetable .timetable-title-wrap .small{color:#7b8793;font-size:11px}.page-timetable .timetable-card .badge{display:inline-flex;padding:5px 8px;border-radius:999px;font-size:8px;letter-spacing:.1em;background:#edf4ff;color:#2f6fca;border:1px solid #d7e4f7}.page-timetable .timetable-preview{margin:0 14px;border:1px solid #e0e7ed;border-radius:17px;background:#f4f7fa;overflow:hidden;min-height:150px;display:flex;align-items:center;justify-content:center}.page-timetable .timetable-preview img{display:block;width:100%;height:auto;max-height:420px;object-fit:contain;background:#f4f7fa}.page-timetable .timetable-preview .notice{width:100%;margin:0;padding:25px;background:#f7faff;border:0;border-radius:0;box-sizing:border-box}.page-timetable .timetable-preview .notice strong{display:block;overflow-wrap:anywhere;color:#33414e}.page-timetable .timetable-card-clean .timetable-clean-note{margin:0 14px;padding:18px 16px;min-height:64px;display:flex;align-items:center;gap:11px;border:1px solid #e0e7ed;border-radius:17px;background:#f7faff;color:#687482;font-size:12px;font-weight:750}.page-timetable .timetable-clean-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:10px;background:#eaf2ff;color:#2f6fca;font-size:15px}.page-timetable .timetable-card-clean .timetable-preview{display:none}.page-timetable .timetable-card-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 18px 18px;margin-top:auto}.page-timetable .timetable-open{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:42px;padding:0 14px;border-radius:12px;background:#17202b;color:#fff;font-size:12px;font-weight:850;box-shadow:0 7px 16px rgba(23,32,43,.12);transition:.18s ease}.page-timetable .timetable-card:hover .timetable-open{background:#2f6fca;transform:translateY(-1px)}.page-timetable .timetable-open-arrow{font-size:16px;line-height:1}.page-timetable .timetable-hint{font-size:10px;color:#89939f}.page-timetable .empty{max-width:1180px;margin:0 auto}@media(max-width:900px){.page-timetable .timetable-list{grid-template-columns:1fr}.page-timetable .timetable-preview img{max-height:none}}@media(max-width:620px){.page-timetable .timetable-head{padding:25px 0 15px}.page-timetable .timetable-head h1{font-size:39px}.page-timetable .timetable-card{border-radius:20px}.page-timetable .timetable-card-head{padding:16px 15px 12px}.page-timetable .timetable-title-wrap h2{font-size:18px}.page-timetable .timetable-preview{margin:0 10px;border-radius:15px}.page-timetable .timetable-card-foot{padding:12px 13px 14px;flex-direction:column;align-items:stretch}.page-timetable .timetable-open{width:100%;box-sizing:border-box}.page-timetable .timetable-hint{text-align:center}}
</style>"""

@app.route("/timetable")
@student_required
def timetable():
    con=db(); rows=_latest_timetables(con,30); _mark_all_page_items_seen(con,session["student_db_id"],"timetable","timetables"); con.commit(); con.close()
    cards=""
    for r in rows:
        # Student-facing timetable cards intentionally hide the uploaded file name
        # and any image/document preview. Students see only the clean admin title.
        cards += f'<a class="timetable-card timetable-card-clean" href="/timetable-file/{r["id"]}" target="_blank" rel="noopener" aria-label="Open {esc(r["title"])} timetable"><div class="timetable-card-head"><span class="timetable-icon" aria-hidden="true">◷</span><div class="timetable-title-wrap"><span class="badge">TIMETABLE</span><h2>{esc(r["title"])}</h2><span class="small">Updated {esc(r["created_at"])}</span></div></div><div class="timetable-clean-note"><span class="timetable-clean-icon">▣</span><span>Timetable document</span></div><div class="timetable-card-foot"><span class="timetable-hint">Tap to open full timetable</span><span class="timetable-open">Open timetable <span class="timetable-open-arrow">↗</span></span></div></a>'
    body=f'{TIMETABLE_PAGE_CSS}<section class="section timetable-head"><div class="badge">CAMPUS TIMETABLE</div><h1>Your timetable.</h1><p class="muted">Find your latest class schedule quickly. Tap a timetable card to open the full document.</p></section><section class="section timetable-list">{cards or "<div class=\"empty\">No timetable has been posted yet.</div>"}</section>'
    return layout("Timetable",body)


@app.route("/timetable-file/<int:tid>")
@student_required
def timetable_file(tid):
    con=db(); row=con.execute("SELECT file_name,original_name,file_data,drive_web_url FROM timetables WHERE id=?",(tid,)).fetchone(); con.close()
    if not row: abort(404)
    if row["drive_web_url"]: return redirect(row["drive_web_url"])
    if row["file_data"] is not None:
        return _send_uploaded_content(row["file_data"], row["original_name"] or row["file_name"])
    path=UPLOAD_DIR/row["file_name"]
    if not path.is_file(): abort(404)
    return _send_uploaded_content(path.read_bytes(), row["original_name"] or path.name)


@app.route("/search")
@student_required
def search():
    q=request.args.get("q","").strip()[:100]
    results=[]
    con=db()
    if q: results=_campus_search(con,q,8)
    con.close()
    cards=""
    for r in results:
        cards += f'''<a class="feed-item" href="{esc(r["url"])}"><span class="pill">{esc(r["type"])}</span><h3 style="margin:9px 0 5px">{esc(r["title"])}</h3><p class="muted" style="margin:0">{esc(r["text"])}</p></a>'''
    body=f'''<section class="section"><div class="badge">VYBE SEARCH</div><h1>Find anything.</h1><div class="card"><form class="form" method="get"><input name="q" value="{esc(q)}" maxlength="100" placeholder="Search announcements, events, resources, community..."><button class="btn accent">Search VYBE →</button></form></div></section><section class="section feed-list">{cards or ('<div class="empty">Search your campus information from one place.</div>' if not q else '<div class="empty">Nothing matched that search.</div>')}</section>'''
    return layout("Search",body)


@app.route("/profile", methods=["GET","POST"])
@student_required
def profile():
    con=db()
    sid=session["student_db_id"]
    if request.method=="POST":
        action=request.form.get("action","")
        if action == "id_card":
            f=request.files.get("id_card")
            if not f or not f.filename:
                con.close(); flash("Choose your ID card file first."); return redirect(url_for("profile"))
            original=Path(f.filename).name[:240]
            suffix=Path(original).suffix.lower()
            if suffix not in {".pdf",".jpg",".jpeg",".png",".webp"}:
                con.close(); flash("ID card must be a PDF, JPG, JPEG, PNG or WEBP file."); return redirect(url_for("profile"))
            data=f.read(3*1024*1024+1)
            if not data:
                con.close(); flash("The selected ID card is empty. Choose another file."); return redirect(url_for("profile"))
            if len(data)>3*1024*1024:
                con.close(); flash("ID card must be 3 MB or smaller."); return redirect(url_for("profile"))
            mime=f.mimetype or mimetypes.guess_type(original)[0] or "application/octet-stream"
            stored=secrets.token_hex(16)+suffix
            try:
                con.execute("UPDATE students SET id_card_file_name=?,id_card_original_name=?,id_card_mime_type=?,id_card_file_data=? WHERE id=?",(stored,original,mime,data,sid))
                con.commit()
            except Exception:
                try: con.rollback()
                except Exception: pass
                app.logger.exception("Student profile ID card upload failed")
                con.close(); flash("Could not save your ID card. Please try again with a PDF or image up to 3 MB."); return redirect(url_for("profile"))
            con.close(); flash("ID card saved privately to your VYBE profile."); return redirect(url_for("profile"))
        if action == "delete_id_card":
            con.execute("UPDATE students SET id_card_file_name=NULL,id_card_original_name=NULL,id_card_mime_type=NULL,id_card_file_data=NULL WHERE id=?",(sid,))
            con.commit(); con.close(); flash("ID card removed from your profile."); return redirect(url_for("profile"))
        con.close(); return redirect(url_for("profile"))

    st=con.execute("SELECT name,student_id,reputation_points,helpful_answers,accepted_solutions,id_card_original_name FROM students WHERE id=?",(sid,)).fetchone()
    accepted=con.execute("SELECT issue_title,solution_text,solver_name,accepted_at FROM accepted_solutions WHERE student_id=? ORDER BY id DESC LIMIT 30",(sid,)).fetchall()
    given=con.execute("SELECT s.id,i.title AS issue_title,s.text AS solution_text,s.created_at,COALESCE(i.status,'') AS issue_status FROM solutions s LEFT JOIN issues i ON i.id=s.issue_id WHERE s.student_id=? ORDER BY s.id DESC LIMIT 50",(sid,)).fetchall()
    con.close()
    initials="".join(x[0] for x in st["name"].split()[:2]).upper() or "V"
    # Keep the profile ID-card plate generic; never expose the uploaded filename.
    card_label="Student ID" if st["id_card_original_name"] else ""
    accepted_html="".join(f'''<div class="profile-solution-item"><div class="solution-top"><strong>{esc(x["issue_title"] or "Campus problem")}</strong><span>ACCEPTED</span></div><p>{esc(x["solution_text"] or "")}</p><small>Solution from {esc(x["solver_name"] or "Student")} · {esc(x["accepted_at"] or "")}</small></div>''' for x in accepted)
    given_html="".join(f'''<div class="profile-solution-item"><div class="solution-top"><strong>{esc(x["issue_title"] or "Campus problem")}</strong><span>YOUR ANSWER</span></div><p>{esc(x["solution_text"] or "")}</p><small>{esc(x["created_at"] or "")}</small></div>''' for x in given)

    body=f'''<section class="section"><div class="profile-hero"><div class="profile-main"><div class="profile-avatar">{esc(initials)}</div><div><div class="badge">VYBE PROFILE</div><h1 class="profile-name">{esc(st["name"])}</h1><p class="profile-sub">Student · Student ID stays private</p></div></div></div></section>
<section class="section"><div class="id-card-panel"><div class="id-card-heading"><div><div class="mini-label">PRIVATE DOCUMENT</div><h2>Student ID card</h2><p>Keep your ID card here for quick access. Only you can access it.</p></div><div class="id-card-icon" aria-hidden="true">▣</div></div><div class="id-card-current"><div class="id-file-icon">▣</div><div class="id-file-info"><strong>{card_label}</strong><span>{"Uploaded privately" if st["id_card_original_name"] else "No ID card uploaded"}</span></div>{('<a class="profile-action profile-outline" href="/profile/id-card" target="_blank" rel="noopener">View</a>' if st["id_card_original_name"] else '')}</div><form id="studentIdCardForm" class="id-upload-form" method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="id_card"><label class="upload-file"><input id="studentIdCardInput" type="file" name="id_card" accept="application/pdf,image/jpeg,image/png,image/webp" required><span id="studentIdCardName">Choose ID card</span></label><button id="studentIdCardButton" class="profile-action profile-primary" type="submit">{"Replace ID card" if st["id_card_original_name"] else "Upload ID card"}</button></form><div id="studentIdCardStatus" class="id-upload-status" aria-live="polite"></div>{('<form method="post" class="id-delete-form"><input type="hidden" name="action" value="delete_id_card"><button class="profile-delete" type="submit">Delete ID card</button></form>' if st["id_card_original_name"] else '')}</div></section>
<section class="section"><div class="profile-stat-grid"><button class="profile-stat-button blue" type="button" data-profile-panel="given"><span class="stat-icon">↗</span><span><strong>{st["helpful_answers"]}</strong><small>Helpful answers</small></span><b>View</b></button><button class="profile-stat-button green" type="button" data-profile-panel="accepted"><span class="stat-icon">✓</span><span><strong>{st["accepted_solutions"]}</strong><small>Accepted solutions</small></span><b>View</b></button></div></section>
<section class="section profile-panel" id="profile-panel-given"><div class="profile-card"><div class="panel-heading"><div><div class="mini-label">YOUR ACTIVITY</div><h2>Solutions you gave</h2><p>Answers and solutions you posted for campus problems.</p></div><button type="button" class="panel-close" data-close-panel="given">Close</button></div><div class="profile-solutions">{given_html or '<div class="profile-empty">You have not given any solutions yet.</div>'}</div></div></section>
<section class="section profile-panel" id="profile-panel-accepted"><div class="profile-card"><div class="panel-heading"><div><div class="mini-label">YOUR SAVED HELP</div><h2>Solutions you received</h2><p>Solutions you accepted from other students.</p></div><button type="button" class="panel-close" data-close-panel="accepted">Close</button></div><div class="profile-solutions">{accepted_html or '<div class="profile-empty">You have not accepted any solutions yet.</div>'}</div></div></section>
<section class="section"><div class="profile-card password-card"><div><div class="mini-label">ACCOUNT SECURITY</div><h2>Password</h2><p>Change your VYBE student password from your account settings.</p></div><a class="profile-action profile-dark" href="/account/password">Password settings →</a></div></section>'''
    body += '''<script>(function(){
const buttons=document.querySelectorAll('[data-profile-panel]');
const panels={given:document.getElementById('profile-panel-given'),accepted:document.getElementById('profile-panel-accepted')};
function openPanel(key){Object.keys(panels).forEach(k=>{if(panels[k]) panels[k].classList.toggle('is-open',k===key);});if(panels[key]) panels[key].scrollIntoView({behavior:'auto',block:'start'});}
buttons.forEach(b=>b.addEventListener('click',()=>openPanel(b.dataset.profilePanel)));
document.querySelectorAll('[data-close-panel]').forEach(b=>b.addEventListener('click',()=>{const p=panels[b.dataset.closePanel];if(p)p.classList.remove('is-open');}));
const idForm=document.getElementById('studentIdCardForm');
const idInput=document.getElementById('studentIdCardInput');
const idButton=document.getElementById('studentIdCardButton');
const idName=document.getElementById('studentIdCardName');
const idStatus=document.getElementById('studentIdCardStatus');
if(idInput)idInput.addEventListener('change',()=>{const f=idInput.files&&idInput.files[0];if(idName)idName.textContent=f?f.name:'Choose ID card';});
if(idForm)idForm.addEventListener('submit',()=>{if(idButton){idButton.disabled=true;idButton.textContent='Saving…';}if(idStatus)idStatus.textContent='Saving your private ID card…';});
})();</script>'''
    body = r'''<style>
.profile-page{max-width:1040px!important;margin:0 auto!important;padding:24px 18px 90px!important}.profile-page .section{margin:0 0 18px!important}
.profile-page .profile-hero{padding:28px!important;border:1px solid #dfe5ea!important;border-radius:26px!important;background:linear-gradient(135deg,#fff 0%,#f8fbff 72%,#eef8e8 100%)!important;box-shadow:0 18px 45px rgba(23,32,43,.07)!important}.profile-main{display:flex;align-items:center;gap:18px}.profile-avatar{width:76px!important;height:76px!important;border-radius:23px!important;display:grid!important;place-items:center!important;background:linear-gradient(145deg,#2f6fca,#245aa8)!important;color:#fff!important;font-size:26px!important;font-weight:800!important;box-shadow:0 10px 25px rgba(47,111,202,.22)!important}.profile-name{margin:5px 0 4px!important;font-size:clamp(30px,4vw,44px)!important;letter-spacing:-1.3px!important;color:#17202b!important}.profile-sub{margin:0!important;color:#687482!important;font-size:14px!important}
.id-card-panel{padding:23px!important;border:1px solid #dfe5ea!important;border-radius:22px!important;background:#fff!important;box-shadow:0 10px 30px rgba(23,32,43,.055)!important}.id-card-heading{display:flex;justify-content:space-between;align-items:center;gap:18px}.id-card-heading h2{margin:3px 0 5px!important;font-size:21px!important}.id-card-heading p{margin:0!important;color:#687482!important;font-size:13px!important}.mini-label{font-size:10px!important;font-weight:800!important;letter-spacing:1.1px!important;color:#2f6fca!important}.id-card-icon{width:52px;height:52px;border-radius:16px;background:#edf8e6;color:#4f8f25;display:grid;place-items:center;font-weight:900}.id-card-current{display:flex;align-items:center;gap:13px;margin-top:18px;padding:13px;border:1px solid #e3e8ed;border-radius:16px;background:#f8fafc}.id-file-icon{width:40px;height:40px;border-radius:12px;background:#eaf2fb;color:#2f6fca;display:grid;place-items:center;font-weight:800;flex:0 0 auto}.id-file-info{min-width:0;flex:1}.id-file-info strong{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#17202b;font-size:13px}.id-file-info span{display:block;color:#687482;font-size:11px;margin-top:3px}.id-upload-form{display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:12px}.upload-file{display:flex;align-items:center;min-height:46px;border:1px dashed #b9c8d8;border-radius:13px;background:#f8fbff;color:#2f6fca;padding:0 14px;cursor:pointer;font-weight:700;font-size:13px}.upload-file input{display:none}.profile-action{display:inline-flex!important;align-items:center;justify-content:center;min-height:46px;border-radius:13px;padding:0 17px;font-weight:750;text-decoration:none;cursor:pointer;box-sizing:border-box}.profile-primary{border:1px solid #245aa8!important;background:#2f6fca!important;color:#fff!important;box-shadow:0 8px 18px rgba(47,111,202,.18)!important}.profile-primary:hover{background:#245aa8!important}.profile-outline{border:1px solid #cbd8e5!important;background:#fff!important;color:#245aa8!important;min-height:38px!important;padding:0 13px!important}.profile-delete{margin-top:9px;border:0;background:none;color:#b34b4b;font-size:12px;font-weight:700;cursor:pointer;padding:3px 0}.id-delete-form{margin:0}
.profile-stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.profile-stat-button{width:100%;display:flex;align-items:center;gap:13px;text-align:left;padding:16px;border:1px solid #dfe5ea;border-radius:19px;background:#fff;cursor:pointer;box-shadow:0 9px 25px rgba(23,32,43,.05);transition:.18s}.profile-stat-button:hover{transform:translateY(-2px);box-shadow:0 14px 30px rgba(23,32,43,.09)}.profile-stat-button .stat-icon{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;font-size:18px;font-weight:900}.profile-stat-button.blue .stat-icon{background:#eaf2fb;color:#2f6fca}.profile-stat-button.green .stat-icon{background:#edf8e6;color:#4f8f25}.profile-stat-button span:nth-child(2){flex:1}.profile-stat-button strong{display:block;font-size:20px;color:#17202b}.profile-stat-button small{display:block;color:#687482;font-size:11px;margin-top:2px}.profile-stat-button b{font-size:11px;color:#2f6fca}.profile-stat-button.green b{color:#4f8f25}
.profile-panel{display:none!important}.profile-panel.is-open{display:block!important}.profile-card{padding:23px!important;border:1px solid #dfe5ea!important;border-radius:22px!important;background:#fff!important;box-shadow:0 10px 30px rgba(23,32,43,.055)!important}.panel-heading{display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.panel-heading h2{margin:3px 0 5px!important}.panel-heading p{margin:0;color:#687482;font-size:13px}.panel-close{border:1px solid #dfe5ea;background:#f7f9fb;border-radius:10px;padding:8px 11px;color:#687482;cursor:pointer}.profile-solutions{display:grid;gap:10px;margin-top:17px}.profile-solution-item{padding:15px 16px;border:1px solid #e1e6eb;border-radius:16px;background:#fafbfd}.solution-top{display:flex;align-items:center;justify-content:space-between;gap:10px}.solution-top strong{color:#17202b;font-size:14px}.solution-top span{font-size:9px;font-weight:800;letter-spacing:.8px;padding:5px 8px;border-radius:999px;background:#edf8e6;color:#4f8f25}.profile-solution-item p{margin:9px 0 7px;color:#344150;white-space:pre-wrap;line-height:1.55;font-size:13px}.profile-solution-item small{color:#7a8590;font-size:10px}.profile-empty{padding:22px;text-align:center;border:1px dashed #cfd7df;border-radius:16px;color:#687482;background:#fafbfd}.password-card{display:flex;align-items:center;justify-content:space-between;gap:18px;background:linear-gradient(135deg,#17202b,#101827)!important;color:#fff!important;border-color:#17202b!important}.password-card h2{color:#fff!important;margin:3px 0 5px!important}.password-card p{color:#b9c3cf!important;margin:0!important;font-size:13px}.password-card .mini-label{color:#8fc2f3!important}.profile-dark{background:#fff!important;color:#17202b!important;border:1px solid rgba(255,255,255,.35)!important;white-space:nowrap}
@media(max-width:700px){.profile-page{padding:12px 12px 112px!important}.profile-page .profile-hero{padding:19px!important;border-radius:21px!important}.profile-avatar{width:61px!important;height:61px!important;border-radius:18px!important;font-size:21px!important}.profile-main{gap:13px}.profile-name{font-size:28px!important}.profile-sub{font-size:12px!important}.id-card-panel,.profile-card{padding:18px!important;border-radius:19px!important}.id-card-heading{align-items:flex-start}.id-card-icon{width:46px;height:46px}.id-card-current{align-items:flex-start}.id-upload-form{grid-template-columns:1fr!important}.id-upload-form .profile-action{width:100%!important}.profile-stat-grid{grid-template-columns:1fr!important;gap:10px}.profile-stat-button{padding:14px}.password-card{display:block!important}.password-card .profile-action{width:100%!important;margin-top:14px}.panel-heading{align-items:flex-start}.panel-close{flex:0 0 auto}.profile-solution-item{padding:13px}.solution-top{align-items:flex-start}.solution-top strong{font-size:13px}}
@media(max-width:390px){.profile-page{padding-left:10px!important;padding-right:10px!important}.profile-name{font-size:25px!important}.profile-avatar{width:55px!important;height:55px!important}.id-card-current{gap:9px}.profile-stat-button{border-radius:16px}}
</style>''' + body
    body = '<div class="profile-page">' + body + '</div>'
    return layout("Profile",body)


@app.route("/profile/id-card")
@student_required
def profile_id_card():
    con=db()
    r=con.execute("SELECT id_card_file_data AS file_data, id_card_mime_type AS mime_type, id_card_original_name AS original_name FROM students WHERE id=?",(session["student_db_id"],)).fetchone()
    con.close()
    if not r or not r["file_data"]: abort(404)
    return send_file(io.BytesIO(bytes(r["file_data"])),mimetype=r["mime_type"] or "application/octet-stream",as_attachment=False,download_name=r["original_name"] or "id-card")

@app.route("/profile/admit-card")
@student_required
def profile_admit_card():
    return profile_id_card()


@app.route("/assistant", methods=["GET","POST"])
@student_required
def assistant():
    con = db()
    enabled = setting(con, "vybe_assistant_enabled", "1") == "1"
    question = request.form.get("question", "").strip()[:1000] if request.method == "POST" else ""
    answer = ""
    sources = []
    if question and enabled:
        answer = _free_vybe_answer(con, question)
        sources = _campus_search(con, question, 6)
    if not enabled:
        con.close()
        body = '''<section class="section"><div class="ai-box"><div class="badge"> ASK VYBE</div><h1 style="margin:15px 0 8px">Assistant is offline.</h1><p class="muted">The VYBE Assistant has been temporarily disabled by the administrator.</p></div></section>'''
        return layout("Ask VYBE", body)
    source_html="".join(f'<a class="feed-item" href="{esc(x["url"])}"><span class="pill">{esc(x["type"])}</span><strong style="display:block;margin-top:8px">{esc(x["title"])}</strong><span class="small">{esc(x["text"])}</span></a>' for x in sources)

    # Timetable questions show the actual uploaded timetable in the answer.
    timetable_html = ""
    marker = re.search(r"\[\[TIMETABLE_IDS:([0-9,]+)\]\]", answer or "")
    if marker:
        ids = []
        for raw_id in marker.group(1).split(","):
            try:
                ids.append(int(raw_id))
            except ValueError:
                pass
        answer = re.sub(r"\n?\[\[TIMETABLE_IDS:[0-9,]+\]\]", "", answer or "").strip()
        tt_cards = []
        for tid in ids[:3]:
            tt = con.execute("SELECT id,title,original_name,created_at FROM timetables WHERE id=?", (tid,)).fetchone()
            if not tt:
                continue
            title = esc(tt["title"] or tt["original_name"] or "Timetable")
            tt_cards.append(
                f'<div style="margin-top:16px;padding:14px;border:1px solid rgba(58,145,214,.22);border-radius:18px;background:rgba(4,12,20,.65)">'
                f'<strong style="display:block;margin-bottom:10px"> {title}</strong>'
                f'<iframe src="/timetable-file/{int(tt["id"])}" title="{title}" style="width:100%;height:680px;border:0;border-radius:14px;background:#08080a"></iframe>'
                f'<a class="btn dark" style="margin-top:10px" href="/timetable-file/{int(tt["id"])}" target="_blank" rel="noopener">Open full timetable →</a>'
                f'</div>'
            )
        timetable_html = "".join(tt_cards)

    # The timetable cards above still use the DB connection, so close it only
    # after all timetable data has been fetched.
    con.close()

    answer_html = esc(answer).replace("\n", "<br>")
    if timetable_html:
        answer_html += timetable_html

    body=f'''<section class="section"><div class="ai-box"><div class="badge"> ASK VYBE · AI</div><h1 style="margin:15px 0 8px">Your campus assistant.</h1><p class="muted">Powered by VYBE AI. Ask about your college, documents, timetable, resources, or any general question.</p><form class="form" method="post" style="margin-top:20px"><textarea name="question" maxlength="1000" placeholder="e.g. What are the latest announcements? Where are the Data Structures notes? What time is it?">{esc(question)}</textarea><button class="btn accent">Ask VYBE →</button></form></div></section>{f'<section class="section"><div class="card"><div class="badge">ANSWER</div><div class="ai-answer" style="margin-top:12px;white-space:pre-wrap">{answer_html}</div></div></section>' if answer else ''}{f'<section class="section"><h2>Related VYBE information.</h2><div class="feed-list">{source_html}</div></section>' if sources else ''}'''
    return layout("Ask VYBE",body)


@app.route("/dashboard")
@student_required
def dashboard():
    con = db()
    s = con.execute("SELECT name FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
    publisher_enabled = publisher_is_active(session["student_db_id"], con=con)
    if publisher_enabled:
        publisher_enabled = bool(publisher_permissions(session["student_db_id"], con=con))
    anns = _active_announcements(con, 4)
    evs = _upcoming_events(con, 4)
    con.close()
    ann_html="".join(f'<a class="home-update" href="/announcements"><span class="home-update-icon"></span><span><strong>{esc(a["title"])}</strong><small>{esc(a["message"][:140])}</small></span><b>›</b></a>' for a in anns)
    event_html="".join(f'<a class="home-update" href="/events"><span class="home-update-icon"></span><span><strong>{esc(e["title"])}</strong><small>{esc(e["event_date"])} · {esc(e["event_time"] or "TBA")}</small></span><b>›</b></a>' for e in evs)
    if not ann_html:
        ann_html = '<div class="home-empty">No new announcements right now.</div>'
    if not event_html:
        event_html = '<div class="home-empty">No upcoming events right now.</div>'
    body = f'''<section class="student-home clean-home live-home">
<div class="home-live-hero">
  <div class="home-live-glow home-live-glow-one"></div><div class="home-live-glow home-live-glow-two"></div>
  <div class="home-live-copy"><div class="student-space-pill">YOUR CAMPUS</div><h1>Welcome back, {esc(s["name"])}.</h1><p>Everything important for your day at VYBE, in one simple space.</p><div class="home-hero-actions"><a class="btn accent" href="/contact-terms" target="_blank" rel="noopener">Contact / Terms</a></div></div>
  <div class="home-live-orbit"><span class="orbit-dot orbit-dot-a"></span><span class="orbit-dot orbit-dot-b"></span><div class="orbit-core">V</div></div>
</div>
<div class="home-section-label">QUICK ACCESS</div>
<div class="home-action-grid live-home-grid">
<a class="home-action home-action-primary" href="/academics"><span class="home-action-icon" aria-hidden="true">▦</span><span><strong>Academic Hub</strong><small>Notes, study material, SLM PDFs and previous papers.</small></span><b>Open</b></a>
<a class="home-action" href="/updates"><span class="home-action-icon" aria-hidden="true">⚑</span><span><strong>Academic Updates</strong><small>Results, date sheets, admit cards and exam forms.</small></span><b>Open</b></a>
<a class="home-action" href="/timetable"><span class="home-action-icon" aria-hidden="true">◷</span><span><strong>Timetable</strong><small>Your latest class schedule and timetable.</small></span><b>Open</b></a>

<a class="home-action" href="/community"><span class="home-action-icon" aria-hidden="true">◉</span><span><strong>Community</strong><small>Talk, ask questions and help other students.</small></span><b>Open</b></a>
<a class="home-action" href="/issues"><span class="home-action-icon" aria-hidden="true">?</span><span><strong>Help Desk</strong><small>Report campus problems and follow their status.</small></span><b>Open</b></a>
<a class="home-action" href="/announcements"><span class="home-action-icon" aria-hidden="true">▤</span><span><strong>Announcements</strong><small>Important notices and campus updates.</small></span><b>View</b></a>
<a class="home-action" href="/events"><span class="home-action-icon" aria-hidden="true">✦</span><span><strong>Events</strong><small>Upcoming campus activities and schedules.</small></span><b>View</b></a>
{f'<a class="home-action home-action-publisher" href="/publisher"><span class="home-action-icon" aria-hidden="true">✎</span><span><strong>Publisher</strong><small>Upload and publish the content your admin has allowed.</small></span><b>Publish</b></a>' if publisher_enabled else ''}
</div>
<div class="home-updates-head"><div><div class="home-section-label">WHAT'S HAPPENING</div><p>Live campus information from VYBE.</p></div><div class="home-live-status"><span></span> VYBE LIVE</div></div>
<div class="home-updates-grid compact-home-updates"><section class="home-update-panel" aria-label="Announcements"><div class="home-panel-title"><span>Announcements</span><a href="/announcements">View all</a></div><div class="home-update-list">{ann_html}</div></section><section class="home-update-panel" aria-label="Upcoming Events"><div class="home-panel-title"><span>Upcoming Events</span><a href="/events">View all</a></div><div class="home-update-list">{event_html}</div></section></div>
</section>'''
    return layout("Dashboard", body)


ACADEMIC_HUB_HOME_CSS = """<style>
.ah-hub-home{max-width:1080px;margin:0 auto;padding:42px 18px 84px;color:#17202b}.ah-hub-head{text-align:center;max-width:760px;margin:0 auto 24px}.ah-hub-head .academic-kicker{margin-bottom:8px}.ah-hub-head h1{margin:0 0 10px;font-size:clamp(38px,6vw,58px);line-height:1;letter-spacing:-.055em}.ah-hub-head p{margin:0;color:#6f7c88;font-size:14px;line-height:1.6}.ah-key-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.ah-key{display:flex;align-items:center;gap:13px;min-width:0;min-height:78px;padding:15px 16px;border:1px solid #dfe6eb;border-radius:17px;background:#fff;color:#17202b;text-decoration:none;box-shadow:0 6px 18px rgba(31,48,66,.035);transition:border-color .15s ease,box-shadow .15s ease,transform .15s ease}.ah-key:hover{border-color:#bfd4e8;box-shadow:0 10px 24px rgba(31,48,66,.07);transform:translateY(-1px)}.ah-key-icon{width:42px;height:42px;flex:0 0 42px;display:grid;place-items:center;border-radius:12px;background:#eef5fb;color:#2f6fca;font-weight:900;font-size:17px}.ah-key-copy{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1}.ah-key-copy strong{font-size:15px;line-height:1.2}.ah-key-copy small{font-size:11px;color:#7a8792;line-height:1.35}.ah-key-arrow{font-size:20px;color:#8498aa;font-weight:500;flex:0 0 auto}@media(max-width:760px){.ah-hub-home{padding:28px 12px 72px}.ah-hub-head{text-align:left;margin-bottom:18px}.ah-hub-head h1{font-size:35px}.ah-hub-head p{font-size:13px}.ah-key-grid{grid-template-columns:1fr}.ah-key{min-height:70px;padding:13px 14px}.ah-key-icon{width:40px;height:40px;flex-basis:40px}.ah-key:hover{transform:none;box-shadow:0 6px 18px rgba(31,48,66,.035)}}@media(prefers-reduced-motion:reduce){.ah-key{transition:none!important}}</style>"""

@app.route("/academics")
@student_required
def academics():
    """Academic Hub landing page with lightweight shortcut cards."""
    legacy_type={
        "Notes":"/academic-hub/notes",
        "Study material":"/academic-hub/study-material",
        "Previous Year Questions":"/academic-hub/pyq",
        "Syllabus":"/academic-hub/syllabus",
    }.get(request.args.get("resource_type", "").strip())
    if legacy_type:
        return redirect(legacy_type)
    shortcuts=[
        ("Notes","Revision notes by semester and subject.","/academic-hub/notes","▤"),
        ("Study Material","Books, PDFs and reference material.","/academic-hub/study-material","▦"),
        ("Previous Year Questions","Previous papers by semester and subject.","/academic-hub/pyq","◫"),
        ("Syllabus","Syllabus files for each semester and subject.","/academic-hub/syllabus","✓"),
    ]
    cards="".join(f"<a class='ah-key' href='{href}'><span class='ah-key-icon' aria-hidden='true'>{icon}</span><span class='ah-key-copy'><strong>{esc(title)}</strong><small>{esc(desc)}</small></span><b class='ah-key-arrow' aria-hidden='true'>→</b></a>" for title,desc,href,icon in shortcuts)
    body=f"""{ACADEMIC_HUB_HOME_CSS}<section class="ah-hub-home"><div class="ah-hub-head"><div class="academic-kicker">ACADEMIC HUB</div><h1>What do you need?</h1><p>Choose a section, then choose your semester and subject. VYBE will show only the material you ask for.</p></div><div class="ah-key-grid">{cards}</div></section>"""
    return layout("Academic Hub",body)

ACADEMIC_COLLECTION_CSS = """
<style>
.ah-collection{max-width:980px;margin:0 auto;padding:28px 14px 82px;color:#17202b}
.ah-filter-head{max-width:760px;margin:0 auto;padding:12px 4px 20px;text-align:center}.ah-filter-head .academic-kicker{margin-bottom:8px}.ah-filter-head h1{margin:0 0 9px;font-size:clamp(32px,5vw,48px);line-height:1.02;letter-spacing:-.045em}.ah-filter-head p{margin:0;color:#71808d;font-size:13px;line-height:1.55}
.ah-choice-panel{max-width:820px;margin:0 auto;padding:18px;border:1px solid #dfe6eb;border-radius:20px;background:#fff;box-shadow:0 8px 22px rgba(31,48,66,.045)}
.ah-step{margin:0}.ah-step+.ah-step{margin-top:18px}.ah-step-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}.ah-step-title{font-size:10px;font-weight:900;letter-spacing:.11em;text-transform:uppercase;color:#647482}.ah-step-current{font-size:11px;font-weight:800;color:#2f6fca}
.ah-choice-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.ah-choice{display:flex;align-items:center;justify-content:space-between;gap:10px;min-height:54px;padding:11px 13px;border:1px solid #d8e1e7;border-radius:14px;background:#fff;color:#17202b;text-decoration:none;font-size:12px;font-weight:800;transition:border-color .15s ease,background .15s ease,box-shadow .15s ease}.ah-choice:hover{border-color:#a9c8e8;background:#f8fbff}.ah-choice.active{border-color:#5d97cc;background:#eef6ff;color:#205e9b;box-shadow:0 0 0 2px rgba(47,111,202,.07)}.ah-choice-arrow{color:#8d9ba8;font-size:14px}.ah-choice.active .ah-choice-arrow{color:#2f6fca}
.ah-back{display:inline-flex;align-items:center;gap:6px;margin:0 0 14px;color:#5f7280;text-decoration:none;font-size:11px;font-weight:800}.ah-back:hover{color:#2f6fca}
.ah-results{max-width:820px;margin:18px auto 0}.ah-results-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:0 0 9px;padding:0 2px}.ah-results-title{font-size:15px;font-weight:900}.ah-count{font-size:10px;color:#87929c;font-weight:800}.ah-result{display:flex;align-items:center;gap:12px;padding:13px 14px;margin-bottom:8px;border:1px solid #e1e7eb;border-radius:14px;background:#fff;color:#17202b;text-decoration:none;transition:border-color .15s ease,background .15s ease}.ah-result:hover{border-color:#b7d0e8;background:#fbfdff}.ah-result-main{min-width:0;flex:1}.ah-result-title{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;font-weight:850}.ah-result-meta{display:block;margin-top:4px;color:#7b8791;font-size:10px;line-height:1.4}.ah-result-open{font-size:10px;font-weight:900;color:#2f6fca;white-space:nowrap}.ah-empty{padding:26px 15px;border:1px dashed #d2dce3;border-radius:14px;background:#fbfcfd;text-align:center;color:#778692;font-size:12px}
.ah-hub-home{max-width:900px;margin:0 auto;padding:42px 18px 80px}.ah-hub-head{text-align:center;padding:10px 0 22px}.ah-hub-head h1{margin:8px 0;font-size:clamp(38px,6vw,56px);letter-spacing:-.055em}.ah-hub-head p{margin:0 auto;max-width:620px;color:#7a8792;font-size:14px;line-height:1.5}.ah-key-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.ah-key{display:flex;align-items:center;gap:13px;min-height:78px;padding:14px 15px;border:1px solid #dfe6eb;border-radius:17px;background:#fff;color:#17202b;text-decoration:none;box-shadow:0 5px 18px rgba(31,48,66,.035);transition:border-color .15s ease,box-shadow .15s ease}.ah-key:hover{border-color:#b8d0e7;box-shadow:0 9px 24px rgba(31,48,66,.06)}.ah-key-icon{width:42px;height:42px;flex:0 0 42px;display:grid;place-items:center;border-radius:12px;background:#eef5fb;color:#2f6fca;font-weight:900}.ah-key-copy{min-width:0;flex:1;display:flex;flex-direction:column;gap:3px}.ah-key-copy strong{font-size:14px}.ah-key-copy small{font-size:11px;color:#7a8792;line-height:1.35}.ah-key-arrow{font-size:20px;color:#7d92a7;font-weight:500}
@media(max-width:760px){.ah-collection{padding:24px 12px 72px}.ah-filter-head{text-align:left;padding:8px 2px 17px}.ah-filter-head h1{font-size:32px}.ah-choice-panel{padding:14px;border-radius:17px}.ah-choice-grid{grid-template-columns:1fr 1fr;gap:8px}.ah-choice{min-height:50px;padding:10px 11px}.ah-results{margin-top:16px}.ah-result{padding:12px}.ah-result-open{font-size:9px}.ah-key-grid{grid-template-columns:1fr}.ah-hub-home{padding:28px 12px 70px}.ah-back{margin-bottom:10px}}
@media(max-width:430px){.ah-choice-grid{grid-template-columns:1fr}.ah-step-head{align-items:flex-start;flex-direction:column;gap:4px}}
@media(prefers-reduced-motion:reduce){.ah-choice,.ah-key,.ah-result{transition:none!important}}
</style>
"""

def _academic_resource_collection(resource_type, title, subtitle, kicker):
    # Sequential student browser: one decision at a time.
    con=db()
    raw_semester=" ".join(request.args.get("semester","").strip().split())[:100]
    semester=_drive_normalize_semester(raw_semester) if raw_semester else ""
    subject=" ".join(request.args.get("subject","").strip().split())[:120]

    sem_rows=con.execute(
        "SELECT DISTINCT semester FROM resources WHERE resource_type=? AND semester IS NOT NULL AND TRIM(semester)<>'' LIMIT 300",
        (resource_type,)
    ).fetchall()
    canonical_to_raw={}
    for row in sem_rows:
        raw=str(row["semester"] or "").strip()
        if not raw:
            continue
        canonical=_drive_normalize_semester(raw)
        if not canonical or canonical=="Uncategorized" or not canonical.lower().endswith("semester"):
            continue
        canonical_to_raw.setdefault(canonical,[]).append(raw)
    semesters=sorted(canonical_to_raw, key=lambda value: (int(re.search(r"\d+",value).group()) if re.search(r"\d+",value) else 999, value.casefold()))

    if semester not in canonical_to_raw:
        semester=""
        subject=""
    accepted_semesters=canonical_to_raw.get(semester,[])

    subjects=[]
    if semester and accepted_semesters:
        ph=','.join('?' for _ in accepted_semesters)
        subject_rows=con.execute(
            f"SELECT DISTINCT subject FROM resources WHERE resource_type=? AND semester IN ({ph}) AND subject IS NOT NULL AND TRIM(subject)<>'' LIMIT 300",
            tuple([resource_type]+accepted_semesters)
        ).fetchall()
        subjects=sorted({str(r["subject"]).strip() for r in subject_rows if str(r["subject"] or "").strip() and str(r["subject"]).strip().lower() not in {"general","subject","all"}}, key=str.casefold)
    if subject and subject not in subjects:
        subject=""

    rows=[]
    if semester and subject and accepted_semesters:
        ph=','.join('?' for _ in accepted_semesters)
        rows=con.execute(
            f"SELECT id,title,course,semester,subject,original_name,drive_file_id,drive_web_url FROM resources WHERE resource_type=? AND semester IN ({ph}) AND subject=? ORDER BY id DESC LIMIT 80",
            tuple([resource_type]+accepted_semesters+[subject])
        ).fetchall()
    con.close()

    def choice_link(name, param):
        if param=="semester":
            href=f"{request.path}?semester={quote(name)}"
        else:
            href=f"{request.path}?semester={quote(semester)}&subject={quote(name)}"
        return f'<a class="ah-choice" href="{esc(href)}"><span>{esc(name)}</span><span class="ah-choice-arrow">→</span></a>'

    if not semester:
        choices="".join(choice_link(item,"semester") for item in semesters)
        selector=f'''<div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">1 · Choose semester</span><span class="ah-step-current">Select one</span></div><div class="ah-choice-grid">{choices or '<div class="ah-empty" style="grid-column:1/-1">No semesters are available yet.</div>'}</div></div>'''
    elif not subject:
        choices="".join(choice_link(item,"subject") for item in subjects)
        selector=f'''<a class="ah-back" href="{request.path}">← Change semester</a><div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">1 · Semester</span><span class="ah-step-current">{esc(semester)}</span></div></div><div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">2 · Choose subject</span><span class="ah-step-current">Select one</span></div><div class="ah-choice-grid">{choices or '<div class="ah-empty" style="grid-column:1/-1">No subjects are available for this semester yet.</div>'}</div></div>'''
    else:
        selector=f'''<a class="ah-back" href="{request.path}?semester={quote(semester)}">← Change subject</a><div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">1 · Semester</span><span class="ah-step-current">{esc(semester)}</span></div></div><div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">2 · Subject</span><span class="ah-step-current">{esc(subject)}</span></div></div>'''

    if semester and subject:
        items=[]
        for r in rows:
            if not (r["drive_file_id"] or r["drive_web_url"] or r["original_name"]):
                continue
            meta=" · ".join(x for x in (semester,subject,r["course"]) if x)
            items.append(f'<a class="ah-result" href="/resource/{r["id"]}" target="_blank" rel="noopener"><span class="ah-result-main"><span class="ah-result-title">{esc(r["title"] or r["original_name"] or "Resource")}</span><span class="ah-result-meta">{esc(meta or r["original_name"] or "Academic resource")}</span></span><span class="ah-result-open">Open ↗</span></a>')
        results="".join(items) or '<div class="ah-empty">No files are available for this subject yet.</div>'
        result_block=f'<div class="ah-results"><div class="ah-results-head"><span class="ah-results-title">{esc(subject)}</span><span class="ah-count">{len(items)} file(s)</span></div>{results}</div>'
    elif semester:
        result_block='<div class="ah-results"><div class="ah-empty">Choose a subject to see the files.</div></div>'
    else:
        result_block='<div class="ah-results"><div class="ah-empty">Choose a semester to continue.</div></div>'

    body=f'''{ACADEMIC_COLLECTION_CSS}<section class="ah-collection"><div class="ah-filter-head"><div class="academic-kicker">{esc(kicker)}</div><h1>{esc(title)}</h1><p>{esc(subtitle)}</p></div><div class="ah-choice-panel">{selector}</div>{result_block}</section>'''
    return layout(title,body)

@app.route("/academic-hub/notes")
@student_required
def academic_hub_notes():
    return _academic_resource_collection("Notes","Study Notes","Choose your semester and subject to see only the notes you need.","STUDY NOTES")

@app.route("/academic-hub/study-material")
@student_required
def academic_hub_study_material():
    return _academic_resource_collection("Study material","Study Material","Choose your semester and subject to see only the material you need.","STUDY MATERIAL")

@app.route("/academic-hub/pyq")
@student_required
def academic_hub_pyq():
    return _academic_resource_collection("Previous Year Questions","PYQ Papers","Choose your semester and subject to see only the papers you need.","PYQ PAPERS")

@app.route("/academic-hub/syllabus")
@student_required
def academic_hub_syllabus():
    return _academic_resource_collection("Syllabus","Syllabus","Choose your semester and subject to see the relevant syllabus.","SYLLABUS")

@app.route("/academic-hub/assignments")
@student_required
def academic_hub_assignments():
    # Legacy bookmark: assignments are now published through Academic Updates.
    return redirect(url_for("academic_hub_assessment"))

def _academic_update_collection(kind, title, subtitle, kicker):
    # Academic updates use meaningful choice buttons rather than a search box.
    con=db()
    rows=con.execute(
        "SELECT id,title,description,event_date,external_url,file_name,drive_file_id,drive_web_url,created_at FROM academic_updates WHERE kind=? ORDER BY id DESC LIMIT 200",
        (kind,)
    ).fetchall()
    con.close()
    years=[]
    for row in rows:
        text_value=" ".join(str(row[k] or "") for k in ("event_date","created_at"))
        m=re.search(r"\b(20\d{2}|19\d{2})\b",text_value)
        if m and m.group(1) not in years:
            years.append(m.group(1))
    years=sorted(years,reverse=True)
    year=" ".join(request.args.get("year","").strip().split())[:4]
    if year not in years:
        year=""

    def year_link(value):
        return f'<a class="ah-choice" href="{request.path}?year={quote(value)}"><span>{esc(value)}</span><span class="ah-choice-arrow">→</span></a>'

    if not year:
        choices="".join(year_link(y) for y in years)
        selector=f'''<div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">1 · Choose year</span><span class="ah-step-current">Select one</span></div><div class="ah-choice-grid">{choices or '<div class="ah-empty" style="grid-column:1/-1">No updates are available yet.</div>'}</div></div>'''
        result_block='<div class="ah-results"><div class="ah-empty">Choose a year to see the published updates.</div></div>'
    else:
        items=[]
        for r in rows:
            text_value=" ".join(str(r[k] or "") for k in ("event_date","created_at"))
            if year not in text_value:
                continue
            href=r["external_url"] or (f'/academic-update-file/{r["id"]}' if (r["file_name"] or r["drive_file_id"] or r["drive_web_url"]) else f'/academic-update/{r["id"]}')
            action="Open official website ↗" if r["external_url"] else "Open ↗"
            items.append(f'<a class="ah-result" href="{esc(href)}" target="_blank" rel="noopener"><span class="ah-result-main"><span class="ah-result-title">{esc(r["title"])}</span><span class="ah-result-meta">{esc(r["event_date"] or r["created_at"])} · {esc(r["description"] or "Academic update")}</span></span><span class="ah-result-open">{action}</span></a>')
        selector=f'''<a class="ah-back" href="{request.path}">← Change year</a><div class="ah-step"><div class="ah-step-head"><span class="ah-step-title">1 · Year</span><span class="ah-step-current">{esc(year)}</span></div></div>'''
        items_html=''.join(items) or '<div class="ah-empty">No updates were found for this year.</div>'
        result_block=f'<div class="ah-results"><div class="ah-results-head"><span class="ah-results-title">{esc(title)}</span><span class="ah-count">{len(items)} update(s)</span></div>{items_html}</div>'

    body=f'''{ACADEMIC_COLLECTION_CSS}<section class="ah-collection"><div class="ah-filter-head"><div class="academic-kicker">{esc(kicker)}</div><h1>{esc(title)}</h1><p>{esc(subtitle)}</p></div><div class="ah-choice-panel">{selector}</div>{result_block}</section>'''
    return layout(title,body)

@app.route("/academic-hub/results")
@student_required
def academic_hub_results():
    return _academic_update_collection("Result","Results","Official result links published by the admin, kept separate from other academic updates.","RESULTS")

@app.route("/academic-hub/date-sheet")
@student_required
def academic_hub_date_sheet():
    return _academic_update_collection("Date Sheet","Date Sheets","Exam schedules and date-sheet documents published by the admin.","DATE SHEET")

@app.route("/academic-hub/admit-card")
@student_required
def academic_hub_admit_card():
    return _academic_update_collection("Admit Card","Admit Cards","Official admit-card links and documents published by the admin.","ADMIT CARD")

@app.route("/academic-hub/exam-forms")
@student_required
def academic_hub_exam_forms():
    return _academic_update_collection("Exam Notice","Exam Forms & Notices","Exam-form instructions are shown here through the published exam notices.","EXAM FORMS")

@app.route("/academic-hub/assessment")
@student_required
def academic_hub_assessment():
    return _academic_update_collection("Assessment","Assessments","Official assessment links published by the admin.","ASSESSMENTS")

@app.route("/papers")
@student_required
def academic_papers():
    return redirect(url_for("academic_hub_pyq"))

ACADEMIC_UPDATES_PAGE_CSS = """<style>
.page-updates .academic-compact{max-width:1180px;margin:0 auto;padding:42px 40px 36px;border-radius:28px;background:linear-gradient(135deg,#fff 0%,#f5f9ff 62%,#f5faef 100%);box-shadow:0 15px 40px rgba(31,48,66,.065);position:relative;overflow:hidden}.page-updates .academic-compact:after{content:"";position:absolute;right:-70px;top:-100px;width:230px;height:230px;border-radius:50%;background:rgba(47,111,202,.06);pointer-events:none}.page-updates .academic-compact h1{font-size:clamp(40px,5vw,64px);line-height:.98;letter-spacing:-.055em;margin:14px 0 10px;color:#17202b}.page-updates .academic-compact .academic-lead{max-width:720px;font-size:14px;line-height:1.65;color:#687482}.page-updates .academic-filter-panel{max-width:1180px;margin:0 auto 22px;padding:14px;border-radius:18px;background:#fff;border:1px solid #e2e7ec;box-shadow:0 9px 28px rgba(31,48,66,.06)}.page-updates .academic-filter-form{display:grid;grid-template-columns:minmax(220px,2fr) 1fr 1fr auto;gap:8px}.page-updates .academic-filter-form input,.page-updates .academic-filter-form select{min-height:44px;border-radius:11px;box-sizing:border-box}.page-updates .academic-filter-form button{min-height:44px;border-radius:11px;background:#17202b;color:#fff;font-weight:800;padding:0 16px;border:1px solid #17202b;cursor:pointer}.page-updates .academic-update-list{max-width:1180px;margin:0 auto;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.page-updates .academic-update-card{position:relative;min-height:230px;padding:0;border-radius:21px;background:#fff;border:1px solid #dfe5ea;box-shadow:0 9px 26px rgba(31,48,66,.055);display:flex;flex-direction:column;overflow:hidden;text-decoration:none;color:#17202b;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease}.page-updates .academic-update-card:hover{transform:translateY(-5px);border-color:#bfd5ec;box-shadow:0 20px 42px rgba(31,48,66,.12)}.page-updates .academic-update-card:focus-visible{outline:3px solid rgba(47,111,202,.22);outline-offset:3px}.page-updates .academic-update-card:before{content:"";height:5px;width:100%;background:linear-gradient(90deg,#2f6fca,#68b82e);display:block}.page-updates .academic-update-content{padding:19px 20px 0;display:flex;flex-direction:column;flex:1}.page-updates .academic-update-line{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.page-updates .academic-update-category,.page-updates .academic-update-kind{display:inline-flex;align-items:center;padding:5px 8px;border-radius:999px;font-size:9px;font-weight:850;letter-spacing:.02em}.page-updates .academic-update-category{background:#edf8e6;border:1px solid #d5e9c4;color:#4f861e}.page-updates .academic-update-kind{background:#edf4ff;border:1px solid #d7e4f7;color:#2f6fca}.page-updates .academic-update-card h2{font-size:21px;line-height:1.22;letter-spacing:-.025em;margin:15px 0 7px;color:#17202b}.page-updates .academic-update-card p{font-size:13px;line-height:1.6;color:#687482;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;margin:0}.page-updates .academic-update-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:auto;padding:15px 20px 18px;border-top:1px solid #edf0f2;color:#89939f;font-size:11px}.page-updates .academic-link{display:inline-flex;align-items:center;gap:5px;padding:9px 12px;border-radius:10px;background:#f2f7ff;color:#2f6fca;border:1px solid #d9e6f4;text-decoration:none;font-size:11px;font-weight:900;transition:.18s ease}.page-updates .academic-update-card:hover .academic-link{background:#2f6fca;color:#fff;border-color:#2f6fca}.page-updates .academic-empty{grid-column:1/-1;padding:55px 24px;border-radius:20px;background:#fff;border:1px dashed #ccd7df;text-align:center;color:#687482}@media(max-width:900px){.page-updates .academic-update-list{grid-template-columns:1fr}.page-updates .academic-filter-form{grid-template-columns:1fr 1fr 1fr}.page-updates .academic-filter-form button{grid-column:1/-1}}@media(max-width:620px){.page-updates .academic-compact{padding:30px 20px;border-radius:22px}.page-updates .academic-compact h1{font-size:39px}.page-updates .academic-filter-form{grid-template-columns:1fr}.page-updates .academic-filter-form button{grid-column:auto}.page-updates .academic-update-card{min-height:215px;border-radius:19px}.page-updates .academic-update-content{padding:16px 16px 0}.page-updates .academic-update-card h2{font-size:18px}.page-updates .academic-update-foot{padding:13px 16px 15px;align-items:flex-start;flex-direction:column;gap:9px}.page-updates .academic-link{width:100%;justify-content:center;box-sizing:border-box}}
</style>"""

# Direct-open academic update cards: clicking the card opens the uploaded file itself.
ACADEMIC_DIRECT_CARD_CSS = """
<style>
.academic-update-open-form{margin:0}.academic-update-open-button{width:100%;display:block;text-align:left;font:inherit;color:inherit}.academic-update-clickable{cursor:pointer;text-decoration:none!important;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease}
.academic-update-clickable:hover{transform:translateY(-4px);box-shadow:0 18px 45px rgba(31,72,120,.13);border-color:#c7dcf6}
.academic-update-clickable:active{transform:translateY(-1px) scale(.995)}
.academic-update-clickable .academic-link{font-weight:800;color:#2f6fca}
@media(max-width:700px){.academic-update-clickable:hover{transform:none}.academic-update-clickable .academic-link{font-size:13px}}
</style>
"""

@app.route("/updates")
@student_required
def academic_updates():
    # Keep the landing page choice-first. Students choose the update type first;
    # the section page then offers a small year-choice panel.
    keys=[
        ("Results","Official result links.","/academic-hub/results","↗"),
        ("Date Sheets","Exam schedules and date sheets.","/academic-hub/date-sheet","◷"),
        ("Admit Cards","Official admit-card links and files.","/academic-hub/admit-card","✓"),
        ("Exam Forms & Notices","Forms and exam notices.","/academic-hub/exam-forms","!"),
        ("Assessments","Official assessment links.","/academic-hub/assessment","✓"),
    ]
    key_html="".join(f'<a class="ah-key" href="{href}"><span class="ah-key-icon" aria-hidden="true">{icon}</span><span class="ah-key-copy"><strong>{esc(title)}</strong><small>{esc(desc)}</small></span><b class="ah-key-arrow" aria-hidden="true">→</b></a>' for title,desc,href,icon in keys)
    body=f'''{ACADEMIC_HUB_HOME_CSS}<section class="ah-hub-home"><div class="ah-hub-head"><div class="academic-kicker">ACADEMIC UPDATES</div><h1>What do you need?</h1><p>Choose an update type first. VYBE will then show the relevant choices and only the updates you select.</p></div><div class="ah-key-grid">{key_html}</div></section>'''
    return layout("Academic Updates",body)

@app.route("/academic-update/<int:uid>")
@student_required
def academic_update(uid):
    con=db(); row=con.execute("SELECT * FROM academic_updates WHERE id=?",(uid,)).fetchone(); con.close()
    if not row or row["kind"] not in ("Result","Date Sheet","Exam Notice","Admit Card","Assessment"): abort(404)
    file_button=f'<a class="btn academic-btn" href="/academic-update-file/{uid}" target="_blank" rel="noopener">Open document</a>' if row["file_name"] or row["file_data"] is not None or row["drive_web_url"] else ""
    external=""
    if row["external_url"]:
        parsed=urlparse(row["external_url"])
        if parsed.scheme in ("http","https") and parsed.netloc: external=f'<a class="btn academic-outline" href="{esc(row["external_url"])}" target="_blank" rel="noopener noreferrer">Open official website ↗</a>'
    body=f'''<section class="section"><div class="academic-detail"><div class="academic-kicker">{esc(row["kind"])}</div><h1>{esc(row["title"])}</h1><p class="academic-lead">{esc(row["description"])}</p><div class="academic-detail-grid"><div><span>Type</span><strong>{esc(row["kind"])}</strong></div><div><span>Date</span><strong>{esc(row["event_date"] or row["created_at"])}</strong></div></div><div class="actions academic-detail-actions">{external}{file_button}<a class="btn dark" href="/updates">Back to updates</a></div></div></section>'''
    return layout("Academic Update",body)

@app.route("/academic-update-file/<int:uid>")
@student_required
def academic_update_file(uid):
    con=db(); row=con.execute("SELECT kind,file_name,original_name,mime_type,file_data,drive_web_url FROM academic_updates WHERE id=?",(uid,)).fetchone(); con.close()
    if not row or row["kind"] not in ("Result","Date Sheet","Exam Notice","Admit Card") or (not row["file_name"] and row["file_data"] is None and not row["drive_web_url"]): abort(404)
    if row["drive_web_url"]:
        return redirect(row["drive_web_url"])
    if row["file_data"] is not None:
        name=row["original_name"] or row["file_name"] or "academic-document"
        return _send_uploaded_content(row["file_data"], name, row["mime_type"])
    path=UPLOAD_DIR/row["file_name"]
    if not path.is_file(): abort(404)
    return _send_uploaded_content(path.read_bytes(), row["original_name"] or path.name, row["mime_type"])

@app.route("/apps")
@student_required
def academic_apps():
    body='''<section class="academic-hero academic-compact section"><div class="academic-kicker">STUDENT APPLICATIONS</div><h1>Useful study tools.</h1><p class="academic-lead">Small tools for everyday academic work, built directly into VYBE.</p></section><section class="section"><div class="academic-app-grid"><article class="academic-app-card"><div class="academic-tool-mark" aria-hidden="true">∑</div><h2>SGPA Calculator</h2><p>Enter subjects, credits and grades to calculate your semester grade point average.</p><div id="sgpaRows" class="sgpa-rows"></div><div class="actions"><button class="btn academic-btn" type="button" onclick="window.addSgpaRow()">Add subject</button><button class="btn dark" type="button" onclick="window.calculateSgpa()">Calculate SGPA</button></div><div id="sgpaResult" class="sgpa-result" aria-live="polite"></div></article><article class="academic-app-card"><div class="academic-tool-mark" aria-hidden="true">⌁</div><h2>Academic shortcuts</h2><p>Jump directly to the resources students use most.</p><div class="academic-shortcuts"><a href="/papers">Previous papers</a><a href="/updates?kind=Result">Results</a><a href="/updates?kind=Date%20Sheet">Date sheets</a><a href="/updates?kind=Admit%20Card">Admit cards</a><a href="/academic-hub/exam-forms">Exam forms</a><a href="/academics">Study material</a></div></article></div></section><script>(function(){function row(){var d=document.createElement("div");d.className="sgpa-row";d.innerHTML="<input type=number min=0.5 step=0.5 placeholder=Credits aria-label=Credits><select aria-label=Grade><option value=10>O</option><option value=9>A+</option><option value=8>A</option><option value=7>B+</option><option value=6>B</option><option value=5>C</option><option value=4>D</option><option value=0>F</option></select><button type=button aria-label=Remove>Remove</button>";d.querySelector("button").onclick=function(){d.remove()};document.getElementById("sgpaRows").appendChild(d)}window.addSgpaRow=row;window.calculateSgpa=function(){var rows=[].slice.call(document.querySelectorAll(".sgpa-row"));var total=0,credits=0;rows.forEach(function(r){var c=parseFloat(r.querySelector("input").value||0),g=parseFloat(r.querySelector("select").value||0);if(c>0){credits+=c;total+=c*g}});document.getElementById("sgpaResult").textContent=credits?"SGPA: "+(total/credits).toFixed(2):"Add at least one subject with credits."};row();row()})();</script>'''
    return layout("Apps",body)


@app.route("/resource/<int:rid>")
@student_required
def resource(rid):
    con = db(); r = con.execute("SELECT file_name, original_name, mime_type, file_data, drive_web_url FROM resources WHERE id=?", (rid,)).fetchone(); con.close()
    if not r or (not r["file_name"] and r["file_data"] is None and not r["drive_web_url"]): abort(404)
    if r["drive_web_url"]: return redirect(r["drive_web_url"])
    # Prefer the database copy so a student can open material even when the
    # web process is on a different instance or the local upload directory
    # was reset during a deployment.
    data = r["file_data"]
    if data is not None:
        download_name = r["original_name"] or r["file_name"] or "resource-file"
        return _send_uploaded_content(data, download_name, r["mime_type"])
    path = UPLOAD_DIR / r["file_name"]
    if not path.is_file(): abort(404)
    return _send_uploaded_content(path.read_bytes(), r["original_name"] or path.name, r["mime_type"])


@app.route("/issues", methods=["GET"])
@student_required
def issues():
    # Help Desk must remain usable even if an older deployed database does not
    # yet contain the faculty table.  Older VYBE deployments can have a
    # perfectly valid database while missing this newer additive table.
    con = db()
    try:
        if con.is_pg:
            con.execute("CREATE TABLE IF NOT EXISTS faculty (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, designation TEXT NOT NULL, email TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        else:
            con.execute("CREATE TABLE IF NOT EXISTS faculty (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, designation TEXT NOT NULL, email TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        con.commit()
        faculty = con.execute("SELECT id,name,designation,email FROM faculty ORDER BY LOWER(name) ASC, id ASC").fetchall()
    except Exception:
        # Do not turn the student Help Desk into a generic 500 page if faculty
        # contact data is temporarily unavailable. The page can still show
        # the Help Desk interface and the admin can repair/add contacts later.
        app.logger.exception("Help Desk faculty lookup failed")
        try:
            con.rollback()
        except Exception:
            pass
        faculty = []
    finally:
        con.close()

    faculty_cards = "".join(
        f'''<article class="campus-faculty-card" data-faculty-name="{esc(x["name"]).lower()}" data-faculty-role="{esc(x["designation"]).lower()}">
            <div class="campus-faculty-avatar">{esc((x["name"] or "?").strip()[0:1]).upper()}</div>
            <div class="campus-faculty-info">
                <h3>{esc(x["name"])}</h3>
                <p class="campus-faculty-role">{esc(x["designation"])}</p>
                <a class="campus-faculty-email" href="mailto:{esc(x["email"])}">{esc(x["email"])}</a>
            </div>
            <a class="campus-mail-btn" href="mailto:{esc(x["email"])}" aria-label="Email {esc(x["name"])}"></a>
        </article>'''
        for x in faculty
    )

    if not faculty_cards:
        faculty_cards = '''<div class="campus-empty-state">
            <div class="campus-empty-icon"></div>
            <h3>Faculty contacts coming soon</h3>
            <p>Faculty contact details will appear here once they are added by VYBE admin.</p>
        </div>'''

    body = f'''<style>
      .vybe-campus-wrap{{max-width:980px;margin:0 auto;padding-bottom:24px}}
      .campus-hero{{position:relative;overflow:hidden;border:1px solid rgba(255,255,255,.10);border-radius:28px;padding:28px 30px;background:linear-gradient(145deg,rgba(255,255,255,.075),rgba(255,255,255,.025));box-shadow:0 24px 70px rgba(0,0,0,.22)}}
      .campus-hero:after{{content:"";position:absolute;width:220px;height:220px;right:-80px;top:-100px;border-radius:50%;background:rgba(70,170,230,.12);filter:blur(12px);pointer-events:none}}
      .campus-hero-top{{display:flex;gap:18px;align-items:flex-start;position:relative;z-index:1}}
      .campus-hero-icon{{width:54px;height:54px;flex:0 0 54px;border-radius:17px;display:grid;place-items:center;background:rgba(50,170,235,.13);border:1px solid rgba(75,180,235,.25);font-size:25px}}
      .campus-hero h1{{margin:2px 0 7px;font-size:clamp(28px,4vw,42px);letter-spacing:-.04em}}
      .campus-hero p{{margin:0;max-width:650px;line-height:1.65}}
      .campus-note{{margin-top:20px;padding:13px 15px;border-radius:15px;background:rgba(0,0,0,.18);border:1px solid rgba(255,255,255,.07);font-size:13px;color:#cfd6dd}}
      .campus-section-head{{display:flex;align-items:end;justify-content:space-between;gap:18px;margin:30px 2px 14px}}
      .campus-section-head h2{{margin:0;font-size:23px;letter-spacing:-.025em}}
      .campus-section-head p{{margin:5px 0 0}}
      .campus-count{{font-size:12px;padding:7px 10px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);white-space:nowrap}}
      .campus-tools-row{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:15px}}
      .campus-search{{position:relative;flex:1;min-width:220px}}
      .campus-search input{{width:100%;box-sizing:border-box;padding:13px 15px 13px 42px;border-radius:14px;border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.045);color:inherit;outline:none}}
      .campus-search input:focus{{border-color:rgba(65,174,235,.55);box-shadow:0 0 0 3px rgba(65,174,235,.09)}}
      .campus-search span{{position:absolute;left:15px;top:50%;transform:translateY(-50%);opacity:.62}}
      .campus-faculty-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}
      .campus-faculty-card{{display:flex;align-items:center;gap:14px;min-width:0;padding:17px;border-radius:21px;border:1px solid rgba(255,255,255,.09);background:rgba(255,255,255,.035);transition:transform .18s ease,border-color .18s ease,background .18s ease;box-shadow:0 12px 30px rgba(0,0,0,.12)}}
      .campus-faculty-card:hover{{transform:translateY(-2px);border-color:rgba(75,180,235,.28);background:rgba(255,255,255,.055)}}
      .campus-faculty-avatar{{width:48px;height:48px;flex:0 0 48px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(145deg,rgba(70,180,235,.24),rgba(255,255,255,.07));border:1px solid rgba(100,190,235,.20);font-weight:750;font-size:18px}}
      .campus-faculty-info{{min-width:0;flex:1}}
      .campus-faculty-info h3{{margin:0 0 4px;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
      .campus-faculty-role{{margin:0 0 7px!important;font-size:12px;color:#aab3bc;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
      .campus-faculty-email{{display:block;color:#8fd7ff;text-decoration:none;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
      .campus-faculty-email:hover{{text-decoration:underline}}
      .campus-mail-btn{{width:38px;height:38px;flex:0 0 38px;border-radius:12px;display:grid;place-items:center;text-decoration:none;background:rgba(60,175,235,.10);border:1px solid rgba(75,180,235,.20);color:#8fd7ff;font-size:17px}}
      .campus-mail-btn:active{{transform:scale(.96)}}
      .campus-empty-state{{grid-column:1/-1;text-align:center;padding:42px 20px;border:1px dashed rgba(255,255,255,.12);border-radius:22px;background:rgba(255,255,255,.025)}}
      .campus-empty-icon{{width:50px;height:50px;margin:0 auto 12px;border-radius:16px;display:grid;place-items:center;background:rgba(255,255,255,.06);font-size:22px}}
      .campus-empty-state h3{{margin:0 0 7px}}
      .campus-empty-state p{{margin:0;color:#9aa3ad;font-size:13px}}
      .campus-no-results{{display:none;text-align:center;padding:28px;border-radius:20px;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.025);color:#9aa3ad}}
      @media(max-width:700px){{
        .vybe-campus-wrap{{padding-bottom:12px}}
        .campus-hero{{padding:22px 18px;border-radius:22px}}
        .campus-hero-top{{gap:13px}}
        .campus-hero-icon{{width:46px;height:46px;flex-basis:46px;border-radius:14px;font-size:21px}}
        .campus-hero h1{{font-size:28px}}
        .campus-faculty-grid{{grid-template-columns:1fr;gap:11px}}
        .campus-faculty-card{{padding:14px;border-radius:18px}}
        .campus-section-head{{margin-top:24px}}
        .campus-section-head h2{{font-size:20px}}
        .campus-tools-row{{display:block}}
        .campus-search{{min-width:0;width:100%}}
        .campus-note{{font-size:12px}}
      }}
    
  /* ===== VYBE FINAL MONOCHROME NAVIGATION ===== */
  .student-desktop-links,
  .admin-navlinks,
  .navlinks {{
    display:flex !important;
    align-items:center !important;
    gap:8px !important;
  }}
  .student-desktop-links > a,
  .admin-navlinks > a,
  .navlinks > a {{
    display:inline-flex !important;
    align-items:center !important;
    justify-content:center !important;
    min-height:36px !important;
    padding:0 12px !important;
    border:1px solid #b9bdc2 !important;
    border-radius:8px !important;
    background:#ffffff !important;
    color:#17191c !important;
    box-shadow:none !important;
    text-decoration:none !important;
    box-sizing:border-box !important;
  }}
  .student-desktop-links > a:hover,
  .admin-navlinks > a:hover,
  .navlinks > a:hover {{
    background:#f0f1f2 !important;
    border-color:#777c82 !important;
    color:#000000 !important;
  }}
  #vybeMobileNav.student-mobile-menu > a,
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a {{
    display:flex !important;
    align-items:center !important;
    justify-content:flex-start !important;
    width:calc(100% - 16px) !important;
    min-height:42px !important;
    margin:5px 8px !important;
    padding:0 12px !important;
    border:1px solid #b9bdc2 !important;
    border-radius:8px !important;
    background:#ffffff !important;
    color:#17191c !important;
    box-sizing:border-box !important;
    text-decoration:none !important;
  }}
  #vybeMobileNav.student-mobile-menu > a:hover,
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:hover {{
    background:#f0f1f2 !important;
    border-color:#777c82 !important;
  }}
  .student-bottom-nav {{
    background:linear-gradient(180deg,#ffffff 0%,#eef7ff 55%,#dceeff 100%) !important;
    background-image:linear-gradient(180deg,#ffffff 0%,#eef7ff 55%,#dceeff 100%) !important;
    border-top:1px solid #b9d4ea !important;
    box-shadow:0 -8px 24px rgba(38,75,105,.14) !important;
  }}
  .student-bottom-nav > .mobile-menu-nav,
  .student-bottom-nav > .mobile-home-nav,
  .student-bottom-nav > .mobile-profile-nav {{
    width:100% !important;
    min-width:0 !important;
    max-width:none !important;
    height:46px !important;
    margin:0 !important;
    padding:0 6px !important;
    display:flex !important;
    align-items:center !important;
    justify-content:center !important;
    border:1px solid #b9cfe0 !important;
    border-radius:9px !important;
    background:#ffffff !important;
    color:#15191d !important;
    box-sizing:border-box !important;
    text-decoration:none !important;
    box-shadow:none !important;
  }}
  .student-bottom-nav > .mobile-home-nav.active {{
    background:#dceeff !important;
    color:#111827 !important;
    border-color:#8fbce0 !important;
    box-shadow:inset 0 1px rgba(255,255,255,.75),0 2px 8px rgba(56,104,145,.10) !important;
  }}
  .student-bottom-nav > .mobile-menu-nav:hover,
  .student-bottom-nav > .mobile-profile-nav:hover {{
    background:#f3f8fc !important;
    color:#111827 !important;
    border-color:#8fbce0 !important;
  }}
  .student-bottom-nav .mobile-menu-label,
  .student-bottom-nav .mobile-home-nav,
  .student-bottom-nav .mobile-profile-nav {{
    font-size:12px !important;
    font-weight:800 !important;
    line-height:1 !important;
  }}

  /* ===== FINAL MOBILE GLASS OVERRIDE ===== */
  @media(max-width:850px){{
    .nav:has(.student-nav-compact){{
      background:rgba(2,10,18,.58)!important;
      border-bottom:1px solid rgba(120,190,230,.18)!important;
      box-shadow:0 8px 30px rgba(0,0,0,.22)!important;
      backdrop-filter:blur(24px) saturate(150%)!important;
      -webkit-backdrop-filter:blur(24px) saturate(150%)!important;
    }}
    .nav:has(.student-nav-compact) .student-nav-compact,
    .nav:has(.student-nav-compact) .student-control-row{{
      background:transparent!important;
    }}
    .student-nav-compact .student-header-back,
    .student-nav-compact .student-header-updates{{
      background:rgba(20,48,70,.48)!important;
      border:1px solid rgba(125,195,235,.25)!important;
      color:#e5f4ff!important;
      box-shadow:inset 0 1px rgba(255,255,255,.07),0 6px 18px rgba(0,0,0,.12)!important;
      backdrop-filter:blur(14px)!important;
      -webkit-backdrop-filter:blur(14px)!important;
    }}
    .student-search input{{
      background:rgba(7,25,42,.48)!important;
      border:1px solid rgba(91,165,215,.25)!important;
      color:#fff!important;
      box-shadow:inset 0 1px rgba(255,255,255,.035)!important;
      backdrop-filter:blur(16px)!important;
      -webkit-backdrop-filter:blur(16px)!important;
    }}
    .student-search input:focus{{
      background:rgba(10,34,55,.62)!important;
      border-color:rgba(80,184,245,.55)!important;
      box-shadow:0 0 0 3px rgba(40,160,225,.10),inset 0 1px rgba(255,255,255,.05)!important;
    }}
    #vybeMobileNav.student-mobile-menu{{
      background:rgba(4,17,29,.58)!important;
      border:1px solid rgba(108,178,220,.25)!important;
      box-shadow:0 20px 55px rgba(0,0,0,.42),inset 0 1px rgba(255,255,255,.055)!important;
      backdrop-filter:blur(26px) saturate(155%)!important;
      -webkit-backdrop-filter:blur(26px) saturate(155%)!important;
    }}
    #vybeMobileNav.student-mobile-menu > a,
    #vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a{{
      background:rgba(18,45,66,.42)!important;
      border:1px solid rgba(110,178,218,.20)!important;
      color:#e6f4ff!important;
      box-shadow:inset 0 1px rgba(255,255,255,.035)!important;
    }}
    #vybeMobileNav.student-mobile-menu > a:hover,
    #vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:hover{{
      background:rgba(40,91,126,.55)!important;
      border-color:rgba(93,190,242,.42)!important;
      color:#fff!important;
    }}
    .student-bottom-nav{{
      background:rgba(2,10,18,.62)!important;
      background-image:none!important;
      border-top:1px solid rgba(105,177,220,.22)!important;
      box-shadow:0 -12px 34px rgba(0,0,0,.30),inset 0 1px rgba(255,255,255,.045)!important;
      backdrop-filter:blur(26px) saturate(160%)!important;
      -webkit-backdrop-filter:blur(26px) saturate(160%)!important;
    }}
    .student-bottom-nav > .mobile-menu-nav,
    .student-bottom-nav > .mobile-home-nav,
    .student-bottom-nav > .mobile-profile-nav{{
      background:rgba(14,39,59,.42)!important;
      border:1px solid rgba(102,175,218,.22)!important;
      color:#bcd7ea!important;
      box-shadow:inset 0 1px rgba(255,255,255,.045)!important;
      backdrop-filter:blur(12px)!important;
      -webkit-backdrop-filter:blur(12px)!important;
    }}
    .student-bottom-nav > .mobile-home-nav.active{{
      background:rgba(10,73,108,.58)!important;
      color:#6fd0ff!important;
      border-color:rgba(62,190,248,.48)!important;
      box-shadow:inset 0 1px rgba(255,255,255,.07),0 6px 20px rgba(0,110,180,.16)!important;
    }}
    .student-bottom-nav > .mobile-menu-nav:hover,
    .student-bottom-nav > .mobile-profile-nav:hover{{
      background:rgba(34,72,99,.52)!important;
      color:#eaf8ff!important;
      border-color:rgba(107,190,232,.38)!important;
    }}
    .mobile-direct-suggestions,
    .vybe-search-suggestions{{
      background:rgba(4,17,29,.72)!important;
      border-color:rgba(105,177,220,.25)!important;
      box-shadow:0 18px 45px rgba(0,0,0,.38)!important;
      backdrop-filter:blur(22px)!important;
      -webkit-backdrop-filter:blur(22px)!important;
    }}
    .mobile-direct-suggestions .vybe-search-suggestion{{
      background:rgba(18,45,66,.35)!important;
      color:#e6f4ff!important;
    }}
    .mobile-direct-suggestions .vybe-search-suggestion:hover{{background:rgba(40,91,126,.48)!important}}
  }}


/* ===== FINAL VYBE LOGIN EXPERIENCE — DESKTOP + PHONE ===== */
@media (min-width:851px){{
  body:has(.authbox){{
    min-height:100vh!important;
    background:
      radial-gradient(700px 420px at 12% 18%,rgba(47,111,202,.12),transparent 68%),
      radial-gradient(700px 420px at 88% 82%,rgba(104,184,46,.10),transparent 68%),
      linear-gradient(135deg,#f7f9fc 0%,#eef4f8 52%,#f8faf7 100%)!important;
  }}
  body:has(.authbox) .auth{{
    min-height:calc(100vh - 64px)!important;
    width:100%!important;
    max-width:none!important;
    padding:56px 28px 70px!important;
    box-sizing:border-box!important;
    display:flex!important;
    align-items:center!important;
    justify-content:center!important;
    position:relative!important;
    overflow:hidden!important;
  }}
  body:has(.authbox) .auth:before,
  body:has(.authbox) .auth:after{{
    content:""!important;position:absolute!important;border-radius:50%!important;pointer-events:none!important;filter:blur(2px)!important;
  }}
  body:has(.authbox) .auth:before{{width:360px;height:360px;left:8%;top:12%;background:rgba(47,111,202,.08)}}
  body:has(.authbox) .auth:after{{width:330px;height:330px;right:9%;bottom:8%;background:rgba(104,184,46,.07)}}
  body:has(.authbox) .authbox{{
    position:relative!important;z-index:1!important;
    width:min(500px,100%)!important;max-width:500px!important;min-width:0!important;
    margin:0!important;padding:38px 38px 32px!important;box-sizing:border-box!important;
    border-radius:28px!important;
    background:rgba(255,255,255,.82)!important;
    border:1px solid rgba(255,255,255,.95)!important;
    box-shadow:0 30px 80px rgba(31,48,66,.14),0 8px 25px rgba(31,48,66,.06),inset 0 1px rgba(255,255,255,.95)!important;
    backdrop-filter:blur(24px) saturate(135%)!important;
    -webkit-backdrop-filter:blur(24px) saturate(135%)!important;
  }}
  body:has(.authbox) .authbox .badge{{
    display:inline-flex!important;align-items:center!important;max-width:100%!important;box-sizing:border-box!important;
    padding:7px 11px!important;border-radius:999px!important;
    background:#edf4ff!important;border:1px solid #d7e5fb!important;color:#2f6fca!important;
    font-size:10px!important;font-weight:850!important;letter-spacing:.12em!important;
  }}
  body:has(.authbox) .authbox h1{{
    margin:17px 0 9px!important;font-size:42px!important;line-height:1.02!important;letter-spacing:-.055em!important;
    color:#17202b!important;background:none!important;-webkit-text-fill-color:#17202b!important;
  }}
  body:has(.authbox) .authbox>p.muted{{margin:0 0 25px!important;color:#687482!important;font-size:15px!important;line-height:1.55!important;max-width:420px!important}}
  body:has(.authbox) .authbox .form{{display:grid!important;gap:17px!important;width:100%!important}}
  body:has(.authbox) .authbox .label{{display:block!important;margin:0 0 7px!important;color:#35414d!important;font-size:12px!important;font-weight:750!important}}
  body:has(.authbox) .authbox input,
  body:has(.authbox) .authbox select,
  body:has(.authbox) .authbox textarea{{
    width:100%!important;min-width:0!important;max-width:100%!important;height:52px!important;box-sizing:border-box!important;
    padding:0 15px!important;border-radius:14px!important;background:rgba(247,250,253,.94)!important;
    color:#17202b!important;border:1px solid #d8e0e7!important;font-size:14px!important;
  }}
  body:has(.authbox) .authbox input::placeholder{{color:#8b97a3!important}}
  body:has(.authbox) .authbox input:focus{{background:#fff!important;border-color:#78a9df!important;box-shadow:0 0 0 4px rgba(47,111,202,.10)!important}}
  body:has(.authbox) .authbox .password-wrap{{position:relative!important;width:100%!important;min-width:0!important}}
  body:has(.authbox) .authbox .password-wrap input{{padding-right:55px!important}}
  body:has(.authbox) .authbox .password-toggle{{position:absolute!important;right:7px!important;top:50%!important;transform:translateY(-50%)!important;width:38px!important;height:38px!important;margin:0!important;border:0!important;border-radius:10px!important;background:transparent!important;color:#71808e!important;display:grid!important;place-items:center!important;cursor:pointer!important}}
  body:has(.authbox) .authbox .password-toggle:hover{{background:#edf3f8!important;color:#2f6fca!important}}
  body:has(.authbox) .authbox .btn.accent{{width:100%!important;min-height:52px!important;margin-top:2px!important;border-radius:14px!important;background:linear-gradient(135deg,#3479d1,#245eae)!important;border:1px solid #2f6fca!important;color:#fff!important;font-size:14px!important;font-weight:800!important;box-shadow:0 10px 25px rgba(47,111,202,.20)!important}}
  body:has(.authbox) .authbox .btn.accent:hover{{background:linear-gradient(135deg,#3d82dc,#245aa8)!important;transform:translateY(-1px)!important}}
  body:has(.authbox) .authbox .actions{{display:grid!important;grid-template-columns:1fr!important;margin-top:11px!important}}
  body:has(.authbox) .authbox .actions .btn.dark{{width:100%!important;min-height:46px!important;border-radius:13px!important;background:#f5f8fb!important;border:1px solid #d8e0e7!important;color:#44515e!important}}
  body:has(.authbox) .authbox .actions .btn.dark:hover{{background:#edf3f8!important;border-color:#c5d1dc!important}}
  body:has(.authbox) .authbox .small{{font-size:12px!important;line-height:1.5!important;color:#7a8793!important;text-align:center!important;margin:18px 0 0!important}}
  body:has(.authbox) .authbox .small a{{color:#2f6fca!important;font-weight:750!important}}
}}

@media (max-width:850px){{
  html,body{{width:100%!important;max-width:100%!important;overflow-x:hidden!important}}
  body:has(.authbox){{min-height:100svh!important;background:linear-gradient(180deg,#f7f9fc 0%,#eef4f8 52%,#f7faf5 100%)!important}}
  body:has(.authbox) .wrap{{width:100%!important;max-width:none!important;padding:0!important;box-sizing:border-box!important}}
  body:has(.authbox) .auth{{
    width:100%!important;min-height:calc(100svh - 58px)!important;height:auto!important;
    margin:0!important;padding:20px 12px 34px!important;box-sizing:border-box!important;
    display:flex!important;align-items:flex-start!important;justify-content:center!important;
  }}
  body:has(.authbox) .authbox{{
    width:100%!important;max-width:520px!important;min-width:0!important;margin:0!important;
    padding:24px 18px 22px!important;box-sizing:border-box!important;border-radius:22px!important;
    background:rgba(255,255,255,.86)!important;border:1px solid rgba(255,255,255,.95)!important;
    box-shadow:0 20px 55px rgba(31,48,66,.12),0 5px 18px rgba(31,48,66,.05),inset 0 1px rgba(255,255,255,.95)!important;
    backdrop-filter:blur(20px) saturate(130%)!important;-webkit-backdrop-filter:blur(20px) saturate(130%)!important;
  }}
  body:has(.authbox) .authbox .badge{{font-size:9px!important;letter-spacing:.10em!important;padding:6px 9px!important;max-width:100%!important;white-space:normal!important}}
  body:has(.authbox) .authbox h1{{font-size:31px!important;line-height:1.05!important;letter-spacing:-.055em!important;margin:14px 0 8px!important;color:#17202b!important;background:none!important;-webkit-text-fill-color:#17202b!important}}
  body:has(.authbox) .authbox>p.muted{{font-size:13px!important;line-height:1.48!important;margin:0 0 20px!important;color:#687482!important}}
  body:has(.authbox) .authbox .form{{display:grid!important;gap:14px!important;width:100%!important;min-width:0!important}}
  body:has(.authbox) .authbox .label{{font-size:11px!important;font-weight:750!important;color:#35414d!important;margin:0 0 6px!important}}
  body:has(.authbox) .authbox input,
  body:has(.authbox) .authbox select,
  body:has(.authbox) .authbox textarea{{width:100%!important;min-width:0!important;max-width:100%!important;height:48px!important;box-sizing:border-box!important;padding:0 13px!important;border-radius:13px!important;background:rgba(248,250,252,.96)!important;color:#17202b!important;border:1px solid #d8e0e7!important;font-size:14px!important}}
  body:has(.authbox) .authbox input:focus{{background:#fff!important;border-color:#78a9df!important;box-shadow:0 0 0 3px rgba(47,111,202,.10)!important}}
  body:has(.authbox) .authbox .password-wrap{{position:relative!important;width:100%!important;min-width:0!important;box-sizing:border-box!important}}
  body:has(.authbox) .authbox .password-wrap input{{padding-right:52px!important}}
  body:has(.authbox) .authbox .password-toggle{{position:absolute!important;right:6px!important;top:50%!important;transform:translateY(-50%)!important;width:36px!important;height:36px!important;margin:0!important;border:0!important;border-radius:9px!important;background:transparent!important;color:#71808e!important;display:grid!important;place-items:center!important}}
  body:has(.authbox) .authbox .btn.accent{{width:100%!important;max-width:100%!important;min-height:48px!important;height:auto!important;padding:11px 13px!important;margin-top:1px!important;border-radius:13px!important;background:linear-gradient(135deg,#3479d1,#245eae)!important;border:1px solid #2f6fca!important;color:#fff!important;font-size:13px!important;font-weight:800!important;white-space:normal!important;box-sizing:border-box!important;box-shadow:0 9px 22px rgba(47,111,202,.18)!important}}
  body:has(.authbox) .authbox .actions{{display:grid!important;grid-template-columns:1fr!important;width:100%!important;gap:8px!important;margin-top:10px!important}}
  body:has(.authbox) .authbox .actions .btn{{width:100%!important;min-height:44px!important;box-sizing:border-box!important;border-radius:12px!important}}
  body:has(.authbox) .authbox .actions .btn.dark{{background:#f5f8fb!important;border:1px solid #d8e0e7!important;color:#44515e!important}}
  body:has(.authbox) .authbox .small{{font-size:11px!important;line-height:1.5!important;text-align:center!important;margin:15px 0 0!important;color:#7a8793!important;overflow-wrap:anywhere!important}}
  body:has(.authbox) .authbox .small a{{color:#2f6fca!important;font-weight:750!important}}
  body:has(.authbox) .authbox .flash{{width:100%!important;max-width:100%!important;box-sizing:border-box!important;overflow-wrap:anywhere!important}}
}}

@media (max-width:380px){{
  body:has(.authbox) .auth{{padding:14px 8px 26px!important}}
  body:has(.authbox) .authbox{{padding:20px 14px 18px!important;border-radius:19px!important}}
  body:has(.authbox) .authbox h1{{font-size:28px!important}}
  body:has(.authbox) .authbox>p.muted{{font-size:12px!important;margin-bottom:17px!important}}
  body:has(.authbox) .authbox input{{height:46px!important;font-size:13px!important}}
  body:has(.authbox) .authbox .btn.accent{{min-height:46px!important}}
}}

      /* ===== HELP DESK PREMIUM REDESIGN ===== */
      .page-issues .vybe-campus-wrap{{max-width:1040px}}
      .page-issues .campus-hero{{padding:34px 34px 26px;border:1px solid rgba(47,111,202,.14);background:linear-gradient(135deg,#ffffff 0%,#f3f8ff 52%,#f2faee 100%);box-shadow:0 22px 60px rgba(31,72,110,.10);color:#17202b}}
      .page-issues .campus-hero:before{{content:"";position:absolute;width:340px;height:340px;right:-120px;top:-170px;border-radius:50%;background:radial-gradient(circle,rgba(47,111,202,.14),transparent 68%);pointer-events:none}}
      .page-issues .campus-hero:after{{width:260px;height:260px;right:80px;bottom:-210px;top:auto;background:rgba(104,184,46,.10);filter:blur(20px)}}
      .page-issues .campus-hero-top{{gap:20px}}
      .page-issues .campus-hero-icon{{width:62px;height:62px;flex-basis:62px;border-radius:20px;background:linear-gradient(145deg,#e8f2ff,#edf8e6);border:1px solid rgba(47,111,202,.16);color:#2f6fca;font-size:28px;box-shadow:0 12px 28px rgba(47,111,202,.10)}}
      .page-issues .campus-hero h1{{color:#17202b;font-weight:800}}
      .page-issues .campus-hero p{{color:#687482}}
      .page-issues .campus-hero .badge{{background:#edf5ff!important;color:#2f6fca!important;border:1px solid #d9e9fb!important}}
      .page-issues .campus-note{{display:flex;align-items:center;gap:7px;margin-top:22px;background:rgba(255,255,255,.72);border:1px solid #dfe8ef;color:#687482;box-shadow:0 8px 22px rgba(31,72,110,.05)}}
      .page-issues .campus-note strong{{color:#17202b}}
      .campus-steps{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px}}
      .campus-steps>div{{display:flex;align-items:center;gap:10px;padding:11px 13px;border-radius:15px;background:rgba(255,255,255,.74);border:1px solid #e2e9ef}}
      .campus-steps b{{font-size:10px;color:#2f6fca;letter-spacing:.08em}}
      .campus-steps span{{font-size:12px;color:#596675;font-weight:650}}
      .page-issues .campus-section-head{{margin-top:34px}}
      .page-issues .campus-section-head h2{{font-size:25px;color:#17202b}}
      .page-issues .campus-section-head p{{color:#7a8793}}
      .page-issues .campus-count{{background:#edf8e6;border-color:#dceccf;color:#4c8f21;font-weight:700}}
      .page-issues .campus-search input{{background:#fff;border:1px solid #dfe5ea;color:#17202b;box-shadow:0 8px 24px rgba(31,72,110,.06);height:48px}}
      .page-issues .campus-search input::placeholder{{color:#8a96a2}}
      .page-issues .campus-search span{{color:#2f6fca;font-weight:800}}
      .page-issues .campus-faculty-grid{{gap:16px}}
      .page-issues .campus-faculty-card{{position:relative;padding:18px;background:rgba(255,255,255,.94);border:1px solid #e1e7ec;border-radius:20px;box-shadow:0 10px 28px rgba(31,72,110,.07);transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}}
      .page-issues .campus-faculty-card:hover{{transform:translateY(-4px);border-color:#c8dcef;box-shadow:0 18px 36px rgba(31,72,110,.11)}}
      .page-issues .campus-faculty-avatar{{background:linear-gradient(145deg,#e8f2ff,#edf8e6);border-color:#dbe7f0;color:#2f6fca;box-shadow:inset 0 1px 0 rgba(255,255,255,.9)}}
      .page-issues .campus-faculty-info h3{{color:#17202b}}
      .page-issues .campus-faculty-role{{color:#73808d}}
      .page-issues .campus-faculty-email{{color:#2f6fca;font-weight:600}}
      .page-issues .campus-mail-btn{{background:#f1f7ff;border-color:#d9e8f7;color:#2f6fca;position:relative;overflow:hidden}}
      .page-issues .campus-mail-btn:before{{content:"✉";font-size:16px}}
      .page-issues .campus-mail-btn{{font-size:0}}
      .page-issues .campus-mail-btn:hover{{background:#e7f1fd;border-color:#c7ddef;transform:translateY(-1px)}}
      .page-issues .campus-empty-state,.page-issues .campus-no-results{{background:#fff;border-color:#dfe7ed;color:#17202b;box-shadow:0 10px 25px rgba(31,72,110,.05)}}
      .page-issues .campus-empty-state p,.page-issues .campus-no-results{{color:#7a8793}}
      @media(max-width:700px){{
        .page-issues .campus-hero{{padding:22px 18px 20px;border-radius:22px}}
        .page-issues .campus-hero-top{{gap:13px}}
        .page-issues .campus-hero-icon{{width:48px;height:48px;flex-basis:48px;border-radius:15px;font-size:22px}}
        .page-issues .campus-hero h1{{font-size:29px}}
        .campus-note{{flex-direction:column;align-items:flex-start!important}}
        .campus-steps{{grid-template-columns:1fr;gap:7px}}
        .campus-steps>div{{padding:10px 12px}}
        .page-issues .campus-section-head{{margin-top:26px}}
        .page-issues .campus-faculty-card{{padding:14px;border-radius:18px}}
      }}


/* ===== VYBE timetable + academic updates visual redesign ===== */
/* Timetable */
.timetable-head{{max-width:1180px!important;margin:0 auto!important;padding:30px 0 20px!important}}
.timetable-head:before{{content:"YOUR ACADEMIC SCHEDULE";display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border-radius:999px;background:#edf4ff;border:1px solid #d7e4f7;color:#2f6fca;font-size:9px;font-weight:900;letter-spacing:.13em}}
.timetable-head h1{{font-size:clamp(38px,5vw,62px)!important;line-height:1!important;letter-spacing:-.055em!important;margin:16px 0 9px!important;color:#17202b!important}}
.timetable-head h1:after{{content:"";display:inline-block;width:10px;height:10px;margin:0 0 6px 9px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 6px #edf8e6}}
.timetable-head .muted{{max-width:680px;font-size:14px!important;line-height:1.6!important}}
.timetable-list{{max-width:1180px!important;margin:0 auto!important;display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px!important;padding-top:4px!important}}
.timetable-card{{padding:14px!important;border-radius:22px!important;background:#fff!important;border:1px solid #dfe5ea!important;box-shadow:0 9px 28px rgba(31,48,66,.065)!important;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease!important}}
.timetable-card:hover{{transform:translateY(-3px)!important;border-color:#c8d8e8!important;box-shadow:0 16px 38px rgba(31,48,66,.11)!important}}
.timetable-card:before{{content:"";display:block;height:4px;width:64px;border-radius:999px;background:linear-gradient(90deg,#2f6fca,#68b82e);margin:0 0 14px 2px}}
.timetable-card .badge{{display:inline-flex!important;margin:0 0 2px!important;padding:6px 9px!important;border-radius:999px!important;font-size:9px!important;letter-spacing:.08em!important}}
.timetable-card h2{{font-size:19px!important;margin:9px 0 4px!important;color:#17202b!important}}
.timetable-card .small{{color:#89939f!important}}
.timetable-preview{{margin-top:14px!important;border-radius:16px!important;border:1px solid #e1e7ec!important;background:#f5f7f9!important;box-shadow:inset 0 1px 0 #fff}}
.timetable-preview img{{background:#f5f7f9!important;transition:transform .3s ease!important}}
.timetable-card:hover .timetable-preview img{{transform:scale(1.012)}}
.timetable-actions{{margin-top:12px!important}}
.timetable-actions .btn{{border-radius:11px!important;background:#17202b!important;color:#fff!important;min-height:44px!important;font-weight:800!important;box-shadow:0 5px 14px rgba(23,32,43,.10)!important}}
.timetable-actions .btn:after{{content:"  ↗";opacity:.7}}
.timetable-card .notice{{border-radius:14px!important;background:#f7faff!important;border:1px solid #dbe6f2!important}}
/* Academic updates */
.academic-compact{{max-width:1180px!important;margin:0 auto!important;padding:46px 40px 38px!important;border-radius:28px!important;background:linear-gradient(135deg,#fff 0%,#f7faff 62%,#f5faef 100%)!important;box-shadow:0 15px 40px rgba(31,48,66,.06)!important;position:relative;overflow:hidden}}
.academic-compact:after{{content:"";position:absolute;right:-90px;top:-120px;width:250px;height:250px;border-radius:50%;background:rgba(47,111,202,.055);pointer-events:none}}
.academic-compact h1{{font-size:clamp(40px,5vw,64px)!important;line-height:.98!important;letter-spacing:-.055em!important;margin:14px 0 10px!important}}
.academic-compact h1:after{{content:"";display:inline-block;width:10px;height:10px;margin:0 0 7px 9px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 6px #edf8e6}}
.academic-compact .academic-lead{{max-width:720px!important;font-size:14px!important;line-height:1.65!important}}
.academic-filter-panel{{max-width:1180px!important;margin:0 auto 22px!important;padding:15px!important;border-radius:18px!important;background:#fff!important;box-shadow:0 9px 28px rgba(31,48,66,.06)!important}}
.academic-filter-form{{grid-template-columns:minmax(220px,2fr) 1fr 1fr auto!important;gap:8px!important}}
.academic-filter-form input,.academic-filter-form select{{min-height:44px!important;border-radius:11px!important}}
.academic-filter-form button{{min-height:44px!important;border-radius:11px!important;background:#17202b!important;color:#fff!important;font-weight:800!important}}
.academic-update-list{{max-width:1180px!important;margin:0 auto!important;display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px!important}}
.academic-update-card{{min-height:220px!important;padding:20px!important;border-radius:19px!important;background:#fff!important;border:1px solid #dfe5ea!important;box-shadow:0 8px 24px rgba(31,48,66,.055)!important;display:flex!important;flex-direction:column!important;overflow:hidden!important;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease!important}}
.academic-update-card:hover{{transform:translateY(-3px)!important;border-color:#c8d8e8!important;box-shadow:0 16px 38px rgba(31,48,66,.10)!important}}
.academic-update-card:before{{content:"";display:block;width:46px;height:4px;border-radius:999px;background:#2f6fca;margin-bottom:13px}}
.academic-update-card:nth-child(2n):before{{background:#68b82e}}
.academic-update-line{{gap:7px!important}}
.academic-update-category{{display:inline-flex!important;padding:5px 8px!important;border-radius:999px!important;background:#edf8e6!important;border:1px solid #d5e9c4!important;color:#4f861e!important;font-size:9px!important}}
.academic-update-kind{{padding:5px 8px!important;border-radius:999px!important;background:#edf4ff!important;border:1px solid #d7e4f7!important;color:#2f6fca!important;font-size:9px!important}}
.academic-update-card h2{{font-size:20px!important;line-height:1.2!important;margin:16px 0 7px!important;color:#17202b!important}}
.academic-update-card p{{font-size:13px!important;line-height:1.6!important;color:#687482!important;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}}
.academic-update-foot{{margin-top:auto!important;padding-top:18px!important;border-top:1px solid #edf0f2!important;color:#89939f!important}}
.academic-link{{display:inline-flex!important;align-items:center;gap:5px;padding:9px 11px;border-radius:9px;background:#f7faff;color:#2f6fca!important;border:1px solid #dbe6f2;text-decoration:none!important;font-weight:900!important;transition:.18s ease}}
.academic-link:hover{{background:#edf4ff!important;border-color:#cbdced!important;transform:translateY(-1px)}}
.academic-empty{{grid-column:1/-1!important;padding:55px 24px!important;border-radius:20px!important;background:#fff!important;border:1px dashed #ccd7df!important}}
@media(max-width:900px){{.timetable-list,.academic-update-list{{grid-template-columns:1fr!important}}.academic-filter-form{{grid-template-columns:1fr 1fr 1fr!important}}.academic-filter-form button{{grid-column:1/-1}}.academic-compact{{padding:38px 28px 32px!important}}}}
@media(max-width:620px){{.timetable-head,.academic-filter-panel,.timetable-list,.academic-update-list{{padding-left:0!important;padding-right:0!important}}.timetable-head{{padding-top:25px!important}}.timetable-head h1,.academic-compact h1{{font-size:39px!important}}.academic-compact{{padding:30px 20px!important;border-radius:22px!important}}.academic-filter-form{{grid-template-columns:1fr!important}}.academic-filter-form button{{grid-column:auto}}.academic-update-card{{min-height:205px!important;padding:17px!important}}.academic-update-card h2{{font-size:18px!important}}.academic-update-foot{{align-items:flex-start!important;flex-direction:column!important;gap:9px!important}}.academic-link{{width:100%;justify-content:center;box-sizing:border-box}}.timetable-card{{border-radius:18px!important}}.timetable-actions .btn{{min-height:46px!important}}}}


/* ===== FINAL HOMEPAGE-MATCHED LIGHT GLASS MOBILE NAV ===== */
@media (max-width:850px){{
  .page-academics{{
    padding-bottom:92px!important;
  }}

  /* The nav is intentionally light and translucent so the page remains visible behind it. */
  #vybeStudentBottomNav.student-bottom-nav{{
    position:fixed!important;
    left:14px!important;
    right:14px!important;
    bottom:10px!important;
    width:auto!important;
    height:64px!important;
    min-height:64px!important;
    padding:6px!important;
    margin:0!important;
    display:grid!important;
    grid-template-columns:1fr 1fr 1fr!important;
    gap:5px!important;
    align-items:stretch!important;
    box-sizing:border-box!important;
    background:rgba(255,255,255,.62)!important;
    background-image:linear-gradient(120deg,rgba(255,255,255,.78),rgba(244,249,255,.60) 52%,rgba(246,251,241,.64))!important;
    border:1px solid rgba(255,255,255,.92)!important;
    border-radius:20px!important;
    box-shadow:0 16px 40px rgba(35,61,84,.16),0 3px 12px rgba(35,61,84,.07),inset 0 1px rgba(255,255,255,.95)!important;
    backdrop-filter:blur(25px) saturate(145%)!important;
    -webkit-backdrop-filter:blur(25px) saturate(145%)!important;
    z-index:10000!important;
  }}

  #vybeStudentBottomNav > .mobile-menu-nav,
  #vybeStudentBottomNav > .mobile-home-nav,
  #vybeStudentBottomNav > .mobile-profile-nav{{
    width:100%!important;
    height:50px!important;
    min-width:0!important;
    min-height:0!important;
    max-width:none!important;
    margin:0!important;
    padding:4px 5px!important;
    display:flex!important;
    flex-direction:column!important;
    align-items:center!important;
    justify-content:center!important;
    gap:3px!important;
    box-sizing:border-box!important;
    border:1px solid rgba(214,224,232,.70)!important;
    border-radius:15px!important;
    background:rgba(255,255,255,.42)!important;
    color:#596878!important;
    box-shadow:inset 0 1px rgba(255,255,255,.85)!important;
    backdrop-filter:blur(10px)!important;
    -webkit-backdrop-filter:blur(10px)!important;
    font-size:10px!important;
    font-weight:800!important;
    line-height:1!important;
    text-decoration:none!important;
    transition:transform .16s ease,background .16s ease,color .16s ease,border-color .16s ease,box-shadow .16s ease!important;
    -webkit-tap-highlight-color:transparent!important;
  }}

  #vybeStudentBottomNav .vybe-nav-icon{{
    width:19px!important;
    height:19px!important;
    display:grid!important;
    place-items:center!important;
    flex:0 0 19px!important;
  }}
  #vybeStudentBottomNav .vybe-nav-icon svg{{
    width:19px!important;
    height:19px!important;
    fill:none!important;
    stroke:currentColor!important;
    stroke-width:1.8!important;
    stroke-linecap:round!important;
    stroke-linejoin:round!important;
  }}
  #vybeStudentBottomNav .mobile-menu-label{{
    display:block!important;
    color:inherit!important;
    font-size:10px!important;
    font-weight:800!important;
    line-height:1!important;
  }}

  /* Menu = clean neutral glass */
  #vybeStudentBottomNav > .mobile-menu-nav{{
    background:rgba(255,255,255,.48)!important;
    color:#596878!important;
  }}

  /* Home = the same soft VYBE blue used across the homepage */
  #vybeStudentBottomNav > .mobile-home-nav.active{{
    background:linear-gradient(145deg,rgba(238,247,255,.90),rgba(222,239,255,.72))!important;
    color:#2f6fca!important;
    border-color:rgba(154,196,231,.72)!important;
    box-shadow:0 5px 16px rgba(47,111,202,.09),inset 0 1px rgba(255,255,255,.95)!important;
  }}

  /* Profile = the same soft VYBE green used across the homepage */
  #vybeStudentBottomNav > .mobile-profile-nav{{
    background:linear-gradient(145deg,rgba(246,251,241,.82),rgba(235,247,225,.62))!important;
    color:#5f9139!important;
    border-color:rgba(183,211,158,.70)!important;
  }}

  #vybeStudentBottomNav > .mobile-menu-nav:hover,
  #vybeStudentBottomNav > .mobile-menu-nav:focus-visible{{
    background:rgba(255,255,255,.76)!important;
    color:#2f6fca!important;
    border-color:#c5dced!important;
  }}
  #vybeStudentBottomNav > .mobile-profile-nav:hover,
  #vybeStudentBottomNav > .mobile-profile-nav:focus-visible{{
    background:rgba(244,250,238,.88)!important;
    color:#4f812b!important;
    border-color:#b9d79e!important;
  }}
  #vybeStudentBottomNav > a:active,
  #vybeStudentBottomNav > button:active{{
    transform:scale(.95)!important;
  }}

  /* Keep the Ask VYBE control in the same light glass family. */
  .vybe-assistant-fab{{
    right:14px!important;
    bottom:82px!important;
    min-height:40px!important;
    padding:8px 11px!important;
    border-radius:14px!important;
    background:rgba(255,255,255,.72)!important;
    color:#263646!important;
    border:1px solid rgba(255,255,255,.92)!important;
    box-shadow:0 10px 28px rgba(35,61,84,.16),inset 0 1px rgba(255,255,255,.9)!important;
    backdrop-filter:blur(20px) saturate(140%)!important;
    -webkit-backdrop-filter:blur(20px) saturate(140%)!important;
  }}
  .vybe-assistant-fab .fab-mark{{
    background:linear-gradient(145deg,#edf6ff,#e4f0ff)!important;
    color:#2f6fca!important;
    border:1px solid #d1e3f5!important;
  }}
}}

@media (max-width:380px){{
  #vybeStudentBottomNav.student-bottom-nav{{
    left:9px!important;
    right:9px!important;
    bottom:8px!important;
    height:61px!important;
    min-height:61px!important;
    border-radius:19px!important;
  }}
  #vybeStudentBottomNav > .mobile-menu-nav,
  #vybeStudentBottomNav > .mobile-home-nav,
  #vybeStudentBottomNav > .mobile-profile-nav{{
    height:48px!important;
    border-radius:14px!important;
  }}
}}
</style>
    <section class="section vybe-campus-wrap">
      <div class="campus-hero">
        <div class="campus-hero-top">
          <div class="campus-hero-icon">✦</div>
          <div>
            <div class="badge">CAMPUS SUPPORT</div>
            <h1>Report campus problems.</h1>
            <p class="muted">Report all the campus problems directly to the faculty.</p>
          </div>
        </div>
        <div class="campus-note"><strong>Need help?</strong><span>Choose the right faculty contact below and email them directly.</span></div><div class="campus-steps"><div><b>01</b><span>Find your area</span></div><div><b>02</b><span>Choose a contact</span></div><div><b>03</b><span>Send your message</span></div></div>
      </div>

      <div class="campus-section-head">
        <div><h2>Faculty &amp; Teachers</h2><p class="small">Find the right contact quickly.</p></div>
        <span class="campus-count" id="campusFacultyCount">{len(faculty)} contacts</span>
      </div>

      <div class="campus-tools-row">
        <label class="campus-search"><span>S</span><input id="campusFacultySearch" type="search" placeholder="Search by name or designation..." autocomplete="off"></label>
      </div>

      <div class="campus-faculty-grid" id="campusFacultyGrid">{faculty_cards}</div>
      <div class="campus-no-results" id="campusNoResults">No matching faculty contact found.</div>
    </section>
    <script>
      (function(){{
        const input=document.getElementById('campusFacultySearch');
        const grid=document.getElementById('campusFacultyGrid');
        const empty=document.getElementById('campusNoResults');
        const count=document.getElementById('campusFacultyCount');
        if(!input||!grid) return;
        const cards=Array.from(grid.querySelectorAll('.campus-faculty-card'));
        function filter(){{
          const q=(input.value||'').trim().toLowerCase(); let shown=0;
          cards.forEach(function(card){{
            const hay=(card.dataset.facultyName+' '+card.dataset.facultyRole).toLowerCase();
            const ok=!q||hay.includes(q); card.style.display=ok?'flex':'none'; if(ok) shown++;
          }});
          if(count) count.textContent=shown+' contact'+(shown===1?'':'s');
          if(empty) empty.style.display=shown?'none':'block';
        }}
        input.addEventListener('input',filter);
      }})();
    </script>'''
    return layout("Campus", body)


def _render_solution_card(row,my_student_id):
    button="" if row["student_id"]==my_student_id else f"<form method=\"post\" action=\"/community/solution/{row['id']}/helpful\" style=\"margin-top:9px\"><button class=\"btn dark\" type=\"submit\"> Helpful answer</button></form>"
    return f'<div class="bubble"><strong>{esc(row["author_name"])}</strong><div>{esc(row["text"])}</div><div class="small">{esc(row["created_at"])}</div>{button}</div>'

@app.route("/community", methods=["GET"])
@student_required
def community():
    # Community launcher: chat, campus problems, and WhatsApp community.
    con = db()
    wa = setting(con, "whatsapp_link", "")
    con.close()
    whatsapp_card = (
        f'<a class="community-choice-card" href="{esc(wa)}" target="_blank" rel="noopener noreferrer"><span class="community-choice-icon">&#128172;</span><span class="community-choice-copy"><strong>WhatsApp Community</strong><small>Join the VYBE WhatsApp community.</small></span><span class="community-choice-arrow">&#8250;</span></a>'
        if valid_url(wa) else
        '<div class="community-choice-card" style="opacity:.65;cursor:default"><span class="community-choice-icon">&#128172;</span><span class="community-choice-copy"><strong>WhatsApp Community</strong><small>Community link is not configured yet.</small></span></div>'
    )
    body = f'''<section class="section community-head-section"><div class="badge">COMMUNITY</div><h1>Students solve together.</h1><p class="muted">Choose how you want to participate in VYBE's student community.</p></section>
<section class="section community-choice-section">
  <div class="community-choice-grid">
    <a class="community-choice-card" href="/community/chat"><span class="community-choice-icon">&#128172;</span><span class="community-choice-copy"><strong>Chat with students</strong><small>Talk with your campus community using your name only.</small></span><span class="community-choice-arrow">&#8250;</span></a>
    <a class="community-choice-card" href="/community/problems"><span class="community-choice-icon">&#128736;</span><span class="community-choice-copy"><strong>Solve campus problem</strong><small>Help students fix Wi-Fi, systems, classrooms and campus issues.</small></span><span class="community-choice-arrow">&#8250;</span></a>
    {whatsapp_card}
  </div>
</section>'''
    return layout("Community", body)

@app.route("/community/chat", methods=["GET", "POST"])
@student_required
def community_chat():
    con = db()
    my_id = session["student_db_id"]

    if request.method == "POST":
        action = (request.form.get("action") or "send").strip().lower()

        if action == "delete_one":
            try: mid = int(request.form.get("message_id", "0"))
            except (TypeError, ValueError): mid = 0
            if mid > 0:
                try:
                    con.execute("DELETE FROM community_messages WHERE id=? AND student_id=?", (mid, my_id))
                    con.commit()
                    if request.headers.get("X-VYBE-Live-Chat") == "1":
                        con.close()
                        return jsonify({"ok": True, "deleted_id": mid})
                    flash("Message deleted.")
                except Exception:
                    con.rollback(); app.logger.exception("Single community message delete failed"); flash("We couldn't delete that message right now. Please try again.")
            con.close(); return redirect(url_for("community_chat"))

        # A student can delete only their own messages. Deleting remains
        # available even when the admin temporarily turns chat sending off.
        if action == "delete_selected":
            raw_ids = request.form.getlist("message_ids")
            ids = []
            for raw in raw_ids:
                try:
                    mid = int(raw)
                    if mid > 0:
                        ids.append(mid)
                except (TypeError, ValueError):
                    continue
            ids = list(dict.fromkeys(ids))
            if ids:
                placeholders = ",".join("?" for _ in ids)
                try:
                    con.execute(
                        f"DELETE FROM community_messages WHERE student_id=? AND id IN ({placeholders})",
                        [my_id] + ids,
                    )
                    con.commit()
                    flash("Selected messages deleted.")
                except Exception:
                    con.rollback()
                    app.logger.exception("Selected community messages delete failed")
                    flash("We couldn't delete those messages right now. Please try again.")
            else:
                flash("Select at least one of your messages to delete.")
            con.close()
            return redirect(url_for("community_chat"))

        if action == "delete_all":
            try:
                con.execute("DELETE FROM community_messages WHERE student_id=?", (my_id,))
                con.commit()
                flash("All of your community messages were deleted.")
            except Exception:
                con.rollback()
                app.logger.exception("All community messages delete failed")
                flash("We couldn't delete your messages right now. Please try again.")
            con.close()
            return redirect(url_for("community_chat"))

        # Normal message sending is controlled by the admin switch.
        chat_enabled = setting(con, "community_chat_enabled", "1") == "1"
        text = request.form.get("message", "").strip()[:1500]
        if not chat_enabled:
            con.close()
            flash("Community Chat is currently turned off by the admin.")
            return redirect(url_for("community_chat"))
        if not text:
            con.close()
            return redirect(url_for("community_chat"))
        try:
            reply_to = request.form.get("reply_to_id", "").strip()
            reply_id = None
            if reply_to:
                try:
                    candidate = int(reply_to)
                    if candidate > 0 and con.execute("SELECT id FROM community_messages WHERE id=?", (candidate,)).fetchone():
                        reply_id = candidate
                except (TypeError, ValueError):
                    reply_id = None
            reply_recipient_id = None
            if reply_id:
                original = con.execute("SELECT student_id FROM community_messages WHERE id=?", (reply_id,)).fetchone()
                if original and int(original["student_id"]) != int(my_id):
                    reply_recipient_id = int(original["student_id"])

            created_at = now()
            con.execute(
                "INSERT INTO community_messages(student_id,message,created_at,reply_to_id) VALUES(?,?,?,?)",
                (my_id, text, created_at, reply_id),
            )

            # Commit the chat message FIRST. Notification storage is deliberately
            # isolated so a notification/database issue can NEVER make the actual
            # student message fail.
            con.commit()

            # If this is a reply to another student, create a personal notification
            # for the original sender. This does not notify the person who replied.
            if reply_recipient_id:
                try:
                    sent_row = con.execute(
                        "SELECT id FROM community_messages WHERE student_id=? AND created_at=? ORDER BY id DESC LIMIT 1",
                        (my_id, created_at),
                    ).fetchone()
                    reply_message_id = int(sent_row["id"]) if sent_row else None
                    sender_row = con.execute("SELECT name FROM students WHERE id=?", (my_id,)).fetchone()
                    sender_name = sender_row["name"] if sender_row else "A student"
                    con.execute(
                        "INSERT INTO student_notifications(recipient_student_id,sender_student_id,reply_message_id,title,message,created_at,read_at) VALUES(?,?,?,?,?,?,NULL)",
                        (reply_recipient_id, my_id, reply_message_id, "New reply in Community Chat", f"{sender_name} replied to your message: {text[:180]}", created_at),
                    )
                    con.commit()
                except Exception:
                    # Notifications are optional; never break Community Chat.
                    try: con.rollback()
                    except Exception: pass
                    app.logger.exception("Student reply notification failed; chat message was preserved")

            con.close()
            if request.headers.get("X-VYBE-Live-Chat") == "1":
                return jsonify({"ok": True})
            return redirect(url_for("community_chat"))
        except Exception:
            try: con.rollback()
            except Exception: pass
            con.close()
            app.logger.exception("Community chat message post failed")
            flash("We couldn't send that message right now. Please try again.")
            return redirect(url_for("community_chat"))

    chat_enabled = setting(con, "community_chat_enabled", "1") == "1"
    chat_rows = con.execute(
        "SELECT cm.*, s.name, r.message AS reply_message, rs.name AS reply_name FROM community_messages cm JOIN students s ON s.id=cm.student_id LEFT JOIN community_messages r ON r.id=cm.reply_to_id LEFT JOIN students rs ON rs.id=r.student_id ORDER BY cm.id ASC LIMIT 300"
    ).fetchall()
    con.close()

    bubbles = []
    for r in chat_rows:
        mine = r["student_id"] == my_id
        mine_class = " mine" if mine else ""
        mine_flag = "1" if mine else "0"
        reply_html = ""
        if r["reply_to_id"] and r["reply_message"]:
            reply_html = (
                f'<button type="button" class="community-reply-reference" data-reply-target="{r["reply_to_id"]}">'
                f'<strong>Replying to {esc(r["reply_name"] or "Student")}</strong>'
                f'<span>{esc(r["reply_message"][:120])}</span></button>'
            )
        bubbles.append(
            f'<div class="community-message{mine_class}" id="community-msg-{r["id"]}" data-message-id="{r["id"]}" data-mine="{mine_flag}" role="button" tabindex="0" aria-pressed="false">'
            f'<div class="community-message-content">'
            f'<div class="community-message-head"><strong>{esc(r["name"])}</strong></div>'
            f'{reply_html}'
            f'<div class="community-message-text">{esc(r["message"])}</div>'
            f'<div class="community-message-meta"><span>{esc(str(r["created_at"])[-5:])}</span></div>'
            f'<div class="community-message-actions"><button type="button" class="community-message-action community-reply-action" data-message-id="{r["id"]}">Reply</button>'
            + (f'<button type="button" class="community-message-action delete community-delete-one-action" data-message-id="{r["id"]}">Delete</button>' if mine else '') +
            f'</div></div></div>'
        )
    chat_bubbles = "".join(bubbles)

    status_text = "&#128994; Chat is ON" if chat_enabled else "&#128308; Chat is OFF"
    empty_chat = '<div class="empty">No messages yet. Start the conversation.</div>'

    select_controls = f'''<div class="community-chat-tools">
        <div class="community-chat-tools-left"><span class="community-chat-live-dot"></span><strong>Community Chat</strong><span class="community-chat-tools-sub">Reply to any message to start a thread</span></div>
      </div>'''
    if not chat_enabled:
        chat_panel = f'''{select_controls}<div class="community-chat-window">{chat_bubbles or empty_chat}</div><div class="community-chat-disabled-note">&#128274; Sending is currently off. You can still read and manage your own messages.</div>'''
    else:
        chat_panel = f'''{select_controls}<div class="community-chat-window">{chat_bubbles or empty_chat}</div><div class="community-reply-bar" id="community-reply-bar" hidden><div><strong id="community-reply-title">Replying</strong><span id="community-reply-preview"></span></div><button type="button" id="community-reply-cancel" aria-label="Cancel reply">×</button></div><form class="community-chat-form" method="post" action="/community/chat" id="community-send-form"><input type="hidden" name="reply_to_id" id="community-reply-to" value=""><textarea name="message" maxlength="1500" rows="1" placeholder="Write a message..." required autocomplete="off" aria-label="Message"></textarea><button class="community-send-button" type="submit" aria-label="Send message" title="Send">➤</button></form>'''

    chat_style = '''<style>
/* ===== VYBE COMMUNITY CHAT — FINAL DESKTOP + PHONE UI ===== */
.community-chat-page-section{width:100%!important;max-width:1120px!important;margin:0 auto!important;padding:20px 22px 34px!important;box-sizing:border-box!important}
.community-chat-page-section .community-page-top{max-width:100%!important;margin:0 0 14px!important;padding:0!important}
.community-chat-page-section .community-page-top h1{font-size:clamp(32px,4.4vw,52px)!important;letter-spacing:-.045em!important;margin:7px 0 5px!important;line-height:1!important}
.community-chat-page-section .community-page-top p{margin:0!important;font-size:12px!important;color:#74818d!important}
.community-chat-page-section .community-chat-page-card{width:100%!important;max-width:1040px!important;height:min(68vh,690px)!important;min-height:500px!important;margin:0 auto!important;padding:0!important;display:flex!important;flex-direction:column!important;overflow:hidden!important;background:#fff!important;border:1px solid #dfe5ea!important;border-radius:24px!important;box-shadow:0 18px 55px rgba(30,48,65,.10),0 2px 8px rgba(30,48,65,.04)!important}
.community-chat-page-section .community-chat-tools{height:58px!important;min-height:58px!important;box-sizing:border-box!important;display:flex!important;align-items:center!important;justify-content:space-between!important;padding:0 18px!important;margin:0!important;background:linear-gradient(180deg,#fff,#fbfcfd)!important;border-bottom:1px solid #e7ebef!important;flex:0 0 auto!important}
.community-chat-tools-left{display:flex!important;align-items:center!important;gap:8px!important;min-width:0!important;color:#17202b!important}
.community-chat-tools-left strong{font-size:13px!important;font-weight:850!important;white-space:nowrap!important}
.community-chat-tools-sub{font-size:11px!important;color:#8995a0!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
.community-chat-live-dot{width:8px!important;height:8px!important;border-radius:50%!important;background:#68b82e!important;box-shadow:0 0 0 4px #edf8e6!important;flex:0 0 8px!important}
.community-chat-page-section .community-chat-window{flex:1 1 auto!important;min-height:0!important;height:auto!important;max-height:none!important;overflow-y:auto!important;overflow-x:hidden!important;padding:20px 22px 16px!important;display:flex!important;flex-direction:column!important;gap:10px!important;background:linear-gradient(180deg,#fbfcfd 0%,#f7f9fb 100%)!important;scroll-behavior:smooth!important;overscroll-behavior:contain!important}
.community-chat-page-section .community-message{max-width:min(70%,650px)!important;padding:11px 13px!important;border-radius:17px!important;background:#fff!important;border:1px solid #e0e6eb!important;box-shadow:0 3px 12px rgba(31,45,58,.055)!important}
.community-chat-page-section .community-message.mine{background:#edf5ff!important;border-color:#d4e4f5!important;border-bottom-right-radius:6px!important;align-self:flex-end!important}
.community-chat-page-section .community-message:not(.mine){align-self:flex-start!important;border-bottom-left-radius:6px!important}
.community-chat-page-section .community-message-head{margin-bottom:4px!important}
.community-chat-page-section .community-message-head strong{font-size:11px!important;font-weight:850!important;color:#38546c!important}
.community-chat-page-section .community-message.mine .community-message-head strong{color:#2862a2!important}
.community-chat-page-section .community-message-text{font-size:14px!important;line-height:1.5!important;color:#1c2934!important;overflow-wrap:anywhere!important}
.community-chat-page-section .community-message-meta{margin-top:5px!important;font-size:9px!important;color:#8a96a0!important}
.community-chat-page-section .community-message-actions{display:flex!important;gap:5px!important;margin-top:7px!important;opacity:0!important;max-height:0!important;overflow:hidden!important;transition:opacity .16s ease,max-height .16s ease!important}
.community-chat-page-section .community-message:hover .community-message-actions,.community-chat-page-section .community-message:focus-within .community-message-actions{opacity:1!important;max-height:34px!important}
.community-chat-page-section .community-message-action{border:1px solid #d9e2e9!important;background:#fff!important;color:#53616d!important;border-radius:9px!important;padding:5px 9px!important;font-size:10px!important;font-weight:800!important;cursor:pointer!important;line-height:1!important}
.community-chat-page-section .community-message-action:hover{background:#f1f6fa!important;color:#245f92!important}
.community-chat-page-section .community-message-action.delete{color:#bd3e4c!important;border-color:#f0d5d8!important}
.community-chat-page-section .community-reply-reference{margin:0 0 7px!important;padding:7px 9px!important;background:#f3f7fa!important;border-left:3px solid #5797c9!important;border-radius:8px!important;color:#536674!important}
.community-chat-page-section .community-reply-bar{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important;margin:0!important;padding:9px 16px!important;background:#f4f8fc!important;border-top:1px solid #dfe7ee!important;border-left:3px solid #2f6fca!important;border-radius:0!important;flex:0 0 auto!important;min-height:42px!important;box-sizing:border-box!important}
.community-chat-page-section .community-reply-bar[hidden]{display:none!important}
.community-chat-page-section .community-reply-bar>div{min-width:0!important;display:flex!important;flex-direction:column!important;gap:2px!important}
.community-chat-page-section .community-reply-bar strong{font-size:10px!important;color:#2f6fca!important}
.community-chat-page-section .community-reply-bar span{font-size:11px!important;color:#6d7b87!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
.community-chat-page-section .community-reply-bar button{border:0!important;background:transparent!important;color:#6f7d88!important;font-size:21px!important;line-height:1!important;cursor:pointer!important;padding:3px 6px!important}
.community-chat-page-section .community-chat-form{display:grid!important;grid-template-columns:minmax(0,1fr) 46px!important;gap:8px!important;margin:0!important;padding:10px 12px!important;background:#fff!important;border-top:1px solid #e5e9ed!important;flex:0 0 auto!important;box-sizing:border-box!important}
.community-chat-page-section .community-chat-form textarea{width:100%!important;box-sizing:border-box!important;height:44px!important;min-height:44px!important;max-height:110px!important;resize:none!important;padding:11px 14px!important;border-radius:15px!important;background:#f5f7f9!important;color:#1e2a34!important;border:1px solid #dce3e8!important;outline:none!important;font-size:13px!important;line-height:1.4!important}
.community-chat-page-section .community-chat-form textarea:focus{background:#fff!important;border-color:#9dbfe0!important;box-shadow:0 0 0 3px rgba(47,111,202,.09)!important}
.community-chat-page-section .community-send-button{width:44px!important;height:44px!important;border:0!important;border-radius:14px!important;background:#2f6fca!important;color:#fff!important;font-size:18px!important;font-weight:850!important;cursor:pointer!important;box-shadow:0 7px 17px rgba(47,111,202,.22)!important;display:grid!important;place-items:center!important;transition:transform .15s ease,box-shadow .15s ease!important}
.community-chat-page-section .community-send-button:hover{transform:translateY(-1px)!important;box-shadow:0 10px 20px rgba(47,111,202,.26)!important}
.community-chat-page-section .community-send-button:active{transform:scale(.96)!important}
.community-chat-page-section .community-chat-disabled-note{padding:14px 18px!important;border-top:1px solid #e5e9ed!important;color:#687482!important;font-size:12px!important;background:#fff!important}
.community-chat-page-section .empty{margin:auto!important;padding:18px!important;color:#8995a0!important;text-align:center!important}
.community-chat-page-section .community-chat-keyboard-hint{display:none!important}
@media(max-width:850px){
  .community-chat-page-section{width:100%!important;max-width:100%!important;box-sizing:border-box!important;overflow-x:hidden!important;padding:8px 7px calc(84px + env(safe-area-inset-bottom))!important}
  .community-chat-page-section .community-page-top{width:100%!important;box-sizing:border-box!important;margin-bottom:8px!important;padding:0 2px!important}
  .community-chat-page-section .community-page-top h1{font-size:28px!important;margin:4px 0!important;line-height:1.02!important}
  .community-chat-page-section .community-page-top p{font-size:10.5px!important;line-height:1.35!important}
  .community-chat-page-section .community-chat-page-card{width:100%!important;max-width:100%!important;height:calc(100dvh - 205px)!important;min-height:360px!important;max-height:760px!important;border-radius:18px!important;box-sizing:border-box!important}
  .community-chat-page-section .community-chat-tools{height:46px!important;min-height:46px!important;padding:0 11px!important}
  .community-chat-tools-sub{display:none!important}
  .community-chat-tools-left strong{font-size:12px!important}
  .community-chat-live-dot{width:7px!important;height:7px!important;flex-basis:7px!important}
  .community-chat-page-section .community-chat-window{width:100%!important;box-sizing:border-box!important;padding:11px 8px 12px!important;gap:7px!important;overflow-y:auto!important;overflow-x:hidden!important;overscroll-behavior-y:contain!important;-webkit-overflow-scrolling:touch!important;scroll-behavior:auto!important;touch-action:pan-y!important}
  .community-chat-page-section .community-message{max-width:88%!important;min-width:0!important;box-sizing:border-box!important;padding:9px 10px!important;border-radius:14px!important}
  .community-chat-page-section .community-message-text{font-size:13px!important;line-height:1.45!important;overflow-wrap:anywhere!important;word-break:break-word!important}
  .community-chat-page-section .community-message-actions{opacity:1!important;max-height:34px!important;margin-top:5px!important}
  .community-chat-page-section .community-message-action{padding:6px 8px!important;font-size:10px!important;min-height:28px!important}
  .community-chat-page-section .community-reply-bar{padding:7px 10px!important;min-width:0!important}
  .community-chat-page-section .community-reply-bar span{font-size:10px!important}
  .community-chat-page-section .community-chat-form{width:100%!important;box-sizing:border-box!important;grid-template-columns:minmax(0,1fr) 42px!important;padding:7px 7px calc(7px + env(safe-area-inset-bottom))!important;gap:6px!important}
  .community-chat-page-section .community-chat-form textarea{width:100%!important;height:42px!important;min-height:42px!important;max-height:96px!important;box-sizing:border-box!important;border-radius:14px!important;padding:10px 12px!important;font-size:13px!important}
  .community-chat-page-section .community-send-button{width:42px!important;height:42px!important;border-radius:13px!important;font-size:17px!important}
}
@media(max-width:390px){
  .community-chat-page-section{padding-left:5px!important;padding-right:5px!important}
  .community-chat-page-section .community-page-top h1{font-size:25px!important}
  .community-chat-page-section .community-chat-page-card{height:calc(100dvh - 192px)!important;min-height:340px!important;border-radius:16px!important}
  .community-chat-page-section .community-chat-window{padding-left:6px!important;padding-right:6px!important}
  .community-chat-page-section .community-message{max-width:91%!important}
  .community-chat-page-section .community-chat-form{grid-template-columns:minmax(0,1fr) 40px!important}
  .community-chat-page-section .community-send-button{width:40px!important;height:40px!important}
  .community-chat-page-section .community-chat-form textarea{height:40px!important;min-height:40px!important}
}
@media(max-width:390px){
  .community-chat-page-section{padding-left:8px!important;padding-right:8px!important}
  .community-chat-page-section .community-page-top h1{font-size:27px!important}
  .community-chat-page-section .community-chat-page-card{height:calc(100dvh - 216px)!important;min-height:400px!important;border-radius:18px!important}
  .community-chat-page-section .community-chat-tools{padding:0 11px!important}
  .community-chat-page-section .community-chat-window{padding-left:7px!important;padding-right:7px!important}
  .community-chat-page-section .community-message{max-width:92%!important}
}
</style>'''
    body = chat_style + f'''<section class="section community-page-section community-chat-page-section">
      <div class="community-page-top"><a class="community-back-link" href="/community">‹ Community</a><div class="badge">CHAT WITH STUDENTS</div><h1>Campus conversation.</h1><p class="muted">{status_text} · Student IDs are never shown here.</p></div>
      <div class="community-chat-card community-chat-page-card">{chat_panel}</div>
    </section>
    <script>
    (function() {{
      const chatWindow=document.querySelector('.community-chat-window');
      const form=document.getElementById('community-send-form');
      const sendBox=form?form.querySelector('textarea[name=\"message\"]'):null;
      const replyBar=document.getElementById('community-reply-bar'), replyTo=document.getElementById('community-reply-to'), replyTitle=document.getElementById('community-reply-title'), replyPreview=document.getElementById('community-reply-preview'), replyCancel=document.getElementById('community-reply-cancel');
      let busy=false;
      function clearReply() {{ if(replyTo)replyTo.value=''; if(replyBar)replyBar.hidden=true; }}
      function startReply(m) {{ if(!m||!replyTo)return; const id=m.dataset.messageId, n=m.querySelector('.community-message-head strong'), t=m.querySelector('.community-message-text'); if(!id||!t)return; replyTo.value=id; replyTitle.textContent='Replying to '+(n?n.textContent:'Student'); replyPreview.textContent=t.textContent.slice(0,120); replyBar.hidden=false; if(sendBox)sendBox.focus(); }}
      function wire(root) {{ root.querySelectorAll('.community-reply-action').forEach(function(b){{if(b.dataset.bound)return;b.dataset.bound='1';b.onclick=function(e){{e.stopPropagation();startReply(document.getElementById('community-msg-'+b.dataset.messageId));}};}}); root.querySelectorAll('.community-delete-one-action').forEach(function(b){{if(b.dataset.bound)return;b.dataset.bound='1';b.onclick=function(e){{e.stopPropagation();if(!confirm('Delete this message?'))return;const id=String(b.dataset.messageId),node=document.getElementById('community-msg-'+id);if(node){{node.style.transition='opacity .12s ease,transform .12s ease';node.style.opacity='0';node.style.transform='translateX(10px)';setTimeout(function(){{if(node&&node.parentNode)node.remove();}},120);}}const fd=new FormData();fd.append('action','delete_one');fd.append('message_id',id);fetch('/community/chat',{{method:'POST',body:fd,credentials:'same-origin',headers:{{'X-VYBE-Live-Chat':'1'}}}}).then(function(r){{if(!r.ok)throw new Error('delete failed');return r.json();}}).then(function(){{}}).catch(function(){{refresh(true);}});}};}}); }}
      function build(m) {{ const mine=String(m.student_id)==String({my_id}),w=document.createElement('div');w.className='community-message'+(mine?' mine':'');w.id='community-msg-'+m.id;w.dataset.messageId=m.id;const c=document.createElement('div');c.className='community-message-content';const h=document.createElement('div');h.className='community-message-head';const st=document.createElement('strong');st.textContent=m.name||'Student';h.appendChild(st);c.appendChild(h);if(m.reply_to_id&&m.reply_message){{const r=document.createElement('div');r.className='community-reply-reference';const a=document.createElement('strong');a.textContent='Replying to '+(m.reply_name||'Student');const q=document.createElement('span');q.textContent=String(m.reply_message).slice(0,120);r.append(a,q);c.appendChild(r);}}const t=document.createElement('div');t.className='community-message-text';t.textContent=m.message||'';c.appendChild(t);const meta=document.createElement('div');meta.className='community-message-meta';meta.textContent=String(m.created_at||'').slice(-5);c.appendChild(meta);const ac=document.createElement('div');ac.className='community-message-actions';const rb=document.createElement('button');rb.type='button';rb.className='community-message-action community-reply-action';rb.dataset.messageId=m.id;rb.textContent='Reply';ac.appendChild(rb);if(mine){{const db=document.createElement('button');db.type='button';db.className='community-message-action delete community-delete-one-action';db.dataset.messageId=m.id;db.textContent='Delete';ac.appendChild(db);}}c.appendChild(ac);w.appendChild(c);return w; }}
      async function refresh(force) {{ if(!chatWindow||busy)return;busy=true;try{{const near=chatWindow.scrollHeight-chatWindow.scrollTop-chatWindow.clientHeight<100;let last=0;chatWindow.querySelectorAll('.community-message').forEach(function(e){{last=Math.max(last,Number(e.dataset.messageId)||0);}});const res=await fetch('/community/chat/messages?after_id='+encodeURIComponent(last)+'&t='+Date.now(),{{credentials:'same-origin',cache:'no-store',headers:{{Accept:'application/json'}}}});if(!res.ok)return;const data=await res.json(),msgs=Array.isArray(data.messages)?data.messages:[];msgs.forEach(function(m){{if(!chatWindow.querySelector('[data-message-id="'+String(m.id)+'"]')){{chatWindow.appendChild(build(m));}}const temp=[...chatWindow.querySelectorAll('[data-message-id^="temp-"]')].find(function(x){{return x.dataset.tempMessage===String(m.message);}});if(temp)temp.remove();}});wire(chatWindow);if(msgs.length&&(force||near))chatWindow.scrollTo({{top:chatWindow.scrollHeight,behavior:'auto'}});}}catch(_){{}}finally{{busy=false;}} }}
      wire(document); if(chatWindow){{chatWindow.scrollTop=chatWindow.scrollHeight;setInterval(function(){{if(document.visibilityState==='visible')refresh(false);}},1200);}} if(replyCancel)replyCancel.onclick=clearReply;
      if(form&&sendBox){{sendBox.addEventListener('input',function(){{this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px';}});form.addEventListener('submit',function(e){{e.preventDefault();const txt=sendBox.value.trim();if(!txt)return;const fd=new FormData(form);sendBox.value='';sendBox.style.height='46px';clearReply();const tempId='temp-'+Date.now();const optimistic={{id:tempId,student_id:{my_id},name:'You',message:txt,created_at:'',reply_to_id:null,reply_message:null,reply_name:null}};chatWindow.appendChild(build(optimistic));const tempNode=chatWindow.querySelector('[data-message-id="'+tempId+'"]');if(tempNode)tempNode.dataset.tempMessage=txt;chatWindow.scrollTo({{top:chatWindow.scrollHeight,behavior:'auto'}});sendBox.disabled=true;fetch(form.action,{{method:'POST',body:fd,credentials:'same-origin',headers:{{'X-VYBE-Live-Chat':'1'}}}}).then(function(r){{if(!r.ok)throw new Error('send failed');return r.json();}}).then(function(){{return refresh(true);}}).catch(function(){{if(tempNode)tempNode.remove();sendBox.value=txt;}}).finally(function(){{sendBox.disabled=false;sendBox.focus();}});}});sendBox.addEventListener('keydown',function(e){{if(e.key==='Enter'&&!e.shiftKey){{e.preventDefault();form.requestSubmit();}}}});}}
    }})();
    </script>'''
    return layout("Chat with Students", body)



@app.route("/community/chat/messages", methods=["GET"])
@student_required
def community_chat_messages():
    """Fast incremental chat feed; after the initial load only new messages are read."""
    con = db()
    try:
        try:
            after_id = max(0, int(request.args.get("after_id", "0")))
        except (TypeError, ValueError):
            after_id = 0
        if after_id:
            rows = con.execute(
                "SELECT cm.id, cm.student_id, cm.message, cm.created_at, cm.reply_to_id, "
                "s.name, r.message AS reply_message, rs.name AS reply_name "
                "FROM community_messages cm "
                "JOIN students s ON s.id=cm.student_id "
                "LEFT JOIN community_messages r ON r.id=cm.reply_to_id "
                "LEFT JOIN students rs ON rs.id=r.student_id "
                "WHERE cm.id>? ORDER BY cm.id ASC LIMIT 100",
                (after_id,),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT cm.id, cm.student_id, cm.message, cm.created_at, cm.reply_to_id, "
                "s.name, r.message AS reply_message, rs.name AS reply_name "
                "FROM community_messages cm "
                "JOIN students s ON s.id=cm.student_id "
                "LEFT JOIN community_messages r ON r.id=cm.reply_to_id "
                "LEFT JOIN students rs ON rs.id=r.student_id "
                "ORDER BY cm.id DESC LIMIT 300"
            ).fetchall()
            rows = list(reversed(rows))
        return jsonify({"messages": [
            {"id": int(r["id"]), "student_id": int(r["student_id"]), "name": r["name"],
             "message": r["message"], "created_at": r["created_at"],
             "reply_to_id": int(r["reply_to_id"]) if r["reply_to_id"] else None,
             "reply_message": r["reply_message"], "reply_name": r["reply_name"]}
            for r in rows
        ]})
    finally:
        con.close()


@app.route("/community/problems", methods=["GET", "POST"])
@student_required
def community_problems():
    con = db()
    if request.method == "POST":
        # This endpoint handles BOTH actions from the page:
        # 1) the top "Report a problem" form (title + description)
        # 2) the solution form attached to an existing problem (issue_id + text)
        # The previous version treated every POST as a solution, so the report
        # form was incorrectly rejected with "Please enter a valid solution.".
        raw_issue_id = request.form.get("issue_id", "").strip()
        try:
            iid = int(raw_issue_id) if raw_issue_id else 0
        except (TypeError, ValueError):
            iid = 0

        # Existing problem -> post a student solution.
        if iid > 0:
            text = request.form.get("text", "").strip()[:1500]
            if not text:
                con.close(); flash("Please enter a solution before posting it."); return redirect(url_for("community_problems") + f"#problem-{iid}")
            try:
                issue = con.execute("SELECT id, student_id FROM issues WHERE id=?", (iid,)).fetchone()
                if not issue:
                    con.rollback(); con.close(); flash("That problem is no longer available."); return redirect(url_for("community_problems"))
                if issue["student_id"] == session["student_db_id"]:
                    con.rollback(); con.close(); flash("You cannot post a solution to your own problem."); return redirect(url_for("community_problems") + f"#problem-{iid}")
                con.execute("INSERT INTO solutions(issue_id,student_id,text,created_at) VALUES(?,?,?,?)", (iid, session["student_db_id"], text, now()))
                con.commit(); con.close(); flash("Solution posted successfully."); return redirect(url_for("community_problems") + f"#problem-{iid}")
            except Exception:
                con.rollback(); con.close(); app.logger.exception("Community solution post failed")
                flash("We couldn't post that solution right now. Please try again."); return redirect(url_for("community_problems") + f"#problem-{iid}")

        # No issue_id -> this is the student's own problem report.
        category = request.form.get("category", "General").strip()[:80] or "General"
        title = request.form.get("title", "").strip()[:120]
        description = request.form.get("description", "").strip()[:2000]
        if not title or not description:
            con.close(); flash("Please enter a problem title and describe what is happening."); return redirect(url_for("community_problems"))
        try:
            con.execute(
                "INSERT INTO issues(student_id,category,title,description,status,created_at) VALUES(?,?,?,?,?,?)",
                (session["student_db_id"], category, title, description, "Open", now())
            )
            con.commit()
            # Keep an admin-side audit notification as a secondary signal.
            # The bell itself reads live open issues, so this can never block the report.
            try:
                reporter=con.execute("SELECT name,student_id FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
                if reporter:
                    create_admin_notification(
                        "student_problem",
                        f"New student problem: {title}",
                        f"{reporter['name']} ({reporter['student_id']}) reported {category}: {description}",
                        student_id=session["student_db_id"],
                    )
            except Exception as exc:
                app.logger.warning("Student problem admin notification failed: %s", exc)
            con.close(); flash("Problem reported successfully. Students and VYBE admin can now help."); return redirect(url_for("community_problems"))
        except Exception:
            con.rollback(); con.close(); app.logger.exception("Community problem report failed")
            flash("We couldn't submit your problem right now. Please try again."); return redirect(url_for("community_problems"))
    issues_rows = con.execute("SELECT i.*, s.name AS reporter_name FROM issues i JOIN students s ON s.id=i.student_id ORDER BY i.id DESC LIMIT 80").fetchall()
    solutions = con.execute("SELECT so.*, s.name AS author_name FROM solutions so JOIN students s ON s.id=so.student_id ORDER BY so.id ASC").fetchall()
    by_issue = {}
    for sol in solutions: by_issue.setdefault(sol["issue_id"], []).append(sol)
    blocks = ""
    for i in issues_rows:
        sols = by_issue.get(i["id"], [])
        sol_html = "".join(_render_solution_card(s, session["student_db_id"]) for s in sols)
        other_solution = any(s["student_id"] != session["student_db_id"] for s in sols)
        accept = ""
        if i["student_id"] == session["student_db_id"] and other_solution:
            accept = f'''<form method="post" action="/community/problem/{i["id"]}/accept" onsubmit="return confirm('Accept a solution? This deletes the problem and its entire chat.')"><button class="btn good">&#10003; Accept solution &amp; delete chat</button></form>'''
        empty_solutions = '<div class="empty">No solutions yet. Be the first to help.</div>'
        blocks += f'''<div class="card community-problem-card" id="problem-{i["id"]}"><div class="resource-meta"><span class="pill">{esc(i["category"])}</span><span class="pill">{esc(i["status"])}</span></div><h2>{esc(i["title"])}</h2><p class="muted">{esc(i["description"])}</p><p class="small">Reported by {esc(i["reporter_name"])} · {esc(i["created_at"])}</p><div class="chat">{sol_html or empty_solutions}</div><form class="form" method="post" style="margin-top:14px"><input type="hidden" name="issue_id" value="{i["id"]}"><textarea name="text" maxlength="1500" placeholder="Suggest a practical solution..." required></textarea><button class="btn dark" type="submit">Post solution</button></form>{accept}</div>'''
    my_rows = con.execute("SELECT * FROM issues WHERE student_id=? ORDER BY id DESC", (session["student_db_id"],)).fetchall()
    saved = con.execute("SELECT * FROM saved_reports WHERE student_id=? ORDER BY id DESC", (session["student_db_id"],)).fetchall()
    con.close()
    my_cards = "".join(f'<div class="card"><span class="pill">{esc(x["status"])}</span><h3>{esc(x["title"])}</h3><p class="small">{esc(x["category"])} · {esc(x["created_at"])}</p><p class="muted">{esc(x["description"])}</p><div class="actions"><a class="btn dark" href="/community/problems#problem-{x["id"]}">Open community chat →</a><form method="post" action="/community/problem/{x["id"]}/delete" onsubmit="return confirm(&quot;Delete this problem and its solutions? This cannot be undone.&quot;)"><button class="btn danger" type="submit">Delete my problem</button></form></div></div>' for x in my_rows)
    saved_cards = "".join(f'<div class="feed-item"><strong>{esc(x["issue_title"])}</strong><p class="muted">{esc(x["issue_description"])}</p><p class="small">Accepted solution: {esc(x["solution_text"])} · from {esc(x["solver_name"])} · {esc(x["saved_at"])}</p></div>' for x in saved)
    empty_problems = '<div class="empty">No campus problems have been reported yet. Be the first to report one.</div>'
    body = f'''{COMMUNITY_PROBLEM_ACTIONS_CSS}<section class="section community-page-section"><div class="community-page-top"><a class="community-back-link" href="/community">‹ Community</a><div class="badge">SOLVE CAMPUS PROBLEM</div><h1>Help fix what matters.</h1><p class="muted">Report a problem or share practical solutions for problems reported by students.</p></div>
<section class="section"><div class="two"><div class="card"><h2>Report a problem</h2><form class="form" method="post"><select name="category">{"".join(f'<option>{esc(c)}</option>' for c in CATEGORIES)}</select><input name="title" maxlength="120" placeholder="Short problem title" required><textarea name="description" maxlength="2000" placeholder="What is happening?" required></textarea><button class="btn accent">Submit report</button></form></div><div><h2>My reports</h2>{my_cards or '<div class="empty">No active reports yet.</div>'}</div></div></section>
<section class="section"><div class="card"><h2> Saved Reports</h2><p class="muted">When you accept a solution, VYBE saves the report and accepted solution here.</p><div class="feed-list">{saved_cards or '<div class="empty">No saved reports yet.</div>'}</div></div></section>
<section class="section"><h2>Campus problems</h2><div class="community-problem-list">{blocks or empty_problems}</div></section></section>'''
    return layout("Solve Campus Problem", body)


@app.route("/community/problem/<int:iid>/delete", methods=["POST"])
@student_required
def delete_my_problem(iid):
    con = db()
    try:
        issue = con.execute("SELECT id,student_id,title FROM issues WHERE id=?", (iid,)).fetchone()
        if not issue:
            con.close(); flash("That problem no longer exists."); return redirect(url_for("community_problems"))
        if int(issue["student_id"]) != int(session["student_db_id"]):
            con.close(); abort(403)

        # Remove everything attached to this report first. This keeps the
        # feature compatible with existing VYBE databases and avoids relying
        # on an issue_id column in accepted_solutions, which older schemas do
        # not have.
        con.execute("DELETE FROM helpful_votes WHERE solution_id IN (SELECT id FROM solutions WHERE issue_id=?)", (iid,))
        con.execute("DELETE FROM accepted_solutions WHERE student_id=? AND issue_title=?", (issue["student_id"], issue["title"]))
        con.execute("DELETE FROM admin_problem_solutions WHERE issue_id=?", (iid,))
        con.execute("DELETE FROM solutions WHERE issue_id=?", (iid,))
        con.execute("DELETE FROM issues WHERE id=?", (iid,))
        con.commit()
        flash("Your campus problem was deleted.")
    except Exception:
        con.rollback()
        app.logger.exception("Student problem deletion failed")
        flash("We couldn't delete that problem right now. Please try again.")
    finally:
        con.close()
    return redirect(url_for("community_problems"))


@app.route("/community/solution/<int:solution_id>/helpful", methods=["POST"])
@student_required
def mark_solution_helpful(solution_id):
    con=db()
    try:
        sol=con.execute("SELECT student_id FROM solutions WHERE id=?",(solution_id,)).fetchone()
        if not sol: con.close(); flash("That solution is no longer available."); return redirect(url_for("community_problems"))
        if sol["student_id"]==session["student_db_id"]: con.close(); flash("You cannot mark your own answer helpful."); return redirect(url_for("community_problems"))
        con.execute("INSERT INTO helpful_votes(solution_id,voter_id,created_at) VALUES(?,?,?)",(solution_id,session["student_db_id"],now()))
        con.execute("UPDATE students SET reputation_points=COALESCE(reputation_points,0)+5,helpful_answers=COALESCE(helpful_answers,0)+1 WHERE id=?",(sol["student_id"],))
        con.commit(); flash("Marked as helpful. +5 VYBE points to the helper.")
    except Exception:
        con.rollback(); flash("You already marked this answer helpful, or it is no longer available.")
    finally: con.close()
    return redirect(url_for("community_problems"))


@app.route("/community/problem/<int:iid>/accept", methods=["POST"])
@student_required
def accept_solution(iid):
    con = db()
    try:
        issue = con.execute("SELECT student_id FROM issues WHERE id=?", (iid,)).fetchone()
        if not issue or issue["student_id"] != session["student_db_id"]:
            con.close(); abort(403)
        accepted = con.execute("SELECT student_id FROM solutions WHERE issue_id=? AND student_id<>? ORDER BY id ASC LIMIT 1", (iid, session["student_db_id"])).fetchone()
        if not accepted:
            con.close(); flash("A solution from another student is required first."); return redirect(url_for("community_problems") + f"#problem-{iid}")
        issue=con.execute("SELECT title,category,description FROM issues WHERE id=?",(iid,)).fetchone()
        accepted_detail=con.execute("SELECT text FROM solutions WHERE issue_id=? AND student_id=? ORDER BY id ASC LIMIT 1",(iid,accepted["student_id"])).fetchone()
        solver=con.execute("SELECT name FROM students WHERE id=?",(accepted["student_id"] ,)).fetchone()
        if issue and accepted_detail and solver:
            con.execute("INSERT INTO saved_reports(student_id,issue_title,issue_category,issue_description,solution_text,solver_name,saved_at) VALUES(?,?,?,?,?,?,?)",(session["student_db_id"],issue["title"],issue["category"],issue["description"],accepted_detail["text"],solver["name"],now()))
            con.execute("INSERT INTO accepted_solutions(student_id,issue_title,solution_text,solver_name,accepted_at) VALUES(?,?,?,?,?)",(session["student_db_id"],issue["title"],accepted_detail["text"],solver["name"],now()))
        con.execute("UPDATE students SET reputation_points=COALESCE(reputation_points,0)+25, helpful_answers=COALESCE(helpful_answers,0)+1, accepted_solutions=COALESCE(accepted_solutions,0)+1 WHERE id=?", (accepted["student_id"],))
        con.execute("DELETE FROM solutions WHERE issue_id=?", (iid,))
        con.execute("DELETE FROM issues WHERE id=?", (iid,))
        con.commit()
        con.close()
        flash("Problem solved. The problem and its entire community chat were deleted.")
        return redirect(url_for("community_problems"))
    except Exception:
        try: con.rollback()
        except Exception: pass
        try: con.close()
        except Exception: pass
        app.logger.exception("Accept solution failed for issue %s", iid)
        flash("We couldn't accept that solution right now. Please try again.")
        return redirect(url_for("community_problems") + f"#problem-{iid}")


# ---------------------------------------------------------------------------
# Admin authentication and control center
# ---------------------------------------------------------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    """Admin login: passkey-only OR password followed by passkey."""
    con = db()
    passkey_count = con.execute("SELECT COUNT(*) AS c FROM passkeys").fetchone()["c"]
    con.close()

    if request.method == "POST":
        password = request.form.get("password", "")
        con = db()
        stored = admin_password_hash(con)
        ok = check_password(password, stored)
        record_admin_login(con, ok, "password_login")
        if not ok:
            blocked, until, _ = _security_failed_login(con, "Admin", "", "Admin")
            con.close()
            if blocked: return _security_block_page(until), 429, {"Cache-Control":"no-store","X-Robots-Tag":"noindex, nofollow"}
            session["admin_login_password_error"] = True
            flash("Incorrect admin password.")
            return redirect(url_for("admin_login"))
        _security_successful_login(con, "Admin", "admin")
        con.commit(); con.close()

        session.clear()
        session.permanent = True
        session["admin_authenticated"] = True
        session["admin_password_verified"] = True
        session["passkey_verified"] = False
        session["_csrf_token"] = secrets.token_urlsafe(32)

        if passkey_count == 0:
            flash("Password accepted. Register your first admin passkey before using the dashboard.")
            return redirect(url_for("admin_password"))
        return redirect(url_for("admin_verify"))

    password_error = bool(session.pop("admin_login_password_error", False))
    body = f"""<div class=\"auth vybe-auth-page\"><div class=\"card authbox\"><a class=\"vybe-auth-logo\" href=\"/\" aria-label=\"VYBE home\">V</a><div class=\"badge\">PRIVATE CONTROL CENTER</div>
    <h1>Admin access.</h1>
    <p class=\"muted\">Choose how you want to sign in.</p>
    <div class=\"card\" style=\"margin:16px 0;padding:18px\">
      <h2> Passkey</h2>
      <p class=\"small\">Use your registered phone/device passkey. No admin password is required.</p>
      <button class=\"btn accent\" id=\"loginPasskey\" type=\"button\" {('disabled' if passkey_count == 0 else '')}>Continue with Passkey →</button>
      <div id=\"loginPkMsg\" class=\"small\" style=\"margin-top:10px\"></div>
      {('<div class=\"small\" style=\"margin-top:8px\">No passkey is registered yet. Use the password option below to set up your first passkey.</div>' if passkey_count == 0 else '')}
    </div>
    <div class=\"card\" style=\"padding:18px\">
      <h2> Admin Password</h2>
      <p class=\"small\">Password login is not enough by itself. After the password is accepted, VYBE will require your registered passkey.</p>
      <form class=\"form\" method=\"post\">
        <div class="password-wrap{" password-error" if password_error else ""}"><input id="adminLoginPassword" type="password" name="password" required autocomplete="current-password" placeholder="Admin password"><button type="button" class="password-toggle toggle-password" data-target="adminLoginPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6 9.5-6 9.5-6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div>
        <button class=\"btn dark\" type=\"submit\">Use Password →</button>
      </form>
    </div><div class="vybe-auth-back-row"><a class="vybe-auth-back" href="/">← Back</a><span class="vybe-auth-hint">Private administration · protected access</span></div></div></div><script>{WEBAUTHN_JS}</script>"""
    return layout("Admin Login", body)


@app.route("/admin/login-passkey/options", methods=["POST"])
def admin_login_passkey_options():
    if not webauthn_configured():
        return jsonify(error="WebAuthn is not configured on this server."), 503
    con = db()
    rows = con.execute("SELECT credential_id FROM passkeys").fetchall()
    con.close()
    if not rows:
        return jsonify(error="No admin passkey is registered yet."), 400
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in rows]
    options = generate_authentication_options(rp_id=PASSKEY_RP_ID, allow_credentials=allow, user_verification=UserVerificationRequirement.REQUIRED)
    session["admin_login_passkey_challenge"] = base64.b64encode(options.challenge).decode("ascii")
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.route("/admin/login-passkey/verify", methods=["POST"])
def admin_login_passkey_verify():
    if not webauthn_configured():
        return jsonify(error="WebAuthn is not configured on this server."), 503
    challenge_b64 = session.pop("admin_login_passkey_challenge", None)
    if not challenge_b64:
        return jsonify(error="Passkey challenge expired. Try again."), 400
    try:
        credential = request.get_json(force=True)
        cid = credential.get("id", "")
        con = db()
        row = con.execute("SELECT * FROM passkeys WHERE credential_id=?", (cid,)).fetchone()
        if not row:
            con.close()
            return jsonify(error="Unknown admin passkey."), 403
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64.b64decode(challenge_b64),
            expected_rp_id=PASSKEY_RP_ID,
            expected_origin=PASSKEY_ORIGIN,
            credential_public_key=base64.urlsafe_b64decode(row["public_key"] + "=" * ((4-len(row["public_key"])%4)%4)),
            credential_current_sign_count=int(row["sign_count"]),
            require_user_verification=True,
        )
        con.execute("UPDATE passkeys SET sign_count=?,device_type=?,backed_up=? WHERE id=?", (int(verification.new_sign_count), str(verification.credential_device_type), bool(verification.credential_backed_up), row["id"]))
        record_admin_login(con, True, "passkey_login")
        con.commit()
        con.close()
        session.clear()
        session.permanent = True
        session["admin_authenticated"] = True
        session["passkey_verified"] = True
        session["_csrf_token"] = secrets.token_urlsafe(32)
        return jsonify(ok=True)
    except Exception as exc:
        try:
            con = db()
            record_admin_login(con, False, "passkey_login")
            con.commit()
            con.close()
        except Exception:
            pass
        session.clear()
        return jsonify(error="Passkey verification failed.", detail=str(exc) if app.debug else None), 403


@app.route("/admin/security-alerts")
@admin_required
def admin_security_alerts():
    con = db()
    try:
        alerts = con.execute("SELECT * FROM vybe_security_alerts ORDER BY id DESC LIMIT 200").fetchall()
        blocks = con.execute("SELECT * FROM vybe_security_devices WHERE blocked_until>? ORDER BY blocked_until DESC", (time.time(),)).fetchall()
    finally:
        con.close()

    def block_time(ts):
        try:
            return datetime.fromtimestamp(float(ts), timezone.utc).astimezone().strftime("%d %b %Y, %I:%M %p")
        except Exception:
            return "—"

    if blocks:
        cards = []
        for r in blocks:
            cards.append(f'''<article class="security-block-card">
              <div class="security-block-main"><div class="security-avatar">!</div><div><div class="security-user">{esc(r["last_name"] or "Unknown")}</div><div class="security-meta">{esc(r["last_student_id"] or "—")} · {esc(r["last_area"] or "—")}</div></div></div>
              <div class="security-block-grid"><div><span>IP ADDRESS</span><b>{esc(r["last_ip"] or "—")}</b></div><div><span>BLOCKED UNTIL</span><b>{block_time(r["blocked_until"])}</b></div><div><span>FAILED ATTEMPTS</span><b>{int(r["failed_attempts"] or 0)}</b></div></div>
              <form method="post" action="/admin/security-alerts/unblock/{quote(str(r["device_hash"]), safe="")}" onsubmit="return confirm('Remove this 24-hour VYBE security block and allow this user to log in again?')"><button class="btn good security-unblock">✓ Remove Block</button></form>
            </article>''')
        active = "".join(cards)
    else:
        active = '<div class="security-empty"><div>✓</div><strong>No active blocks</strong><span>VYBE has no devices currently restricted.</span></div>'

    rows = "".join(
        f'''<tr><td>{esc(r["created_at"])}</td><td><strong>{esc(r["name"] or "Unknown")}</strong><br><span class="small">{esc(r["student_id"] or "—")}</span></td><td>{esc(r["ip_address"] or "—")}</td><td>{esc(r["area"] or "—")}</td><td>{esc(r["message"] or "—")}</td><td><form method="post" action="/admin/security-alerts/delete/{int(r["id"])}" onsubmit="return confirm('Delete this security history entry?')"><button class="btn danger security-history-delete" type="submit">Delete</button></form></td></tr>'''
        for r in alerts
    ) or '<tr><td colspan="6">No security alerts yet.</td></tr>'

    body = f'''<section class="section security-center-page">
      <div class="security-center-head"><div><a href="/admin/password" class="admin-back">← Password Access</a><div class="badge" style="margin-top:14px">VYBE SECURITY</div><h1>Security alerts.</h1><p class="muted">Review temporary login blocks created after three failed password attempts. The IP is recorded for investigation, but it is not the primary block key.</p></div><div class="security-summary"><strong>{len(blocks)}</strong><span>currently blocked</span></div></div>
      <section class="security-panel"><div class="security-panel-head"><div><span class="security-kicker">ACTION REQUIRED</span><h2>Currently blocked</h2><p>Remove a block when you have confirmed the student is genuine. Removing it resets the failed-attempt counter and allows immediate login.</p></div><a class="btn dark" href="/admin/password">← Password Access</a></div><div class="security-block-list">{active}</div></section>
      <section class="security-panel"><div class="security-panel-head"><div><span class="security-kicker">AUDIT TRAIL</span><h2>Security alert history</h2><p>Unblock actions are recorded here instead of deleting the original security event.</p></div></div><div class="tablewrap"><table><tr><th>Time</th><th>User</th><th>IP address</th><th>Area</th><th>Event</th><th>Action</th></tr>{rows}</table></div></section>
    </section>
    <style>.security-center-page{{max-width:1080px;margin:0 auto}}.security-center-head{{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin-bottom:22px}}.security-center-head h1{{margin:8px 0}}.security-summary{{min-width:145px;padding:20px;border:1px solid rgba(255,255,255,.09);border-radius:18px;background:rgba(255,255,255,.035);text-align:center}}.security-summary strong{{display:block;font-size:30px}}.security-summary span{{display:block;color:#9fb3c0;font-size:12px;margin-top:3px}}.security-panel{{margin-top:18px;padding:20px;border:1px solid rgba(255,255,255,.08);border-radius:20px;background:rgba(255,255,255,.025)}}.security-panel-head{{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:16px}}.security-panel-head h2{{margin:5px 0}}.security-panel-head p{{max-width:680px;margin:0;color:#9fb3c0}}.security-kicker{{font-size:10px;letter-spacing:.14em;font-weight:850;color:#7dc4e8}}.security-block-list{{display:grid;gap:12px}}.security-block-card{{padding:17px;border:1px solid rgba(255,112,112,.16);border-radius:17px;background:linear-gradient(145deg,rgba(255,82,82,.055),rgba(255,255,255,.025))}}.security-block-main{{display:flex;gap:12px;align-items:center}}.security-avatar{{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:rgba(255,100,100,.12);color:#ff9c9c;font-weight:900}}.security-user{{font-weight:850;font-size:16px}}.security-meta{{color:#9fb3c0;font-size:12px;margin-top:3px}}.security-block-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:15px 0}}.security-block-grid div{{padding:11px 12px;border-radius:12px;background:rgba(255,255,255,.035)}}.security-block-grid span{{display:block;font-size:9px;letter-spacing:.12em;color:#8299a8;margin-bottom:5px}}.security-block-grid b{{font-size:12px;word-break:break-word}}.security-empty{{padding:34px;text-align:center;color:#9fb3c0}}.security-empty div{{font-size:26px;color:#76d59a;margin-bottom:7px}}.security-empty strong{{display:block;color:#eef8ff}}.security-empty span{{display:block;font-size:12px;margin-top:4px}}.security-history-delete{{min-height:34px!important;padding:0 11px!important;font-size:10px!important}}.security-center-page .tablewrap td:last-child{{white-space:nowrap}}@media(max-width:700px){{.security-center-head,.security-panel-head{{display:block}}.security-summary{{margin-top:16px}}.security-panel-head .btn{{display:inline-flex;margin-top:12px}}.security-block-grid{{grid-template-columns:1fr}}}}</style>'''
    return layout("Security Alerts", body, admin=True)


@app.route("/admin/security-alerts/delete/<int:alert_id>", methods=["POST"])
@admin_required
def admin_security_alert_delete(alert_id):
    con = db()
    try:
        row = con.execute("SELECT id FROM vybe_security_alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            con.close()
            flash("That security history entry no longer exists.")
            return redirect(url_for("admin_security_alerts"))
        con.execute("DELETE FROM vybe_security_alerts WHERE id=?", (alert_id,))
        con.commit()
        con.close()
        flash("Security history entry deleted.")
    except Exception:
        try: con.rollback()
        except Exception: pass
        con.close()
        flash("We could not delete that security history entry. Please try again.")
    return redirect(url_for("admin_security_alerts"))


@app.route("/admin/security-alerts/unblock/<device_hash>", methods=["POST"])
@admin_required
def admin_security_unblock(device_hash):
    con = db()
    try:
        row = con.execute("SELECT * FROM vybe_security_devices WHERE device_hash=?", (device_hash,)).fetchone()
        if not row:
            con.close()
            flash("That security block no longer exists.")
            return redirect(url_for("admin_security_alerts"))
        # A student may have more than one VYBE device record (for example
        # after clearing cookies or switching between phone/desktop). Remove
        # every active block belonging to this student, not just the one
        # device card the admin happened to click. This prevents another
        # device row from continuing to return the 429 security page.
        student_id = str(row["last_student_id"] or "").strip()
        if student_id:
            device_rows = con.execute(
                "SELECT device_hash,last_area,last_ip FROM vybe_security_devices WHERE last_student_id=? AND blocked_until>?",
                (student_id, time.time()),
            ).fetchall()
            con.execute(
                "UPDATE vybe_security_devices SET failed_attempts=0, first_failed_at=0, blocked_until=0, updated_at=? WHERE last_student_id=?",
                (now(), student_id),
            )
            account_keys = []
            for area in {str(r["last_area"] or "Student").strip() or "Student" for r in device_rows} or {str(row["last_area"] or "Student").strip() or "Student"}:
                account_keys.append(hashlib.sha256((area.lower() + "|" + student_id.lower()).encode("utf-8")).hexdigest())
            if account_keys:
                placeholders = ",".join("?" for _ in account_keys)
                con.execute(
                    f"DELETE FROM vybe_security_attempts WHERE account_key IN ({placeholders}) AND area IS NOT NULL AND area != ''",
                    tuple(account_keys),
                )
            for device_row in device_rows:
                _security_cache_set(device_row["device_hash"], 0)
        else:
            device_rows = []
            con.execute("UPDATE vybe_security_devices SET failed_attempts=0, first_failed_at=0, blocked_until=0, updated_at=? WHERE device_hash=?", (now(), device_hash))
            con.execute("DELETE FROM vybe_security_attempts WHERE device_hash=?", (device_hash,))
            _security_cache_set(device_hash, 0)

        con.execute("INSERT INTO vybe_security_alerts(created_at,alert_type,name,student_id,ip_address,area,blocked_until,message) VALUES(?,?,?,?,?,?,?,?)",
                     (now_ist(), "admin_unblock", row["last_name"] or "Unknown", student_id, row["last_ip"] or "", row["last_area"] or "", 0, "Security block manually removed by an administrator; all active device blocks for this student were cleared."))
        con.commit()
        _security_cache_set(row["device_hash"], 0)
        con.close()
        flash(f'Security block removed for {row["last_name"] or "the user"}. All active VYBE device blocks for this student were cleared, so they can log in again immediately.')
    except Exception:
        try: con.rollback()
        except Exception: pass
        con.close()
        flash("We could not remove that security block. Please try again.")
    return redirect(url_for("admin_security_alerts"))


@app.route("/admin/panel")
@admin_required
def admin_panel():
    con = db()
    stats = {
        "students": con.execute("SELECT COUNT(*) AS c FROM students WHERE status='approved'").fetchone()["c"],
        "pending": con.execute("SELECT COUNT(*) AS c FROM students WHERE status='pending'").fetchone()["c"],
        "messages": con.execute("SELECT COUNT(*) AS c FROM community_messages").fetchone()["c"],
        "timetables": con.execute("SELECT COUNT(*) AS c FROM timetables").fetchone()["c"],
        "updates": con.execute("SELECT COUNT(*) AS c FROM academic_updates").fetchone()["c"],
        "resources": con.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"],
        "problems": con.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"],
        "announcements": con.execute("SELECT COUNT(*) AS c FROM announcements").fetchone()["c"],
        "events": con.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],
    }
    online = setting(con, "vybe_online", "1") == "1"
    con.close()
    cards = [
        ("01", "Students & Access", "Approve requests, block/unblock students and manage publisher access.", "/admin/students", stats["students"], "STUDENTS", "blue", "♙"),
        ("02", "Community", "Turn Community Chat on/off and moderate student messages.", "/admin/community-chat", stats["messages"], "MESSAGES", "purple", "◉"),
        ("03", "Timetable", "Upload new timetable versions, view them and delete old files.", "/admin/timetable", stats["timetables"], "FILES", "green", "◷"),
        ("04", "Academic Update", "Publish results, date sheets, exam notices and other updates.", "/admin/academic-updates", stats["updates"], "UPDATES", "blue", "⚑"),
        ("05", "Academic Hub", "Manage resources, study material, PYQs and academic content.", "/admin/academic-hub", stats["resources"], "RESOURCES", "green", "▦"),
        ("06", "Help Desk", "Review student problems, send official solutions and manage reports.", "/admin/problems", stats["problems"], "REPORTS", "orange", "?"),
        ("07", "Announcements", "Create campus-wide announcements and remove outdated ones.", "/admin/announcements", stats["announcements"], "LIVE", "orange", "▤"),
        ("08", "Events", "Create upcoming campus events and delete finished or incorrect ones.", "/admin/events", stats["events"], "EVENTS", "purple", "✦"),
    ]
    card_html = ''.join(f'<a class="admin-home-card admin-home-card-{tone}" href="{href}"><div class="admin-home-card-top"><span class="admin-home-number">{num}</span><span class="admin-home-count">{count} {label}</span></div><div class="admin-home-icon" aria-hidden="true">{icon}</div><h2>{title}</h2><p>{desc}</p><span class="admin-home-open">Open page <b>→</b></span></a>' for num,title,desc,href,count,label,tone,icon in cards)
    body = f"""<section class="section admin-home-page">
      <div class="admin-home-hero">
        <div><span class="admin-home-kicker">PRIVATE VYBE ADMIN</span><h1>Control everything<br><em>from one place.</em></h1><p>Choose exactly what you want to manage. Every card opens its own admin page with the controls for that area.</p></div>
        <div class="admin-home-status {"online" if online else "offline"}"><span></span><div><strong>{"VYBE is online" if online else "VYBE is offline"}</strong><small>Public access status</small></div><a href="/admin/status">Manage</a></div>
      </div>
      <div class="admin-home-stats"><div><b>{stats["students"]}</b><span>Students</span></div><div><b>{stats["pending"]}</b><span>Pending</span></div><div><b>{stats["updates"]}</b><span>Academic updates</span></div><div><b>{stats["problems"]}</b><span>Help desk</span></div><div><b>{stats["events"]}</b><span>Events</span></div></div>
      <div class="admin-home-section-title"><div><span>ADMIN AREAS</span><h2>Choose a section</h2></div><small>Each card opens a separate management page.</small></div>
      <div class="admin-home-grid">{card_html}</div>
      <div class="admin-home-bottom"><a href="/admin/settings"><span>⚙</span><div><b>Settings</b><small>General VYBE configuration, Drive links and notifications.</small></div><strong>→</strong></a><a href="/admin/analytics"><span>↗</span><div><b>Analytics</b><small>See usage, students, content and community activity.</small></div><strong>→</strong></a><a href="/admin/assistant"><span>✦</span><div><b>VYBE AI Settings</b><small>Manage assistant knowledge and controls.</small></div><strong>→</strong></a></div>
    </section>"""
    return layout("Admin Dashboard", body, admin=True)




@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    con=db()
    stats={"students":con.execute("SELECT COUNT(*) AS c FROM students WHERE status='approved'").fetchone()["c"],"pending":con.execute("SELECT COUNT(*) AS c FROM students WHERE status='pending'").fetchone()["c"],"resources":con.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"],"announcements":con.execute("SELECT COUNT(*) AS c FROM announcements").fetchone()["c"],"events":con.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],"problems":con.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"],"solutions":con.execute("SELECT COUNT(*) AS c FROM solutions").fetchone()["c"],"saved":con.execute("SELECT COUNT(*) AS c FROM saved_reports").fetchone()["c"],"helpful":con.execute("SELECT COUNT(*) AS c FROM helpful_votes").fetchone()["c"],"timetables":con.execute("SELECT COUNT(*) AS c FROM timetables").fetchone()["c"]}
    top=con.execute("SELECT name,reputation_points,helpful_answers,accepted_solutions FROM students WHERE status='approved' ORDER BY reputation_points DESC,helpful_answers DESC LIMIT 10").fetchall(); con.close()
    rows="".join(f'<tr><td>{esc(x["name"])}</td><td>{x["reputation_points"]}</td><td>{x["helpful_answers"]}</td><td>{x["accepted_solutions"]}</td></tr>' for x in top)
    body=f'''<section class="section"><div class="badge">ADMIN ANALYTICS</div><h1>Campus analytics.</h1><p class="muted">Operational counts from VYBE's own database. No external analytics service is required.</p><section class="grid"><div class="card"><div class="kpi">{stats["students"]}</div><h3>Approved students</h3></div><div class="card"><div class="kpi">{stats["resources"]}</div><h3>Resources</h3></div><div class="card"><div class="kpi">{stats["problems"]}</div><h3>Campus problems</h3></div><div class="card"><div class="kpi">{stats["solutions"]}</div><h3>Open solutions</h3></div><div class="card"><div class="kpi">{stats["helpful"]}</div><h3>Helpful votes</h3></div><div class="card"><div class="kpi">{stats["saved"]}</div><h3>Saved reports</h3></div><div class="card"><div class="kpi">{stats["timetables"]}</div><h3>Timetables</h3></div><div class="card"><div class="kpi">{stats["pending"]}</div><h3>Pending students</h3></div></section><section class="section"><div class="card tablewrap"><h2>Top VYBE contributors</h2><table><tr><th>Student</th><th>Points</th><th>Helpful answers</th><th>Accepted solutions</th></tr>{rows or '<tr><td colspan="4">No contributor data yet.</td></tr>'}</table></div></section></section>'''
    return layout("Analytics",body,admin=True)


@app.route("/admin/assistant", methods=["GET", "POST"])
@admin_required
def admin_assistant():
    con = db()
    current = setting(con, "vybe_assistant_enabled", "1") == "1"
    raw_selected = setting(con, "vybe_ai_shortcuts", "[]") or "[]"
    try:
        selected = json.loads(raw_selected)
        if not isinstance(selected, list): selected = []
    except Exception:
        selected = []

    shortcut_catalog = [
        ("study_material", "Study Material", "Open the main study-material collection.", "/academic-hub/study-material"),
        ("notes", "Notes", "Quick access to student notes.", "/academic-hub/notes"),
        ("syllabus", "Syllabus", "Open syllabus resources.", "/academic-hub/syllabus"),
        ("assignments", "Assessments", "Open official assessment updates.", "/academic-hub/assessment"),
        ("previous_papers", "Previous Papers", "Open previous-year papers.", "/papers"),
        ("admit_card", "Admit Card", "Open the student's admit-card area.", "/academic-hub/admit-card"),
        ("date_sheets", "Date Sheets", "Open examination/date-sheet updates.", "/updates?category=Examination"),
        ("updates", "Results & Updates", "Open the latest academic updates.", "/updates"),
        ("timetable", "Timetable", "Open the current campus timetable.", "/timetable"),
        ("helpdesk", "Help Desk", "Open campus problem reporting and support.", "/issues"),
        ("announcements", "Announcements", "Open campus-wide announcements.", "/announcements"),
        ("events", "Events", "Open upcoming campus events.", "/events"),
        ("community", "Community", "Open the student community area.", "/community"),
        ("profile", "My Profile", "Open the student's profile.", "/profile"),
    ]

    if request.method == "POST":
        action = request.form.get("action", "").strip()
        if action == "toggle":
            current = not current
            set_setting(con, "vybe_assistant_enabled", "1" if current else "0")
            con.commit(); con.close()
            flash("Ask VYBE is now ON for students." if current else "Ask VYBE is now OFF for students.")
            return redirect(url_for("admin_assistant"))
        if action == "shortcuts":
            allowed = {x[0] for x in shortcut_catalog}
            selected = [x for x in request.form.getlist("shortcuts") if x in allowed]
            set_setting(con, "vybe_ai_shortcuts", json.dumps(selected))
            con.commit(); con.close()
            flash(f"Ask VYBE shortcuts updated. {len(selected)} shortcut(s) will appear for students.")
            return redirect(url_for("admin_assistant"))

    con.close()
    state = "ON" if current else "OFF"
    state_class = "is-on" if current else "is-off"
    allowed_keys = {c[0] for c in shortcut_catalog}
    checked_count = len([x for x in selected if x in allowed_keys])
    cards = []
    for key, label, description, href in shortcut_catalog:
        checked = " checked" if key in selected else ""
        cards.append(f"""<label class=\"ai-shortcut-card\"><input type=\"checkbox\" name=\"shortcuts\" value=\"{esc(key)}\"{checked}><span class=\"ai-shortcut-check\" aria-hidden=\"true\">✓</span><span class=\"ai-shortcut-copy\"><strong>{esc(label)}</strong><small>{esc(description)}</small></span><span class=\"ai-shortcut-arrow\">›</span></label>""")

    body = f"""<section class=\"section ai-settings-page\">
      <div class=\"ai-settings-head\"><div><a href=\"/admin/panel\" class=\"admin-back\">← Dashboard</a><span class=\"admin-page-kicker\">VYBE AI SETTINGS</span><h1>Ask VYBE.</h1><p>Control the floating Ask VYBE button students see. Turn it on or off, then choose exactly which shortcuts appear inside its panel.</p></div><div class=\"ai-live-status {state_class}\"><span class=\"ai-status-dot\"></span><strong>{state}</strong><small>Student access</small></div></div>
      <div class=\"ai-control-card\"><div><span class=\"ai-control-label\">FLOATING BUTTON</span><h2>Ask VYBE is {state}</h2><p>{'Students can see and open the floating Ask VYBE button.' if current else 'The floating Ask VYBE button and its panel are completely hidden from student pages.'}</p></div><form method=\"post\"><input type=\"hidden\" name=\"action\" value=\"toggle\"><button class=\"ai-toggle-button {'on' if current else 'off'}\" type=\"submit\"><span class=\"ai-toggle-track\"><span></span></span>{'Turn OFF' if current else 'Turn ON'} Ask VYBE</button></form></div>
      <form method=\"post\" class=\"ai-shortcuts-section\"><input type=\"hidden\" name=\"action\" value=\"shortcuts\"><div class=\"ai-shortcuts-head\"><div><span class=\"ai-control-label\">STUDENT SHORTCUTS</span><h2>What should appear in the Ask VYBE panel?</h2><p>Select the shortcuts students should see. The panel updates from this list automatically.</p></div><span class=\"ai-selected-count\"><b id=\"aiShortcutCount\">{checked_count}</b> selected</span></div><div class=\"ai-shortcut-grid\">{''.join(cards)}</div><div class=\"ai-save-row\"><span>Changes affect the student side immediately after saving.</span><button class=\"btn accent\" type=\"submit\">Save shortcuts →</button></div></form>
    </section>
    <script>
    (function(){{const boxes=[...document.querySelectorAll('.ai-shortcut-card input[type=\"checkbox\"]')];const count=document.getElementById('aiShortcutCount');function update(){{if(count)count.textContent=boxes.filter(x=>x.checked).length;}}boxes.forEach(x=>x.addEventListener('change',update));}})();
    </script>"""
    return layout("VYBE AI Settings", body, admin=True)


@app.route("/admin/assistant/knowledge/<int:kid>/delete", methods=["POST"])
@admin_required
def delete_assistant_knowledge(kid):
    con=db(); row=con.execute("SELECT file_name FROM assistant_knowledge WHERE id=?",(kid,)).fetchone(); con.execute("DELETE FROM assistant_knowledge WHERE id=?",(kid,)); con.commit(); con.close()
    if row and row["file_name"]:
        try: (UPLOAD_DIR/row["file_name"]).unlink(missing_ok=True)
        except OSError: pass
    flash("Assistant knowledge item deleted."); return redirect(url_for("admin_assistant"))

@app.route("/admin/status", methods=["GET", "POST"])
@admin_required
def admin_status():
    con = db()
    current = setting(con, "vybe_online", "1") == "1"
    if request.method == "POST":
        set_setting(con, "vybe_online", "0" if current else "1")
        con.commit(); con.close()
        flash("VYBE is now offline." if current else "VYBE is now online.")
        return redirect(url_for("admin_status"))
    con.close()
    state = " ONLINE" if current else " OFFLINE"
    action = " Take VYBE Offline" if current else " Bring VYBE Online"
    tone = "danger" if current else "good"
    body = f'<section class="section"><div class="badge">PUBLIC STATUS CONTROL</div><h1>VYBE availability.</h1><div class="card"><h2>{state}</h2><p class="muted">When VYBE is offline, public and student routes are blocked while admin access remains available.</p><form method="post"><button class="btn {tone}">{action}</button></form></div></section>'
    return layout("Online / Offline", body, admin=True)


@app.route("/admin/students")
@admin_required
def admin_students():
    """Student approval/access management with lightweight server-side search."""
    q = request.args.get("q", "").strip()[:100]
    students = []
    publisher_by_student = {}
    db_error = None
    con = None
    try:
        con = db()
        params = []
        where = ""
        if q:
            where = " WHERE LOWER(CAST(name AS TEXT)) LIKE LOWER(?) OR LOWER(CAST(student_id AS TEXT)) LIKE LOWER(?) "
            like = f"%{q}%"
            params = [like, like]
        try:
            raw_students = con.execute(
                f"SELECT id,name,student_id,status,created_at,last_seen FROM students{where} ORDER BY id DESC LIMIT 300",
                params,
            ).fetchall()
        except Exception:
            try:
                raw_students = con.execute(
                    f"SELECT id,name,student_id,status,created_at FROM students{where} ORDER BY id DESC LIMIT 300",
                    params,
                ).fetchall()
            except Exception:
                if q:
                    raw_students = con.execute(
                        "SELECT id,name,student_id FROM students WHERE LOWER(CAST(name AS TEXT)) LIKE LOWER(?) OR LOWER(CAST(student_id AS TEXT)) LIKE LOWER(?) ORDER BY id DESC LIMIT 300",
                        params,
                    ).fetchall()
                else:
                    raw_students = con.execute(
                        "SELECT id,name,student_id FROM students ORDER BY id DESC LIMIT 300"
                    ).fetchall()
        try:
            access_rows = con.execute(
                "SELECT key,value FROM settings WHERE key LIKE 'content_manager_%' OR key LIKE 'publisher_permissions_%'"
            ).fetchall()
        except Exception:
            access_rows = []
        publisher_by_student = {}
        allowed_publisher_keys = {k for k, _, _ in PUBLISHER_PERMISSION_CATALOG}
        for ar in access_rows:
            key = str(ar["key"] or "").strip()
            value = str(ar["value"] or "").strip()
            try:
                if key.startswith("content_manager_"):
                    sid_key = key[len("content_manager_"):].strip()
                    if value.lower() in {"1", "true", "yes", "on"}:
                        publisher_by_student[sid_key] = True
                elif key.startswith("publisher_permissions_"):
                    sid_key = key[len("publisher_permissions_"):].strip()
                    data = json.loads(value or "[]")
                    if isinstance(data, list) and any(str(x) in allowed_publisher_keys for x in data):
                        publisher_by_student[sid_key] = True
            except Exception:
                continue
        for row in raw_students:
            students.append({
                "id": int(row["id"]),
                "name": str(row["name"] or "Unnamed student"),
                "student_id": str(row["student_id"] or ""),
                "status": str(row["status"] or "pending") if "status" in row.keys() else "pending",
                "created_at": str(row["created_at"] or "") if "created_at" in row.keys() else "",
                "last_seen": str(row["last_seen"] or "") if "last_seen" in row.keys() else "",
            })
    except Exception as exc:
        db_error = exc
    finally:
        if con is not None:
            try: con.close()
            except Exception: pass

    card_rows=[]
    desktop_rows=[]
    for srow in students:
        sid=srow["id"]
        status=srow["status"] if srow["status"] in {"pending","approved","blocked"} else "pending"
        publisher=publisher_by_student.get(str(sid),False)
        if status=="pending":
            state=f'<form method="post" action="/admin/student/{sid}/approve"><button class="btn good" type="submit">Approve</button></form>'
        elif status=="approved":
            state=f'<form method="post" action="/admin/student/{sid}/block"><button class="btn danger" type="submit">Block</button></form>'
        else:
            state=f'<form method="post" action="/admin/student/{sid}/unblock"><button class="btn good" type="submit">Unblock</button></form>'
        if status=="approved":
            access=(f'<form method="post" action="/admin/content-access/{sid}/revoke"><button class="btn" type="submit">Revoke publisher</button></form>' if publisher else f'<form method="post" action="/admin/content-access/{sid}/grant"><button class="btn accent" type="submit">Give publisher access</button></form>')
        else:
            access='<span class="small muted">Approve first</span>'
        delete=f'<form method="post" action="/admin/student/{sid}/delete" onsubmit="return confirm(\'Delete this student and all dependent records?\')"><button class="btn danger" type="submit">Delete</button></form>'
        is_online = status=="approved" and student_is_online(srow.get("last_seen"))
        dot='is-online' if is_online else 'is-offline'
        presence_label='Online' if is_online else 'Offline'
        card_rows.append(f'<article class="admin-student-card"><div class="admin-student-card-head"><div class="admin-student-person"><span class="presence-dot {dot}"></span><div><strong>{esc(srow["name"])}</strong><small>{esc(srow["student_id"]) or "No Student ID"}</small></div></div><span class="pill">{esc(status)}</span></div><div class="admin-student-meta"><div><small>Login status</small><strong>{presence_label}</strong></div><div><small>Registered</small><strong>{esc(srow["created_at"]) or "—"}</strong></div><div><small>Access</small><strong>{"Publisher" if publisher else "Student"}</strong></div></div><div class="admin-student-card-actions">{state}{access}{delete}</div></article>')
        desktop_rows.append(f'<tr><td><span class="student-presence"><span class="presence-dot {dot}"></span>{esc(srow["name"])}</span></td><td>{esc(srow["student_id"])}</td><td><span class="pill">{esc(status)} · {presence_label}</span></td><td>{esc(srow["created_at"])}</td><td><div class="actions">{state}{access}{delete}</div></td></tr>')

    warning='<div class="admin-students-warning">Students could not be loaded right now. Please refresh once the database connection is available.</div>' if db_error else ''
    search_value=esc(q)
    result_text=f'{len(students)} matching student(s)' if q else f'{len(students)} student(s) shown'
    body=f"""<section class="section admin-students-page" id="pending"><div class="admin-page-head"><div><a href="/admin/panel" class="admin-back">← Dashboard</a><span class="admin-page-kicker">STUDENTS / ACCESS</span><h1>Students.</h1><p class="muted">Approve students, block or unblock access, and manage limited publisher access.</p></div><div class="admin-student-count"><strong>{len(students)}</strong><small>{"matches" if q else "students shown"}</small></div></div>{warning}<div class="admin-student-search"><form method="get" action="/admin/students" autocomplete="off"><input type="search" name="q" value="{search_value}" maxlength="100" placeholder="Search student name or Student ID…" aria-label="Search students"><button class="btn accent" type="submit">Search</button>{f'<a class="btn" href="/admin/students">Clear</a>' if q else ''}</form><small>{esc(result_text)}{f' for “{search_value}”' if q else ''}</small></div><div class="admin-student-actions"><a class="btn" href="/admin/publisher-access">Manage Publisher Access →</a><form method="post" action="/admin/students/delete-all" onsubmit="return confirm(\'Delete ALL students and their dependent records?\')"><button class="btn danger" type="submit">Delete all students</button></form></div><div class="admin-students-desktop card tablewrap"><table><thead><tr><th>Name</th><th>Student ID</th><th>Status</th><th>Registered</th><th>Access / Actions</th></tr></thead><tbody>{''.join(desktop_rows) or '<tr><td colspan="5">No students match your search.</td></tr>'}</tbody></table></div><div class="admin-students-mobile">{''.join(card_rows) or '<div class="card admin-students-empty">No students match your search.</div>'}</div></section>"""
    return layout("Students & Access", body, admin=True)


@app.route("/admin/student/<int:sid>/<action>", methods=["POST"])
@admin_required
def student_action(sid, action):
    if action not in ("approve", "block", "unblock", "delete"): abort(400)
    con = db()
    if action == "delete":
        # Explicit dependent deletes make this safe on legacy schemas without CASCADE.
        con.execute("DELETE FROM helpful_votes WHERE voter_id=? OR solution_id IN (SELECT id FROM solutions WHERE student_id=?)", (sid,sid))
        con.execute("DELETE FROM saved_reports WHERE student_id=?", (sid,))
        con.execute("DELETE FROM accepted_solutions WHERE student_id=?", (sid,))
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
    con.execute("DELETE FROM helpful_votes")
    con.execute("DELETE FROM saved_reports")
    con.execute("DELETE FROM accepted_solutions")
    con.execute("DELETE FROM solutions")
    con.execute("DELETE FROM issues")
    con.execute("DELETE FROM students")
    con.commit(); con.close(); flash("All students and dependent campus/community records were deleted."); return redirect(url_for("admin_students"))


@app.route("/publisher", methods=["GET", "POST"])
@content_manager_required
def publisher():
    sid = int(session.get("student_db_id"))
    permissions = publisher_permissions(sid)
    if request.method == "POST":
        kind = request.form.get("kind", "").strip()
        if kind not in permissions:
            flash("That publishing permission is not enabled for your account.")
            return redirect(url_for("publisher"))
        con = db()
        try:
            if kind == "announcements":
                title = request.form.get("title", "").strip()[:160]
                message = request.form.get("message", "").strip()[:3000]
                priority = request.form.get("priority", "Normal").strip()
                expires = request.form.get("expires_at", "").strip()[:40]
                if priority not in ("Normal", "Important", "High"): priority = "Normal"
                if not title or not message:
                    flash("Title and announcement message are required.")
                else:
                    con.execute("INSERT INTO announcements(title,message,priority,created_at,expires_at) VALUES(?,?,?,?,?)", (title,message,priority,now(),expires or None))
                    con.commit(); flash("Announcement published to VYBE.")
            elif kind == "events":
                title = request.form.get("event_title", "").strip()[:160]
                event_date = request.form.get("event_date", "").strip()[:20]
                event_time = request.form.get("event_time", "").strip()[:20]
                location = request.form.get("location", "").strip()[:160]
                description = request.form.get("description", "").strip()[:1500]
                if not title or not event_date:
                    flash("Event title and date are required.")
                else:
                    con.execute("INSERT INTO events(title,event_date,event_time,location,description,created_at) VALUES(?,?,?,?,?,?)", (title,event_date,event_time,location,description,now()))
                    con.commit(); flash("Event added to VYBE.")
            elif kind == "timetable":
                title = request.form.get("timetable_title", "").strip()[:160]
                f = request.files.get("timetable_file")
                if not title or not f or not f.filename:
                    flash("Timetable title and file are required.")
                else:
                    suffix=Path(f.filename).suffix.lower()
                    allowed={".pdf",".png",".jpg",".jpeg",".webp"}
                    if suffix not in allowed:
                        flash("Timetable must be a PDF or image file.")
                    else:
                        original_name=Path(f.filename).name[:240]
                        file_data=f.read()
                        assistant_text=_timetable_text(file_data,suffix,request.form.get("assistant_text",""))
                        _drive_store_timetable(con,title=title,original_name=original_name,mime_type=f.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream",data=file_data,assistant_text=assistant_text)
                        con.commit(); flash("Timetable posted to VYBE and stored in Google Drive.")
            elif kind == "academic_updates":
                title=request.form.get("title","").strip()[:180]
                description=request.form.get("description","").strip()[:4000]
                category=request.form.get("category","General").strip()[:80]
                update_kind=request.form.get("update_kind","General Update").strip()[:80]
                course=request.form.get("course","").strip()[:100]
                semester=request.form.get("semester","").strip()[:100]
                subject=request.form.get("subject","").strip()[:120]
                event_date=request.form.get("event_date","").strip()[:80]
                external_url=request.form.get("external_url","").strip()[:500]
                f=request.files.get("file")
                if not title or not description:
                    flash("Title and description are required.")
                elif external_url and (urlparse(external_url).scheme not in ("http","https") or not urlparse(external_url).netloc):
                    flash("Use a valid http or https external URL.")
                else:
                    filename=original_name=mime_type=None; file_data=None
                    if f and f.filename:
                        suffix=Path(f.filename).suffix.lower()
                        if suffix not in ALLOWED_EXT:
                            flash("That file type is not allowed.")
                            raise ValueError("unsupported academic update file")
                        original_name=Path(f.filename).name[:240]
                        mime_type=f.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream"; file_data=f.read()
                        if len(file_data)>20*1024*1024:
                            flash("Academic update files must be 20 MB or smaller.")
                            raise ValueError("academic update file too large")
                        _drive_store_academic_update(con,update_kind=update_kind,category=category,title=title,description=description,course=course,semester=semester,subject=subject,event_date=event_date,external_url=external_url,original_name=original_name,mime_type=mime_type,data=file_data)
                    con.commit(); flash("Academic update published.")
            elif kind == "academic_resources":
                title=request.form.get("resource_title","").strip()[:150]
                typ=request.form.get("resource_type","Study material").strip()[:80]
                course=request.form.get("resource_course","").strip()[:100]
                sem=request.form.get("resource_semester","").strip()[:100]
                subject=request.form.get("resource_subject","").strip()[:100]
                desc=request.form.get("resource_description","").strip()[:1000]
                f=request.files.get("resource_file")
                filename=original_name=mime_type=None; file_data=None; assistant_text=request.form.get("resource_assistant_text","").strip()[:50000]
                if not title or not course or not sem or not subject:
                    flash("Resource title, course, semester and subject are required.")
                else:
                    if f and f.filename:
                        suffix=Path(f.filename).suffix.lower()
                        if suffix not in ALLOWED_EXT:
                            flash("That file type is not allowed.")
                            raise ValueError("unsupported resource file")
                        original_name=Path(f.filename).name[:240]
                        mime_type=f.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream"; file_data=f.read()
                        if len(file_data)>20*1024*1024:
                            flash("Resource files must be 20 MB or smaller.")
                            raise ValueError("resource file too large")
                        if not assistant_text: assistant_text=_extract_doc_text(file_data,suffix,50000)
                        _drive_store_resource(con,title=title,resource_type=typ,course=course,semester=sem,subject=subject,description=desc,original_name=original_name,mime_type=mime_type,data=file_data,assistant_text=assistant_text)
                    con.commit(); flash("Academic resource added and indexed for Ask VYBE.")
        except ValueError:
            try: con.rollback()
            except Exception: pass
        except Exception:
            con.rollback(); app.logger.exception("Publisher action failed")
            flash("Could not publish right now. Please try again.")
        finally:
            con.close()
        return redirect(url_for("publisher"))

    cards=[]
    if "announcements" in permissions:
        cards.append('''<div class="card"><div class="admin-page-kicker">ANNOUNCEMENTS</div><h2>Publish announcement</h2><form class="form" method="post"><input type="hidden" name="kind" value="announcements"><input name="title" maxlength="160" placeholder="Announcement title" required><select name="priority"><option>Normal</option><option>Important</option><option>High</option></select><textarea name="message" maxlength="3000" placeholder="Write the campus update..." required></textarea><input type="datetime-local" name="expires_at"><button class="btn accent">Publish announcement →</button></form></div>''')
    if "events" in permissions:
        cards.append('''<div class="card"><div class="admin-page-kicker">EVENTS</div><h2>Create event</h2><form class="form" method="post"><input type="hidden" name="kind" value="events"><input name="event_title" maxlength="160" placeholder="Event name" required><div class="two"><input type="date" name="event_date" required><input type="time" name="event_time"></div><input name="location" maxlength="160" placeholder="Location"><textarea name="description" maxlength="1500" placeholder="Event details"></textarea><button class="btn accent">Create event →</button></form></div>''')
    if "timetable" in permissions:
        cards.append(f'''<div class="card"><div class="admin-page-kicker">TIMETABLE</div><h2>Upload timetable</h2><form id="publisherTimetableForm" class="form" method="post" enctype="multipart/form-data"><input type="hidden" name="kind" value="timetable"><input name="timetable_title" maxlength="160" placeholder="Semester / class timetable" required><input id="publisherTimetableFile" type="file" name="timetable_file" accept=".pdf,.png,.jpg,.jpeg,.webp" required><input id="publisherTimetableText" type="hidden" name="assistant_text"><div id="publisherTimetableStatus" class="small">PDF text is extracted automatically. Images are read before upload.</div><button class="btn accent">Post timetable →</button></form>{_timetable_ocr_script("publisherTimetableForm","publisherTimetableFile","publisherTimetableText","publisherTimetableStatus")}</div>''')
    if "academic_updates" in permissions:
        cards.append('''<div class="card"><div class="admin-page-kicker">ACADEMIC UPDATES</div><h2>Publish academic update</h2><form class="form" method="post" enctype="multipart/form-data"><input type="hidden" name="kind" value="academic_updates"><select name="update_kind"><option>General Update</option><option>Result</option><option>Date Sheet</option><option>Admit Card</option><option>Exam Form</option><option>Online Class</option><option>Recorded Lecture</option><option>E-Book</option><option>Finance Support</option></select><select name="category"><option>General</option><option>Examination</option><option>Results</option><option>Admission</option><option>Schedule</option><option>Portal</option></select><input name="title" placeholder="Update title" required><textarea name="description" placeholder="What should students know?" required></textarea><div class="two"><input name="course" placeholder="Course (optional)"><input name="semester" placeholder="Semester (optional)"></div><input name="subject" placeholder="Subject (optional)"><input name="event_date" placeholder="Date / schedule (optional)"><input name="external_url" placeholder="External portal URL (optional)"><input type="file" name="file"><button class="btn accent">Publish update →</button></form></div>''')
    if "academic_resources" in permissions:
        cards.append(f'''<div class="card"><div class="admin-page-kicker">ACADEMIC HUB</div><h2>Add study resource</h2><form id="publisherResourceForm" class="form" method="post" enctype="multipart/form-data"><input type="hidden" name="kind" value="academic_resources"><input name="resource_title" placeholder="Resource title" required><select name="resource_type"><option>Notes</option><option>Previous Year Questions</option><option>Syllabus</option><option>Study material</option></select><div class="two"><input name="resource_course" placeholder="Course" required><input name="resource_semester" placeholder="Semester" required></div><input name="resource_subject" placeholder="Subject" required><textarea name="resource_description" placeholder="Description"></textarea><input id="publisherResourceFile" type="file" name="resource_file"><input id="publisherResourceText" type="hidden" name="resource_assistant_text"><div id="publisherResourceStatus" class="small">Files are indexed for Ask VYBE when supported.</div><button class="btn accent">Add resource →</button></form>{_resource_ocr_script("publisherResourceForm","publisherResourceFile","publisherResourceText","publisherResourceStatus")}</div>''')
    if not cards:
        cards.append('<div class="card"><h2>No publishing permissions yet</h2><p class="muted">Ask an admin to enable one or more publishing categories for your account.</p></div>')
    names=[label for key,label,_ in PUBLISHER_PERMISSION_CATALOG if key in permissions]
    body=f'''<section class="section publisher-page"><div class="admin-page-head"><div><a href="/dashboard" class="admin-back">← Dashboard</a><span class="admin-page-kicker">PUBLISHER ACCESS</span><h1>Publish to VYBE.</h1><p>You can only create content in the categories selected by the admin. Existing content cannot be deleted from this account.</p></div><div class="card publisher-permission-summary"><strong>{len(names)} permissions</strong><small>{esc(", ".join(names) if names else "None")}</small></div></div><div class="publisher-grid">{''.join(cards)}</div><div class="card"><strong>Publisher safety</strong><p class="muted">Your permissions are limited to publishing new student-facing content. Admins retain delete, settings, student-management and security controls.</p></div></section>'''
    return layout("Publisher", body)


@app.route("/admin/announcements", methods=["GET","POST"])
@admin_required
def admin_announcements():
    con=db()
    if request.method=="POST":
        title=request.form.get("title","").strip()[:160]
        message=request.form.get("message","").strip()[:3000]
        priority=request.form.get("priority","Normal").strip()
        publish_at=request.form.get("publish_at","").strip()[:40]
        expires=request.form.get("expires_at","").strip()[:40]
        if priority not in ("Normal","Important","High"): priority="Normal"
        if not title or not message or not publish_at or not expires:
            con.close(); flash("Title, message, publish date and automatic deletion date are required."); return redirect(url_for("admin_announcements"))
        publish_utc=_admin_datetime_to_utc(publish_at); expires_utc=_admin_datetime_to_utc(expires)
        if expires_utc <= publish_utc:
            con.close(); flash("Automatic deletion must be after the publish date."); return redirect(url_for("admin_announcements"))
        con.execute("INSERT INTO announcements(title,message,priority,created_at,publish_at,expires_at) VALUES(?,?,?,?,?,?)", (title,message,priority,publish_utc,publish_utc,expires_utc))
        con.commit(); con.close()
        flash("Announcement published to VYBE.")
        return redirect(url_for("admin_announcements"))
    rows=con.execute("SELECT * FROM announcements ORDER BY id DESC").fetchall()
    con.close()
    html_rows="".join(f'''<tr><td><span class="pill">{esc(r["priority"])}</span></td><td><strong>{esc(r["title"])}</strong><br><span class="small">{esc(r["message"][:220])}</span></td><td>{esc(r["publish_at"] or r["created_at"])}</td><td>{esc(r["expires_at"] or "No expiry")}</td><td><form method="post" action="/admin/announcement/{r["id"]}/delete" onsubmit="return confirm('Delete this announcement?')"><button class="btn danger">Delete</button></form></td></tr>''' for r in rows)
    body=f'''<section class="section"><div class="badge">CAMPUS ANNOUNCEMENTS</div><h1>Announcements.</h1><div class="grid2"><div class="card"><h2>Publish update</h2><form class="form" method="post"><input name="title" maxlength="160" placeholder="Announcement title" required><select name="priority"><option>Normal</option><option>Important</option><option>High</option></select><textarea name="message" maxlength="3000" placeholder="Write the campus update..." required></textarea><div class="two"><label class="small">Date of publish<input type="datetime-local" name="publish_at" required></label><label class="small">Automatic deletion<input type="datetime-local" name="expires_at" required></label></div><div class="small">Shown after publish time and automatically deleted at the deletion time.</div><button class="btn accent">Publish announcement →</button></form></div><div class="card"><h2>How it works</h2><p class="muted">Published announcements appear on student dashboards, the Announcements page, search and Ask VYBE context.</p></div></div><section class="section"><div class="card tablewrap"><table><tr><th>Priority</th><th>Announcement</th><th>Publish date</th><th>Auto-delete</th><th>Action</th></tr>{html_rows or '<tr><td colspan="5">No announcements yet.</td></tr>'}</table></div></section></section>'''
    return layout("Announcements",body,admin=True)


@app.route("/admin/announcement/<int:aid>/delete", methods=["POST"])
@admin_required
def delete_announcement(aid):
    con=db(); con.execute("DELETE FROM announcements WHERE id=?",(aid,)); con.commit(); con.close()
    flash("Announcement deleted.")
    return redirect(url_for("admin_announcements"))


@app.route("/admin/events", methods=["GET","POST"])
@admin_required
def admin_events():
    con=db()
    if request.method=="POST":
        title=request.form.get("title","").strip()[:160]
        event_date=request.form.get("event_date","").strip()[:20]
        event_time=request.form.get("event_time","").strip()[:20]
        publish_at=request.form.get("publish_at","").strip()[:40]
        location=request.form.get("location","").strip()[:240]
        location_url=request.form.get("location_url","").strip()[:500]
        description=request.form.get("description","").strip()[:1500]
        if not title or not event_date or not event_time or not publish_at:
            con.close(); flash("Event name, publish date, event date and event time are required."); return redirect(url_for("admin_events"))
        if location_url and (urlparse(location_url).scheme not in ("http","https") or not urlparse(location_url).netloc):
            con.close(); flash("Use a valid http or https map link."); return redirect(url_for("admin_events"))
        try:
            from zoneinfo import ZoneInfo
            event_dt=datetime.fromisoformat(f"{event_date}T{event_time}").replace(tzinfo=ZoneInfo("Asia/Kolkata"))
            publish_utc=_admin_datetime_to_utc(publish_at)
            event_utc=event_dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if event_utc <= publish_utc:
                con.close(); flash("Event publish date must be before the event date and time."); return redirect(url_for("admin_events"))
        except Exception:
            con.close(); flash("Please enter a valid event date and time."); return redirect(url_for("admin_events"))
        con.execute("INSERT INTO events(title,event_date,event_time,location,location_url,description,created_at,publish_at) VALUES(?,?,?,?,?,?,?,?)", (title,event_date,event_time,location,location_url,description,publish_utc,publish_utc))
        con.commit(); con.close()
        flash("Event added to VYBE.")
        return redirect(url_for("admin_events"))
    rows=con.execute("SELECT * FROM events ORDER BY event_date ASC,event_time ASC,id DESC").fetchall()
    con.close()
    html_rows="".join(f'''<tr><td>{esc(r["event_date"])}<br><span class="small">{esc(r["event_time"] or "TBA")}</span></td><td><strong>{esc(r["title"])}</strong></td><td>{esc(r["publish_at"] or r["created_at"])}</td><td>{esc(r["description"][:150])}<br><span class="small">{esc(r["location"] or "No location")}</span>{(f'<br><a class="btn" href="{esc(r["location_url"])}" target="_blank" rel="noopener">Open map ↗</a>' if r["location_url"] else '')}</td><td><form method="post" action="/admin/event/{r["id"]}/delete" onsubmit="return confirm('Delete this event?')"><button class="btn danger">Delete now</button></form></td></tr>''' for r in rows)
    body=f'''<section class="section"><div class="badge">CAMPUS EVENTS</div><h1>Events.</h1><div class="grid2"><div class="card"><h2>Create event</h2><form class="form" method="post"><input name="title" maxlength="160" placeholder="Event name" required><div class="two"><label class="small">Date of publishing<input type="datetime-local" name="publish_at" required></label><label class="small">Date of event<input type="date" name="event_date" required></label></div><label class="small">Time of event<input type="time" name="event_time" required></label><input name="location" maxlength="240" placeholder="Location name / venue"><input name="location_url" maxlength="500" placeholder="Google Maps location link" type="url"><textarea name="description" maxlength="1500" placeholder="Event details"></textarea><div class="small">Automatically deleted 5 hours after the event date and time. You can also delete it manually anytime.</div><button class="btn accent">Create event →</button></form></div><div class="card"><h2>Student experience</h2><p class="muted">Events appear on dashboards, the Events page, search and Ask VYBE context.</p></div></div><section class="section"><div class="card tablewrap"><table><tr><th>Event date</th><th>Event</th><th>Publish date</th><th>Details / location</th><th>Action</th></tr>{html_rows or '<tr><td colspan="5">No events yet.</td></tr>'}</table></div></section></section>'''
    return layout("Events",body,admin=True)


@app.route("/admin/event/<int:eid>/delete", methods=["POST"])
@admin_required
def delete_event(eid):
    con=db(); con.execute("DELETE FROM events WHERE id=?",(eid,)); con.commit(); con.close()
    flash("Event deleted.")
    return redirect(url_for("admin_events"))


@app.route("/admin/content-access/<int:sid>/<action>", methods=["POST"])
@admin_required
def admin_content_access(sid, action):
    if action not in ("grant", "revoke"):
        abort(404)
    con = db()
    student = con.execute("SELECT id,name,status FROM students WHERE id=?", (sid,)).fetchone()
    if not student:
        con.close(); flash("Student not found."); return redirect(url_for("admin_publisher_access"))
    if action == "grant":
        if student["status"] != "approved":
            con.close(); flash("Only approved students can receive publisher access."); return redirect(url_for("admin_students"))
        # Persist both sides of the grant. The student dashboard and publisher
        # guard require an explicit permission list, so the access flag alone
        # is not sufficient for a newly granted publisher.
        set_setting(con, f"content_manager_{sid}", "1")
        set_setting(con, f"publisher_permissions_{sid}", json.dumps(["announcements", "events", "timetable"]))
        flash(f"Publisher access granted to {student['name']}.")
    else:
        set_setting(con, f"content_manager_{sid}", "0")
        set_setting(con, f"publisher_permissions_{sid}", json.dumps([]))
        flash(f"Publisher access revoked from {student['name']}.")
    con.commit(); con.close()
    # Publisher access is managed from Students / Access. Return there so the
    # same row immediately changes between "Give publisher access" and
    # "Revoke publisher access" without sending the admin to another page.
    return redirect(url_for("admin_students"))


@app.route("/admin/publisher-access", methods=["GET", "POST"])
@admin_required
def admin_publisher_access():
    """Manage publishing controls only for students who already have publisher access."""
    con = db()
    try:
        allowed = {k for k, _, _ in PUBLISHER_PERMISSION_CATALOG}
        try:
            selected_sid = int(request.values.get("student_id", "0") or 0)
        except (TypeError, ValueError):
            selected_sid = 0

        if request.method == "POST":
            student = None
            if selected_sid:
                # The publisher-control screen must accept only students who were
                # already granted publisher access from Students & Access.
                student = con.execute("SELECT id,name,status FROM students WHERE id=? AND status='approved'", (selected_sid,)).fetchone()
                if student and not publisher_is_active(selected_sid, con=con):
                    student = None
            if not student:
                flash("Select a student who already has publisher access.")
                return redirect(url_for("admin_publisher_access"))
            selected = [x for x in request.form.getlist("permissions") if x in allowed]
            set_setting(con, f"publisher_permissions_{selected_sid}", json.dumps(selected))
            set_setting(con, f"content_manager_{selected_sid}", "1" if selected else "0")
            con.commit()
            flash(f"Publisher controls updated for {student['name']}." if selected else f"Publisher access revoked for {student['name']} because no publishing controls were selected.")
            return redirect(url_for("admin_publisher_access", student_id=selected_sid))

        # Query active publisher students directly from the relationship between
        # students and their content-manager setting. This avoids stale/incomplete
        # in-memory lists and guarantees the selector reflects Students & Access.
        # Read publisher access settings once and build the active publisher set in Python.
        # This works consistently on both PostgreSQL and SQLite and also recognizes
        # older records where permissions were saved before content_manager_* existed.
        publisher_ids=set()
        allowed_publisher_keys = {k for k, _, _ in PUBLISHER_PERMISSION_CATALOG}
        try:
            access_rows=con.execute(
                "SELECT key,value FROM settings WHERE key LIKE 'content_manager_%' OR key LIKE 'publisher_permissions_%'"
            ).fetchall()
        except Exception:
            access_rows=[]
        for r in access_rows:
            key=str(r["key"] or "").strip()
            value=str(r["value"] or "").strip()
            try:
                if key.startswith("content_manager_") and value.lower() in {"1","true","yes","on"}:
                    publisher_ids.add(int(key[len("content_manager_"):].strip()))
                elif key.startswith("publisher_permissions_"):
                    data=json.loads(value or "[]")
                    if isinstance(data,list) and any(str(x) in allowed_publisher_keys for x in data):
                        publisher_ids.add(int(key[len("publisher_permissions_"):].strip()))
            except (TypeError,ValueError,OverflowError,json.JSONDecodeError):
                continue
        approved=[]
        if publisher_ids:
            placeholders=",".join("?" for _ in publisher_ids)
            try:
                approved=con.execute(
                    f"SELECT id,name,student_id,status FROM students WHERE status='approved' AND id IN ({placeholders}) ORDER BY name,id LIMIT 300",
                    tuple(sorted(publisher_ids)),
                ).fetchall()
            except Exception:
                approved=[]

        selected_student = None
        selected = set()
        if selected_sid:
            selected_student = next((r for r in approved if int(r["id"]) == selected_sid), None)
            if not selected_student or not publisher_is_active(selected_sid, con=con):
                selected_sid = 0
                selected_student = None
            else:
                selected = publisher_permissions(selected_sid, con=con)
                if not selected:
                    selected = {"announcements", "events", "timetable"}

        options = ['<option value="">Choose a publisher…</option>']
        for row in approved:
            sid = int(row["id"])
            mark = " selected" if sid == selected_sid else ""
            options.append(f'<option value="{sid}"{mark}>{esc(row["name"])} · {esc(row["student_id"] or "No Student ID")}</option>')

        controls = []
        for key, label, desc in PUBLISHER_PERMISSION_CATALOG:
            checked = " checked" if key in selected else ""
            controls.append(f'<label class="publisher-control-option"><input type="checkbox" name="permissions" value="{esc(key)}"{checked}><span><strong>{esc(label)}</strong><small>{esc(desc)}</small></span></label>')

        if selected_student:
            summary = (f'<div class="publisher-selected"><div><strong>{esc(selected_student["name"])}</strong>'
                       f'<small>Student ID: {esc(selected_student["student_id"] or "No Student ID")}</small></div>'
                       f'<span class="pill publisher-on">Publisher active</span></div>')
        else:
            summary = '<div class="publisher-selected publisher-selected-empty"><strong>Choose a publisher above.</strong><small>Only students already granted publisher access from Students &amp; Access are listed here.</small></div>'

        disabled = " disabled" if not selected_student else ""
        body = f'''{PUBLISHER_ACCESS_PICKER_CSS}<section class="section publisher-access-page"><div class="admin-page-head"><div><a href="/admin/students" class="admin-back">← Students / Access</a><span class="admin-page-kicker">PUBLISHER ACCESS</span><h1>Publisher controls.</h1><p>Choose a student who already has publisher access, then select exactly what they can publish.</p></div><div class="card publisher-access-note"><strong>{len(approved)}</strong><small>publisher students</small></div></div><div class="card publisher-picker-card"><span class="publisher-picker-label">PUBLISHER STUDENT</span><form method="get" class="publisher-picker-form"><select name="student_id" onchange="this.form.submit()">{"".join(options)}</select></form>{summary}</div><div class="card publisher-controls-card"><span class="publisher-picker-label">PUBLISHING CONTROLS</span><h2>What can this student publish?</h2><p>Select only the permissions you want this publisher to have.</p><form method="post" class="publisher-control-form"><input type="hidden" name="student_id" value="{selected_sid}"><div class="publisher-control-grid">{"".join(controls)}</div><div class="publisher-control-actions"><button class="btn accent" type="submit"{disabled}>Save selected controls</button></div></form></div></section>'''
        return layout("Publisher Access", body, admin=True)
    except Exception:
        try: con.rollback()
        except Exception: pass
        app.logger.exception("Publisher Access page failed")
        flash("Publisher Access could not be loaded. Please try again.")
        return redirect(url_for("admin_students"))
    finally:
        try: con.close()
        except Exception: pass


VYBE_DIRECT_DRIVE_JS = r'''<script>
window.vybeDriveUpload = async function(file,status,category){
  const csrf=(document.querySelector('meta[name="vybe-csrf-token"]')||{}).content||'';
  async function j(url,opts){opts=opts||{};opts.credentials='same-origin';opts.headers=Object.assign({'Accept':'application/json','X-VYBE-CSRF':csrf},opts.headers||{});const r=await fetch(url,opts);let d={};try{d=await r.json()}catch(_){ }if(!r.ok)throw new Error(d.error||('Request failed (HTTP '+r.status+')'));return d}
  const init=await j('/admin/drive/upload-session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category:category,name:file.name,mimeType:file.type||'application/octet-stream',size:file.size})});
  const direct=()=>new Promise((resolve,reject)=>{const x=new XMLHttpRequest();x.open('PUT',init.upload_url,true);x.upload.onprogress=e=>{if(e.lengthComputable&&status)status.textContent='Uploading '+file.name+' · '+Math.round(e.loaded/e.total*100)+'%';};x.onload=()=>{if(x.status>=200&&x.status<300){try{resolve(x.response?JSON.parse(x.response):JSON.parse(x.responseText||'{}'));}catch(_){reject(new Error('Drive returned an invalid upload response.'));}}else reject(new Error('Direct Drive upload failed (HTTP '+x.status+').'));};x.onerror=()=>reject(new Error('Direct Drive connection was blocked.'));x.ontimeout=()=>reject(new Error('Drive upload timed out.'));x.timeout=900000;x.responseType='json';x.send(file);});
  try{return await direct();}catch(_){let start=0,done=null;const stat=await j('/admin/drive/upload-status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_url:init.upload_url,total:file.size})});if(stat.complete)done=stat.metadata;else start=Number(stat.next_start||0);while(!done&&start<file.size){const end=Math.min(start+4*1024*1024,file.size);if(status)status.textContent='Uploading '+file.name+' · '+Math.round(start/file.size*100)+'%';const r=await fetch('/admin/drive/upload-chunk?session_url='+encodeURIComponent(init.upload_url)+'&start='+start+'&end='+(end-1)+'&total='+file.size,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/octet-stream','X-VYBE-CSRF':csrf},body:file.slice(start,end)});let d={};try{d=await r.json()}catch(_){ }if(!r.ok)throw new Error(d.error||('Upload chunk failed (HTTP '+r.status+').'));start=Number(d.next_start||end);if(d.complete)done=d.metadata;}if(!done||!done.id)throw new Error('Google Drive did not return the uploaded file.');return done;}
};
</script>'''

VYBE_TIMETABLE_FORM_JS = '<script>(function(){const f=document.getElementById(\'adminTimetableDriveForm\');if(!f)return;f.addEventListener(\'submit\',async()=>{const b=f.querySelector(\'button\'),file=f.elements.file.files[0],status=document.getElementById(\'adminTimetableDriveStatus\');if(!file)return;b.disabled=true;try{const meta=await window.vybeDriveUpload(file,status,\'Timetable\');const csrf=(document.querySelector(\'meta[name="vybe-csrf-token"]\')||{}).content||\'\';const r=await fetch(\'/admin/drive/register-timetable\',{method:\'POST\',credentials:\'same-origin\',headers:{\'Content-Type\':\'application/json\',\'X-VYBE-CSRF\':csrf},body:JSON.stringify({file_id:meta.id,title:f.elements.title.value,assistant_text:\'\'})});let d={};try{d=await r.json()}catch(_){ }if(!r.ok)throw new Error(d.error||\'Could not publish timetable.\');status.textContent=\'✓ Timetable uploaded and published successfully.\';f.reset()}catch(e){status.textContent=\'Upload failed: \'+e.message}finally{b.disabled=false}})})();</script>'
VYBE_ACADEMIC_UPDATE_FORM_JS = '<script>(function(){const f=document.getElementById(\'adminAcademicDriveForm\');if(!f)return;f.addEventListener(\'submit\',async()=>{const b=f.querySelector(\'button\'),file=f.elements.file?f.elements.file.files[0]:document.getElementById(\'adminAcademicDriveFile\').files[0],status=document.getElementById(\'adminAcademicDriveStatus\'),kind=f.elements.kind.value,title=f.elements.title.value,external=f.elements.external_url.value.trim();if(!kind||!title||!f.elements.description.value.trim()){status.textContent=\'Choose an update type and enter the title and description.\';return}if((kind===\'Result\'||kind===\'Admit Card\')&&!external){status.textContent=\'A direct website link is required for \'+kind+\'.\';return}b.disabled=true;try{let meta=null;if(file){const category=kind===\'Result\'?\'Results\':kind===\'Date Sheet\'?\'Date Sheets\':kind===\'Admit Card\'?\'Admit Cards\':kind===\'Assessment\'?\'Assessments\':\'Exam Forms & Notices\';meta=await window.vybeDriveUpload(file,status,category)}const csrf=(document.querySelector(\'meta[name="vybe-csrf-token"]\')||{}).content||\'\';const r=await fetch(\'/admin/drive/register-update\',{method:\'POST\',credentials:\'same-origin\',headers:{\'Content-Type\':\'application/json\',\'X-VYBE-CSRF\':csrf},body:JSON.stringify({kind,title,description:f.elements.description.value,event_date:f.elements.event_date.value,external_url:external,file_id:meta?meta.id:\'\'})});let d={};try{d=await r.json()}catch(_){ }if(!r.ok)throw new Error(d.error||\'Could not publish update.\');status.textContent=\'✓ Update published successfully.\';f.reset()}catch(e){status.textContent=\'Upload failed: \'+e.message}finally{b.disabled=false}})})();</script>'

@app.route("/admin/timetable", methods=["GET","POST"])
@admin_required
def admin_timetable():
    con=db()
    if request.method=="POST":
        title=request.form.get("title","").strip()[:160]
        f=request.files.get("file")
        if not title or not f or not f.filename:
            con.close(); flash("Timetable title and file are required."); return redirect(url_for("admin_timetable"))
        suffix=Path(f.filename).suffix.lower()
        allowed={".pdf",".png",".jpg",".jpeg",".webp"}
        if suffix not in allowed:
            con.close(); flash("Timetable must be a PDF or image file."); return redirect(url_for("admin_timetable"))
        try:
            file_data=f.read()
            if len(file_data)>20*1024*1024:
                raise ValueError("Timetable files must be 20 MB or smaller.")
            assistant_text=_timetable_text(file_data,suffix,request.form.get("assistant_text",""))
            _drive_store_timetable(con,title=title,original_name=Path(f.filename).name[:240],mime_type=f.mimetype or mimetypes.guess_type(f.filename)[0] or "application/octet-stream",data=file_data,assistant_text=assistant_text)
            con.commit(); flash("Timetable posted to VYBE and stored in Google Drive.")
        except Exception as exc:
            con.rollback()
            app.logger.error("Timetable upload failed: %s: %s", type(exc).__name__, exc, exc_info=(type(exc), exc, exc.__traceback__))
            flash("Could not save the timetable. Please try again. The error has been logged.")
        finally: con.close()
        return redirect(url_for("admin_timetable"))
    rows=con.execute("SELECT id,title,original_name,created_at,drive_file_id,drive_web_url FROM timetables ORDER BY id DESC").fetchall(); con.close()
    html_rows="".join(f'''<tr><td><strong>{esc(r["title"])}</strong><br><span class="small">{esc(r["original_name"])}</span></td><td>{esc(r["created_at"])}</td><td><a class="btn dark" href="/timetable-file/{r["id"]}" target="_blank" rel="noopener">View</a> <form style="display:inline" method="post" action="/admin/timetable/{r["id"]}/delete" onsubmit="return confirm('Delete this timetable?')"><button class="btn danger">Delete</button></form></td></tr>''' for r in rows)
    body=f'''<section class="section"><div class="badge">CAMPUS TIMETABLE</div><h1>Timetable.</h1><div class="grid2"><div class="card"><h2>Post timetable</h2><form id="adminTimetableDriveForm" class="form" onsubmit="return false"><input name="title" maxlength="160" placeholder="Timetable title" required><input id="adminTimetableDriveFile" type="file" name="file" required><div id="adminTimetableDriveStatus" class="small">Any file type can be uploaded. The file is sent directly to Google Drive.</div><button class="btn accent" type="submit">Post timetable →</button></form>{VYBE_DIRECT_DRIVE_JS}{VYBE_TIMETABLE_FORM_JS}</div><div class="card"><h2>Student access</h2><p class="muted">Students can open the latest timetable from the Timetable button. Approved Publishers can also post new timetable versions, but only admins can delete them.</p></div></div></section><section class="section"><div class="card tablewrap"><table><tr><th>Timetable</th><th>Posted</th><th>Actions</th></tr>{html_rows or '<tr><td colspan="3">No timetables posted yet.</td></tr>'}</table></div></section>'''
    return layout("Timetable",body,admin=True)


@app.route("/admin/timetable/<int:tid>/delete", methods=["POST"])
@admin_required
def delete_timetable(tid):
    con=db(); row=con.execute("SELECT file_name,drive_file_id FROM timetables WHERE id=?",(tid,)).fetchone()
    if row:
        if row["drive_file_id"]:
            try: _drive_delete_file(row["drive_file_id"])
            except Exception: app.logger.exception("Could not delete Drive timetable %s", row["drive_file_id"])
        if row["file_name"]:
            try: (UPLOAD_DIR/row["file_name"]).unlink(missing_ok=True)
            except Exception: pass
        con.execute("DELETE FROM timetables WHERE id=?",(tid,)); con.commit(); flash("Timetable deleted.")
    else: flash("Timetable not found.")
    con.close(); return redirect(url_for("admin_timetable"))


@app.route("/admin/academic-updates", methods=["GET", "POST"])
@admin_required
def admin_academic_updates():
    con=db(); allowed_kinds=("Result","Date Sheet","Exam Notice","Admit Card","Assessment")
    if request.method=="POST":
        kind=request.form.get("kind","").strip()[:80]; title=request.form.get("title","").strip()[:180]; description=request.form.get("description","").strip()[:4000]; event_date=request.form.get("event_date","").strip()[:80]; external_url=request.form.get("external_url","").strip()[:500]; f=request.files.get("file")
        if kind not in allowed_kinds: con.close(); flash("Choose Result, Date Sheet, Exam Notice, Admit Card or Assessment."); return redirect(url_for("admin_academic_updates"))
        if not title or not description: con.close(); flash("Title and description are required."); return redirect(url_for("admin_academic_updates"))
        if external_url:
            parsed=urlparse(external_url)
            if parsed.scheme not in ("http","https") or not parsed.netloc: con.close(); flash("Use a valid http or https direct website URL."); return redirect(url_for("admin_academic_updates"))
        if kind in ("Result","Admit Card","Assessment") and not external_url: con.close(); flash(f"A direct official website link is required for {kind}."); return redirect(url_for("admin_academic_updates"))
        original_name=mime_type=None; file_data=None
        if f and f.filename:
            suffix=Path(f.filename).suffix.lower()
            if suffix not in ALLOWED_EXT: con.close(); flash("That file type is not allowed."); return redirect(url_for("admin_academic_updates"))
            original_name=Path(f.filename).name[:240]; mime_type=f.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream"; file_data=f.read()
            if len(file_data)>20*1024*1024: con.close(); flash("Academic update files must be 20 MB or smaller."); return redirect(url_for("admin_academic_updates"))
        try:
            if file_data is not None:
                _drive_store_academic_update(con,update_kind=kind,category=kind,title=title,description=description,course="",semester="",subject="",event_date=event_date,external_url=external_url,original_name=original_name,mime_type=mime_type,data=file_data)
            else:
                con.execute("INSERT INTO academic_updates(kind,category,title,description,course,semester,subject,event_date,external_url,file_name,original_name,mime_type,file_data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(kind,kind,title,description,"","","",event_date,external_url,None,None,None,None,now()))
            con.commit(); con.close(); flash(f"{kind} published successfully." if file_data is None else f"{kind} published to Google Drive successfully."); return redirect(url_for("admin_academic_updates"))
        except Exception as exc:
            con.rollback(); con.close(); app.logger.exception("Academic update Drive upload failed")
            flash(f"Could not publish the academic update to Google Drive: {type(exc).__name__}: {exc}")
            return redirect(url_for("admin_academic_updates"))
    rows=con.execute("SELECT id,kind,title,event_date,external_url,file_name,original_name,(file_data IS NOT NULL) AS has_local_file,created_at,drive_file_id,drive_web_url FROM academic_updates WHERE kind IN (?,?,?,?,?) ORDER BY id DESC",allowed_kinds).fetchall(); con.close()
    table="".join(f'''<div class="admin-list-row"><div><span class="pill">{esc(r["kind"])}</span><strong>{esc(r["title"])}</strong><small>{esc(r["event_date"] or r["created_at"])}{(" · direct link" if r["external_url"] else (" · document" if r["file_name"] or r["has_local_file"] or r["drive_file_id"] or r["drive_web_url"] else ""))}</small></div><form method="post" action="/admin/academic-update/{r["id"]}/delete" onsubmit="return confirm('Delete this academic update?')"><button class="btn danger">Delete</button></form></div>''' for r in rows)
    body=f'''<section class="section admin-content-page"><div class="admin-page-head"><div><a href="/admin/panel" class="admin-back">← Dashboard</a><span class="admin-page-kicker">ACADEMIC UPDATES</span><h1>Important academic updates.</h1><p>Publish only Results, Date Sheets, Exam Notices, Admit Cards and Assessments. Assessment links should point directly to the official university/college assessment page.</p></div></div><div class="admin-editor-grid"><div class="card admin-editor-card"><div class="admin-editor-label">PUBLISH NEW</div><h2>New academic update</h2><form id="adminAcademicDriveForm" class="form" onsubmit="return false"><select name="kind" required><option value="">Choose update type</option><option>Result</option><option>Date Sheet</option><option>Exam Notice</option><option>Admit Card</option><option>Assessment</option></select><input name="title" placeholder="Title e.g. Semester Result 2026" required><textarea name="description" placeholder="What should students know?" required></textarea><input name="event_date" placeholder="Date / schedule (optional)"><input name="external_url" type="url" placeholder="Direct official website link (required for Result, Admit Card and Assessment)"><input id="adminAcademicDriveFile" type="file"><div id="adminAcademicDriveStatus" class="small">Add a file, a website link, or both. Files go directly to Google Drive.</div><button class="btn accent" type="submit">Publish update →</button></form>{VYBE_DIRECT_DRIVE_JS}{VYBE_ACADEMIC_UPDATE_FORM_JS}</div><div class="card admin-editor-side"><span class="admin-side-icon" aria-hidden="true">⚑</span><h2>Student view</h2><p>Students will see these five update types. Assessment and other official links open the supplied website directly.</p><div class="admin-side-rule"></div><b>{len(rows)} published updates</b></div></div><div class="admin-list-card"><div class="admin-list-head"><div><span>CONTENT LIBRARY</span><h2>Published academic updates</h2></div><small>Delete anything outdated.</small></div>{table or '<div class="admin-empty">No academic updates yet.</div>'}</div></section>'''
    return layout("Academic Updates",body,admin=True)

ACADEMIC_HUB_ADMIN_CSS = """
<style>
.admin-ah-page{max-width:1180px!important;margin:0 auto!important;padding:50px 0 90px!important}.admin-ah-hero{margin-bottom:24px}.admin-ah-hero h1{margin:10px 0 8px;font-size:clamp(36px,5vw,56px);letter-spacing:-.05em;color:#17202b}.admin-ah-hero p{margin:0;max-width:720px;color:#687482;line-height:1.6}.admin-ah-tabs{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px}.admin-ah-tab{display:block;padding:18px 19px;border:1px solid #dfe5ea;border-radius:18px;background:#fff;text-decoration:none;color:#17202b;box-shadow:0 9px 24px rgba(31,48,66,.05)}.admin-ah-tab b{display:block;font-size:15px}.admin-ah-tab span{display:block;margin-top:4px;color:#7b8792;font-size:11px;line-height:1.4}.admin-ah-tab.active{border-color:#a9c8e8;background:linear-gradient(145deg,#f5f9ff,#fff)}.admin-ah-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.admin-ah-card{border:1px solid #dfe5ea;border-radius:22px;background:#fff;padding:22px;box-shadow:0 12px 30px rgba(31,48,66,.055)}.admin-ah-card h2{margin:5px 0 8px;color:#17202b}.admin-ah-card p{color:#6b7884;line-height:1.55}.admin-ah-label{font-size:10px;font-weight:900;letter-spacing:.12em;color:#2f6fca}.admin-ah-form{display:grid;gap:11px}.admin-ah-form input,.admin-ah-form select,.admin-ah-form textarea{box-sizing:border-box;width:100%;min-height:44px}.admin-ah-form textarea{min-height:80px;resize:vertical}.admin-ah-two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.admin-ah-files{padding:14px;border:1px dashed #cbd8e4;border-radius:15px;background:#f8fbfe}.admin-ah-help{font-size:11px;color:#7a8793}.admin-ah-list{margin-top:18px;border:1px solid #e1e6eb;border-radius:18px;overflow:hidden;background:#fff}.admin-ah-list-head{padding:16px 18px;border-bottom:1px solid #e7ebee;display:flex;justify-content:space-between;gap:12px;align-items:center}.admin-ah-list-head strong{font-size:14px}.admin-ah-list-head span{font-size:11px;color:#7d8994}.admin-ah-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:15px;padding:15px 18px;border-bottom:1px solid #eef1f3;align-items:center}.admin-ah-row:last-child{border-bottom:0}.admin-ah-row-main strong{display:block;color:#17202b;font-size:14px}.admin-ah-meta{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}.admin-ah-meta span{font-size:10px;font-weight:800;padding:5px 8px;border-radius:999px;background:#f2f5f7;color:#66737e}.admin-ah-row-actions{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}.admin-ah-note{padding:13px 14px;border-radius:14px;background:#edf8e6;color:#547d37;border:1px solid #d8ebc9;font-size:11px;line-height:1.5}
@media(max-width:850px){.admin-ah-page{padding:35px 16px 78px!important}.admin-ah-tabs,.admin-ah-grid{grid-template-columns:1fr}.admin-ah-two{grid-template-columns:1fr}.admin-ah-row{grid-template-columns:1fr}.admin-ah-row-actions{justify-content:flex-start}.admin-ah-row-actions .btn{flex:1;min-width:120px;text-align:center}}
</style>
"""


AH_DIRECT_UPLOAD_JS = r'''
<script>(function(){const csrf=(document.querySelector('meta[name="vybe-csrf-token"]')||{}).content||'';async function j(url,opts){opts=opts||{};opts.credentials='same-origin';opts.headers=Object.assign({'Accept':'application/json','X-VYBE-CSRF':csrf},opts.headers||{});const r=await fetch(url,opts);let d={};try{d=await r.json()}catch(_){ }if(!r.ok)throw new Error(d.error||('Request failed (HTTP '+r.status+')'));return d}async function upload(file,status,semester,subject){const init=await j('/admin/drive/upload-session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category:({'notes':'Notes','study_material':'Study Material','pyq':'Previous Year Questions','syllabus':'Syllabus','assignments':'Assignments'})['__AH_SECTION__']||'Notes',name:file.name,mimeType:file.type||'application/octet-stream',size:file.size,semester:(semester||'').toString().trim(),subject:(subject||'').toString().trim()})});const xhrUpload=()=>new Promise((resolve,reject)=>{const x=new XMLHttpRequest();x.open('PUT',init.upload_url,true);x.upload.onprogress=e=>{if(e.lengthComputable)status.textContent='Uploading '+file.name+' · '+Math.round(e.loaded/e.total*100)+'%'};x.onload=()=>{if(x.status>=200&&x.status<300){try{resolve(x.response?JSON.parse(x.response):JSON.parse(x.responseText||'{}'))}catch(e){reject(new Error('Drive returned an invalid upload response.'))}}else reject(new Error('Direct Drive upload failed (HTTP '+x.status+').'))};x.onerror=()=>reject(new Error('Direct Drive connection was blocked.'));x.ontimeout=()=>reject(new Error('Drive upload timed out.'));x.timeout=900000;x.responseType='json';x.send(file)});let meta;try{meta=await xhrUpload()}catch(_){let start=0,done=null;const stat=await j('/admin/drive/upload-status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_url:init.upload_url,total:file.size})});if(stat.complete)done=stat.metadata;else start=Number(stat.next_start||0);while(!done&&start<file.size){const end=Math.min(start+4*1024*1024,file.size);status.textContent='Uploading '+file.name+' · '+Math.round(start/file.size*100)+'%';const r=await fetch('/admin/drive/upload-chunk?session_url='+encodeURIComponent(init.upload_url)+'&start='+start+'&end='+(end-1)+'&total='+file.size,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/octet-stream','X-VYBE-CSRF':csrf},body:file.slice(start,end)});let d={};try{d=await r.json()}catch(_){ }if(!r.ok)throw new Error(d.error||('Upload chunk failed (HTTP '+r.status+').'));start=Number(d.next_start||end);if(d.complete)done=d.metadata}meta=done}if(!meta||!meta.id)throw new Error('Google Drive completed the upload but returned no file ID.');meta.__vybe_folder_id=init.folder_id||'';return meta}async function publish(form,file,status){const data=new FormData(form);status.textContent='Starting '+file.name+'…';const meta=await upload(file,status,(data.get('semester')||'').toString().trim(),(data.get('subject')||'').toString().trim());await j('/admin/drive/register-resource',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category:({'notes':'Notes','study_material':'Study Material','pyq':'Previous Year Questions','syllabus':'Syllabus','assignments':'Assignments'})['__AH_SECTION__']||'Notes',file_id:meta.id,title:(data.get('title')||file.name.replace(/\.[^.]+$/,'')).toString(),course:data.get('course'),semester:data.get('semester'),subject:data.get('subject'),description:data.get('description'),folder_id:meta.__vybe_folder_id||''})});}const single=document.getElementById('ahSingleUpload');if(single)single.addEventListener('submit',async()=>{const status=document.getElementById('ahSingleStatus'),file=single.elements.file.files[0];if(!file)return;const b=single.querySelector('button');b.disabled=true;try{await publish(single,file,status);status.textContent='✓ Uploaded and published successfully.';single.reset()}catch(e){status.textContent='Upload failed: '+e.message}finally{b.disabled=false}});const bulk=document.getElementById('ahBulkUpload');if(bulk)bulk.addEventListener('submit',async()=>{const status=document.getElementById('ahBulkStatus'),files=Array.from(bulk.elements.files.files||[]);if(!files.length)return;const b=bulk.querySelector('button');b.disabled=true;let done=0;try{for(const file of files){await publish(bulk,file,status);done++;status.textContent='✓ '+done+'/'+files.length+' uploaded · '+file.name}status.textContent='✓ All '+done+' files uploaded and published successfully.';bulk.reset()}catch(e){status.textContent='Upload stopped after '+done+' file(s): '+e.message}finally{b.disabled=false}})})();</script>
'''

@app.route("/admin/academic-hub", methods=["GET", "POST"])
@admin_required
def admin_academic_hub():
    allowed={"notes":"Notes","study_material":"Study material","pyq":"Previous Year Questions","syllabus":"Syllabus"}
    section=request.args.get("section","notes").strip()
    if section not in allowed: section="notes"
    con=db()
    if request.method=="POST":
        mode=request.form.get("mode","single").strip()
        section=request.form.get("section","notes").strip()
        if section not in allowed: section="notes"
        typ=allowed[section]
        course=request.form.get("course","All").strip()[:100]
        semester=request.form.get("semester","").strip()[:100]
        subject=request.form.get("subject","").strip()[:120]
        description=request.form.get("description","").strip()[:1000]
        files=request.files.getlist("files") if mode=="bulk" else [request.files.get("file")]
        files=[f for f in files if f and f.filename]
        title=request.form.get("title","").strip()[:150]
        if not semester or not subject:
            con.close(); flash("Semester and subject are required."); return redirect(url_for("admin_academic_hub",section=section))
        if not files:
            con.close(); flash("Choose at least one file to upload."); return redirect(url_for("admin_academic_hub",section=section))
        if mode!="bulk" and not title:
            con.close(); flash("Resource title is required for a single upload."); return redirect(url_for("admin_academic_hub",section=section))
        added=0
        try:
            for f in files:
                suffix=Path(f.filename).suffix.lower()
                if suffix not in ALLOWED_EXT: raise ValueError(f"Unsupported file type: {Path(f.filename).name}")
                data=f.read()
                if len(data)>20*1024*1024: raise ValueError(f"File is larger than 20 MB: {Path(f.filename).name}")
                original=Path(f.filename).name[:240]
                mime=f.mimetype or mimetypes.guess_type(original)[0] or "application/octet-stream"
                assistant_text=_extract_doc_text(data,suffix,50000)
                item_title=title if mode!="bulk" else Path(original).stem[:150]
                _drive_store_resource(con,title=item_title,resource_type=typ,course=course,semester=semester,subject=subject,description=description,original_name=original,mime_type=mime,data=data,assistant_text=assistant_text)
                added+=1
            con.commit(); con.close(); flash(f"{added} {typ} resource{'s' if added!=1 else ''} uploaded successfully.")
        except ValueError as e:
            con.rollback(); con.close(); flash(str(e))
        except Exception:
            con.rollback(); con.close(); app.logger.exception("Academic Hub upload failed"); flash("Could not upload the academic resources. Please try again.")
        return redirect(url_for("admin_academic_hub",section=section))
    rows=con.execute("SELECT id,title,resource_type,course,semester,subject,original_name,created_at FROM resources WHERE resource_type=? ORDER BY id DESC LIMIT 100",(allowed[section],)).fetchall()
    con.close()
    descriptions={
        "notes":"Revision notes by semester and subject.",
        "study_material":"Study files organized by semester and subject.",
        "pyq":"Previous-year question papers by semester and subject.",
        "syllabus":"Syllabus files organized by semester and subject.",
        "assignments":"Assignments organized by semester and subject.",
    }
    tabs=[]
    for k,v in allowed.items():
        active=" active" if k==section else ""
        tabs.append(f'<a class="admin-ah-tab{active}" href="/admin/academic-hub?section={k}"><b>{v}</b><span>{descriptions[k]}</span></a>')
    rows_html="".join(f'''<div class="admin-ah-row"><div><strong>{esc(r["title"])}</strong><div class="admin-ah-meta"><span>{esc(r["semester"] or "Semester")}</span><span>{esc(r["subject"] or "Subject")}</span><span>{esc(r["course"] or "All courses")}</span><span>{esc(r["original_name"] or "File")}</span></div></div><div class="admin-ah-row-actions"><a class="btn" href="/resource/{r["id"]}" target="_blank" rel="noopener">Open</a><form method="post" action="/admin/academic-hub/resource/{r["id"]}/delete" onsubmit="return confirm('Delete this resource?')"><button class="btn danger">Delete</button></form></div></div>''' for r in rows)
    body=f'''{ACADEMIC_HUB_ADMIN_CSS}<section class="admin-ah-page"><div class="admin-ah-hero"><a href="/admin/panel" class="admin-back">← Dashboard</a><span class="admin-page-kicker">ACADEMIC HUB</span><h1>Academic collections.</h1><p>Upload any file type directly to Google Drive. Single files and large bulk batches use resumable Drive uploads, so Vercel request-size limits do not interrupt the transfer.</p></div><div class="admin-ah-tabs">{"".join(tabs)}</div><div class="admin-ah-grid"><div class="admin-ah-card"><span class="admin-ah-label">SINGLE UPLOAD</span><h2>Add one file</h2><p>Give one resource its own student-facing title.</p><form id="ahSingleUpload" class="admin-ah-form" onsubmit="return false"><input name="title" placeholder="Resource title" required><div class="admin-ah-two"><input name="course" placeholder="Course / program" value="All"><input name="semester" placeholder="Semester (e.g. 1st Semester)" required></div><input name="subject" placeholder="Subject" required><textarea name="description" placeholder="Short description (optional)"></textarea><div class="admin-ah-files"><input type="file" name="file" required><div class="admin-ah-help">Any file format supported by Google Drive.</div></div><div id="ahSingleStatus" class="admin-ah-help"></div><button class="btn accent" type="submit">Upload directly to Drive →</button></form></div><div class="admin-ah-card"><span class="admin-ah-label">BULK UPLOAD</span><h2>Add many files</h2><p>Select as many files as you need. VYBE uploads them sequentially with a visible progress message.</p><form id="ahBulkUpload" class="admin-ah-form" onsubmit="return false"><div class="admin-ah-two"><input name="course" placeholder="Course / program" value="All"><input name="semester" placeholder="Semester (e.g. 1st Semester)" required></div><input name="subject" placeholder="Subject" required><textarea name="description" placeholder="Description for all uploaded files (optional)"></textarea><div class="admin-ah-files"><input type="file" name="files" multiple required><div class="admin-ah-help">Large batches are sent directly to Google Drive one file at a time.</div></div><div id="ahBulkStatus" class="admin-ah-help"></div><button class="btn dark" type="submit">Upload all directly to Drive →</button></form><div class="admin-ah-note" style="margin-top:12px">Keep files for the same subject and semester in one batch.</div></div></div>{AH_DIRECT_UPLOAD_JS.replace("__AH_SECTION__", section)}<div class="admin-ah-list"><div class="admin-ah-list-head"><strong>Published {esc(allowed[section])}</strong><span>{len(rows)} item(s)</span></div>{rows_html or '<div style="padding:24px;color:#7b8792">No resources uploaded in this section yet.</div>'}</div></section>'''
    return layout("Academic Hub",body,admin=True)


@app.route("/admin/academic-update/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_academic_update(uid):
    con=db(); row=con.execute("SELECT file_name,drive_file_id FROM academic_updates WHERE id=?",(uid,)).fetchone()
    if row and row["drive_file_id"]:
        try: _drive_delete_file(row["drive_file_id"])
        except Exception: app.logger.exception("Could not delete Drive academic update %s", row["drive_file_id"])
    if row and row["file_name"]:
        try: (UPLOAD_DIR/row["file_name"]).unlink(missing_ok=True)
        except Exception: pass
    con.execute("DELETE FROM academic_updates WHERE id=?",(uid,)); con.commit(); con.close(); flash("Academic update deleted."); return redirect(url_for("admin_academic_hub"))


@app.route("/admin/academic-hub/resource/<int:rid>/delete", methods=["POST"])
@admin_required
def admin_academic_hub_delete_resource(rid):
    con=db(); row=con.execute("SELECT file_name,resource_type,drive_file_id FROM resources WHERE id=?",(rid,)).fetchone()
    if not row:
        con.close(); flash("Resource not found."); return redirect(url_for("admin_academic_hub"))
    typ=row["resource_type"] or "Notes"
    section={
        "Notes":"notes",
        "Study material":"study_material",
        "Previous Year Questions":"pyq",
        "Syllabus":"syllabus",
        "Assignments":"assignments",
    }.get(typ,"notes")
    con.execute("DELETE FROM resources WHERE id=?",(rid,)); con.commit(); con.close()
    if row["drive_file_id"]:
        try: _drive_delete_file(row["drive_file_id"])
        except Exception: app.logger.exception("Could not delete Drive resource %s", row["drive_file_id"])
    if row["file_name"]:
        try: (UPLOAD_DIR/row["file_name"]).unlink(missing_ok=True)
        except OSError: pass
    flash("Academic resource deleted.")
    return redirect(url_for("admin_academic_hub",section=section))


@app.route("/admin/resources")
@admin_required
def admin_resources():
    # Legacy resource manager retained as a compatibility URL. All new uploads
    # use the resumable, direct-to-Drive Academic Hub uploader.
    return redirect(url_for("admin_academic_hub", section="notes"))


@app.route("/admin/resource", methods=["POST"])
@admin_required
def add_resource():
    # Older forms/bookmarks should never send large files through Vercel.
    flash("Please use the VYBE Academic Hub upload center; files are uploaded directly to Google Drive.")
    return redirect(url_for("admin_academic_hub", section="notes"))

@app.route("/admin/resource/<int:rid>/delete", methods=["POST"])
@admin_required
def delete_resource(rid):
    con=db(); r=con.execute("SELECT file_name,drive_file_id FROM resources WHERE id=?",(rid,)).fetchone(); con.execute("DELETE FROM resources WHERE id=?",(rid,)); con.commit(); con.close()
    if r and r["drive_file_id"]:
        try: _drive_delete_file(r["drive_file_id"])
        except Exception: app.logger.exception("Could not delete Drive resource %s", r["drive_file_id"])
    if r and r["file_name"]:
        try: (UPLOAD_DIR/r["file_name"]).unlink(missing_ok=True)
        except OSError: pass
    flash("Resource deleted."); return redirect(url_for("admin_resources"))




COMMUNITY_PROBLEM_ACTIONS_CSS = """
<style>
.community-page-section .actions{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-top:12px}
.community-page-section .actions form{margin:0}
@media(max-width:600px){.community-page-section .actions{display:grid;grid-template-columns:1fr}.community-page-section .actions .btn,.community-page-section .actions form,.community-page-section .actions form .btn{width:100%;box-sizing:border-box;text-align:center}}
</style>
"""

ADMIN_PROBLEMS_CSS = """
<style>
.admin-problems-page,.admin-campus-page{max-width:1180px!important;margin:0 auto!important;padding:54px 0 90px!important}
.admin-problems-head,.admin-campus-head{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:28px}
.admin-problems-head h1,.admin-campus-head h1{margin:12px 0 8px;font-size:clamp(34px,5vw,54px);letter-spacing:-.045em;color:#17202b}
.admin-problems-head p,.admin-campus-head p{max-width:720px;margin:0;color:#687482;line-height:1.6}
.admin-problems-head-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end}
.admin-problem-count{padding:10px 13px;border:1px solid #dfe5ea;border-radius:999px;background:#fff;color:#5e6b77;font-size:12px;font-weight:850}
.admin-campus-problems-link{display:flex;flex-direction:column;gap:4px;min-width:255px;padding:16px 18px;border:1px solid #cfe0f4;border-radius:18px;background:linear-gradient(145deg,#f5f9ff,#fff);color:#17202b;text-decoration:none;box-shadow:0 10px 26px rgba(31,48,66,.06)}
.admin-campus-problems-link span{font-size:10px;font-weight:900;letter-spacing:.1em;color:#2f6fca;text-transform:uppercase}.admin-campus-problems-link strong{font-size:14px}
.admin-problem-list{display:grid;gap:16px}.admin-problem-card{scroll-margin-top:90px;border:1px solid #dfe5ea;border-radius:22px;background:rgba(255,255,255,.96);padding:22px;box-shadow:0 12px 30px rgba(31,48,66,.055)}
.admin-problem-top{display:flex;align-items:center;justify-content:space-between;gap:12px}.admin-problem-number{font-size:11px;font-weight:900;color:#2f6fca;margin-right:8px}.admin-problem-card h2{margin:13px 0 9px;font-size:22px;color:#17202b}.admin-problem-reporter{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.admin-problem-reporter span,.admin-problem-reporter strong{padding:6px 9px;border-radius:999px;background:#f3f6f8;color:#64717d;font-size:11px}.admin-problem-reporter strong{background:#edf4ff;color:#2f6fca}.admin-problem-description{margin:15px 0 0;padding:14px 15px;border-radius:15px;background:#f8fafb;color:#52606c;line-height:1.6;white-space:pre-wrap}.admin-problem-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}.admin-solution-compose{margin-top:18px;padding:17px;border:1px solid #d8e5f4;border-radius:18px;background:linear-gradient(145deg,#f7fbff,#fff)}.admin-solution-compose-head{display:flex;justify-content:space-between;gap:15px;align-items:flex-start;margin-bottom:11px}.admin-solution-compose-head div{display:flex;flex-direction:column;gap:3px}.admin-solution-compose-head span:first-child{font-size:10px;font-weight:900;letter-spacing:.1em;color:#2f6fca}.admin-solution-compose-head strong{font-size:16px;color:#17202b}.admin-solution-compose-head>span:last-child{font-size:10px;font-weight:800;color:#579c24;background:#edf8e6;padding:7px 9px;border-radius:999px}.admin-solution-compose textarea{width:100%;min-height:105px;resize:vertical;box-sizing:border-box;padding:13px 14px;border:1px solid #d7e0e8;border-radius:14px;background:#fff;color:#17202b;font:inherit;outline:none}.admin-solution-compose textarea:focus{border-color:#8fbce0;box-shadow:0 0 0 4px rgba(47,111,202,.08)}.admin-solution-compose-foot{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-top:10px}.admin-solution-compose-foot small{color:#778592;line-height:1.4}.admin-solution-history{margin-top:12px;padding:14px;border:1px solid #e5eaee;border-radius:15px;background:#fbfcfd}.admin-solution-history>div:first-child{display:flex;justify-content:space-between;gap:10px}.admin-solution-history strong{font-size:12px;color:#2f6fca}.admin-solution-history small{font-size:10px;color:#8a96a0}.admin-solution-history p{margin:8px 0;color:#56636f;white-space:pre-wrap;line-height:1.5}.admin-solution-student-page{max-width:820px;margin:0 auto;padding:50px 16px 90px}.admin-solution-student-card{padding:26px;border:1px solid #dfe5ea;border-radius:24px;background:rgba(255,255,255,.96);box-shadow:0 18px 42px rgba(31,48,66,.08)}.admin-solution-student-card h1{margin:12px 0 5px;font-size:clamp(30px,5vw,46px);letter-spacing:-.04em;color:#17202b}.admin-solution-problem{margin-top:22px;padding:16px;border-radius:17px;background:#f6f8fa;border:1px solid #e3e8ec}.admin-solution-problem strong{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#7a8793}.admin-solution-problem p{margin:8px 0 0;color:#56636f;line-height:1.6;white-space:pre-wrap}.admin-solution-message{margin-top:14px;padding:18px;border-radius:18px;background:linear-gradient(145deg,#edf4ff,#f7fbff);border:1px solid #cfe0f4}.admin-solution-message-head{display:flex;justify-content:space-between;gap:12px}.admin-solution-message-head span{font-weight:900;color:#2f6fca}.admin-solution-message-head small{color:#7a8793}.admin-solution-message p{margin:12px 0 0;color:#26333f;line-height:1.7;white-space:pre-wrap}
@media(max-width:850px){.admin-problems-page,.admin-campus-page{padding:34px 16px 78px!important}.admin-problems-head,.admin-campus-head{align-items:stretch;flex-direction:column}.admin-problems-head h1,.admin-campus-head h1{font-size:38px}.admin-problems-head-actions{justify-content:flex-start}.admin-campus-problems-link{min-width:0}.admin-problem-card{padding:17px;border-radius:19px}.admin-problem-card h2{font-size:19px}.admin-solution-compose-foot{align-items:stretch;flex-direction:column}.admin-solution-compose-foot .btn{width:100%;text-align:center}.admin-solution-student-page{padding:30px 14px 78px}.admin-solution-student-card{padding:19px;border-radius:19px}}
</style>

"""
@app.route("/student/content-version")
@student_required
def student_content_version():
    """Return the latest admin content version without rendering a page."""
    con = db()
    try:
        row = con.execute("SELECT value FROM settings WHERE key=?", ("student_content_version",)).fetchone()
        version = row["value"] if row else "0"
    finally:
        con.close()
    return jsonify({"version": str(version)})


@app.route("/admin/problem-alerts")
@admin_required
def admin_problem_alerts():
    con=db()
    try:
        rows=con.execute(
            "SELECT i.id,i.title,i.description,i.category,i.status,i.created_at,s.name,s.student_id "
            "FROM issues i JOIN students s ON s.id=i.student_id "
            "WHERE i.status NOT IN ('Resolved','Closed') ORDER BY i.id DESC LIMIT 8"
        ).fetchall()
    finally:
        con.close()
    return jsonify({"count": len(rows), "items": [{
        "id": int(r["id"]), "title": r["title"], "description": r["description"],
        "category": r["category"], "status": r["status"], "created_at": r["created_at"],
        "name": r["name"], "student_id": r["student_id"]
    } for r in rows]})


@app.route("/admin/problems")
@app.route("/admin/problems-solutions")
@admin_required
def admin_problems():
    con=db()
    rows=con.execute("SELECT i.*,s.name,s.student_id FROM issues i JOIN students s ON s.id=i.student_id ORDER BY i.id DESC").fetchall()
    solution_rows=con.execute("SELECT aps.*,i.title AS issue_title FROM admin_problem_solutions aps JOIN issues i ON i.id=aps.issue_id ORDER BY aps.id DESC").fetchall()
    con.close()
    cards=[]
    for r in rows:
        previous=[x for x in solution_rows if int(x["issue_id"])==int(r["id"])]
        previous_html=''.join(f"""<div class=\"admin-solution-history\"><div><strong>{esc(x["admin_label"])}</strong><small>{esc(x["created_at"])}</small></div><p>{esc(x["solution_text"])}</p><div class=\"actions\"><form method=\"post\" action=\"/admin/problem/{r["id"]}/solution/{x["id"]}/resend\"><button class=\"btn dark\" type=\"submit\">Show as new</button></form><form method=\"post\" action=\"/admin/problem/{r["id"]}/solution/{x["id"]}/delete\" onsubmit=\"return confirm('Delete this admin solution?')\"><button class=\"btn danger\" type=\"submit\">Delete</button></form></div></div>""" for x in previous)
        cards.append(f"""<article class=\"admin-problem-card\" id=\"problem-{r["id"]}\"><div class=\"admin-problem-top\"><div><span class=\"admin-problem-number\">#{r["id"]}</span><span class=\"pill\">{esc(r["status"])}</span></div></div><h2>{esc(r["title"])}</h2><div class=\"admin-problem-reporter\"><strong>{esc(r["name"])}</strong><span>Student ID: {esc(r["student_id"])}</span><span>{esc(r["category"])}</span><span>{esc(r["created_at"])}</span></div><p class=\"admin-problem-description\">{esc(r["description"])}</p><div class=\"admin-problem-actions\"><a class=\"btn dark\" href=\"/admin/problem/{r["id"]}/status\">Next status</a><form method=\"post\" action=\"/admin/problem/{r["id"]}/delete\" onsubmit=\"return confirm('Delete this student problem and its solutions?')\"><button class=\"btn danger\" type=\"submit\">Delete problem</button></form></div><div class=\"admin-solution-compose\"><div class=\"admin-solution-compose-head\"><div><span>ADMIN SOLUTION</span><strong>Send directly to this student</strong></div><span>Alert notification</span></div><form method=\"post\" action=\"/admin/problem/{r["id"]}/solution\"><textarea name=\"solution_text\" maxlength=\"3000\" placeholder=\"Write the solution or instructions for this student...\" required></textarea><div class=\"admin-solution-compose-foot\"><small>The student will receive this message in the VYBE alert button.</small><button class=\"btn accent\" type=\"submit\">Send solution →</button></div></form></div>{previous_html}</article>""")
    body=f"""{ADMIN_PROBLEMS_CSS}<section class=\"section admin-problems-page\"><div class=\"admin-problems-head\"><div><a href=\"/admin/campus\" class=\"admin-back\">← Faculty &amp; Contacts</a><span class=\"admin-page-kicker\">CAMPUS SUPPORT</span><h1>Student problems &amp; solutions.</h1><p>Review every problem reported through Solve Campus Problem, then send an official solution directly to the student.</p></div><div class=\"admin-problems-head-actions\"><a class=\"btn dark\" href=\"/admin/campus\">Faculty contacts</a><span class=\"admin-problem-count\">{len(rows)} reports</span></div></div><div class=\"admin-problem-list\">{''.join(cards) or '<div class=\"empty\">No student problems have been reported yet.</div>'}</div></section>"""
    return layout("Problems & Solutions",body,admin=True)


@app.route("/admin/problem/<int:iid>/delete", methods=["POST"])
@admin_required
def delete_problem(iid):
    con = db()
    # accepted_solutions in older VYBE databases does not have issue_id.
    # Remove matching saved/accepted records using the issue owner + title
    # instead of querying a column that may not exist.
    issue = con.execute("SELECT student_id,title FROM issues WHERE id=?", (iid,)).fetchone()
    if issue:
        con.execute("DELETE FROM accepted_solutions WHERE student_id=? AND issue_title=?", (issue["student_id"], issue["title"]))
    con.execute("DELETE FROM helpful_votes WHERE solution_id IN (SELECT id FROM solutions WHERE issue_id=?)", (iid,))
    con.execute("DELETE FROM admin_problem_solutions WHERE issue_id=?", (iid,))
    con.execute("DELETE FROM solutions WHERE issue_id=?", (iid,))
    con.execute("DELETE FROM issues WHERE id=?", (iid,))
    con.commit(); con.close(); flash("Help desk report deleted.")
    return redirect(url_for("admin_problems"))


@app.route("/admin/problem/<int:iid>/status", methods=["POST"])
@admin_required
def problem_status(iid):
    con=db(); row=con.execute("SELECT status FROM issues WHERE id=?",(iid,)).fetchone()
    if row:
        idx=STATUSES.index(row["status"]) if row["status"] in STATUSES else 0; con.execute("UPDATE issues SET status=? WHERE id=?",(STATUSES[(idx+1)%len(STATUSES)],iid)); con.commit()
    con.close(); return redirect(url_for("admin_problems"))


@app.route("/admin/campus", methods=["GET", "POST"])
@admin_required
def admin_campus():
    con = db()
    if request.method == "POST":
        action = request.form.get("action", "add").strip()
        fid = request.form.get("faculty_id", "").strip()
        name = request.form.get("name", "").strip()[:160]
        designation = request.form.get("designation", "").strip()[:160]
        email = request.form.get("email", "").strip()[:254]
        if action == "delete":
            if fid.isdigit():
                con.execute("DELETE FROM faculty WHERE id=?", (int(fid),)); con.commit(); flash("Faculty member removed.")
            else: flash("Invalid faculty record.")
        elif not name or not designation or not email or "@" not in email or " " in email:
            flash("Name, designation and a valid email address are required.")
        elif action == "edit" and fid.isdigit():
            con.execute("UPDATE faculty SET name=?, designation=?, email=?, updated_at=? WHERE id=?", (name, designation, email, now(), int(fid)))
            con.commit(); flash("Faculty member updated.")
        else:
            con.execute("INSERT INTO faculty(name,designation,email,created_at,updated_at) VALUES(?,?,?,?,?)", (name, designation, email, now(), now()))
            con.commit(); flash("Faculty member added.")
        con.close(); return redirect(url_for("admin_campus"))
    rows = con.execute("SELECT id,name,designation,email FROM faculty ORDER BY LOWER(name) ASC, id ASC").fetchall()
    con.close()
    cards = "".join(f"""<div class="card"><h2 style="margin:0 0 6px">{esc(x['name'])}</h2><p class="muted">{esc(x['designation'])}</p><p><a href="mailto:{esc(x['email'])}">{esc(x['email'])}</a></p><div class="actions"><details><summary class="btn dark">Edit</summary><form class="form" method="post" style="margin-top:12px"><input type="hidden" name="action" value="edit"><input type="hidden" name="faculty_id" value="{x['id']}"><input name="name" value="{esc(x['name'])}" maxlength="160" required><input name="designation" value="{esc(x['designation'])}" maxlength="160" required><input type="email" name="email" value="{esc(x['email'])}" maxlength="254" required><button class="btn accent">Save changes</button></form></details><form method="post" onsubmit="return confirm('Remove this faculty member?')"><input type="hidden" name="action" value="delete"><input type="hidden" name="faculty_id" value="{x['id']}"><button class="btn danger">Delete</button></form></div></div>""" for x in rows)
    body = f"""<section class="section admin-campus-page"><div class="admin-campus-head"><div><div class="badge">ADMIN CAMPUS</div><h1>Faculty contacts.</h1><p class="muted">These contacts appear on the student Help Desk page. Add, edit or delete them anytime.</p></div><a class="admin-campus-problems-link" href="/admin/problems-solutions"><span>Campus problems</span><strong>View reports &amp; send solutions →</strong></a></div><div class="card"><h2>Add faculty / teacher</h2><form class="form" method="post"><input type="hidden" name="action" value="add"><div class="two"><input name="name" maxlength="160" placeholder="Full name" required><input name="designation" maxlength="160" placeholder="Designation" required></div><input type="email" name="email" maxlength="254" placeholder="Email ID" required><button class="btn accent">Add faculty</button></form></div></section><section class="section"><div class="grid">{cards or '<div class="empty">No faculty members added yet.</div>'}</div></section>"""
    return layout("Campus", body, admin=True)


def _ensure_contact_terms_table(con):
    """Ensure the consent table exists even on an older Render database.

    This is intentionally called from the public/admin routes as well as init_db,
    so an older deployment can self-heal without requiring a manual SQL migration.
    """
    if con.is_pg:
        con.execute("""CREATE TABLE IF NOT EXISTS contact_terms_consents (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL DEFAULT '',
            consented_at TEXT NOT NULL
        )""")
    else:
        con.execute("""CREATE TABLE IF NOT EXISTS contact_terms_consents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL DEFAULT '',
            consented_at TEXT NOT NULL
        )""")



CONTACT_TERMS_CSS = """<style>
*{box-sizing:border-box}
html,body{margin:0!important;padding:0!important;min-height:100%!important;background:#02050b!important}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Arial,sans-serif;color:#f4f7fb;overflow-x:hidden}
.contact-terms-page{position:relative;isolation:isolate;min-height:100vh;width:100%;padding:clamp(24px,4vw,58px) clamp(16px,4vw,58px) 70px;overflow:hidden;background:#02050b}
.contact-terms-page:before{content:"";position:fixed;inset:-35%;z-index:-5;background:radial-gradient(circle at 18% 18%,rgba(43,113,255,.30),transparent 24%),radial-gradient(circle at 84% 16%,rgba(91,226,104,.20),transparent 22%),radial-gradient(circle at 52% 88%,rgba(126,76,255,.18),transparent 27%),radial-gradient(circle at 8% 80%,rgba(0,214,255,.12),transparent 20%),#02050b;animation:contactAura 16s ease-in-out infinite alternate}
.contact-terms-page:after{content:"";position:fixed;inset:0;z-index:-4;opacity:.17;background-image:linear-gradient(rgba(255,255,255,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.045) 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(to bottom,black 0%,rgba(0,0,0,.75) 55%,transparent 100%);animation:gridMove 18s linear infinite}
@keyframes contactAura{0%{transform:scale(1) rotate(0deg)}100%{transform:scale(1.13) rotate(2deg) translate3d(1%,-1%,0)}}
@keyframes gridMove{to{background-position:44px 44px}}
@keyframes contactPulse{0%,100%{box-shadow:0 0 0 0 rgba(104,184,46,.22)}50%{box-shadow:0 0 0 9px rgba(104,184,46,0)}}
@keyframes contactFloat{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(0,-9px,0)}}
@keyframes contactShine{0%{transform:translateX(-130%) rotate(12deg)}55%,100%{transform:translateX(130%) rotate(12deg)}}
.contact-terms-shell{position:relative;max-width:1500px;min-height:calc(100vh - 100px);margin:0 auto;overflow:hidden;border:1px solid rgba(255,255,255,.13);border-radius:clamp(26px,3vw,42px);background:linear-gradient(145deg,rgba(11,20,35,.91),rgba(3,8,16,.96));box-shadow:0 45px 130px rgba(0,0,0,.56),inset 0 1px 0 rgba(255,255,255,.08);backdrop-filter:blur(28px)}
.contact-terms-shell:before{content:"";position:absolute;width:620px;height:620px;right:-270px;top:-340px;border-radius:50%;background:radial-gradient(circle,rgba(55,125,255,.25),transparent 67%);filter:blur(6px);animation:contactFloat 8s ease-in-out infinite}
.contact-terms-shell:after{content:"";position:absolute;width:520px;height:520px;left:-280px;bottom:-330px;border-radius:50%;background:radial-gradient(circle,rgba(104,184,46,.14),transparent 68%);filter:blur(8px)}
.contact-terms-hero{position:relative;z-index:1;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:40px;align-items:center;padding:clamp(38px,6vw,82px) clamp(26px,6vw,82px) clamp(32px,5vw,60px);border-bottom:1px solid rgba(255,255,255,.08)}
.contact-terms-kicker{display:inline-flex;align-items:center;gap:8px;font-size:10px;font-weight:950;letter-spacing:.2em;color:#7fb3ff}.contact-terms-kicker:before{content:"";width:8px;height:8px;border-radius:50%;background:#6ee15b;box-shadow:0 0 18px rgba(110,225,91,.75);animation:contactPulse 2s infinite}
.contact-terms-hero h1{margin:14px 0 15px;font-size:clamp(54px,8vw,116px);line-height:.86;letter-spacing:-.075em;background:linear-gradient(105deg,#fff 10%,#b6d3ff 48%,#8be36d 90%);-webkit-background-clip:text;background-clip:text;color:transparent;text-wrap:balance}
.contact-terms-hero p{max-width:760px;color:#9eacbf;line-height:1.75;margin:0;font-size:clamp(12px,1.1vw,15px)}
.contact-terms-admin{display:inline-flex;align-items:center;gap:9px;margin-top:24px;padding:10px 14px;border:1px solid rgba(127,179,255,.18);border-radius:999px;background:rgba(127,179,255,.07);color:#c5dcff;font-size:11px;font-weight:850;box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.contact-terms-admin:before{content:"";width:7px;height:7px;border-radius:50%;background:#72e85e;box-shadow:0 0 0 5px rgba(114,232,94,.09),0 0 20px rgba(114,232,94,.8);animation:contactPulse 1.8s infinite}
.contact-admin-identity{display:flex;align-items:center;gap:15px;padding:13px;min-width:290px;border:1px solid rgba(255,255,255,.12);border-radius:28px;background:linear-gradient(145deg,rgba(255,255,255,.08),rgba(255,255,255,.035));box-shadow:0 22px 55px rgba(0,0,0,.28),inset 0 1px 0 rgba(255,255,255,.06);backdrop-filter:blur(20px);animation:contactFloat 6s ease-in-out infinite}
.contact-admin-photo,.contact-admin-photo-fallback{width:94px;height:94px;border-radius:25px;flex:0 0 94px;object-fit:cover;border:1px solid rgba(255,255,255,.16);box-shadow:0 18px 42px rgba(0,0,0,.34)}
.contact-admin-photo-fallback{display:grid;place-items:center;background:linear-gradient(145deg,#245aa8,#68b82e);color:#fff;font-size:32px;font-weight:950}
.contact-admin-identity small{display:block;color:#718096;font-size:9px;font-weight:900;letter-spacing:.16em}.contact-admin-identity strong{display:block;margin-top:5px;font-size:18px;color:#fff}.contact-admin-identity span{display:block;margin-top:5px;color:#9ba9bb;font-size:10px}
.contact-terms-grid{position:relative;z-index:1;display:grid;grid-template-columns:1.05fr .95fr;gap:18px;padding:18px}
.contact-terms-card{position:relative;overflow:hidden;border:1px solid rgba(255,255,255,.10);background:linear-gradient(145deg,rgba(255,255,255,.075),rgba(255,255,255,.032));box-shadow:0 22px 55px rgba(0,0,0,.25),inset 0 1px 0 rgba(255,255,255,.045);border-radius:28px;padding:clamp(20px,3vw,32px);backdrop-filter:blur(20px)}
.contact-terms-card:before{content:"";position:absolute;left:-30%;top:-70%;width:55%;height:220%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.055),transparent);transform:rotate(12deg);animation:contactShine 9s ease-in-out infinite}
.contact-terms-card h2{position:relative;margin:0 0 8px;font-size:clamp(21px,2vw,27px);letter-spacing:-.035em;color:#fff}.contact-terms-card>p{position:relative;color:#8492a6;font-size:12px;line-height:1.65;margin:0 0 18px}
.contact-terms-list{position:relative;display:grid;gap:10px;padding:0;margin:0;list-style:none}.contact-terms-list li{display:flex;gap:11px;padding:15px;border:1px solid rgba(255,255,255,.07);border-radius:18px;background:rgba(2,7,14,.46);color:#b9c4d3;font-size:12px;line-height:1.6}.contact-terms-list li:before{content:"✓";display:grid;place-items:center;flex:0 0 25px;height:25px;border-radius:9px;background:rgba(104,184,46,.13);color:#8de05d;font-weight:950}
.contact-terms-form{position:relative;display:grid;gap:13px}.contact-terms-form label:not(.contact-terms-consent){display:grid;gap:7px;color:#7e8ca0;font-size:9px;font-weight:900;letter-spacing:.12em;text-transform:uppercase}.contact-terms-form input:not([type="checkbox"]){width:100%;padding:15px 16px;border:1px solid rgba(255,255,255,.12);border-radius:15px;background:rgba(0,0,0,.28);color:#fff;font:inherit;outline:none;box-shadow:inset 0 1px 0 rgba(255,255,255,.03);transition:.2s}.contact-terms-form input:not([type="checkbox"]):focus{border-color:rgba(101,163,255,.65);box-shadow:0 0 0 4px rgba(63,132,255,.10)}
.contact-terms-consent{display:flex;gap:11px;align-items:flex-start;padding:14px;border:1px solid rgba(255,255,255,.08);border-radius:17px;background:rgba(0,0,0,.24);color:#aeb9c8;font-size:11px;line-height:1.55;cursor:pointer}.contact-terms-consent input{margin-top:3px;accent-color:#6cc84a}.contact-terms-consent strong{display:block;color:#fff;font-size:11px;margin-bottom:3px}
.contact-terms-form .btn{position:relative;overflow:hidden;border:0;border-radius:15px;padding:15px 18px;cursor:pointer;font-weight:900;background:linear-gradient(135deg,#3276dc,#245aa8);color:#fff;box-shadow:0 14px 35px rgba(37,91,168,.28);transition:transform .18s,box-shadow .18s}.contact-terms-form .btn:hover{transform:translateY(-2px);box-shadow:0 18px 42px rgba(37,91,168,.38)}
.contact-reveal{position:relative;margin-top:15px}.contact-terms-email{padding:17px;border:1px solid rgba(104,184,46,.20);border-radius:18px;background:linear-gradient(145deg,rgba(104,184,46,.09),rgba(255,255,255,.035));box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}.contact-terms-email small{display:block;color:#8ed66d;font-size:8px;font-weight:950;letter-spacing:.16em}.contact-terms-email a{display:block;margin-top:7px;color:#fff;font-size:16px;font-weight:850;text-decoration:none;word-break:break-word}.contact-terms-email a:hover{text-decoration:underline}.contact-revealed-admin{display:flex;align-items:center;gap:11px;margin-top:10px;padding:10px;border-radius:16px;background:rgba(0,0,0,.22);border:1px solid rgba(255,255,255,.07)}.contact-revealed-admin img,.contact-revealed-admin .contact-admin-photo-fallback{width:48px;height:48px;flex-basis:48px;border-radius:14px;font-size:17px}.contact-revealed-admin strong{display:block;color:#fff;font-size:11px}.contact-revealed-admin span{display:block;margin-top:3px;color:#7f8da1;font-size:10px}
.contact-terms-locked{padding:16px;border:1px dashed rgba(255,255,255,.13);border-radius:18px;background:rgba(0,0,0,.20);color:#7f8da0;font-size:11px;line-height:1.6}.contact-terms-foot{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-top:17px}.contact-terms-ip{color:#66758a;font-size:9px;line-height:1.5}.contact-terms-foot .btn{display:inline-flex;align-items:center;justify-content:center;padding:11px 14px;border-radius:13px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#cbd6e5;text-decoration:none;font-size:10px;font-weight:850}
.contact-friend-note{position:relative;z-index:1;display:flex;align-items:center;gap:15px;margin:0 18px 18px;padding:22px 24px;border:1px solid rgba(255,255,255,.09);border-radius:24px;background:linear-gradient(100deg,rgba(47,111,202,.10),rgba(104,184,46,.07),rgba(255,255,255,.035));box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}.friend-mark{display:grid;place-items:center;width:48px;height:48px;flex:0 0 48px;border-radius:16px;background:linear-gradient(145deg,#2f6fca,#68b82e);color:#fff;font-size:18px;font-weight:950;box-shadow:0 10px 28px rgba(47,111,202,.25)}.contact-friend-note small{display:block;color:#7eaaf0;font-size:8px;font-weight:950;letter-spacing:.16em}.contact-friend-note strong{display:block;margin-top:4px;color:#fff;font-size:15px;letter-spacing:-.02em}.contact-friend-note span{display:block;margin-top:5px;color:#8593a6;font-size:11px;line-height:1.6}
.contact-terms-success{position:relative;z-index:2;margin:0 18px 0;padding:11px 14px;border:1px solid rgba(104,184,46,.2);border-radius:14px;background:rgba(104,184,46,.08);color:#a7e18d;font-size:10px;font-weight:800}
@media(max-width:900px){.contact-terms-hero{grid-template-columns:1fr}.contact-admin-identity{max-width:100%}.contact-terms-grid{grid-template-columns:1fr}}
@media(max-width:620px){.contact-terms-page{padding:10px 8px 34px}.contact-terms-shell{min-height:calc(100vh - 44px);border-radius:24px}.contact-terms-hero{padding:34px 20px 28px;gap:24px}.contact-terms-hero h1{font-size:clamp(48px,16vw,72px)}.contact-admin-identity{min-width:0;padding:11px}.contact-admin-photo,.contact-admin-photo-fallback{width:72px;height:72px;flex-basis:72px;border-radius:19px}.contact-terms-grid{padding:10px;gap:10px}.contact-terms-card{padding:19px;border-radius:21px}.contact-terms-list li{padding:13px}.contact-friend-note{margin:0 10px 10px;padding:18px;border-radius:20px;align-items:flex-start}.contact-terms-foot{display:grid}.contact-terms-foot .btn{width:100%}.contact-terms-success{margin:0 10px 10px}}
</style>"""
ADMIN_CONTACT_TERMS_CSS = """<style>
.admin-contact-page{max-width:1180px;margin:0 auto;padding:28px 22px 60px}
.admin-contact-page .admin-page-head{margin-bottom:22px}
.admin-contact-page .admin-page-kicker{display:inline-flex;align-items:center;gap:7px;margin-top:8px;color:#2f6fca;font-size:10px;font-weight:900;letter-spacing:.16em}
.admin-contact-page .admin-page-kicker:before{content:"";width:7px;height:7px;border-radius:50%;background:#68b82e;box-shadow:0 0 0 5px #edf8e6}
.admin-contact-page .admin-page-head h1{margin:8px 0 7px;color:#17202b;font-size:clamp(30px,4vw,46px);letter-spacing:-.045em}
.admin-contact-page .admin-page-head p{max-width:720px;margin:0;color:#687482;font-size:13px;line-height:1.65}
.admin-contact-page .admin-back{display:inline-flex;align-items:center;gap:7px;padding:8px 11px;border:1px solid #dfe5ea;border-radius:11px;background:#fff;color:#405164;text-decoration:none;font-size:11px;font-weight:850;box-shadow:0 5px 16px rgba(23,32,43,.05)}
.admin-contact-page .admin-contact-grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr);gap:18px;align-items:stretch}
.admin-contact-page .admin-contact-card{position:relative;overflow:hidden;border:1px solid #dfe5ea;border-radius:24px;background:linear-gradient(145deg,#fff,#f8fbfe);padding:24px;box-shadow:0 18px 45px rgba(23,32,43,.08),inset 0 1px 0 #fff}
.admin-contact-page .admin-contact-card:before{content:"";position:absolute;width:260px;height:260px;right:-150px;top:-150px;border-radius:50%;background:radial-gradient(circle,rgba(47,111,202,.12),transparent 68%);pointer-events:none}
.admin-contact-page .admin-contact-card h2{position:relative;margin:0 0 7px;color:#17202b;font-size:22px;letter-spacing:-.03em}
.admin-contact-page .admin-contact-card>p{position:relative;margin:0 0 18px;color:#687482;font-size:12px;line-height:1.65}
.admin-contact-page .admin-contact-photo-box{position:relative;display:flex;align-items:center;gap:17px;margin:0 0 18px;padding:16px;border:1px solid #dfe7ef;border-radius:19px;background:linear-gradient(135deg,#f7fbff,#f3f9ef)}
.admin-contact-page .admin-photo-preview,.admin-contact-page .admin-photo-fallback{width:92px;height:92px;flex:0 0 92px;border-radius:20px;object-fit:cover;border:1px solid #d7e1eb;box-shadow:0 10px 25px rgba(23,32,43,.12);background:#edf4fb}
.admin-contact-page .admin-photo-fallback{display:grid;place-items:center;background:linear-gradient(145deg,#2f6fca,#68b82e);color:#fff;font-size:30px;font-weight:950}
.admin-contact-page .admin-contact-photo-box b{display:block;color:#17202b;font-size:14px}
.admin-contact-page .admin-contact-photo-box small{display:block;color:#687482;font-size:10px;line-height:1.5}
.admin-contact-page .admin-contact-photo-box input[type=file]{width:100%;max-width:360px;margin-top:7px;padding:8px;border:1px solid #dfe5ea;border-radius:10px;background:#fff;color:#4d5b69;font-size:11px}
.admin-contact-page .form{position:relative;display:grid;gap:12px}
.admin-contact-page .form>input:not([type=hidden]),.admin-contact-page .form>textarea{width:100%;box-sizing:border-box;border:1px solid #d7e0e8;border-radius:13px;background:#fff;color:#17202b;padding:13px 14px;font:inherit;font-size:12px;outline:none;transition:border-color .18s,box-shadow .18s,transform .18s}
.admin-contact-page .form>input:not([type=hidden]):focus,.admin-contact-page .form>textarea:focus{border-color:#72a7e8;box-shadow:0 0 0 4px rgba(47,111,202,.09)}
.admin-contact-page .form>textarea{min-height:150px;resize:vertical;line-height:1.6}
.admin-contact-page .form>label{color:#4c5b69;font-size:11px;font-weight:850}
.admin-contact-page .btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:11px 16px;border-radius:13px;border:1px solid #d8e1e9;text-decoration:none;font-size:11px;font-weight:900;cursor:pointer;transition:transform .18s,box-shadow .18s,background .18s}
.admin-contact-page .btn:hover{transform:translateY(-1px);box-shadow:0 10px 22px rgba(23,32,43,.10)}
.admin-contact-page .btn.accent{border-color:#2f6fca;background:linear-gradient(135deg,#3778cf,#245aa8);color:#fff;box-shadow:0 10px 24px rgba(47,111,202,.22)}
.admin-contact-page .btn.dark{background:#17202b;color:#fff;border-color:#17202b}
.admin-contact-page .btn.danger{background:#fff4f4;color:#b52d2d;border-color:#f0caca}
.admin-contact-page .admin-contact-preview{display:flex;flex-direction:column;justify-content:space-between;min-height:100%}
.admin-contact-page .admin-preview-visual{position:relative;display:grid;place-items:center;min-height:220px;margin:-2px -2px 18px;border-radius:19px;background:radial-gradient(circle at 50% 20%,rgba(47,111,202,.16),transparent 45%),linear-gradient(145deg,#0a1424,#17273c);overflow:hidden}
.admin-contact-page .admin-preview-visual:before{content:"";position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);background-size:25px 25px;opacity:.7}
.admin-contact-page .admin-preview-orb{position:relative;z-index:1;width:92px;height:92px;border-radius:28px;display:grid;place-items:center;background:linear-gradient(145deg,#2f6fca,#68b82e);color:#fff;font-size:30px;font-weight:950;box-shadow:0 0 0 10px rgba(255,255,255,.04),0 20px 55px rgba(0,0,0,.35)}
.admin-contact-page .admin-preview-copy{position:relative;z-index:1;text-align:center;margin-top:14px;color:#dbe8f7}.admin-contact-page .admin-preview-copy strong{display:block;font-size:15px}.admin-contact-page .admin-preview-copy span{display:block;margin-top:4px;color:#91a3b8;font-size:10px}
.admin-contact-page .admin-preview-note{padding:13px 14px;border:1px solid #dfe7ef;border-radius:15px;background:#f8fbfe;color:#687482;font-size:10px;line-height:1.6;margin-bottom:14px}
.admin-contact-page .admin-consent-section{margin-top:18px}
.admin-contact-page .admin-consent-list{display:grid;gap:10px}
.admin-contact-page .admin-consent-row{display:grid;grid-template-columns:minmax(170px,1.1fr) minmax(130px,.8fr) minmax(150px,.9fr) auto auto;gap:12px;align-items:center;padding:14px;border:1px solid #e0e6ec;border-radius:17px;background:#fff;box-shadow:0 8px 24px rgba(23,32,43,.045)}
.admin-contact-page .admin-consent-row>div{min-width:0}.admin-contact-page .admin-consent-row strong{display:block;color:#25313e;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.admin-contact-page .admin-consent-row small{display:block;color:#7a8794;font-size:9px;margin-bottom:4px}.admin-contact-page .admin-consent-pill{display:inline-flex;align-items:center;justify-content:center;padding:6px 8px;border-radius:999px;background:#edf8e6;color:#4f9424;font-size:8px;font-weight:950;letter-spacing:.08em}.admin-contact-page .admin-consent-delete{border:1px solid #f0caca;border-radius:10px;background:#fff5f5;color:#b52d2d;padding:8px 10px;font-size:9px;font-weight:900;cursor:pointer}.admin-contact-page .admin-consent-delete:hover{background:#ffe9e9}
@media(max-width:900px){.admin-contact-page .admin-contact-grid{grid-template-columns:1fr}.admin-contact-page .admin-consent-row{grid-template-columns:1fr 1fr}.admin-contact-page .admin-consent-pill{justify-self:start}.admin-contact-page .admin-consent-row form{justify-self:end}}
@media(max-width:600px){.admin-contact-page{padding:18px 12px 40px}.admin-contact-page .admin-contact-card{padding:18px;border-radius:19px}.admin-contact-page .admin-contact-photo-box{align-items:flex-start;flex-direction:column}.admin-contact-page .admin-photo-preview,.admin-contact-page .admin-photo-fallback{width:84px;height:84px;flex-basis:84px}.admin-contact-page .admin-contact-photo-box input[type=file]{max-width:none}.admin-contact-page .admin-consent-row{grid-template-columns:1fr}.admin-contact-page .admin-consent-row form,.admin-contact-page .admin-consent-pill{justify-self:stretch}.admin-contact-page .admin-consent-delete{width:100%;min-height:40px}.admin-contact-page .admin-preview-visual{min-height:180px}}

/* ===== VYBE MOBILE SCROLL PERFORMANCE ===== */
@media (max-width:850px){
  html{
    scroll-behavior:auto!important;
    -webkit-overflow-scrolling:touch!important;
    overscroll-behavior-y:auto!important;
  }
  body{
    touch-action:pan-y!important;
    -webkit-overflow-scrolling:touch!important;
    overscroll-behavior-y:auto!important;
  }
  .page-shell,.wrap,.section,.student-page,.content,.main-content{
    -webkit-overflow-scrolling:touch!important;
  }
  /* Native momentum scrolling for internal phone panels. */
  .community-chat-window,
  .vybe-assistant-body,
  #vybeMobileNav.student-mobile-menu,
  .mobile-only-menu-links{
    -webkit-overflow-scrolling:touch!important;
    overscroll-behavior:contain!important;
    touch-action:pan-y!important;
  }
  /* Avoid expensive visual effects while the finger is moving. */
  .student-bottom-nav,.nav,.vybe-assistant-panel{
    will-change:transform;
  }
}
/* ===== VYBE FINAL MENU PANEL — DARK BLUE, LOW-COST RENDERING ===== */
/* One final override so older page-specific menu styles cannot turn the panel white. */
#vybeMobileNav.student-mobile-menu {
  background: linear-gradient(145deg, #0b2238 0%, #071827 100%) !important;
  color: #eef8ff !important;
  border: 1px solid rgba(92, 177, 225, .30) !important;
  border-radius: 18px !important;
  box-shadow: 0 18px 42px rgba(0,0,0,.38), inset 0 1px rgba(255,255,255,.055) !important;
  backdrop-filter: none !important;
  -webkit-backdrop-filter: none !important;
}
#vybeMobileNav.student-mobile-menu.open { display:flex !important; }
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links {
  display:flex !important;
  flex-direction:column !important;
  gap:8px !important;
}
#vybeMobileNav.student-mobile-menu .mobile-menu-head {
  display:flex !important;
  align-items:center !important;
  justify-content:flex-start !important;
  min-height:30px !important;
  padding:2px 5px 9px !important;
  margin:0 1px 2px !important;
  border-bottom:1px solid rgba(126,193,229,.16) !important;
}
#vybeMobileNav.student-mobile-menu .mobile-menu-title {
  color:#f5fbff !important;
  font-size:13px !important;
  font-weight:850 !important;
}
#vybeMobileNav.student-mobile-menu .mobile-menu-close { display:none !important; }
#vybeMobileNav.student-mobile-menu > a,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a {
  display:flex !important;
  align-items:center !important;
  justify-content:flex-start !important;
  width:100% !important;
  min-height:46px !important;
  margin:0 !important;
  padding:0 13px !important;
  box-sizing:border-box !important;
  border:1px solid rgba(102,182,226,.20) !important;
  border-radius:12px !important;
  background:linear-gradient(180deg, rgba(18,55,82,.88), rgba(10,35,56,.88)) !important;
  color:#e9f6ff !important;
  text-decoration:none !important;
  font-size:12px !important;
  font-weight:750 !important;
  line-height:1.15 !important;
  box-shadow:inset 0 1px rgba(255,255,255,.035) !important;
  transition:background .12s ease, border-color .12s ease, transform .12s ease !important;
}
#vybeMobileNav.student-mobile-menu > a:hover,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:hover,
#vybeMobileNav.student-mobile-menu > a:active,
#vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a:active {
  background:#174d70 !important;
  border-color:rgba(88,193,245,.42) !important;
  color:#fff !important;
}
#vybeMobileNav.student-mobile-menu .student-menu-icon {
  color:#62c5f7 !important;
}
/* Desktop menu uses the same dark-blue panel language. */
@media (min-width:851px) {
  #vybeMobileNav.student-mobile-menu {
    width:270px !important;
    max-width:270px !important;
    max-height:calc(100vh - 110px) !important;
    overflow-y:auto !important;
    padding:12px !important;
  }
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links { gap:7px !important; }
  #vybeMobileNav.student-mobile-menu > a,
  #vybeMobileNav.student-mobile-menu .mobile-only-menu-links > a {
    min-height:44px !important;
  }
}
@media (max-width:850px) {
  #vybeMobileNav.student-mobile-menu {
    left:8px !important;
    top:62px !important;
    bottom:76px !important;
    width:min(82vw,270px) !important;
    max-width:270px !important;
    max-height:calc(100vh - 150px) !important;
    padding:12px !important;
    overflow-y:auto !important;
    overflow-x:hidden !important;
  }
}

</style>"""
@app.route("/contact-terms", methods=["GET","POST"])
def contact_terms():
    con=db()
    _ensure_contact_terms_table(con)
    admin_name=setting(con,"contact_admin_name","VYBE Admin")
    admin_email=setting(con,"contact_admin_email","")
    whatsapp_support_link=setting(con,"whatsapp_link","")
    custom_terms=setting(con,"contact_terms_text","")
    admin_photo=setting(con,"contact_admin_photo","")
    name_prefill=""; sid_prefill=""
    if session.get("student_db_id"):
        try:
            st=con.execute("SELECT name,student_id FROM students WHERE id=?",(int(session["student_db_id"]),)).fetchone()
            if st: name_prefill=st["name"]; sid_prefill=st["student_id"]
        except Exception: pass
    if request.method=="POST":
        name=request.form.get("name","").strip()[:160]
        student_id=request.form.get("student_id","").strip()[:80]
        if not name or not student_id:
            con.close(); flash("Please enter your name and Student ID."); return redirect(url_for("contact_terms"))
        if request.form.get("agree_terms")!="1":
            con.close(); flash("Please accept the terms before continuing."); return redirect(url_for("contact_terms"))
        ip=(request.remote_addr or "unknown")[:120]
        ua=request.headers.get("User-Agent","")[:500]
        try:
            con.execute("INSERT INTO contact_terms_consents(name,student_id,ip_address,user_agent,consented_at) VALUES(?,?,?,?,?)",(name,student_id,ip,ua,now_ist()))
            con.commit()
            session["contact_terms_consent"]=True
            session["contact_terms_name"]=name
            session["contact_terms_student_id"]=student_id
            session["contact_terms_just_consented"] = True
        except Exception:
            try: con.rollback()
            except Exception: pass
            con.close(); session["contact_terms_error"] = "Could not save your consent. Please try again."; return redirect(url_for("contact_terms"))
        con.close(); return redirect(url_for("contact_terms"))
    consented=bool(session.get("contact_terms_consent"))
    if consented:
        name_prefill=session.get("contact_terms_name",name_prefill) or name_prefill
        sid_prefill=session.get("contact_terms_student_id",sid_prefill) or sid_prefill
    name_display=esc(name_prefill); sid_display=esc(sid_prefill)
    terms_html="""<ul class="contact-terms-list"><li>VYBE uses your name and Student ID to provide your campus account and support you when you contact the admin.</li><li>Information you choose to submit on VYBE, such as campus questions, problems, community messages or contributions, may be kept so the requested features can work.</li><li>Your password is protected as a secure password hash rather than being stored as plain text.</li><li>If VYBE AI is enabled, questions may be sent to the configured AI service to generate answers. Please do not share sensitive information with the assistant.</li><li>Your contact details are used to unlock the VYBE admin email and, when configured, the student Support Group link.</li></ul>"""
    if custom_terms: terms_html += f'<p style="margin-top:14px;white-space:pre-wrap">{esc(custom_terms)}</p>'
    if admin_photo:
        admin_identity_photo=f'<img class="contact-admin-photo" src="{esc(admin_photo)}" alt="VYBE admin photo">'
        revealed_photo=f'<img src="{esc(admin_photo)}" alt="VYBE admin photo">'
    else:
        initial=esc((admin_name or "V")[:1].upper())
        admin_identity_photo=f'<div class="contact-admin-photo-fallback">{initial}</div>'
        revealed_photo=f'<div class="contact-admin-photo-fallback">{initial}</div>'
    if consented:
        reveal_blocks=[]
        if admin_email:
            reveal_blocks.append(f'<div class="contact-terms-email"><small>DIRECT VYBE ADMIN CONTACT</small><a href="mailto:{esc(admin_email)}?subject=VYBE%20Support">{esc(admin_email)}</a></div>')
        if valid_url(whatsapp_support_link):
            reveal_blocks.append(f'<div class="contact-terms-email contact-terms-support"><small>SUPPORT GROUP</small><a href="{esc(whatsapp_support_link)}" target="_blank" rel="noopener noreferrer">Join VYBE Support Group →</a></div>')
        reveal_blocks.append(f'<div class="contact-revealed-admin">{revealed_photo}<div><strong>Contact revealed</strong><span>{esc(admin_name)} · VYBE Admin</span></div></div>')
        email_html="".join(reveal_blocks)
        if not admin_email and not valid_url(whatsapp_support_link):
            email_html='<div class="contact-terms-locked">Consent recorded. The admin has not configured direct contact details yet.</div>'
    else:
        email_html='<div class="contact-terms-locked">Your admin contact and support group will appear here after you enter your details and accept the terms.</div>'
    checked=" checked" if consented else ""
    body=f"""{CONTACT_TERMS_CSS}<section class="contact-terms-page"><div class="contact-terms-shell"><div class="contact-terms-hero"><div><span class="contact-terms-kicker">CONTACT &amp; SUPPORT</span><h1>Need help? Contact VYBE.</h1><p>Enter your details, accept the simple terms, and get the VYBE admin contact and Support Group link in one place.</p><div class="contact-terms-admin">Here when you need me · keeping VYBE simple and human</div></div><div class="contact-admin-identity">{admin_identity_photo}<div><small>VYBE ADMIN</small><strong>{esc(admin_name)}</strong><span>Campus support &amp; administration</span></div></div></div><div class="contact-terms-grid"><section class="contact-terms-card contact-direct-card"><h2>Unlock direct contact.</h2><p>Enter your name and Student ID, accept the simple terms, and your VYBE support contacts will appear.</p><form class="contact-terms-form" method="post"><input type="hidden" name="csrf_token" value="{esc(session.get("_csrf_token", ""))}"><div><label>Your name</label><input name="name" value="{name_display}" maxlength="160" required placeholder="Enter your name"></div><div><label>Student ID</label><input name="student_id" value="{sid_display}" maxlength="80" required placeholder="Enter your Student ID"></div><label class="contact-terms-consent"><input type="checkbox" name="agree_terms" value="1"{checked} required><span><strong>I understand and agree.</strong>I understand that my details are used for this contact request and VYBE support.</span></label><button class="btn accent" type="submit">Accept &amp; reveal contact →</button></form><div class="contact-reveal">{email_html}</div><div class="contact-terms-foot"><span class="contact-terms-ip">Their details are used for the contact/support flow.</span><a class="btn dark" href="/">Back to VYBE</a></div></section><section class="contact-terms-card contact-keeps-card"><h2>What VYBE keeps.</h2><p>Just the useful information needed to run VYBE and provide support.</p>{terms_html}</section></div><div class="contact-friend-note"><div class="friend-mark">V</div><div><small>THE VYBE PROMISE</small><strong>Running VYBE with you, not above you.</strong><span>Questions, ideas or a campus problem? Reach out directly. I’ll keep the platform useful, transparent and easy to talk to.</span></div></div></div></section>"""
    success_message = "" if not session.pop("contact_terms_just_consented", False) else "Contact unlocked. You can now reach the VYBE admin directly."
    error_message = session.pop("contact_terms_error", "")
    notice = (f'<div class="contact-terms-success">{esc(success_message)}</div>' if success_message else (f'<div class="contact-terms-success" style="border-color:rgba(255,100,100,.25);background:rgba(255,80,80,.08);color:#ffb0b0">{esc(error_message)}</div>' if error_message else ""))
    standalone = f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'><meta name='theme-color' content='#02050b'><title>Contact / Terms · VYBE</title>{CONTACT_TERMS_CSS}</head><body><main class='contact-terms-page'>{notice}{body.split('<section class=\"contact-terms-page\">',1)[-1].rsplit('</section>',1)[0]}</main></body></html>"
    con.close(); return standalone

@app.route("/admin/contact-terms", methods=["GET","POST"])
@admin_required
def admin_contact_terms():
    con=db()
    _ensure_contact_terms_table(con)
    if request.method=="POST":
        action=request.form.get("action","save").strip()
        if action=="delete_photo":
            set_setting(con,"contact_admin_photo","")
            con.commit(); con.close(); flash("Admin contact photo removed."); return redirect(url_for("admin_contact_terms"))
        if action=="delete_consent":
            try:
                consent_id=int(request.form.get("consent_id","0"))
            except Exception:
                consent_id=0
            if consent_id>0:
                con.execute("DELETE FROM contact_terms_consents WHERE id=?",(consent_id,))
                con.commit(); con.close(); flash("Consent record deleted."); return redirect(url_for("admin_contact_terms"))
            con.close(); flash("Invalid consent record."); return redirect(url_for("admin_contact_terms"))
        admin_name=request.form.get("admin_name","").strip()[:160]
        admin_email=request.form.get("admin_email","").strip()[:254]
        custom_terms=request.form.get("custom_terms","").strip()[:10000]
        if not admin_name or not admin_email or "@" not in admin_email:
            con.close(); flash("Please enter a valid admin name and email."); return redirect(url_for("admin_contact_terms"))
        set_setting(con,"contact_admin_name",admin_name)
        set_setting(con,"contact_admin_email",admin_email)
        set_setting(con,"contact_terms_text",custom_terms)
        photo=request.files.get("admin_photo")
        if photo and photo.filename:
            mime=(photo.mimetype or "").lower()
            raw=photo.read(3*1024*1024+1)
            if mime not in ("image/png", "image/jpeg", "image/webp") or len(raw)>3*1024*1024:
                con.close(); flash("Please upload a PNG, JPG or WEBP image up to 3 MB."); return redirect(url_for("admin_contact_terms"))
            set_setting(con,"contact_admin_photo",f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}")
        con.commit(); con.close(); flash("Contact / Terms settings saved."); return redirect(url_for("admin_contact_terms"))
    admin_name=setting(con,"contact_admin_name","VYBE Admin")
    admin_email=setting(con,"contact_admin_email","")
    custom_terms=setting(con,"contact_terms_text","")
    admin_photo=setting(con,"contact_admin_photo","")
    rows=con.execute("SELECT id,name,student_id,ip_address,consented_at FROM contact_terms_consents ORDER BY id DESC LIMIT 200").fetchall()
    con.close()
    photo_html=(f'<img class="admin-photo-preview" src="{esc(admin_photo)}" alt="Admin photo">' if admin_photo else f'<div class="admin-photo-fallback">{esc((admin_name or "V")[:1].upper())}</div>')
    rows_html="".join(f'<div class="admin-consent-row"><div><strong>{esc(r["name"])}</strong><small>ID: {esc(r["student_id"])}</small></div><div><small>IP address</small><strong>{esc(r["ip_address"])}</strong></div><div><small>Consent time</small><strong>{esc(r["consented_at"])}</strong></div><span class="admin-consent-pill">CONSENTED</span><form method="post" onsubmit="return confirm(\'Delete this consent record?\')"><input type="hidden" name="action" value="delete_consent"><input type="hidden" name="consent_id" value="{int(r["id"])}"><button class="admin-consent-delete" type="submit">Delete</button></form></div>' for r in rows)
    body=f"""{ADMIN_CONTACT_TERMS_CSS}<section class="section admin-contact-page"><div class="admin-page-head"><div><a href="/admin/settings" class="admin-back">← Settings</a><span class="admin-page-kicker">CONTACT / TERMS</span><h1>Contact &amp; terms.</h1><p class="muted">Control the public contact identity, your photo, the terms shown to users, and the consent audit.</p></div></div><div class="admin-contact-grid"><div class="admin-contact-card"><h2>Admin identity</h2><p>Your name, email and photo are shown only according to the consent flow.</p><form class="form" method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="save"><div class="admin-contact-photo-box">{photo_html}<div><b>Profile photo</b><small style="display:block;color:#687482;margin:4px 0 9px">PNG, JPG, WEBP · maximum 3 MB</small><input type="file" name="admin_photo" accept="image/png,image/jpeg,image/webp"></div></div><input name="admin_name" value="{esc(admin_name)}" placeholder="Admin name" required><input type="email" name="admin_email" value="{esc(admin_email)}" placeholder="Admin email" required><label>Additional terms (optional)</label><textarea name="custom_terms" maxlength="10000" placeholder="Add extra VYBE terms here...">{esc(custom_terms)}</textarea><button class="btn accent">Save Contact / Terms →</button></form>{'<form method="post" style="margin-top:10px"><input type="hidden" name="action" value="delete_photo"><button class="btn danger" type="submit">Remove admin photo</button></form>' if admin_photo else ''}</div><div class="admin-contact-card admin-contact-preview"><div><span class="admin-contact-kicker">STUDENT / PUBLIC VIEW</span><div class="admin-preview-visual"><div><div class="admin-preview-orb">V</div><div class="admin-preview-copy"><strong>Contact VYBE</strong><span>Consent → identity → direct contact</span></div></div></div><h2>Preview</h2><p>Users enter their name and Student ID, accept the data-use terms, and then see your clickable email and profile photo.</p><div class="admin-preview-note">This opens the same standalone Contact / Terms experience students see. Use it to check the current public contact flow.</div></div><a class="btn dark" href="/contact-terms" target="_blank" rel="noopener">Open Contact / Terms →</a></div></div><section class="section" style="padding-left:0;padding-right:0"><div class="admin-contact-card"><h2>Consent records</h2><p>Latest users who accepted the contact/data-use terms.</p><div class="admin-consent-list">{rows_html or '<div class="empty">No consent records yet.</div>'}</div></div></section></section>"""
    return layout("Contact / Terms",body,admin=True)



@app.route("/admin/drive/connect")
@admin_required
def admin_drive_connect():
    if not GOOGLE_AUTH_AVAILABLE:
        flash("Google Drive OAuth libraries are not installed. Please redeploy with the updated requirements.txt.")
        return redirect(url_for("admin_drive"))
    try:
        flow = GoogleOAuthFlow.from_client_config(_drive_oauth_client_config(), scopes=DRIVE_OAUTH_SCOPES)
        flow.redirect_uri = _drive_oauth_redirect_uri()
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        session["drive_oauth_state"] = state
        return redirect(authorization_url)
    except Exception as exc:
        flash(f"Could not start Google Drive authorization: {type(exc).__name__}: {exc}")
        return redirect(url_for("admin_drive"))


@app.route("/admin/drive/oauth/callback")
@admin_required
def admin_drive_oauth_callback():
    expected_state = session.pop("drive_oauth_state", "")
    returned_state = request.args.get("state", "")
    if not expected_state or not returned_state or not secrets.compare_digest(expected_state, returned_state):
        return "Invalid Google Drive authorization state. Please start the connection again from VYBE Admin → Drive Library.", 400
    if request.args.get("error"):
        flash("Google Drive authorization was cancelled or denied.")
        return redirect(url_for("admin_drive"))
    try:
        flow = GoogleOAuthFlow.from_client_config(_drive_oauth_client_config(), scopes=DRIVE_OAUTH_SCOPES, state=expected_state)
        flow.redirect_uri = _drive_oauth_redirect_uri()
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        _drive_save_oauth_credentials(creds)
        # Verify that the authorized account can see the configured VYBE folder.
        meta = _drive_file_meta(VYBE_DRIVE_ROOT_FOLDER_ID)
        if meta.get("mimeType") != "application/vnd.google-apps.folder":
            raise RuntimeError("VYBE_DRIVE_ROOT_FOLDER_ID does not point to a Drive folder.")
        flash("Google Drive connected successfully. VYBE will now use your normal My Drive storage.")
        return redirect(url_for("admin_drive"))
    except Exception as exc:
        app.logger.exception("Google Drive OAuth callback failed")
        flash(f"Google Drive connection failed: {type(exc).__name__}: {exc}")
        return redirect(url_for("admin_drive"))


@app.route("/admin/drive/disconnect", methods=["POST"])
@admin_required
def admin_drive_disconnect():
    global _DRIVE_CREDS_CACHE
    con=db(); con.execute("DELETE FROM settings WHERE key=?", (DRIVE_OAUTH_TOKEN_SETTING,)); con.commit(); con.close()
    with _DRIVE_CREDS_CACHE_LOCK:
        _DRIVE_CREDS_CACHE = None
    flash("Google Drive connection removed from VYBE. Your files remain in Google Drive.")
    return redirect(url_for("admin_drive"))


@app.route("/admin/drive")
@admin_required
def admin_drive():
    con=db(); oauth_row=con.execute("SELECT value FROM settings WHERE key=?", (DRIVE_OAUTH_TOKEN_SETTING,)).fetchone(); con.close()
    configured=bool(oauth_row and oauth_row["value"])
    cats=list(DRIVE_CATEGORY_MAP.keys())
    opts=''.join(f'<option value="{esc(c)}">{esc(c)}</option>' for c in cats)
    body=f'''<section class="section"><div class="admin-page-head"><div><a href="/admin/settings" class="admin-back">← Settings</a><span class="admin-page-kicker">VYBE DRIVE MASTER</span><h1>Drive Library.</h1><p>Google Drive is the master file storage for the student-facing document sections. Large files upload directly from the browser to Drive instead of through Vercel.</p></div></div><div class="two"><div class="card"><h2>Upload to Drive</h2><p class="muted">Choose the exact student section. The file goes directly to its matching Drive folder and is indexed in VYBE.</p><form id="vybeDriveUploadForm" class="form"><select name="category">{opts}</select><input name="title" placeholder="Title (optional)"><input name="course" placeholder="Course / program" value="All"><input name="semester" placeholder="Semester (e.g. 1st Semester)"><input name="subject" placeholder="Subject (required for academic resources)"><textarea name="description" placeholder="Description (optional)"></textarea><input type="file" name="file" required><div id="vybeDriveStatus" class="small">Direct-to-Drive upload. No large file is sent through Vercel.</div><button class="btn accent" type="submit">Upload directly to Drive →</button></form></div><div class="card"><h2>Google Drive connection</h2><p class="muted">VYBE uses your Google account for your normal My Drive. No Shared Drive or service-account storage is required.</p><p class="small">Connected: <b>{'YES' if configured else 'NO'}</b></p><a class="btn dark" href="/admin/drive/connect">{'Reconnect Google Drive' if configured else 'Connect Google Drive'} →</a><p class="small" style="margin-top:12px">After connecting, VYBE can upload into your existing <b>My Drive → Vybe</b> folder.</p></div><div class="card"><h2>Automatic sync</h2><p class="muted">Files added directly inside the VYBE category folders are indexed through Drive change notifications, with a daily safety sync.</p><button class="btn dark" type="button" onclick="window.vybeDriveSync()">Sync Drive now</button><button class="btn" type="button" onclick="window.vybeDriveWatch()">Enable automatic Drive sync</button><div id="vybeDriveSyncStatus" class="small" style="margin-top:12px"></div></div></div><div class="card" style="margin-top:18px"><h3>Drive structure</h3><p class="small">VYBE stores every Academic Hub resource section as <b>&lt;Section&gt; / &lt;Semester&gt; / &lt;Subject&gt;</b> — for example <b>Study Material / 3rd Semester / Python</b>. Notes, Previous Year Questions and Syllabus use the same hierarchy. Assessments are published through Academic Updates. Academic Updates and Timetable keep their existing structure.</p><button class="btn dark" type="button" onclick="window.vybeOrganizeSubjects()">Organize existing files into semester / subject folders →</button><div id="vybeOrganizeStatus" class="small" style="margin-top:10px"></div></div></section><script>(function(){{const form=document.getElementById('vybeDriveUploadForm'),status=document.getElementById('vybeDriveStatus');const csrf=document.querySelector('meta[name=vybe-csrf-token]')?.content||'';async function j(url,opts){{const r=await fetch(url,Object.assign({{credentials:'same-origin'}},opts||{{}}));let d={{}};try{{d=await r.json()}}catch(_ ){{}}if(!r.ok)throw new Error(d.error||'Request failed');return d}}window.vybeDriveSync=async()=>{{const el=document.getElementById('vybeDriveSyncStatus');el.textContent='Syncing Drive…';try{{const d=await j('/admin/drive/sync',{{method:'POST',headers:{{'X-VYBE-CSRF':csrf}}}});el.textContent='Synced '+(d.synced||0)+' file(s).';}}catch(e){{el.textContent=e.message}}}};window.vybeDriveWatch=async()=>{{const el=document.getElementById('vybeDriveSyncStatus');el.textContent='Connecting Drive change notifications…';try{{const d=await j('/admin/drive/watch',{{method:'POST',headers:{{'X-VYBE-CSRF':csrf}}}});el.textContent=d.message||'Automatic sync enabled.';}}catch(e){{el.textContent=e.message}}}};window.vybeOrganizeSubjects=async()=>{{const el=document.getElementById('vybeOrganizeStatus');el.textContent='Checking Drive folder structure…';try{{const d=await j('/admin/drive/organize-subjects',{{method:'POST',headers:{{'X-VYBE-CSRF':csrf}}}});el.textContent=d.message||((d.moved||0)+' file(s) organized.');}}catch(e){{el.textContent='Drive folder organization could not complete: '+e.message}}}};form?.addEventListener('submit',async e=>{{e.preventDefault();const f=form.file.files[0];if(!f)return;status.textContent='Starting Drive upload…';try{{const init=await j('/admin/drive/upload-session',{{method:'POST',headers:{{'Content-Type':'application/json','X-VYBE-CSRF':csrf}},body:JSON.stringify({{name:f.name,mimeType:f.type||'application/octet-stream',size:f.size,category:form.category.value,semester:form.semester.value,subject:form.subject.value}})}});status.textContent='Uploading '+(f.size/1048576).toFixed(1)+' MB directly to Drive…';const uploaded=await new Promise((resolve,reject)=>{{const xhr=new XMLHttpRequest();xhr.open('PUT',init.upload_url,true);xhr.responseType='json';xhr.upload.onprogress=e=>{{if(e.lengthComputable)status.textContent='Uploading '+(e.loaded/1048576).toFixed(1)+' / '+(e.total/1048576).toFixed(1)+' MB directly to Drive…';}};xhr.onload=()=>{{if(xhr.status>=200&&xhr.status<300){{resolve(xhr.response||JSON.parse(xhr.responseText||'{{}}'));}}else{{let detail='';try{{detail=xhr.response?.error?.message||xhr.responseText||'';}}catch(_ ){{}}reject(new Error('Drive upload failed: HTTP '+xhr.status+(detail?' — '+detail:'')));}}}};xhr.onerror=async()=>{{try{{status.textContent='Direct Google upload was blocked by the browser. Switching to a secure chunked upload…';const chunkSize=4*1024*1024;window.__vybeDriveFallbackMeta=null;const stat=await j('/admin/drive/upload-status',{{method:'POST',headers:{{'Content-Type':'application/json','X-VYBE-CSRF':csrf}},body:JSON.stringify({{session_url:init.upload_url,total:f.size}})}});if(stat.complete&&stat.metadata){{resolve(stat.metadata);return;}}let start=Number(stat.next_start||0);if(!Number.isFinite(start)||start<0||start>f.size)throw new Error('Google Drive returned an invalid upload position.');while(start<f.size){{const end=Math.min(start+chunkSize,f.size);const chunk=f.slice(start,end);const qs=new URLSearchParams({{session_url:init.upload_url,start:String(start),end:String(end-1),total:String(f.size)}});const r=await fetch('/admin/drive/upload-chunk?'+qs.toString(),{{method:'POST',credentials:'same-origin',headers:{{'Content-Type':'application/octet-stream','X-VYBE-CSRF':csrf,'Content-Range':'bytes '+start+'-'+(end-1)+'/'+f.size}},body:chunk}});let d={{}};try{{d=await r.json();}}catch(_){{}}if(!r.ok)throw new Error(d.error||('Chunk upload failed: HTTP '+r.status));if(d.complete&&d.metadata)window.__vybeDriveFallbackMeta=d.metadata;start=Number(d.next_start);if(!Number.isFinite(start)||start<=0&&end<f.size)throw new Error('Google Drive returned an invalid upload position.');status.textContent='Uploading '+(start/1048576).toFixed(1)+' / '+(f.size/1048576).toFixed(1)+' MB…';}}const meta=window.__vybeDriveFallbackMeta||{{}};if(!meta.id)throw new Error('Google Drive completed the upload but did not return a file ID.');resolve(meta); }}catch(fallbackErr){{reject(new Error('Drive upload could not reach Google Drive directly, and the secure fallback also failed: '+fallbackErr.message));}}}};xhr.ontimeout=()=>reject(new Error('Drive upload timed out. Please retry.'));xhr.timeout=0;xhr.send(f);}});status.textContent='Publishing in VYBE…';const d=await j('/admin/drive/register',{{method:'POST',headers:{{'Content-Type':'application/json','X-VYBE-CSRF':csrf}},body:JSON.stringify({{category:form.category.value,title:form.title.value,course:form.course.value,semester:form.semester.value,subject:form.subject.value,description:form.description.value,file_id:uploaded.id,folder_id:init.folder_id}})}});status.textContent=d.message||'Uploaded and published.';form.reset();}}catch(err){{status.textContent=err.message}}}});}})();</script>'''
    return layout("Drive Library",body,admin=True)

def _drive_iter_file_tree(folder_id, max_depth=3, _depth=0):
    # Yield file metadata plus folder names below the given Drive folder.
    if not folder_id or _depth > max_depth:
        return
    for item in _drive_list_children(folder_id):
        if item.get("trashed"):
            continue
        if item.get("mimeType")=="application/vnd.google-apps.folder":
            name=str(item.get("name") or "").strip()
            for meta,path in _drive_iter_file_tree(item.get("id"),max_depth,_depth+1) or ():
                yield meta,[name]+path
        else:
            yield item,[]


def _drive_repair_and_sync_library():
    # Repair legacy Drive layouts and index missing update files.
    # Canonical resource layout: Academic Hub / Section / Semester / Subject.
    # Canonical update layout: Academic Updates / Update Type.
    # Older builds sometimes created: Academic Hub / Semester / Section.
    con=db(); moved=0; indexed=0; normalized=0; skipped=0; errors=[]
    resource_by_fid={}
    update_by_fid={}
    try:
        for row in con.execute("SELECT id,resource_type,semester,subject,drive_file_id,drive_folder_id FROM resources WHERE drive_file_id IS NOT NULL LIMIT 5000").fetchall():
            resource_by_fid[str(row["drive_file_id"])]=row
        for row in con.execute("SELECT id,kind,drive_file_id FROM academic_updates WHERE drive_file_id IS NOT NULL LIMIT 5000").fetchall():
            update_by_fid[str(row["drive_file_id"])]=row

        resource_categories={v[1]:k for k,v in DRIVE_CATEGORY_MAP.items() if v[2]=="resource"}
        update_categories={v[1]:k for k,v in DRIVE_CATEGORY_MAP.items() if v[2]=="update"}

        # First repair every known resource from its stored subject and semester.
        for fid,row in list(resource_by_fid.items()):
            subject=" ".join(str(row["subject"] or "").strip().split())[:120]
            if not subject or subject.lower() in {"general","subject","all"}:
                skipped+=1; continue
            semester=_drive_normalize_semester(row["semester"])
            if semester=="Uncategorized" or not semester or not semester.lower().endswith("semester"):
                skipped+=1; continue
            category=_drive_category_for_resource_type(row["resource_type"] or "Study material")
            try:
                if str(row["semester"] or "").strip()!=semester:
                    con.execute("UPDATE resources SET semester=? WHERE id=?",(semester,row["id"]))
                    normalized+=1
                target=_drive_category_folder(category,True,semester=semester,subject=subject)
                meta=_drive_file_meta(fid)
                parents=[str(x) for x in (meta.get("parents") or []) if x]
                if str(target) not in parents or len(parents)!=1:
                    if _drive_move_file_to_folder(fid,target,parents): moved+=1
                con.execute("UPDATE resources SET drive_folder_id=? WHERE id=?",(target,row["id"]))
            except Exception as exc:
                errors.append(f"resource {fid}: {exc}")

        # Normalize the canonical Academic Hub / Section / Semester / Subject tree.
        hub_canonical=_drive_find_or_create_folder(VYBE_DRIVE_ROOT_FOLDER_ID,"Academic Hub")
        for section_folder in _drive_list_children(hub_canonical):
            if section_folder.get("trashed") or section_folder.get("mimeType")!="application/vnd.google-apps.folder":
                continue
            category=resource_categories.get(str(section_folder.get("name") or "").strip())
            if not category:
                continue
            for sem_folder in _drive_list_children(section_folder.get("id")):
                if sem_folder.get("trashed") or sem_folder.get("mimeType")!="application/vnd.google-apps.folder":
                    continue
                canonical_sem=_drive_normalize_semester(sem_folder.get("name"))
                if canonical_sem=="Uncategorized" or not canonical_sem.lower().endswith("semester"):
                    continue
                for subject_folder in _drive_list_children(sem_folder.get("id")):
                    if subject_folder.get("trashed") or subject_folder.get("mimeType")!="application/vnd.google-apps.folder":
                        continue
                    subject_name=" ".join(str(subject_folder.get("name") or "").strip().split())[:120]
                    if not subject_name or subject_name.lower() in {"general","subject","all"}:
                        continue
                    for meta in _drive_list_children(subject_folder.get("id")):
                        if meta.get("trashed") or meta.get("mimeType")=="application/vnd.google-apps.folder":
                            continue
                        fid=str(meta.get("id") or "")
                        row=resource_by_fid.get(fid)
                        if not row:
                            continue
                        try:
                            if str(row["semester"] or "").strip()!=canonical_sem or str(row["subject"] or "").strip()!=subject_name:
                                con.execute("UPDATE resources SET semester=?,subject=? WHERE id=?",(canonical_sem,subject_name,row["id"]))
                                normalized+=1
                            con.execute("UPDATE resources SET drive_folder_id=? WHERE id=?",(subject_folder.get("id"),row["id"]))
                        except Exception as exc:
                            errors.append(f"canonical {category}/{fid}: {exc}")

        # Then repair the legacy Academic Hub / Semester / Section layout.
        hub_root=_drive_find_or_create_folder(VYBE_DRIVE_ROOT_FOLDER_ID,"Academic Hub")
        for sem_folder in _drive_list_children(hub_root):
            if sem_folder.get("trashed") or sem_folder.get("mimeType")!="application/vnd.google-apps.folder":
                continue
            legacy_sem=_drive_normalize_semester(sem_folder.get("name"))
            if legacy_sem=="Uncategorized" or not legacy_sem.lower().endswith("semester"):
                continue
            for section_folder in _drive_list_children(sem_folder.get("id")):
                if section_folder.get("trashed") or section_folder.get("mimeType")!="application/vnd.google-apps.folder":
                    continue
                section_name=str(section_folder.get("name") or "").strip()
                category=resource_categories.get(section_name) or update_categories.get(section_name)
                if not category:
                    continue
                kind=DRIVE_CATEGORY_MAP[category][2]
                for meta,path in _drive_iter_file_tree(section_folder.get("id"),max_depth=2) or ():
                    fid=str(meta.get("id") or "")
                    if not fid:
                        continue
                    try:
                        if kind=="resource":
                            row=resource_by_fid.get(fid)
                            if not row:
                                # Without DB metadata, do not invent a subject.
                                skipped+=1
                                continue
                            subject=" ".join(str(row["subject"] or "").strip().split())[:120]
                            if not subject or subject.lower() in {"general","subject","all"}:
                                skipped+=1; continue
                            target=_drive_category_folder(category,True,semester=legacy_sem,subject=subject)
                            parents=[str(x) for x in (meta.get("parents") or []) if x]
                            if str(target) not in parents or len(parents)!=1:
                                if _drive_move_file_to_folder(fid,target,parents): moved+=1
                            con.execute("UPDATE resources SET semester=?,drive_folder_id=? WHERE id=?",(legacy_sem,target,row["id"]))
                            normalized+=1
                        else:
                            target=_drive_category_folder(category,True)
                            parents=[str(x) for x in (meta.get("parents") or []) if x]
                            if str(target) not in parents or len(parents)!=1:
                                if _drive_move_file_to_folder(fid,target,parents): moved+=1
                            if not update_by_fid.get(fid):
                                if _drive_record_file(con,category,meta,semester=legacy_sem,subject="General"):
                                    indexed+=1
                                    update_by_fid[fid]=True
                    except Exception as exc:
                        errors.append(f"legacy {section_name}/{fid}: {exc}")

        # Repair Academic Updates files that may be present in Drive but missing from Neon.
        updates_root=_drive_find_or_create_folder(VYBE_DRIVE_ROOT_FOLDER_ID,"Academic Updates")
        for update_folder in _drive_list_children(updates_root):
            if update_folder.get("trashed") or update_folder.get("mimeType")!="application/vnd.google-apps.folder":
                continue
            category=update_categories.get(str(update_folder.get("name") or "").strip())
            if not category:
                continue
            for file_meta,_path in _drive_iter_file_tree(update_folder.get("id"),max_depth=2) or ():
                if file_meta.get("trashed") or file_meta.get("mimeType")=="application/vnd.google-apps.folder":
                    continue
                fid=str(file_meta.get("id") or "")
                if not fid:
                    continue
                try:
                    if not update_by_fid.get(fid):
                        if _drive_record_file(con,category,file_meta):
                            indexed+=1
                            update_by_fid[fid]=True
                except Exception as exc:
                    errors.append(f"Academic Updates/{fid}: {exc}")

        con.commit()
    except Exception as exc:
        try: con.rollback()
        except Exception: pass
        errors.append(f"repair: {exc}")
    finally:
        con.close()
    return {"moved":moved,"indexed":indexed,"normalized":normalized,"skipped":skipped,"errors":errors}


@app.route("/admin/drive/organize-subjects", methods=["POST"])
@admin_required
def admin_drive_organize_subjects():
    result=_drive_repair_and_sync_library()
    errors=result["errors"]
    if errors:
        app.logger.warning("Drive library repair finished with errors: %s",errors[:20])
        return jsonify(**result,ok=False,message=f"Drive repair moved {result['moved']} file(s), indexed {result['indexed']}; {len(errors)} item(s) still need attention."),502
    return jsonify(**result,ok=True,message=f"Drive repaired: {result['moved']} file(s) moved, {result['indexed']} file(s) indexed and {result['normalized']} record(s) normalized.")

@app.route("/admin/drive/upload-session", methods=["POST"])
@admin_required
def admin_drive_upload_session():
    data=request.get_json(force=True) or {}; category=str(data.get("category") or "").strip(); name=Path(str(data.get("name") or "uploaded-file")).name[:240]
    semester=_drive_normalize_semester(data.get("semester")) if str(data.get("semester") or "").strip() else "Uncategorized"
    subject=" ".join(str(data.get("subject") or "").strip().split())[:120] or "General"
    if category not in DRIVE_CATEGORY_MAP: return jsonify(error="Choose a valid VYBE Drive section."),400
    if DRIVE_CATEGORY_MAP[category][2]=="resource" and (not semester or not subject):
        return jsonify(error="Semester and subject are required for academic resource uploads."),400
    try:
        _drive_credentials()
        size=int(data.get("size") or 0)
        if size < 0: return jsonify(error="Invalid upload size."),400
        folder=_drive_category_folder(category,True,semester=semester,subject=subject)
        upload_url=_drive_start_resumable(name,str(data.get("mimeType") or "application/octet-stream"),folder,size)
        return jsonify(upload_url=upload_url,folder_id=folder)
    except Exception as e: return jsonify(error=str(e)),502

def _drive_validate_session_url(session_url):
    parsed = urlparse(session_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in {"www.googleapis.com", "googleapis.com"}:
        raise ValueError("Invalid Google Drive upload session URL.")
    return session_url

@app.route("/admin/drive/upload-status", methods=["POST"])
@admin_required
def admin_drive_upload_status():
    data=request.get_json(force=True) or {}
    session_url=str(data.get("session_url") or "").strip()
    try:
        total=int(data.get("total") or 0)
    except (TypeError,ValueError):
        return jsonify(error="Invalid upload size."),400
    if not session_url or total <= 0:
        return jsonify(error="Missing upload session or size."),400
    try:
        session_url=_drive_validate_session_url(session_url)
        req=URLRequest(
            session_url,
            data=b"",
            headers={
                "Authorization": f"Bearer {_drive_access_token()}",
                "Content-Length": "0",
                "Content-Range": f"bytes */{total}",
            },
            method="PUT",
        )
        try:
            with urlopen(req, timeout=60) as resp:
                body=resp.read()
                payload=json.loads(body.decode("utf-8")) if body else {}
                if resp.status in (200,201):
                    return jsonify(complete=True,next_start=total,metadata=payload)
        except HTTPError as e:
            if e.code == 308:
                rng=e.headers.get("Range", "")
                m=re.search(r"(\d+)-(\d+)$", rng)
                next_start=int(m.group(2))+1 if m else 0
                return jsonify(complete=False,next_start=next_start),200
            raw_error=e.read()
            try: detail=json.loads(raw_error.decode("utf-8"))
            except Exception: detail=raw_error.decode("utf-8",errors="replace")
            return jsonify(error=f"Google Drive API {e.code}: {detail}"),502
    except Exception as e:
        return jsonify(error=f"Google Drive upload status failed: {type(e).__name__}: {e}"),502
    return jsonify(error="Google Drive did not return an upload status."),502

@app.route("/admin/drive/upload-chunk", methods=["POST"])
@admin_required
def admin_drive_upload_chunk():
    """Fallback for browsers that block CORS to Google's resumable session URL.

    Each request is deliberately small so it stays within typical Vercel request
    body limits. The file is still written to the Google Drive resumable session;
    VYBE does not store the uploaded file on disk or in the database.
    """
    session_url = request.args.get("session_url", "").strip()
    try:
        session_url = _drive_validate_session_url(session_url)
    except ValueError as e:
        return jsonify(error=str(e)),400
    try:
        start = int(request.args.get("start", "0"))
        end = int(request.args.get("end", "-1"))
        total = int(request.args.get("total", "0"))
    except ValueError:
        return jsonify(error="Invalid upload range."),400
    if not session_url or start < 0 or end < start or total <= end:
        return jsonify(error="Invalid Drive upload session or range."),400
    raw = request.get_data(cache=False, as_text=False)
    expected = end - start + 1
    if len(raw) != expected:
        return jsonify(error=f"Upload chunk size mismatch: expected {expected} bytes, received {len(raw)}."),400
    try:
        req = URLRequest(
            session_url,
            data=raw,
            headers={
                "Authorization": f"Bearer {_drive_access_token()}",
                "Content-Length": str(len(raw)),
                "Content-Range": f"bytes {start}-{end}/{total}",
                "Content-Type": "application/octet-stream",
            },
            method="PUT",
        )
        try:
            with urlopen(req, timeout=120) as resp:
                body = resp.read()
                payload = json.loads(body.decode("utf-8")) if body else {}
                return jsonify(next_start=total if resp.status in (200,201) else end + 1, complete=resp.status in (200,201), metadata=payload)
        except HTTPError as e:
            raw_error = e.read()
            if e.code == 308:
                rng = e.headers.get("Range", "")
                m = re.search(r"(\d+)-(\d+)$", rng)
                next_start = int(m.group(2)) + 1 if m else end + 1
                return jsonify(next_start=next_start, complete=False),200
            try:
                detail=json.loads(raw_error.decode("utf-8"))
            except Exception:
                detail=raw_error.decode("utf-8", errors="replace")
            return jsonify(error=f"Google Drive API {e.code}: {detail}"),502
    except Exception as e:
        return jsonify(error=f"Google Drive upload failed: {type(e).__name__}: {e}"),502

@app.route("/admin/drive/register", methods=["POST"])
@admin_required
def admin_drive_register():
    data=request.get_json(force=True) or {}
    category=str(data.get("category") or "").strip(); fid=str(data.get("file_id") or "").strip()
    if category not in DRIVE_CATEGORY_MAP or not fid: return jsonify(error="Missing Drive file/category."),400
    semester=_drive_normalize_semester(data.get("semester")) if DRIVE_CATEGORY_MAP.get(category, (None,None,None))[2]=="resource" else str(data.get("semester") or "").strip()[:100]
    subject=" ".join(str(data.get("subject") or "").strip().split())[:120]
    if DRIVE_CATEGORY_MAP[category][2]=="resource" and (not semester or not subject):
        return jsonify(error="Semester and subject are required for academic resource uploads."),400
    con=None
    try:
        meta=_drive_file_meta(fid)
        if not meta or meta.get("trashed"):
            raise RuntimeError("The uploaded Drive file could not be found.")
        if DRIVE_CATEGORY_MAP[category][2]=="resource":
            requested_folder=str(data.get("folder_id") or "").strip()
            parents=[str(x) for x in (meta.get("parents") or []) if x]
            target=requested_folder if requested_folder and requested_folder in parents else _drive_category_folder(category,True,semester=semester,subject=subject)
            if target not in parents:
                _drive_move_file_to_folder(fid,target,parents)
                meta=_drive_file_meta(fid)
        _drive_make_public(fid)
        con=db()
        created=_drive_record_file(con,category,meta,title=str(data.get("title") or "").strip()[:150] or None,course=str(data.get("course") or "All")[:100],semester=semester or "Uncategorized",subject=subject or "General",description=str(data.get("description") or "")[:1000])
        con.commit()
        return jsonify(message="File uploaded to Drive and published in VYBE.",already_published=not created)
    except Exception as e:
        if con:
            try: con.rollback()
            except Exception: pass
        return jsonify(error=str(e)),502
    finally:
        if con:
            try: con.close()
            except Exception: pass

@app.route("/admin/drive/register-resource", methods=["POST"])
@admin_required
def admin_drive_register_resource():
    data=request.get_json(force=True) or {}
    category=str(data.get("category") or "").strip()
    fid=str(data.get("file_id") or "").strip()
    if category not in {"Notes","Study Material","Previous Year Questions","Syllabus","Assignments"} or not fid:
        return jsonify(error="Missing Drive file or resource category."),400
    semester=_drive_normalize_semester(data.get("semester"))
    subject=" ".join(str(data.get("subject") or "").strip().split())[:120]
    if not semester or semester=="Uncategorized" or not subject or subject=="General":
        return jsonify(error="Semester and subject are required for academic resource uploads."),400
    try:
        meta=_drive_file_meta(fid)
        if not meta or meta.get("trashed"):
            raise RuntimeError("The uploaded Drive file could not be found.")
        mapped={"Notes":"Notes","Study Material":"Study material","Previous Year Questions":"Previous Year Questions","Syllabus":"Syllabus","Assignments":"Assignments"}[category]
        requested_folder=str(data.get("folder_id") or "").strip()
        parents=[str(x) for x in (meta.get("parents") or []) if x]
        target=requested_folder if requested_folder and requested_folder in parents else _drive_category_folder(category,True,semester=semester,subject=subject)
        if target not in parents:
            _drive_move_file_to_folder(fid,target,parents)
            meta=_drive_file_meta(fid)
        _drive_make_public(fid)
        con=db()
        if con.execute("SELECT id FROM resources WHERE drive_file_id=?",(fid,)).fetchone():
            con.close(); return jsonify(message="File is already published in VYBE.",metadata=meta)
        con.execute("INSERT INTO resources(title,resource_type,course,semester,subject,description,file_name,original_name,mime_type,file_data,assistant_text,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(str(data.get("title") or Path(meta.get("name") or "Drive file").stem)[:150],mapped,str(data.get("course") or "All")[:100],semester,subject,str(data.get("description") or "")[:1000],None,meta.get("name"),meta.get("mimeType"),None,str(data.get("assistant_text") or "")[:50000],now(),fid,(meta.get("parents") or [None])[0],meta.get("webContentLink") or meta.get("webViewLink")))
        con.commit(); con.close()
        return jsonify(message="File uploaded to Drive and published in VYBE.",metadata=meta)
    except Exception as e:
        try: con.close()
        except Exception: pass
        return jsonify(error=str(e)),502

@app.route("/admin/drive/register-update", methods=["POST"])
@admin_required
def admin_drive_register_update():
    data=request.get_json(force=True) or {}
    kind=str(data.get("kind") or "").strip()
    title=str(data.get("title") or "").strip()[:180]
    external_url=str(data.get("external_url") or "").strip()[:500]
    fid=str(data.get("file_id") or "").strip()
    if kind not in {"Result","Date Sheet","Exam Notice","Admit Card","Assessment"} or not title:
        return jsonify(error="Choose a valid update type and title."),400
    if external_url:
        parsed=urlparse(external_url)
        if parsed.scheme not in ("http","https") or not parsed.netloc:
            return jsonify(error="Please enter a valid http or https website link."),400
    if kind in {"Result","Admit Card","Assessment"} and not external_url:
        return jsonify(error=f"A direct official website link is required for {kind}."),400
    try:
        meta={}
        if fid:
            _drive_make_public(fid); meta=_drive_file_meta(fid)
        con=db()
        con.execute("INSERT INTO academic_updates(kind,category,title,description,course,semester,subject,event_date,external_url,file_name,original_name,mime_type,file_data,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(kind,kind,title,str(data.get("description") or "")[:4000],str(data.get("course") or "")[:100],str(data.get("semester") or "")[:100],str(data.get("subject") or "")[:120],str(data.get("event_date") or "")[:80],external_url,None,meta.get("name") if meta else None,meta.get("mimeType") if meta else None,None,now(),meta.get("id") if meta else None,(meta.get("parents") or [None])[0] if meta else None,(meta.get("webContentLink") or meta.get("webViewLink")) if meta else None))
        con.commit(); con.close()
        return jsonify(message="Academic update published successfully.",metadata=meta)
    except Exception as e:
        try: con.close()
        except Exception: pass
        return jsonify(error=str(e)),502

@app.route("/admin/drive/register-timetable", methods=["POST"])
@admin_required
def admin_drive_register_timetable():
    data=request.get_json(force=True) or {}
    fid=str(data.get("file_id") or "").strip(); title=str(data.get("title") or "").strip()[:160]
    if not fid or not title: return jsonify(error="Missing timetable title or Drive file."),400
    try:
        _drive_make_public(fid); meta=_drive_file_meta(fid); con=db()
        con.execute("INSERT INTO timetables(title,file_name,original_name,mime_type,file_data,created_at,drive_file_id,drive_folder_id,drive_web_url,assistant_text) VALUES(?,?,?,?,?,?,?,?,?,?)",(title,meta.get("name") or "Drive file",meta.get("name") or "Drive file",meta.get("mimeType") or "application/octet-stream",None,now(),fid,(meta.get("parents") or [None])[0],meta.get("webContentLink") or meta.get("webViewLink"),str(data.get("assistant_text") or "")[:50000]))
        con.commit(); con.close(); return jsonify(message="Timetable uploaded to Drive and published in VYBE.",metadata=meta)
    except Exception as e:
        try: con.close()
        except Exception: pass
        return jsonify(error=str(e)),502

@app.route("/admin/drive/sync", methods=["POST"])
@admin_required
def admin_drive_sync():
    try: return jsonify(drive_sync_all())
    except Exception as e: return jsonify(error=str(e)),502

@app.route("/admin/drive/watch", methods=["POST"])
@admin_required
def admin_drive_watch():
    try:
        _drive_credentials()
        con=db(); page=setting(con,"drive_start_page_token","")
        if not page:
            _,_,d=_drive_api("GET","changes/startPageToken",query={"supportsAllDrives":"true"}); page=d.get("startPageToken",""); set_setting(con,"drive_start_page_token",page)
        import uuid
        webhook=request.url_root.rstrip("/")+"/api/drive-webhook"
        _,_,resp=_drive_http("POST","https://www.googleapis.com/drive/v3/changes/watch",query={"pageToken":page},body={"id":str(uuid.uuid4()),"type":"web_hook","address":webhook,"token":VYBE_DRIVE_WEBHOOK_TOKEN,"expiration":int(time.time()*1000)+604000000})
        set_setting(con,"drive_channel_id",resp.get("id","")); set_setting(con,"drive_channel_resource_id",resp.get("resourceId","")); set_setting(con,"drive_channel_expiration",str(resp.get("expiration",0))); con.commit(); con.close(); drive_sync_all(); return jsonify(message="Automatic Drive sync is enabled.")
    except Exception as e: return jsonify(error=str(e)),502

@app.route("/api/drive-webhook", methods=["POST"])
def drive_webhook():
    if request.headers.get("X-Goog-Channel-Token","") != VYBE_DRIVE_WEBHOOK_TOKEN: return ("",403)
    try: drive_sync_all()
    except Exception: pass
    return ("",204)

@app.route("/api/drive-cron", methods=["GET","POST"])
def drive_cron():
    expected=os.environ.get("CRON_SECRET","").strip()
    if expected and request.headers.get("Authorization") != f"Bearer {expected}": return jsonify(error="Unauthorized"),401
    try:
        _drive_credentials()
    except Exception:
        return jsonify(skipped=True, reason="Google Drive is not connected")
    result=drive_sync_all()
    try:
        con=db(); exp=int(float(setting(con,"drive_channel_expiration","0") or 0)); con.close()
        if exp < int(time.time()*1000)+2*86400000:
            con=db(); page=setting(con,"drive_start_page_token","")
            if not page:
                _,_,d=_drive_api("GET","changes/startPageToken",query={"supportsAllDrives":"true"}); page=d.get("startPageToken",""); set_setting(con,"drive_start_page_token",page)
            import uuid
            webhook=request.url_root.rstrip("/")+"/api/drive-webhook"
            _,_,resp=_drive_http("POST","https://www.googleapis.com/drive/v3/changes/watch",query={"pageToken":page},body={"id":str(uuid.uuid4()),"type":"web_hook","address":webhook,"token":VYBE_DRIVE_WEBHOOK_TOKEN,"expiration":int(time.time()*1000)+604000000})
            set_setting(con,"drive_channel_expiration",str(resp.get("expiration",0))); set_setting(con,"drive_channel_id",resp.get("id","")); set_setting(con,"drive_channel_resource_id",resp.get("resourceId","")); con.commit(); con.close()
    except Exception: pass
    return jsonify(result)

ADMIN_DESKTOP_POLISH_CSS = r"""
<style>
/* ===== ADMIN DESKTOP POLISH ===== */
@media (min-width:851px){
  body:has(.admin-header) .wrap{
    width:min(1360px,calc(100vw - 56px))!important;
    max-width:none!important;
    margin:0 auto!important;
    padding:34px 0 70px!important;
    box-sizing:border-box!important;
  }
  body:has(.admin-header) .section{margin:0 0 22px!important}
  body:has(.admin-header) .admin-page-head{
    display:flex!important;align-items:flex-end!important;justify-content:space-between!important;
    gap:28px!important;margin:0 0 22px!important;
  }
  body:has(.admin-header) .admin-page-head > div:first-child{min-width:0!important}
  body:has(.admin-header) .admin-page-head h1{margin:8px 0 8px!important;line-height:1.02!important}
  body:has(.admin-header) .admin-page-head p{max-width:760px!important;margin:0!important;line-height:1.55!important}
  body:has(.admin-header) .card{box-sizing:border-box!important}
  body:has(.admin-header) .tablewrap{overflow-x:auto!important}

  /* Settings */
  body:has(.settings-hub) .settings-grid{
    display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;
    gap:16px!important;margin-top:24px!important;
  }
  body:has(.settings-hub) .settings-tile{
    display:flex!important;align-items:center!important;gap:15px!important;
    min-height:112px!important;padding:20px!important;
    border:1px solid #dfe5ea!important;border-radius:20px!important;
    background:#fff!important;box-shadow:0 8px 22px rgba(31,48,66,.06)!important;
    text-decoration:none!important;color:#17202b!important;
    box-sizing:border-box!important;
  }
  body:has(.settings-hub) .settings-tile:hover{
    border-color:#bcd5ea!important;box-shadow:0 12px 28px rgba(31,48,66,.09)!important;
  }
  body:has(.settings-hub) .settings-icon{
    width:48px!important;height:48px!important;flex:0 0 48px!important;
    display:grid!important;place-items:center!important;border-radius:14px!important;
    background:#eef5ff!important;font-size:20px!important;
  }
  body:has(.settings-hub) .settings-tile>div{min-width:0!important;flex:1!important}
  body:has(.settings-hub) .settings-tile b{display:block!important;font-size:16px!important;line-height:1.25!important;color:#17202b!important}
  body:has(.settings-hub) .settings-tile small{display:block!important;margin-top:6px!important;color:#6f7d8a!important;font-size:11px!important;line-height:1.45!important}
  body:has(.settings-hub) .settings-tile>strong{font-size:19px!important;color:#8193a4!important;flex:0 0 auto!important}
  body:has(.settings-hub) .settings-state{
    flex:0 0 auto!important;font-size:9px!important;font-weight:900!important;
    letter-spacing:.08em!important;padding:6px 8px!important;border-radius:999px!important;
    background:#edf5ff!important;color:#2f6fca!important;white-space:nowrap!important;
  }
  body:has(.settings-hub) .settings-state.off{background:#fff1f1!important;color:#c45b61!important}
  body:has(.settings-hub) .settings-footer-grid{
    display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;
    gap:16px!important;margin-top:16px!important;
  }
  body:has(.settings-hub) .settings-mini{
    min-height:100px!important;padding:20px!important;text-decoration:none!important;
  }

  /* Publisher / settings detail pages */
  body:has(.settings-detail) .settings-editor,
  body:has(.settings-detail) .settings-preview{
    background:#fff!important;border:1px solid #dfe5ea!important;
    box-shadow:0 8px 22px rgba(31,48,66,.055)!important;
  }
  body:has(.settings-detail) .settings-detail-grid{grid-template-columns:1.2fr .8fr!important;gap:18px!important}
}
</style>
"""

@app.route("/admin/settings")
@admin_required
def admin_settings():
    con=db()
    online=setting(con,"vybe_online","1")=="1"
    wa=setting(con,"whatsapp_link","")
    pub=con.execute("SELECT COUNT(*) AS c FROM settings WHERE key LIKE ? AND value=?", ("content_manager_%", "1")).fetchone()["c"]
    con_email=setting(con,"contact_admin_email","")
    con.close()
    body=f'''<section class="section settings-hub"><div class="admin-page-head"><div><a href="/admin/panel" class="admin-back">← Dashboard</a><span class="admin-page-kicker">VYBE SETTINGS</span><h1>Settings.</h1><p>Keep the important controls separate and easy to operate. Open a section, make the change, then return here.</p></div></div><div class="settings-grid"><a class="settings-tile security" href="/admin/password"><span class="settings-icon">🔐</span><div><b>Security Center</b><small>Change admin password, verify passkey and register passkeys.</small></div><strong>→</strong></a><a class="settings-tile status" href="/admin/status"><span class="settings-icon">◉</span><div><b>VYBE ON / OFF</b><small>Control whether students and public visitors can access VYBE.</small></div><span class="settings-state {'on' if online else 'off'}">{'ON' if online else 'OFF'}</span></a><a class="settings-tile whatsapp" href="/admin/whatsapp-community"><span class="settings-icon">💬</span><div><b>WhatsApp Community</b><small>Set the student WhatsApp group link and control the student community button.</small></div><span class="settings-state {'on' if wa else 'off'}">{'LINKED' if wa else 'NOT SET'}</span></a><a class="settings-tile drive" href="/admin/drive"><span class="settings-icon">☁</span><div><b>VYBE Drive Library</b><small>Master file storage, direct large uploads and automatic Drive sync.</small></div><span class="settings-state on">OPEN</span></a><a class="settings-tile publisher" href="/admin/publisher-access"><span class="settings-icon">✎</span><div><b>Publisher Access</b><small>Choose trusted students and select exactly what they can publish.</small></div><span class="settings-state on">{pub} ACTIVE</span></a><a class="settings-tile contact-terms" href="/admin/contact-terms"><span class="settings-icon">✉</span><div><b>Contact / Terms</b><small>Set your admin name/email and review consent records from visitors and students.</small></div><span class="settings-state {'on' if con_email else 'off'}">{'READY' if con_email else 'SETUP'}</span></a></div><div class="settings-footer-grid"><a class="card settings-mini" href="/admin/assistant"><b>VYBE AI Settings</b><small>Ask VYBE switch and student shortcuts.</small><span>Open →</span></a><a class="card settings-mini" href="/admin/analytics"><b>Analytics</b><small>Usage and activity overview.</small><span>Open →</span></a></div></section>'''
    return layout("Settings",body,admin=True)


@app.route("/admin/whatsapp-community", methods=["GET","POST"])
@admin_required
def admin_whatsapp_community():
    con=db()
    if request.method=="POST":
        link=request.form.get("whatsapp_link","").strip()[:500]
        chat_enabled="1" if request.form.get("community_chat_enabled")=="1" else "0"
        if link and not valid_url(link):
            con.close(); flash("WhatsApp group link must be a valid URL."); return redirect(url_for("admin_whatsapp_community"))
        set_setting(con,"whatsapp_link",link)
        set_setting(con,"community_chat_enabled",chat_enabled)
        con.commit(); con.close(); flash("WhatsApp Community settings saved."); return redirect(url_for("admin_whatsapp_community"))
    link=setting(con,"whatsapp_link","")
    chat=setting(con,"community_chat_enabled","1")=="1"
    con.close()
    body=f'''<section class="section settings-detail"><div class="admin-page-head"><div><a href="/admin/settings" class="admin-back">← Settings</a><span class="admin-page-kicker">WHATSAPP COMMUNITY</span><h1>Community links.</h1><p>Put the current WhatsApp group link here. Students will see the same link in their Community area.</p></div></div><div class="settings-detail-grid"><div class="card settings-editor"><div class="settings-editor-icon">💬</div><h2>Student WhatsApp group</h2><p class="muted">Paste a WhatsApp invite link. Students can tap the Community button to open it.</p><form class="form" method="post"><label>WhatsApp group link</label><input name="whatsapp_link" value="{esc(link)}" placeholder="https://chat.whatsapp.com/..." autocomplete="off"><label class="settings-check"><input type="checkbox" name="community_chat_enabled" value="1"{' checked' if chat else ''}><span><b>Enable VYBE Community Chat</b><small>Allow students to use the built-in student-to-student chat.</small></span></label><button class="btn accent">Save Community settings →</button></form></div><div class="card settings-preview"><span class="admin-page-kicker">STUDENT SIDE</span><h2>What students get</h2><div class="preview-row"><span>WhatsApp Community</span><b>{'Available' if link else 'Not configured'}</b></div><div class="preview-row"><span>VYBE Community Chat</span><b>{'ON' if chat else 'OFF'}</b></div>{('<a class="btn dark" target="_blank" rel="noopener" href="'+esc(link)+'">Test WhatsApp link →</a>') if link else '<p class="small">Save a WhatsApp link to enable the test button.</p>'}</div></div></section>'''
    return layout("WhatsApp Community",body,admin=True)


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
    blocked_count = con.execute("SELECT COUNT(*) AS c FROM vybe_security_devices WHERE blocked_until>?", (time.time(),)).fetchone()["c"]
    con.close()
    web_status = "ready" if webauthn_configured() else "not configured"
    if count == 0:
        registration_note = "No passkey exists yet. Register your first passkey after entering the admin password."
    elif session.get("passkey_verified"):
        registration_note = "Current passkey verified. You may register another passkey."
    else:
        registration_note = "Verify your current passkey before registering another passkey."
    body = f'''<section class="section"><div class="security-password-head"><div><div class="badge">SECURITY CENTER</div><h1>Protect VYBE.</h1><p class="muted">Manage admin authentication and review student login security from one place.</p></div></div><a href="/admin/security-alerts" style="display:flex;align-items:center;gap:14px;width:100%;box-sizing:border-box;margin:0 0 22px;padding:18px 20px;border:1px solid rgba(125,196,232,.35);border-radius:18px;background:linear-gradient(135deg,rgba(18,82,112,.55),rgba(20,35,48,.9));color:#fff;text-decoration:none;box-shadow:0 10px 28px rgba(0,0,0,.18)"><span style="font-size:28px;line-height:1">🛡️</span><span style="flex:1"><strong style="display:block;font-size:16px">Security Alerts &amp; Blocked Users</strong><small style="display:block;margin-top:5px;color:#b8ced9">{blocked_count} currently blocked · View login alerts, blocked devices, IP details, and remove a block instantly.</small></span><span style="font-size:24px">→</span></a>
    <div class="two">
      <div class="card"><h2> Passkeys</h2>
        <p class="muted">Current credentials: {count}. Adding a second or later passkey requires verification of an existing passkey first.</p>
        <p class="small">WebAuthn: {web_status}</p>
        <button class="btn accent" id="registerPasskey">Register New Passkey</button>
        <div id="pkMsg" class="small" style="margin-top:10px">{esc(registration_note)}</div>
        <p style="margin-top:14px"><a class="btn dark" href="/admin/verify">Verify Current Passkey</a></p>
      </div>
      <div class="card"><h2> Change Admin Password</h2>
        <p class="muted">You do not need the current password. A fresh current-passkey verification authorizes the change.</p>
        <form class="form" method="post" style="margin-top:16px">
          <div class="password-wrap"><input id="newPassword" type="password" name="new_password" placeholder="New password (12+ chars)" minlength="12" required autocomplete="new-password"><button type="button" class="password-toggle toggle-password" data-target="newPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div>
          <div class="password-wrap"><input id="confirmPassword" type="password" name="confirm_password" placeholder="Confirm new password" minlength="12" required autocomplete="new-password"><button type="button" class="password-toggle toggle-password" data-target="confirmPassword" aria-label="Show password" title="Show password"><svg class="eye-icon eye-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.3-6 9.5-6 9.5 6 9.5 6-3.3 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.7"/></svg><svg class="eye-icon eye-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 6.3A10.9 10.9 0 0 1 12 6c6.2 0 9.5 6 9.5 6a16.7 16.7 0 0 1-3.2 3.7"/><path d="M6.4 6.8C3.9 8.5 2.5 12 2.5 12s3.3 6 9.5 6a10.9 10.9 0 0 0 3.1-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg></button></div>
          <button class="btn accent" {"disabled" if not session.get("passkey_verified") else ""}>Change Password</button>
        </form>
        <div class="small">{"Current passkey verified " if session.get("passkey_verified") else "Verify current passkey above before changing the password."}</div>
      </div>
    </div></section><script>{WEBAUTHN_JS}</script>'''
    body = body.replace("</section><script>", "</section><style>.security-password-head{display:flex;justify-content:space-between;align-items:flex-end;gap:22px;margin-bottom:20px}.security-password-head h1{margin:7px 0}.security-alert-button{display:flex;align-items:center;gap:12px;min-width:280px;padding:15px 17px;border:1px solid rgba(125,196,232,.2);border-radius:17px;background:linear-gradient(145deg,rgba(20,75,105,.32),rgba(255,255,255,.035));color:inherit;text-decoration:none}.security-alert-button>span{font-size:20px}.security-alert-button div{flex:1}.security-alert-button strong,.security-alert-button small{display:block}.security-alert-button small{color:#9fb3c0;font-size:11px;margin-top:3px}.security-alert-button>b{font-size:18px}@media(max-width:760px){.security-password-head{display:block}.security-alert-button{margin-top:16px;min-width:0;width:100%;box-sizing:border-box}}</style><script>")
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
    status = " ON" if enabled else " OFF"
    body = f'''<section class="section"><div class="badge">COMMUNITY CHAT CONTROL</div><h1>Community Chat.</h1><div class="grid2"><div class="card"><h2>{status}</h2><p class="muted">Students can {"send and read messages" if enabled else "not use the chat while it is disabled"}.</p><form method="post"><input type="hidden" name="action" value="toggle"><button class="btn {"danger" if enabled else "good"}">{" Turn Chat OFF" if enabled else " Turn Chat ON"}</button></form></div><div class="card"><h2>Moderation</h2><p class="muted">Delete individual messages or clear the entire community chat.</p><form method="post" onsubmit="return confirm('Delete ALL community chat messages? This cannot be undone.')"><input type="hidden" name="action" value="delete_all"><button class="btn danger">Delete all messages</button></form></div></div><section class="section"><div class="card"><h2>Recent messages</h2><div class="chat">{bubbles or '<div class="empty">No community messages yet.</div>'}</div></div></section></section>'''
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
    body=f'''<section class="section"><div class="badge">ACCOUNT RECOVERY</div><h1>Password requests.</h1><p class="muted">Students can request a password change. After admin approval, the student's open VYBE password-recovery page automatically unlocks a new-password form. No reset code is shown, and admins never see the student's existing password.</p><div class="notice">After approval, the student is taken directly to the new-password page. No reset code is required. The approval can only be used once.</div><div class="card tablewrap" style="margin-top:18px"><table><tr><th>Requested</th><th>Student</th><th>Status</th><th>Approval</th><th>Action</th></tr>{''.join(html_rows) or '<tr><td colspan="5">No password requests.</td></tr>'}</table></div></section>'''
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

    approved = now()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S UTC")
    con.execute("UPDATE password_reset_requests SET status='approved', approved_at=?, approval_code_hash=NULL, approval_code_token=NULL, expires_at=? WHERE id=?", (approved, expires, rid))
    con.commit(); con.close()
    flash("Approved. The student can now set a new password directly on their recovery page for the next 15 minutes.")
    return redirect(url_for("admin_password_requests"))


WEBAUTHN_JS = r'''
function b64ToBuf(v){v=v.replace(/-/g,"+").replace(/_/g,"/");while(v.length%4)v+="=";return Uint8Array.from(atob(v),c=>c.charCodeAt(0)).buffer}
function bufToB64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function decodeCreation(o){o.challenge=b64ToBuf(o.challenge);o.user.id=b64ToBuf(o.user.id);(o.excludeCredentials||[]).forEach(x=>x.id=b64ToBuf(x.id));const host=location.hostname.toLowerCase();if(!o.rp||!o.rp.id)throw new Error("WebAuthn RP ID is missing from the server response.");const rp=o.rp.id.toLowerCase();if(host!==rp&&!host.endsWith("."+rp))throw new Error("This passkey is configured for a different domain. Open VYBE on its configured HTTPS domain.");window.VYBE_RP_ID=o.rp.id;return o}
function decodeRequest(o){o.challenge=b64ToBuf(o.challenge);(o.allowCredentials||[]).forEach(x=>x.id=b64ToBuf(x.id));return o}
function serializeCredential(c){return {id:c.id,rawId:bufToB64(c.rawId),type:c.type,response:{clientDataJSON:bufToB64(c.response.clientDataJSON),attestationObject:c.response.attestationObject?bufToB64(c.response.attestationObject):undefined,authenticatorData:c.response.authenticatorData?bufToB64(c.response.authenticatorData):undefined,signature:c.response.signature?bufToB64(c.response.signature):undefined,userHandle:c.response.userHandle?bufToB64(c.response.userHandle):undefined},clientExtensionResults:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
async function postJSON(url,payload){const meta=document.querySelector('meta[name="vybe-csrf-token"]');const csrf=meta&&meta.content;const headers={"Content-Type":"application/json","Accept":"application/json"};if(csrf)headers["X-VYBE-CSRF"]=csrf;let r=await fetch(url,{method:"POST",headers,credentials:"same-origin",body:JSON.stringify(payload)});let j={};try{j=await r.json()}catch(_){throw new Error("Server returned an invalid response.")}if(!r.ok)throw new Error(j.error||j.detail||"Request failed");return j}
function pkError(e){if(e&&e.name==="NotAllowedError")return "Passkey request was cancelled or timed out. Try again and choose your phone/device.";if(e&&e.name==="InvalidStateError")return "This passkey is already registered on this device.";if(e&&e.name==="SecurityError")return "WebAuthn SecurityError. Open VYBE using HTTPS on its configured domain.";return (e&&e.name?e.name+": ":"")+(e&&e.message)||"Passkey operation failed."}
const loginPk=document.getElementById("loginPasskey");
if(loginPk)loginPk.onclick=async()=>{const msg=document.getElementById("loginPkMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys. Try current Chrome, Edge, Safari or Firefox.");loginPk.disabled=true;loginPk.textContent="Waiting for device…";msg.textContent="Approve the passkey on your phone/device.";let o=await postJSON("/admin/login-passkey/options",{});o=decodeRequest(o);let c=await navigator.credentials.get({publicKey:o});if(!c)throw new Error("No passkey was selected.");await postJSON("/admin/login-passkey/verify",serializeCredential(c));msg.textContent="Passkey verified. Opening admin panel…";setTimeout(()=>location.href="/admin/panel",250)}catch(e){msg.textContent=pkError(e);loginPk.disabled=false;loginPk.textContent="Continue with Passkey →"}}
const reg=document.getElementById("registerPasskey");
if(reg)reg.onclick=async()=>{const msg=document.getElementById("pkMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys. Try current Chrome, Edge, Safari or Firefox.");reg.disabled=true;reg.textContent="Waiting for device…";msg.textContent="Choose your phone or another passkey device when your browser asks.";let o=await postJSON("/passkey/register/options",{});o=decodeCreation(o);let c=await navigator.credentials.create({publicKey:o});if(!c)throw new Error("No passkey was created.");await postJSON("/passkey/register/verify",serializeCredential(c));msg.textContent="Phone passkey registered successfully.";setTimeout(()=>location.reload(),500)}catch(e){msg.textContent=pkError(e);reg.disabled=false;reg.textContent="Register New Passkey"}}
const ver=document.getElementById("verifyPasskey");
if(ver)ver.onclick=async()=>{const msg=document.getElementById("authMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys.");ver.disabled=true;ver.textContent="Waiting for device…";let o=await postJSON("/passkey/auth/options",{});o=decodeRequest(o);let c=await navigator.credentials.get({publicKey:o});if(!c)throw new Error("No passkey was selected.");await postJSON("/passkey/auth/verify",serializeCredential(c));msg.textContent="Phone passkey verified.";ver.textContent="Passkey verified ";if(location.pathname==="/admin/verify")setTimeout(()=>location.href="/admin/panel",400)}catch(e){msg.textContent=pkError(e);ver.disabled=false;ver.textContent="Verify Current Passkey"}}
'''



@app.route("/admin/passkey/reset-session", methods=["POST"])
@admin_required
def reset_passkey_session():
    session["passkey_verified"] = False
    return redirect(url_for("admin_verify"))



# ---------------------------------------------------------------------------
# Google Drive master storage
# ---------------------------------------------------------------------------
DRIVE_CATEGORY_MAP = {
    "Notes": ("Academic Hub", "Notes", "resource", "Notes"),
    "Study Material": ("Academic Hub", "Study Material", "resource", "Study material"),
    "Previous Year Questions": ("Academic Hub", "Previous Year Questions", "resource", "Previous Year Questions"),
    "Syllabus": ("Academic Hub", "Syllabus", "resource", "Syllabus"),
    "Results": ("Academic Updates", "Results", "update", "Result"),
    "Date Sheets": ("Academic Updates", "Date Sheets", "update", "Date Sheet"),
    "Exam Forms & Notices": ("Academic Updates", "Exam Forms & Notices", "update", "Exam Notice"),
    "Admit Cards": ("Academic Updates", "Admit Cards", "update", "Admit Card"),
    "Assessments": ("Academic Updates", "Assessments", "update", "Assessment"),
    "Timetable": ("Timetable", None, "timetable", "Timetable"),
}

def _drive_oauth_client_config():
    """Return the Google OAuth web-client configuration used for My Drive."""
    if VYBE_GOOGLE_OAUTH_CLIENT_JSON:
        try:
            cfg = json.loads(VYBE_GOOGLE_OAUTH_CLIENT_JSON)
        except json.JSONDecodeError as exc:
            raise RuntimeError("VYBE_GOOGLE_OAUTH_CLIENT_JSON is not valid JSON.") from exc
        # Google client JSON normally wraps the values under "web" or "installed".
        if isinstance(cfg, dict) and isinstance(cfg.get("web"), dict):
            cfg = cfg["web"]
        elif isinstance(cfg, dict) and isinstance(cfg.get("installed"), dict):
            cfg = cfg["installed"]
        if not isinstance(cfg, dict):
            raise RuntimeError("VYBE_GOOGLE_OAUTH_CLIENT_JSON must contain a Google OAuth client object.")
        client_id = str(cfg.get("client_id") or "").strip()
        client_secret = str(cfg.get("client_secret") or "").strip()
        auth_uri = str(cfg.get("auth_uri") or "https://accounts.google.com/o/oauth2/auth")
        token_uri = str(cfg.get("token_uri") or "https://oauth2.googleapis.com/token")
    else:
        client_id = VYBE_GOOGLE_OAUTH_CLIENT_ID
        client_secret = VYBE_GOOGLE_OAUTH_CLIENT_SECRET
        auth_uri = "https://accounts.google.com/o/oauth2/auth"
        token_uri = "https://oauth2.googleapis.com/token"
    if not client_id or not client_secret:
        raise RuntimeError(
            "Google Drive OAuth is not configured. Add VYBE_GOOGLE_OAUTH_CLIENT_ID and "
            "VYBE_GOOGLE_OAUTH_CLIENT_SECRET (or VYBE_GOOGLE_OAUTH_CLIENT_JSON) in Vercel."
        )
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": auth_uri,
            "token_uri": token_uri,
        }
    }

DRIVE_OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive"]
DRIVE_OAUTH_TOKEN_SETTING = "google_drive_oauth_credentials"
_DRIVE_CREDS_CACHE_LOCK = threading.Lock()
_DRIVE_CREDS_CACHE = None


def _drive_oauth_redirect_uri():
    if VYBE_GOOGLE_OAUTH_REDIRECT_URI:
        return VYBE_GOOGLE_OAUTH_REDIRECT_URI
    return url_for("admin_drive_oauth_callback", _external=True)


def _drive_oauth_fernet():
    if Fernet is None:
        raise RuntimeError(
            "Google Drive OAuth encryption is unavailable. Ensure cryptography is installed and redeploy."
        )
    key = base64.urlsafe_b64encode(hashlib.sha256(("vybe-drive-oauth|" + SECRET_KEY).encode("utf-8")).digest())
    return Fernet(key)


def _drive_save_oauth_credentials(creds):
    global _DRIVE_CREDS_CACHE
    payload = json.loads(creds.to_json())
    if not payload.get("refresh_token"):
        # Preserve an existing refresh token when Google omits it on a subsequent authorization.
        existing = _drive_load_oauth_credentials(raise_if_missing=False)
        if existing and existing.refresh_token:
            payload["refresh_token"] = existing.refresh_token
    encrypted = _drive_oauth_fernet().encrypt(json.dumps(payload).encode("utf-8")).decode("ascii")
    con = db()
    try:
        set_setting(con, DRIVE_OAUTH_TOKEN_SETTING, encrypted)
        con.commit()
    finally:
        con.close()
    with _DRIVE_CREDS_CACHE_LOCK:
        _DRIVE_CREDS_CACHE = creds


def _drive_cached_credentials_valid(creds):
    if not creds or not creds.token or not creds.valid:
        return False
    expiry=getattr(creds,"expiry",None)
    if expiry is None:
        return True
    try:
        return expiry.timestamp() > time.time()+60
    except Exception:
        return True


def _drive_load_oauth_credentials(*, raise_if_missing=True):
    global _DRIVE_CREDS_CACHE
    with _DRIVE_CREDS_CACHE_LOCK:
        cached=_DRIVE_CREDS_CACHE
    if _drive_cached_credentials_valid(cached):
        return cached

    con = db()
    try:
        row = con.execute("SELECT value FROM settings WHERE key=?", (DRIVE_OAUTH_TOKEN_SETTING,)).fetchone()
    finally:
        con.close()
    if not row or not row["value"]:
        if raise_if_missing:
            raise RuntimeError(
                "Google Drive is not connected. In VYBE Admin → Drive Library, click "
                "Connect Google Drive and authorize the Google account that owns the VYBE folder."
            )
        return None
    try:
        raw = _drive_oauth_fernet().decrypt(str(row["value"]).encode("ascii"))
        info = json.loads(raw.decode("utf-8"))
        creds = GoogleOAuthCredentials.from_authorized_user_info(info, scopes=DRIVE_OAUTH_SCOPES)
    except (FernetInvalidToken, ValueError, json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError(
            "The saved Google Drive authorization is invalid. Disconnect/reconnect Google Drive from VYBE Admin → Drive Library."
        ) from exc
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(GoogleAuthRequest())
            _drive_save_oauth_credentials(creds)
        except Exception as exc:
            raise RuntimeError(
                "Google Drive authorization expired and could not be refreshed. Reconnect Google Drive from VYBE Admin → Drive Library."
            ) from exc
    if not creds.valid or not creds.token:
        raise RuntimeError(
            "Google Drive authorization is not active. Reconnect Google Drive from VYBE Admin → Drive Library."
        )
    with _DRIVE_CREDS_CACHE_LOCK:
        _DRIVE_CREDS_CACHE = creds
    return creds

def _drive_credentials():
    """Return user OAuth credentials for the owner's normal My Drive."""
    if not GOOGLE_AUTH_AVAILABLE:
        detail = GOOGLE_AUTH_IMPORT_ERROR or "unknown import error"
        raise RuntimeError(
            "Google Drive OAuth libraries could not be imported. "
            f"Import error: {detail}. Ensure google-auth-oauthlib and cryptography are installed."
        )
    return _drive_load_oauth_credentials()

def _drive_access_token():
    return _drive_credentials().token

def _drive_http(method, url, body=None, headers=None, timeout=30, query=None):
    if query:
        from urllib.parse import urlencode
        sep = "&" if "?" in url else "?"
        url += sep + urlencode(query)
    hdr={"Authorization": f"Bearer {_drive_access_token()}", "Accept":"application/json"}
    if headers: hdr.update(headers)
    data=body
    if isinstance(body,(dict,list)):
        data=json.dumps(body).encode("utf-8")
        hdr.setdefault("Content-Type","application/json")
    req=URLRequest(url, data=data, headers=hdr, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw=resp.read()
            return resp.status, dict(resp.headers), json.loads(raw.decode("utf-8")) if raw else {}
    except HTTPError as e:
        raw=e.read()
        try: detail=json.loads(raw.decode("utf-8"))
        except Exception: detail=raw.decode("utf-8",errors="replace")
        raise RuntimeError(f"Google Drive API {e.code}: {detail}") from e

def _drive_api(method, path, query=None, body=None):
    url="https://www.googleapis.com/drive/v3/"+path.lstrip("/")
    if query:
        from urllib.parse import urlencode
        url += "?"+urlencode(query)
    return _drive_http(method,url,body=body)

_DRIVE_FOLDER_CACHE_LOCK = threading.Lock()
_DRIVE_FOLDER_CACHE = {}
_DRIVE_FOLDER_CACHE_TTL = 120.0

def _drive_folder_cache_get(key):
    now_m=time.monotonic()
    with _DRIVE_FOLDER_CACHE_LOCK:
        item=_DRIVE_FOLDER_CACHE.get(key)
        if item and item[0] > now_m:
            return item[1]
        if item:
            _DRIVE_FOLDER_CACHE.pop(key,None)
    return None

def _drive_folder_cache_set(key, folder_id):
    with _DRIVE_FOLDER_CACHE_LOCK:
        _DRIVE_FOLDER_CACHE[key]=(time.monotonic()+_DRIVE_FOLDER_CACHE_TTL,str(folder_id))
        if len(_DRIVE_FOLDER_CACHE)>1000:
            now_m=time.monotonic()
            for k,(expires,_) in list(_DRIVE_FOLDER_CACHE.items()):
                if expires<=now_m: _DRIVE_FOLDER_CACHE.pop(k,None)

def _drive_list_children(parent_id):
    q=f"'{parent_id}' in parents and trashed=false"
    files=[]; token=None
    while True:
        query={"q":q,"pageSize":1000,"fields":"nextPageToken,files(id,name,mimeType,size,modifiedTime,webViewLink,webContentLink,parents)"}
        if token: query["pageToken"]=token
        _,_,data=_drive_api("GET","files",query=query)
        files.extend(data.get("files",[])); token=data.get("nextPageToken")
        if not token: break
    return files

def _drive_find_or_create_folder(parent_id,name):
    # Google Drive query strings require a backslash-escaped apostrophe.
    safe=str(name).replace("\\","\\\\").replace("'","\\'")
    q=f"'{parent_id}' in parents and trashed=false and mimeType='application/vnd.google-apps.folder' and name='{safe}'"
    _,_,data=_drive_api("GET","files",query={"q":q,"pageSize":10,"fields":"files(id,name)"})
    if data.get("files"): return data["files"][0]["id"]
    _,_,created=_drive_api("POST","files",query={"fields":"id,name"},body={"name":name,"mimeType":"application/vnd.google-apps.folder","parents":[parent_id]})
    return created["id"]

def _drive_normalize_semester(value):
    """Normalize user-entered semester labels so Drive folders stay consistent."""
    raw=" ".join(str(value or "").strip().split())
    if not raw: return "Uncategorized"
    if raw.lower() in {"all","general","semester","semesters","uncategorized"}: return "Uncategorized"
    low=raw.lower().replace("semester", "").replace("sem", "").strip()
    words={"first":"1st","second":"2nd","third":"3rd","fourth":"4th","fifth":"5th","sixth":"6th","seventh":"7th","eighth":"8th"}
    if low in words: return words[low]+" Semester"
    m=re.fullmatch(r"(\d+)(?:st|nd|rd|th)?",low)
    if m:
        n=int(m.group(1)); suffix="th" if 10<=n%100<=20 else {1:"st",2:"nd",3:"rd"}.get(n%10,"th")
        return f"{n}{suffix} Semester"
    return raw[:100]

def _drive_category_folder(category,create=True,semester=None,subject=None):
    """Return the Drive folder for a VYBE category using Semester -> Subject hierarchy."""
    top,sub,kind,_=DRIVE_CATEGORY_MAP[category]
    semester_name=_drive_normalize_semester(semester) if semester is not None else None
    subject_name=" ".join(str(subject or "").strip().split())[:120] if subject is not None else None
    if subject_name is not None and subject_name.lower() in {"","all","general","subject","subjects"}: subject_name="General"
    key=(category,semester_name,subject_name)
    if create:
        cached=_drive_folder_cache_get(key)
        if cached: return cached
    parent=VYBE_DRIVE_ROOT_FOLDER_ID
    if create:
        parent=_drive_find_or_create_folder(parent,top)
    else:
        found=[x for x in _drive_list_children(parent) if x.get("name")==top and x.get("mimeType")=="application/vnd.google-apps.folder"]
        if not found: return None
        parent=found[0]["id"]
    if sub:
        if create: parent=_drive_find_or_create_folder(parent,sub)
        else:
            found=[x for x in _drive_list_children(parent) if x.get("name")==sub and x.get("mimeType")=="application/vnd.google-apps.folder"]
            if not found: return None
            parent=found[0]["id"]
    if kind=="resource" and (semester is not None or subject is not None):
        if create:
            parent=_drive_find_or_create_folder(parent,semester_name)
            parent=_drive_find_or_create_folder(parent,subject_name)
        else:
            found=[x for x in _drive_list_children(parent) if x.get("name")==semester_name and x.get("mimeType")=="application/vnd.google-apps.folder"]
            if not found: return None
            parent=found[0]["id"]
            found=[x for x in _drive_list_children(parent) if x.get("name")==subject_name and x.get("mimeType")=="application/vnd.google-apps.folder"]
            if not found: return None
            parent=found[0]["id"]
    if create: _drive_folder_cache_set(key,parent)
    return parent

def _drive_move_file_to_folder(file_id,target_folder_id,current_parents=None):
    if not file_id or not target_folder_id:
        return False
    parents=[str(x) for x in (current_parents or []) if x]
    if str(target_folder_id) in parents and len(parents)==1:
        return False
    remove=','.join(x for x in parents if x and str(x)!=str(target_folder_id))
    query={"addParents":str(target_folder_id),"fields":"id,parents"}
    if remove: query["removeParents"]=remove
    _drive_api("PATCH",f"files/{file_id}",query=query,body={})
    return True

def _drive_delete_file(file_id):
    if not file_id:
        return
    _drive_api("DELETE", f"files/{file_id}")

def _drive_make_public(file_id):
    if not VYBE_DRIVE_PUBLIC_FILES: return
    try:
        _drive_api("POST",f"files/{file_id}/permissions",query={"sendNotificationEmail":"false","fields":"id,type,role"},body={"type":"anyone","role":"reader"})
    except Exception as e:
        if "already exists" not in str(e).lower(): raise

def _drive_file_meta(file_id):
    _,_,data=_drive_api("GET",f"files/{file_id}",query={"fields":"id,name,mimeType,size,modifiedTime,webViewLink,webContentLink,parents,trashed"})
    return data

def _drive_start_resumable(name,mime_type,folder_id,size=None):
    headers={"X-Upload-Content-Type":mime_type or "application/octet-stream"}
    if size is not None: headers["X-Upload-Content-Length"]=str(int(size))
    _,resp_headers,_=_drive_http("POST","https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",body={"name":name,"mimeType":mime_type or "application/octet-stream","parents":[folder_id]},headers=headers)
    location=resp_headers.get("Location") or resp_headers.get("location")
    if not location: raise RuntimeError("Google Drive did not return a resumable upload session.")
    return location

def _drive_upload_bytes(name, mime_type, folder_id, data):
    """Upload an in-memory file to Drive and return its Drive metadata.

    Normal admin uploads are intentionally stored in Drive first. The database
    then keeps only the Drive metadata/reference, not the uploaded bytes.
    """
    if data is None:
        raise ValueError("No file data supplied.")
    session_url = _drive_start_resumable(name, mime_type, folder_id, len(data))
    headers = {
        "Content-Type": mime_type or "application/octet-stream",
        "Content-Length": str(len(data)),
    }
    _, _, meta = _drive_http("PUT", session_url, body=data, headers=headers, timeout=120)
    fid = meta.get("id")
    if not fid:
        raise RuntimeError("Google Drive upload completed without returning a file ID.")
    _drive_make_public(fid)
    return _drive_file_meta(fid)

def _drive_category_for_resource_type(resource_type):
    mapping = {
        "Notes": "Notes",
        "Study material": "Study Material",
        "Previous Year Questions": "Previous Year Questions",
        "Syllabus": "Syllabus",
        "Assignments": "Assignments",
    }
    return mapping.get(resource_type, "Study Material")

def _drive_category_for_update_kind(update_kind):
    mapping = {
        "Result": "Results",
        "Date Sheet": "Date Sheets",
        "Admit Card": "Admit Cards",
        "Assessment": "Assessments",
        "Exam Form": "Exam Forms & Notices",
        "General Update": "Exam Forms & Notices",
        "Online Class": "Exam Forms & Notices",
        "Recorded Lecture": "Exam Forms & Notices",
        "E-Book": "Exam Forms & Notices",
        "Finance Support": "Exam Forms & Notices",
    }
    return mapping.get(update_kind, "Exam Forms & Notices")

def _drive_metadata_values(meta):
    return (
        meta.get("id"),
        (meta.get("parents") or [None])[0],
        meta.get("webContentLink") or meta.get("webViewLink"),
    )

def _drive_store_resource(con, *, title, resource_type, course, semester, subject,
                          description, original_name, mime_type, data, assistant_text):
    category = _drive_category_for_resource_type(resource_type)
    folder = _drive_category_folder(category, create=True, semester=semester, subject=subject)
    meta = _drive_upload_bytes(original_name, mime_type, folder, data)
    fid, folder_id, web = _drive_metadata_values(meta)
    con.execute(
        "INSERT INTO resources(title,resource_type,course,semester,subject,description,file_name,original_name,mime_type,file_data,assistant_text,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (title, resource_type, course, semester, subject, description, None,
         original_name, mime_type, None, assistant_text, now(), fid, folder_id, web)
    )
    return meta

def _drive_store_academic_update(con, *, update_kind, category, title, description,
                                 course, semester, subject, event_date, external_url,
                                 original_name, mime_type, data):
    drive_category = _drive_category_for_update_kind(update_kind)
    folder = _drive_category_folder(drive_category, create=True)
    meta = _drive_upload_bytes(original_name, mime_type, folder, data)
    fid, folder_id, web = _drive_metadata_values(meta)
    con.execute(
        "INSERT INTO academic_updates(kind,category,title,description,course,semester,subject,event_date,external_url,file_name,original_name,mime_type,file_data,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (update_kind, category, title, description, course, semester, subject,
         event_date, external_url, None, original_name, mime_type, None, now(),
         fid, folder_id, web)
    )
    return meta

def _drive_store_timetable(con, *, title, original_name, mime_type, data, assistant_text):
    folder = _drive_category_folder("Timetable", create=True)
    meta = _drive_upload_bytes(original_name, mime_type, folder, data)
    fid, folder_id, web = _drive_metadata_values(meta)
    con.execute(
        "INSERT INTO timetables(title,file_name,original_name,mime_type,file_data,created_at,drive_file_id,drive_folder_id,drive_web_url,assistant_text) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (title, original_name, original_name, mime_type or "application/octet-stream", None, now(), fid, folder_id, web, assistant_text)
    )
    return meta

def _drive_record_file(con, category, meta, title=None, course="All", semester="All", subject="General", description="", assistant_text=""):
    """Index one Drive file; return True only when a new DB record is created."""
    _,_,kind,mapped=DRIVE_CATEGORY_MAP[category]
    fid=meta.get("id"); name=meta.get("name") or title or "Drive file"; web=meta.get("webContentLink") or meta.get("webViewLink")
    if not fid:
        return False
    if kind=="resource":
        if con.execute("SELECT id FROM resources WHERE drive_file_id=?",(fid,)).fetchone(): return False
        subject=str(subject or "General").strip()[:120] or "General"
        con.execute("INSERT INTO resources(title,resource_type,course,semester,subject,description,file_name,original_name,mime_type,file_data,assistant_text,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(title or Path(name).stem,mapped,course,semester,subject,description,None,name,meta.get("mimeType"),None,assistant_text,now(),fid,(meta.get("parents") or [None])[0],web))
        return True
    if kind=="update":
        if con.execute("SELECT id FROM academic_updates WHERE drive_file_id=?",(fid,)).fetchone(): return False
        con.execute("INSERT INTO academic_updates(kind,category,title,description,course,semester,subject,event_date,external_url,file_name,original_name,mime_type,file_data,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(mapped,"Examination" if mapped!="Result" else "Results",title or Path(name).stem,description,course,semester,subject,"","",None,name,meta.get("mimeType"),None,now(),fid,(meta.get("parents") or [None])[0],web))
        return True
    if con.execute("SELECT id FROM timetables WHERE drive_file_id=?",(fid,)).fetchone(): return False
    con.execute("INSERT INTO timetables(title,file_name,original_name,mime_type,file_data,created_at,drive_file_id,drive_folder_id,drive_web_url) VALUES(?,?,?,?,?,?,?,?,?)",(title or Path(name).stem,name,name,meta.get("mimeType") or "application/octet-stream",None,now(),fid,(meta.get("parents") or [None])[0],web))
    return True

def drive_sync_all():
    # Fast Drive sync for canonical folders plus legacy Semester / Section folders.
    total=0; errors=[]; con=db()
    try:
        resource_categories={v[1]:k for k,v in DRIVE_CATEGORY_MAP.items() if v[2]=="resource"}
        update_categories={v[1]:k for k,v in DRIVE_CATEGORY_MAP.items() if v[2]=="update"}
        for category in DRIVE_CATEGORY_MAP:
            try:
                root=_drive_category_folder(category,create=True)
                kind=DRIVE_CATEGORY_MAP[category][2]
                if kind=="resource":
                    for sem_item in _drive_list_children(root):
                        if sem_item.get("trashed") or sem_item.get("mimeType")!="application/vnd.google-apps.folder": continue
                        semester=_drive_normalize_semester(sem_item.get("name"))
                        if semester=="Uncategorized": continue
                        for sub_item in _drive_list_children(sem_item.get("id")):
                            if sub_item.get("trashed"): continue
                            if sub_item.get("mimeType")=="application/vnd.google-apps.folder":
                                subject=str(sub_item.get("name") or "").strip()[:120] or "General"
                                file_items=_drive_list_children(sub_item.get("id"))
                            else:
                                subject="General"; file_items=[sub_item]
                            for meta in file_items:
                                if meta.get("trashed") or meta.get("mimeType")=="application/vnd.google-apps.folder": continue
                                fid=str(meta.get("id") or "")
                                if not fid: continue
                                if _drive_record_file(con,category,meta,semester=semester,subject=subject):
                                    _drive_make_public(fid); total+=1
                elif kind=="update":
                    for item in _drive_list_children(root):
                        if item.get("trashed") or item.get("mimeType")=="application/vnd.google-apps.folder": continue
                        fid=str(item.get("id") or "")
                        if fid and _drive_record_file(con,category,item):
                            _drive_make_public(fid); total+=1
                else:
                    for item in _drive_list_children(root):
                        if item.get("trashed") or item.get("mimeType")=="application/vnd.google-apps.folder": continue
                        fid=str(item.get("id") or "")
                        if fid and _drive_record_file(con,category,item):
                            _drive_make_public(fid); total+=1
            except Exception as e:
                errors.append(f"{category}: {e}")

        # Recognize the old Academic Hub / Semester / Section layout during sync.
        hub_root=_drive_find_or_create_folder(VYBE_DRIVE_ROOT_FOLDER_ID,"Academic Hub")
        for sem_folder in _drive_list_children(hub_root):
            if sem_folder.get("trashed") or sem_folder.get("mimeType")!="application/vnd.google-apps.folder": continue
            semester=_drive_normalize_semester(sem_folder.get("name"))
            if semester=="Uncategorized": continue
            for section_folder in _drive_list_children(sem_folder.get("id")):
                if section_folder.get("trashed") or section_folder.get("mimeType")!="application/vnd.google-apps.folder": continue
                section_name=str(section_folder.get("name") or "").strip()
                category=resource_categories.get(section_name) or update_categories.get(section_name)
                if not category: continue
                kind=DRIVE_CATEGORY_MAP[category][2]
                for meta,path in _drive_iter_file_tree(section_folder.get("id"),max_depth=2) or ():
                    if meta.get("mimeType")=="application/vnd.google-apps.folder" or meta.get("trashed"): continue
                    fid=str(meta.get("id") or "")
                    if not fid: continue
                    if kind=="resource":
                        row=con.execute("SELECT subject FROM resources WHERE drive_file_id=?",(fid,)).fetchone()
                        subject=str(row["subject"] or "General") if row else "General"
                        if _drive_record_file(con,category,meta,semester=semester,subject=subject):
                            _drive_make_public(fid); total+=1
                    elif _drive_record_file(con,category,meta,semester=semester,subject="General"):
                        _drive_make_public(fid); total+=1
        con.commit()
    finally:
        con.close()
    return {"ok":not errors,"synced":total,"errors":errors}


def init_drive_db():
    con=db()
    try:
        if getattr(con,"is_pg",False):
            for table in ("resources","academic_updates","timetables"):
                for col in ("drive_file_id","drive_folder_id","drive_web_url"): con.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} TEXT")
        else:
            for table in ("resources","academic_updates","timetables"):
                cols={r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}
                for col in ("drive_file_id","drive_folder_id","drive_web_url"):
                    if col not in cols: con.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
        for _idx in (
            "CREATE INDEX IF NOT EXISTS idx_resources_drive_file ON resources(drive_file_id)",
            "CREATE INDEX IF NOT EXISTS idx_academic_updates_drive_file ON academic_updates(drive_file_id)",
            "CREATE INDEX IF NOT EXISTS idx_timetables_drive_file ON timetables(drive_file_id)",
        ):
            try: con.execute(_idx)
            except Exception: pass
        con.commit()
    finally: con.close()

def _ensure_login_security_schema():
    """Create the persistent login-security tables used by VYBE.

    This is deliberately idempotent so an existing production Neon database can
    be upgraded without deleting or rewriting existing student/admin data.
    """
    con = db()
    try:
        if con.is_pg:
            con.execute("""CREATE TABLE IF NOT EXISTS vybe_security_devices (
                device_hash TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                first_failed_at DOUBLE PRECISION NOT NULL DEFAULT 0,
                blocked_until DOUBLE PRECISION NOT NULL DEFAULT 0,
                last_name TEXT NOT NULL DEFAULT '',
                last_student_id TEXT NOT NULL DEFAULT '',
                last_area TEXT NOT NULL DEFAULT '',
                last_ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS vybe_security_attempts (
                account_key TEXT NOT NULL,
                device_hash TEXT NOT NULL,
                area TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                first_failed_at DOUBLE PRECISION NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(account_key, device_hash, area)
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS vybe_security_alerts (
                id BIGSERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                student_id TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                area TEXT NOT NULL DEFAULT '',
                blocked_until DOUBLE PRECISION,
                message TEXT NOT NULL DEFAULT '',
                read_at TEXT
            )""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_vybe_security_alerts_created ON vybe_security_alerts(created_at)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_vybe_security_devices_blocked ON vybe_security_devices(blocked_until)")
        else:
            con.execute("""CREATE TABLE IF NOT EXISTS vybe_security_devices (
                device_hash TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                first_failed_at REAL NOT NULL DEFAULT 0,
                blocked_until REAL NOT NULL DEFAULT 0,
                last_name TEXT NOT NULL DEFAULT '',
                last_student_id TEXT NOT NULL DEFAULT '',
                last_area TEXT NOT NULL DEFAULT '',
                last_ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS vybe_security_attempts (
                account_key TEXT NOT NULL,
                device_hash TEXT NOT NULL,
                area TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                first_failed_at REAL NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(account_key, device_hash, area)
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS vybe_security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                student_id TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                area TEXT NOT NULL DEFAULT '',
                blocked_until REAL,
                message TEXT NOT NULL DEFAULT '',
                read_at TEXT
            )""")
            con.execute("CREATE INDEX IF NOT EXISTS idx_vybe_security_alerts_created ON vybe_security_alerts(created_at)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_vybe_security_devices_blocked ON vybe_security_devices(blocked_until)")
        con.commit()
    finally:
        con.close()

init_db()
_ensure_login_security_schema()
init_drive_db()


# Admin login history deletion


@app.route('/admin/login-history/delete/<int:history_id>', methods=['POST'])
@admin_required
def admin_delete_login_history(history_id):
    con = db()
    try:
        # Delete by primary key from the actual login-log table.
        cur = con.execute("SELECT id FROM admin_login_logs WHERE id = ?", (int(history_id),))
        row = cur.fetchone()
        if not row:
            flash("That login history entry no longer exists.", "error")
        else:
            con.execute("DELETE FROM admin_login_logs WHERE id = ?", (int(history_id),))
            con.commit()
            flash("Login history entry deleted.", "success")
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        flash("Could not delete that login history entry. Please try again.", "error")
    finally:
        con.close()
    return redirect("/admin/login-history")


@app.route('/admin/login-history/delete-all', methods=['POST'])
@admin_required
def admin_delete_all_login_history():
    con = db()
    try:
        con.execute("DELETE FROM admin_login_logs")
        con.commit()
        flash("All login history deleted.", "success")
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        flash("Could not delete login history. Please try again.", "error")
    finally:
        con.close()
    return redirect("/admin/login-history")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)

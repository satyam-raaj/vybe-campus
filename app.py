# VYBE V14  |  clean page-based password reset + IST admin login audit
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
from datetime import datetime, timezone, timedelta
from html.parser import HTMLParser
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse, urljoin
from urllib.request import Request as URLRequest, urlopen

from flask import Flask, request, redirect, url_for, session, flash, abort, send_from_directory, send_file, jsonify, render_template_string
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
PASSKEY_RP_ID = os.environ.get("VYBE_PASSKEY_RP_ID", "vybe-campus.onrender.com")
PASSKEY_ORIGIN = os.environ.get("VYBE_PASSKEY_ORIGIN", "https://vybe-campus.onrender.com")
DRIVE_URL = "https://drive.google.com/drive/folders/1xHRB6-j6UI8F_-q_E9w6GDlmeXWxKkc_?usp=sharing"
VYBE_AI_API_KEY = os.environ.get("VYBE_AI_API_KEY", "").strip()
VYBE_AI_MODEL = os.environ.get("VYBE_AI_MODEL", "").strip()
VYBE_AI_ENDPOINT = os.environ.get("VYBE_AI_ENDPOINT", "").strip()
ALLOWED_EXT = {".pdf", ".doc", ".docx", ".ppt", ".pptx", ".txt", ".png", ".jpg", ".jpeg", ".webp", ".zip"}
CATEGORIES = ["Wi-Fi", "Systems / computers", "Classroom", "Electricity", "Facilities", "Other"]
LAUNCH_READY = os.environ.get("VYBE_LAUNCH_READY", "0") == "1"
PUBLIC_DOMAIN = os.environ.get("VYBE_PUBLIC_DOMAIN", "").strip().lower()
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


class _CampusPageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.parts=[]; self.links=[]; self.title_parts=[]; self.in_title=False; self.skip_depth=0
    def handle_starttag(self, tag, attrs):
        tag=tag.lower()
        if tag in ('script','style','noscript','svg','canvas'): self.skip_depth += 1
        if tag=='title': self.in_title=True
        if tag=='a':
            href=dict(attrs).get('href')
            if href: self.links.append(href)
    def handle_endtag(self, tag):
        tag=tag.lower()
        if tag=='title': self.in_title=False
        if tag in ('script','style','noscript','svg','canvas') and self.skip_depth: self.skip_depth -= 1
    def handle_data(self, data):
        if self.skip_depth: return
        text=re.sub(r'\s+',' ',data or '').strip()
        if not text: return
        if self.in_title: self.title_parts.append(text)
        self.parts.append(text)

def _normalize_public_url(value):
    value=(value or '').strip()
    if not value: return ''
    if not re.match(r'^https?://',value,re.I): value='https://'+value
    parsed=urlparse(value)
    return value.rstrip('/') if parsed.scheme in ('http','https') and parsed.netloc else ''

def _crawl_college_website(start_url,max_pages=25):
    start=_normalize_public_url(start_url)
    if not start: raise ValueError('Enter a valid http(s) college website URL.')
    host=urlparse(start).netloc.lower(); queue=[start]; seen=set(); pages=[]
    blocked={'.jpg','.jpeg','.png','.gif','.webp','.svg','.zip','.mp4','.mp3','.doc','.docx','.xls','.xlsx','.ppt','.pptx'}
    while queue and len(pages)<max_pages:
        url=queue.pop(0).split('#',1)[0]; parsed=urlparse(url)
        if url in seen or parsed.netloc.lower()!=host or Path(parsed.path.lower()).suffix in blocked: continue
        seen.add(url)
        try:
            req=URLRequest(url,headers={'User-Agent':'VYBE-Campus-Assistant/1.0'})
            with urlopen(req,timeout=7) as resp:
                if 'text/html' not in (resp.headers.get('Content-Type') or '').lower(): continue
                raw=resp.read(350000)
            parser=_CampusPageParser(); parser.feed(raw.decode('utf-8','ignore'))
            text=re.sub(r'\s+',' ',' '.join(parser.parts)).strip()
            if len(text)>=40:
                title=' '.join(parser.title_parts).strip()[:250] or parsed.path.strip('/') or 'College website'
                pages.append((url,title,text[:18000]))
            for href in parser.links:
                nxt=urljoin(url,href).split('#',1)[0]; np=urlparse(nxt)
                if np.scheme in ('http','https') and np.netloc.lower()==host and nxt not in seen and len(queue)<100: queue.append(nxt)
        except Exception: continue
    return pages

def _sync_college_website(con,start_url):
    pages=_crawl_college_website(start_url)
    if not pages: raise RuntimeError('No readable public HTML pages were found on that website.')
    con.execute('DELETE FROM campus_pages')
    for url,title,text in pages: con.execute('INSERT INTO campus_pages(source_url,title,text,updated_at) VALUES(?,?,?,?)',(url,title,text,now()))
    set_setting(con,'college_website_url',_normalize_public_url(start_url)); set_setting(con,'college_website_last_sync',now())
    return len(pages)


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
                interests TEXT NOT NULL DEFAULT ''
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
            """CREATE TABLE IF NOT EXISTS timetables (
                id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, file_name TEXT NOT NULL, original_name TEXT NOT NULL, created_at TEXT NOT NULL,
                file_data BYTEA
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
                interests TEXT NOT NULL DEFAULT ''
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
            """CREATE TABLE IF NOT EXISTS timetables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, file_name TEXT NOT NULL, original_name TEXT NOT NULL, created_at TEXT NOT NULL,
                file_data BLOB
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

    if con.is_pg:
        con.executescript([
            "CREATE TABLE IF NOT EXISTS saved_reports (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, issue_category TEXT NOT NULL, issue_description TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, saved_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS accepted_solutions (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, accepted_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS helpful_votes (id BIGSERIAL PRIMARY KEY, solution_id BIGINT NOT NULL REFERENCES solutions(id) ON DELETE CASCADE, voter_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, created_at TEXT NOT NULL, UNIQUE(solution_id,voter_id))",
            "CREATE TABLE IF NOT EXISTS campus_pages (id BIGSERIAL PRIMARY KEY, source_url TEXT NOT NULL UNIQUE, title TEXT NOT NULL, text TEXT NOT NULL, updated_at TEXT NOT NULL)"
        ])
    else:
        con.executescript([
            "CREATE TABLE IF NOT EXISTS saved_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, issue_category TEXT NOT NULL, issue_description TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, saved_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS accepted_solutions (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, issue_title TEXT NOT NULL, solution_text TEXT NOT NULL, solver_name TEXT NOT NULL, accepted_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS helpful_votes (id INTEGER PRIMARY KEY AUTOINCREMENT, solution_id INTEGER NOT NULL REFERENCES solutions(id) ON DELETE CASCADE, voter_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, created_at TEXT NOT NULL, UNIQUE(solution_id,voter_id))",
            "CREATE TABLE IF NOT EXISTS campus_pages (id INTEGER PRIMARY KEY AUTOINCREMENT, source_url TEXT NOT NULL UNIQUE, title TEXT NOT NULL, text TEXT NOT NULL, updated_at TEXT NOT NULL)"
        ])
    if not con.is_pg:
        cols_now={r['name'] for r in con.execute('PRAGMA table_info(students)').fetchall()}
        for col,definition in (('admit_card_file_name','TEXT'),('admit_card_original_name','TEXT'),('admit_card_mime_type','TEXT'),('admit_card_file_data','BLOB')):
            if col not in cols_now: con.execute(f'ALTER TABLE students ADD COLUMN {col} {definition}')
    else:
        con.execute('ALTER TABLE students ADD COLUMN IF NOT EXISTS admit_card_file_name TEXT')
        con.execute('ALTER TABLE students ADD COLUMN IF NOT EXISTS admit_card_original_name TEXT')
        con.execute('ALTER TABLE students ADD COLUMN IF NOT EXISTS admit_card_mime_type TEXT')
        con.execute('ALTER TABLE students ADD COLUMN IF NOT EXISTS admit_card_file_data BYTEA')

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
        tt_cols = {r["name"] for r in con.execute("PRAGMA table_info(timetables)").fetchall()}
        if "file_data" not in tt_cols:
            con.execute("ALTER TABLE timetables ADD COLUMN file_data BLOB")
    else:
        # PostgreSQL migrations are idempotent and safe on existing deployments.
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT 'Study material'")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS original_name TEXT")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS mime_type TEXT")
        con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS file_data BYTEA")
        con.execute("ALTER TABLE timetables ADD COLUMN IF NOT EXISTS file_data BYTEA")
        # Existing V14 deployments may already have this table. Keep the PostgreSQL
        # column Boolean-compatible so inserts using True/False never hit a type mismatch.
        con.execute("ALTER TABLE admin_login_logs ADD COLUMN IF NOT EXISTS success BOOLEAN NOT NULL DEFAULT FALSE")

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

    if con.is_pg:
        extra_tables = [
            "CREATE TABLE IF NOT EXISTS faculty (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, department TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, last_login TEXT)",
            "CREATE TABLE IF NOT EXISTS helpdesk_tickets (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, category TEXT NOT NULL, subject TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open', assigned_to TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS clubs (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'General', created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS club_members (id BIGSERIAL PRIMARY KEY, club_id BIGINT NOT NULL REFERENCES clubs(id) ON DELETE CASCADE, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, joined_at TEXT NOT NULL, UNIQUE(club_id,student_id))",
            "CREATE TABLE IF NOT EXISTS emergency_alerts (id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, message TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, expires_at TEXT)",
            "CREATE TABLE IF NOT EXISTS universities (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS departments (id BIGSERIAL PRIMARY KEY, university_id BIGINT REFERENCES universities(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(university_id,name))",
            "CREATE TABLE IF NOT EXISTS student_sessions (id BIGSERIAL PRIMARY KEY, student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE, session_token TEXT NOT NULL UNIQUE, user_agent TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_seen TEXT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)"
        ]
    else:
        extra_tables = [
            "CREATE TABLE IF NOT EXISTS faculty (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, department TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, last_login TEXT)",
            "CREATE TABLE IF NOT EXISTS helpdesk_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, category TEXT NOT NULL, subject TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open', assigned_to TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS clubs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'General', created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS club_members (id INTEGER PRIMARY KEY AUTOINCREMENT, club_id INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, joined_at TEXT NOT NULL, UNIQUE(club_id,student_id))",
            "CREATE TABLE IF NOT EXISTS emergency_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, message TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, expires_at TEXT)",
            "CREATE TABLE IF NOT EXISTS universities (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY AUTOINCREMENT, university_id INTEGER REFERENCES universities(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(university_id,name))",
            "CREATE TABLE IF NOT EXISTS student_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, session_token TEXT NOT NULL UNIQUE, user_agent TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, last_seen TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)"
        ]
    con.executescript(extra_tables)
    if not con.is_pg:
        student_cols={r['name'] for r in con.execute('PRAGMA table_info(students)').fetchall()}
        if 'role' not in student_cols: con.execute("ALTER TABLE students ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
        if 'university_id' not in student_cols: con.execute("ALTER TABLE students ADD COLUMN university_id INTEGER")
    else:
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'student'")
        con.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS university_id BIGINT")

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
        "vybe_assistant_enabled": "1",
        "college_website_url": "",
        "college_website_last_sync": "",
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


def content_manager_required(fn):
    @wraps(fn)
    @student_required
    def wrapper(*args, **kwargs):
        sid = session.get("student_db_id")
        con = db()
        row = con.execute("SELECT value FROM settings WHERE key=?", (f"content_manager_{sid}",)).fetchone()
        con.close()
        if not row or row["value"] != "1":
            flash("You do not have publisher access.")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper


def faculty_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        fid=session.get('faculty_id')
        if not fid: return redirect(url_for('faculty_login'))
        con=db(); row=con.execute('SELECT id,status FROM faculty WHERE id=?',(fid,)).fetchone(); con.close()
        if not row or row['status']!='active': session.pop('faculty_id',None); flash('Faculty access is not active.'); return redirect(url_for('faculty_login'))
        return fn(*args,**kwargs)
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
    path=request.path
    public_allowed={"/","/privacy","/terms","/favicon.svg","/offline","/launch-gate"}
    host=request.host.split(":",1)[0].lower()
    domain_ok=bool(PUBLIC_DOMAIN) and host in {PUBLIC_DOMAIN, "www."+PUBLIC_DOMAIN}
    if (not LAUNCH_READY or not domain_ok) and path not in public_allowed and not path.startswith("/admin") and not path.startswith("/passkey") and not path.startswith("/faculty"):
        return redirect(url_for("launch_gate"))
    if path.startswith("/admin") or path.startswith("/passkey") or path.startswith("/faculty") or path in public_allowed:
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


@app.errorhandler(500)
def handle_internal_server_error(error):
    app.logger.exception("Unhandled VYBE server error", exc_info=error)
    try:
        return layout("VYBE Error", '<section class="section"><div class="auth"><div class="card authbox"><div class="badge">VYBE</div><h1>Something went wrong.</h1><p class="muted">That action could not be completed. Your data was not intentionally changed. Please go back and try again.</p><div class="actions"><a class="btn accent" href="javascript:history.back()">Go back</a><a class="btn dark" href="/dashboard">Dashboard</a></div></div></div></section>'), 500
    except Exception:
        return "VYBE could not complete that request. Please try again.", 500


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    if session.get("student_db_id"):
        response.headers["Cache-Control"] = "private, no-store, max-age=0"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


CSS = r"""
:root{--bg:#05080d;--panel:#0b1520;--panel2:#0e1a28;--line:#1d2a39;--line2:#2a3b50;--text:#f3f6fa;--muted:#98a7b8;--blue:#67adf2;--good:#62d99a;--bad:#ff6f7d;--shadow:0 18px 45px rgba(0,0,0,.22)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI",sans-serif;min-height:100vh}a{text-decoration:none;color:inherit}
.nav{position:sticky;top:0;z-index:50;background:#07101a;border-bottom:1px solid var(--line)}.navin{max-width:1180px;margin:auto;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;gap:14px}.brand{font-weight:800;font-size:23px;letter-spacing:-.055em}.brandmark{display:inline-grid;place-items:center;width:31px;height:31px;margin-right:8px;border-radius:8px;background:#eaf2fb;color:#05080d;font-size:14px;font-weight:900}.navlinks{display:flex;gap:4px;flex-wrap:wrap}.navlinks a{padding:9px 11px;border-radius:8px;color:#aebdcb;font-size:13px}.navlinks a:hover{background:#101e2d;color:#fff}.wrap{max-width:1180px;margin:auto;padding:24px 20px 80px}
.hero{min-height:68vh;display:grid;place-items:center;text-align:center;padding:80px 0 50px}.hero h1{font-size:clamp(76px,14vw,155px);line-height:.8;margin:18px 0;letter-spacing:-.1em;color:#f4f7fb}.hero p{max-width:720px;color:var(--muted);font-size:18px;line-height:1.65;margin:0 auto 28px}
.badge,.pill{display:inline-block;border:1px solid var(--line);background:#0c1723;padding:6px 9px;border-radius:7px;color:#b9c7d5;font-size:11px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.grid2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:var(--shadow)}.card:hover{border-color:var(--line2)}.card h2,.card h3{margin:0 0 9px;letter-spacing:-.035em}.muted{color:var(--muted)}.small{font-size:13px;color:var(--muted)}.eyebrow{font-size:11px;letter-spacing:.09em;color:#7ea8d1;margin-bottom:10px;font-weight:700}
.btn{display:inline-flex;align-items:center;justify-content:center;border:1px solid #dbe7f2;cursor:pointer;padding:11px 16px;border-radius:9px;background:#edf4fa;color:#07101a;font-weight:750}.btn:hover{background:#dbe8f3}.btn.dark{background:#0e1a27;color:#eef5fb;border-color:var(--line2);box-shadow:none}.btn.good{background:#10261e;color:#9be7ba;border-color:#1f4937;box-shadow:none}.btn.danger{background:#2a1217;color:#ffb0b9;border-color:#5a222b;box-shadow:none}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}.section{padding:30px 0}.auth{min-height:80vh;display:grid;place-items:center}.authbox{width:min(470px,100%)}.form{display:grid;gap:13px}.label{font-size:13px;color:#b5c1cc;margin-bottom:5px}
input,textarea,select{width:100%;padding:13px 14px;background:#09131e;color:#fff;border:1px solid #263548;border-radius:9px;outline:none}input::placeholder,textarea::placeholder{color:#667688}input:focus,textarea:focus,select:focus{border-color:#5c86ad;box-shadow:0 0 0 3px rgba(92,169,255,.10)}textarea{min-height:125px;resize:vertical}.flash{padding:13px 15px;border:1px solid var(--line2);background:#0d1722;border-radius:10px;margin:10px 0}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid #202d3c;vertical-align:top}.tablewrap{overflow:auto}.kpi{font-size:38px;font-weight:850;letter-spacing:-.065em}.footer{padding:50px 20px;color:#647487;text-align:center}.empty{text-align:center;padding:45px;color:var(--muted);border:1px dashed #2b3a4b;border-radius:14px}.status-good{color:var(--good)}.status-warn{color:#e6bd67}.status-bad{color:var(--bad)}
.feed-list{display:grid;gap:12px}.feed-item{padding:17px 18px;border:1px solid var(--line);border-radius:12px;background:#0b1520}.community-launch{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:20px 22px;min-height:92px;background:#0b1520;border:1px solid var(--line);border-radius:14px}.community-icon{width:50px;height:50px;display:grid;place-items:center;border-radius:10px;background:#eaf2fb;color:#080c12;font-size:12px;font-weight:800}.community-copy{flex:1}.community-copy h3{margin:0 0 4px;font-size:18px}.community-copy p{margin:0;color:var(--muted);font-size:13px;line-height:1.45}.community-arrow{width:38px;height:38px;border:1px solid var(--line);border-radius:9px;display:grid;place-items:center;color:#fff;background:#101d2b}.ai-box{background:#0b1520;border:1px solid var(--line);border-radius:16px;padding:24px}.ai-answer{white-space:pre-wrap;line-height:1.7}.profile-avatar{width:74px;height:74px;border-radius:14px;background:#eaf2fb;color:#080c12;display:grid;place-items:center;font-size:28px;font-weight:900}.stat-row{display:flex;gap:10px;flex-wrap:wrap}.stat-chip{padding:9px 11px;border-radius:9px;border:1px solid var(--line);background:#0b1520}.student-top-tools{display:flex;align-items:center;gap:6px;flex:1;justify-content:flex-end}.top-stat,.top-tool{min-height:38px;border:1px solid var(--line);border-radius:8px;background:#0b1520;display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:7px 9px;color:#eee;font-size:12px;white-space:nowrap}.top-stat{flex-direction:column;line-height:1;min-width:58px}.top-stat small{font-size:8px;color:var(--muted);text-transform:uppercase}.top-search{display:flex;align-items:center;width:190px}.top-search input{height:38px;border-radius:8px 0 0 8px;padding:8px 10px;font-size:12px}.top-search button{height:38px;width:38px;border:1px solid #263548;border-left:0;border-radius:0 8px 8px 0;background:#101d2b;color:#fff;cursor:pointer}.page-back,.mobile-back{border:1px solid var(--line);background:#0b1520;color:#ddd;border-radius:8px;padding:8px 12px;cursor:pointer}.page-back{margin:2px 0 4px}.mobile-back{display:none;width:100%;text-align:left}.nav-toggle{display:none;width:42px;height:42px;border:1px solid var(--line);border-radius:8px;background:#0b1520;color:#fff;font-size:14px;cursor:pointer}.mobile-nav{display:none}.mobile-nav a{display:block;padding:12px 14px;border-radius:8px;color:#ddd}.mobile-nav a:hover{background:#101d2b}.legal{max-width:850px;margin:auto}.legal h2{margin-top:34px}
@media(max-width:850px){.grid,.grid2,.two{grid-template-columns:1fr}.navin{padding:9px 10px;gap:5px}.navlinks{display:none}.nav-toggle{display:grid;place-items:center;width:40px;height:40px}.brand{font-size:0;flex:0 0 34px}.brandmark{margin:0;width:32px;height:32px}.student-top-tools{gap:4px;overflow:hidden;justify-content:flex-start}.top-stat{min-width:38px;width:38px;padding:5px 2px;font-size:9px}.top-stat small{display:none}.top-tool{width:55px;min-width:55px;padding:6px 2px;font-size:9px}.top-search{width:64px;min-width:64px}.top-search input{font-size:10px;padding:7px}.top-search button{width:30px}.mobile-nav.open{display:grid;gap:4px;padding:10px 14px 14px;border-top:1px solid var(--line);background:#07101a}.mobile-back{display:block}.menu-sub{padding-left:28px!important;font-size:12px!important;color:#aaa!important}.wrap{padding:12px}.page-back{display:inline-flex}.hero{padding:55px 0 35px}.hero h1{font-size:74px}.card{border-radius:14px}}
"""



def layout(title, body, admin=False):
    if admin:
        links = '<a href="/admin/panel">Dashboard</a><a href="/admin/timetable">Timetable</a><a href="/admin/settings">Settings</a><a href="/admin/faculty">Faculty</a><a href="/admin/helpdesk">Help Desk</a><a href="/admin/clubs">Clubs</a><a href="/admin/emergency">Alerts</a><a href="/admin/password">Security</a><a href="/admin/logout">Logout</a>'
    elif session.get("student_db_id"):
        publisher_link = ""
        try:
            _lc = db(); _lr = _lc.execute("SELECT value FROM settings WHERE key=?", (f"content_manager_{session.get('student_db_id')}",)).fetchone(); _lc.close()
            if _lr and _lr["value"] == "1": publisher_link = '<a href="/publisher">Publisher</a>'
        except Exception:
            publisher_link = ""
        links = '<a href="/dashboard">Home</a><a href="/academics">Academics</a><a href="/issues">Campus</a><a href="/community">Community</a><a href="/chat"> Chat</a><a href="/search">Search</a>' + publisher_link + '<a href="/profile">Profile</a><a href="/security">Security</a><a href="/logout">Logout</a>'
        try:
            _tc=db(); _ts=_tc.execute("SELECT reputation_points,helpful_answers FROM students WHERE id=?",(session.get("student_db_id"),)).fetchone(); _tc.close()
            points=int(_ts["reputation_points"] if _ts else 0); helpful=int(_ts["helpful_answers"] if _ts else 0)
        except Exception:
            points=helpful=0
        student_tools=f'<div class="student-top-tools"><a class="top-stat" href="/profile#points"> <span>{points}</span><small>VYBE</small></a><a class="top-stat" href="/profile#helpful"> <span>{helpful}</span><small>Helpful</small></a><a class="top-tool" href="/assistant"> Ask VYBE</a><a class="top-tool" href="/chat"> Chat</a><form class="top-search" action="/search" method="get"><input name="q" placeholder="Search campus..." aria-label="Search campus"><button type="submit">⌕</button></form></div>'
    else:
        links = '<a href="/login">Student Login</a><a href="/register">Register</a><a href="/admin">Admin</a>'
        student_tools=""
    mobile_links = links.replace('<a href="/issues">Campus</a>', '<a href="/issues">Campus</a><a class="menu-sub" href="/issues#saved-reports">↳ Saved Reports</a>') if student_tools else links
    flashes = "".join(f'<div class="flash">{esc(m)}</div>' for m in session.pop("_flashes", []))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#07111f"><link rel="icon" href="/favicon.svg" type="image/svg+xml"><title>{esc(title)} · VYBE</title><style>{CSS}</style></head><body><div class="nav"><div class="navin"><a class="brand" href="/"><span class="brandmark">V</span><span class="brandtext">VYBE</span></a>{student_tools}<div class="navlinks">{links}</div><button class="nav-toggle" id="vybeNavToggle" type="button" aria-label="Open menu" aria-expanded="false">MENU</button></div><div class="mobile-nav" id="vybeMobileNav"><button class="mobile-back" type="button" onclick="history.back()">← Back</button>{mobile_links}</div></div><main class="wrap"><button class="page-back" type="button" onclick="if(history.length>1)history.back();else location.href='/dashboard'">← Back</button>{flashes}{body}</main><footer class="footer">VYBE | Your Campus. Your Community. Your Space. | <a href="/privacy">Privacy</a> | <a href="/terms">Terms</a></footer><script>(function(){{document.addEventListener("click",function(e){{const btn=e.target.closest(".toggle-password");if(!btn)return;e.preventDefault();e.stopPropagation();const id=btn.getAttribute("data-target");const el=id?document.getElementById(id):null;if(!el)return;const show=el.type==="password";el.type=show?"text":"password";btn.textContent=show?"Hide":"View";}});const toggle=document.getElementById("vybeNavToggle"),menu=document.getElementById("vybeMobileNav");if(toggle&&menu){{toggle.addEventListener("click",function(){{const open=menu.classList.toggle("open");toggle.setAttribute("aria-expanded",open?"true":"false");toggle.textContent=open?"CLOSE":"MENU";}});menu.addEventListener("click",function(e){{if(e.target.closest("a")){{menu.classList.remove("open");toggle.setAttribute("aria-expanded","false");toggle.textContent="MENU";}}}});}}}})();</script></body></html>'''


@app.route('/launch-gate')
def launch_gate():
    return layout('Private preview', '<section class="section"><div class="card" style="max-width:760px;margin:70px auto"><div class="badge">PRIVATE PREVIEW</div><h1>VYBE is not launched yet.</h1><p class="muted">Production access stays locked until the custom domain, favicon, legal pages, branding cleanup and final verification are complete.</p><div class="actions"><a class="btn dark" href="/privacy">Privacy Policy</a><a class="btn dark" href="/terms">Terms & Conditions</a></div></div></section>')

@app.route('/privacy')
def privacy_policy():
    return layout('Privacy Policy', '<section class="section legal"><div class="badge">LEGAL</div><h1>Privacy Policy</h1><p class="muted">VYBE is designed for campus use. This draft describes information the platform may process and should be reviewed by the deploying university before production launch.</p><h2>Information</h2><p>VYBE may process account details, authentication records, campus resources, community posts, help desk tickets and operational security records when those features are used.</p><h2>Passwords and passkeys</h2><p>VYBE should not store student passwords in plain text. WebAuthn passkeys use device-held private keys and server-side credential data needed for verification.</p><h2>Campus content</h2><p>University-managed announcements, events, resources and support records are controlled by authorized administrators. Community visibility follows the permissions implemented by the university.</p><h2>Security</h2><p>Production should use HTTPS, strong secrets, PostgreSQL, regular backups and appropriate access controls.</p><h2>Deletion and retention</h2><p>Retention should follow the deploying university policy and applicable law. Supported administrative tools can remove student and campus records.</p><h2>Contact</h2><p>Replace this draft contact section with the university approved privacy contact before launch.</p></section>')

@app.route('/terms')
def terms_conditions():
    return layout('Terms & Conditions', '<section class="section legal"><div class="badge">LEGAL</div><h1>Terms & Conditions</h1><p class="muted">This draft governs use of VYBE as a campus platform and must be reviewed and approved by the deploying university before launch.</p><h2>Acceptable use</h2><p>Users must provide accurate information, protect credentials, respect other members and use VYBE for legitimate academic and campus purposes.</p><h2>Prohibited use</h2><p>Harassment, impersonation, unauthorized access, malicious files and attempts to bypass permissions are prohibited.</p><h2>Administration</h2><p>The university controls administrative permissions, campus content and account access subject to its policies and applicable law.</p><h2>Availability</h2><p>VYBE may be unavailable for maintenance, upgrades or circumstances outside the platform operator control.</p><h2>Production review</h2><p>The university should replace this draft with approved legal terms, legal entity information, governing law, contact information and complaint procedures.</p></section>')

@app.route('/favicon.svg')
def favicon():
    return send_file(APP_DIR / 'static' / 'favicon.svg', mimetype='image/svg+xml')

@app.route("/offline")
def offline():
    return layout("Offline", '''<section class="offline-page"><div><div class="badge">VYBE STATUS</div><h1> OFFLINE</h1><p class="muted">VYBE is temporarily unavailable. Please check back later.</p><p><a class="btn dark" href="/admin">Admin access</a></p></div></section>''')


@app.route("/")
def home():
    if session.get("student_db_id"):
        return redirect(url_for("dashboard"))
    if session.get("admin_authenticated"):
        return redirect(url_for("admin_panel"))
    body = '''<section class="hero"><div><div class="badge">Student-powered campus operating system</div><h1>VYBE</h1><p>Your Campus. Your Community. Your Space.</p><div class="actions" style="justify-content:center"><a class="btn accent" href="/login">Enter VYBE →</a><a class="btn dark" href="/register">Request access</a></div></div></section><section class="grid"><div class="card"><div class="icon"></div><h2>Academics</h2><p class="muted">Notes, PYQs, syllabus, assignments and study material in one place.</p></div><div class="card"><div class="icon"></div><h2>Campus</h2><p class="muted">Report real campus problems and follow their status.</p></div><div class="card"><div class="icon"></div><h2>Community</h2><p class="muted">Students help students with immediate, visible solutions.</p></div></section>'''
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
            con.commit()
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
        session.clear(); session["student_db_id"] = row["id"]; token=secrets.token_urlsafe(32); session["student_session_token"]=token
        con=db(); con.execute("INSERT INTO student_sessions(student_id,session_token,user_agent,ip_address,created_at,last_seen,revoked) VALUES(?,?,?,?,?,?,?)",(row["id"],token,request.headers.get("User-Agent","")[:500],request.remote_addr or "",stamp,stamp,False)); con.commit(); con.close()
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
            flash("Request sent successfully. Keep this page open while the admin reviews it.")
            return redirect(url_for("forgot_password"))
        finally:
            con.close()

    request_id = session.get("password_reset_request_id")
    waiting_ui = ""
    if request_id:
        waiting_ui = f"""
        <div class=\"notice\" id=\"resetStatusBox\" style=\"margin-top:16px\">
          <strong id=\"resetStatusTitle\">Waiting for admin approval...</strong>
          <p class=\"small\" id=\"resetStatusText\" style=\"margin:7px 0 0\">Your request is with the admin. Keep this page open; when approved, VYBE will open the new-password page automatically.</p>
        </div>
        <script>
        (()=>{{
          const requestId = {int(request_id)};
          const title = document.getElementById(\"resetStatusTitle\");
          const text = document.getElementById(\"resetStatusText\");
          let timer = null;
          async function check(){{
            try{{
              const r = await fetch(`/forgot-password/status?request_id=${{requestId}}`, {{credentials: 'same-origin', cache: 'no-store'}});
              if(!r.ok) return;
              const j = await r.json();
              if(j.status === 'approved'){{
                title.textContent = 'Approved ';
                text.textContent = 'Opening secure password page...';
                if(timer) clearInterval(timer);
                window.location.href = '/reset-password';
              }} else if(j.status === 'rejected'){{
                title.textContent = 'Request rejected';
                text.textContent = 'Please submit a new request if you still need to change your password.';
                if(timer) clearInterval(timer);
              }} else if(['used','expired','invalid'].includes(j.status)){{
                title.textContent = 'Request is no longer active';
                text.textContent = 'Please submit a new password-change request.';
                if(timer) clearInterval(timer);
              }}
            }}catch(e){{}}
          }}
          check(); timer=setInterval(check, 2000);
        }})();
        </script>
        """
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


def _active_announcements(con, limit=6):
    return con.execute(
        "SELECT * FROM announcements WHERE expires_at IS NULL OR expires_at='' OR expires_at>=? "
        "ORDER BY CASE WHEN priority='High' THEN 0 WHEN priority='Important' THEN 1 ELSE 2 END, id DESC LIMIT ?",
        (now(), limit)
    ).fetchall()


def _upcoming_events(con, limit=6):
    return con.execute(
        "SELECT * FROM events WHERE event_date>=? ORDER BY event_date ASC, event_time ASC, id ASC LIMIT ?",
        (datetime.now(timezone.utc).strftime("%Y-%m-%d"), limit)
    ).fetchall()


def _latest_timetables(con, limit=20):
    return con.execute("SELECT * FROM timetables ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


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
        "SELECT id,title,original_name,created_at FROM timetables WHERE title LIKE ? OR original_name LIKE ? ORDER BY id DESC LIMIT ?",
        (like,like,limit)
    ).fetchall():
        out.append({"type":"Timetable","title":r["title"],"text":r["original_name"],"url":"/timetable","date":r["created_at"]})
    for r in con.execute(
        "SELECT id,title,course,semester,subject,description FROM resources "
        "WHERE title LIKE ? OR course LIKE ? OR subject LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ?",
        (like,like,like,like,limit)
    ).fetchall():
        out.append({"type":"Resource","title":r["title"],"text":f'{r["course"]} · {r["semester"]} · {r["subject"]} · {r["description"]}',"url":"/academics?q="+q,"date":""})
    for r in con.execute("SELECT source_url,title,text,updated_at FROM campus_pages WHERE title LIKE ? OR text LIKE ? ORDER BY id DESC LIMIT ?",(like,like,limit)).fetchall():
        out.append({"type":"College Website","title":r["title"],"text":r["text"][:500],"url":r["source_url"],"date":r["updated_at"]})
    return out[:limit*4]


def _ai_context(con, question):
    results=_campus_search(con, question, limit=5)
    if results:
        return "\n".join(f'[{x["type"]}] {x["title"]}: {x["text"]}' for x in results)
    anns=_active_announcements(con,4)
    evs=_upcoming_events(con,4)
    return "\n".join(
        [f'[Announcement] {x["title"]}: {x["message"]}' for x in anns] +
        [f'[Event] {x["title"]}: {x["event_date"]} {x["event_time"]} at {x["location"]}: {x["description"]}' for x in evs]
    )


def _current_ist():
    from zoneinfo import ZoneInfo
    return datetime.now(ZoneInfo("Asia/Kolkata"))


def _format_ist(dt):
    return dt.strftime("%A, %d %B %Y at %I:%M %p IST")


def _free_vybe_answer(con, question):
    """Free, deterministic VYBE assistant: no external AI/API is required."""
    q = re.sub(r"\s+", " ", question.lower()).strip()
    ist = _current_ist()

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
            lines.append(f"• {r['title']}  |  {r['message']}")
        return "\n".join(lines)

    if any(x in q for x in ("event", "events", "happening", "schedule", "program", "programs", "this week", "upcoming")):
        rows = _upcoming_events(con, 8)
        if not rows:
            return " There are no upcoming events listed in VYBE right now."
        lines = [" Upcoming VYBE events:"]
        for r in rows[:5]:
            lines.append(f"• {r['title']}  |  {r['event_date']} · {r['event_time'] or 'Time TBA'} · {r['location'] or 'Location TBA'}")
        return "\n".join(lines)

    resource_words = ("note", "notes", "pyq", "pyqs", "assignment", "assignments", "study material", "syllabus", "file", "files", "resource", "resources", "where is", "where are", "find")
    if any(x in q for x in resource_words):
        search_terms = [w for w in re.findall(r"[a-z0-9]+", q) if len(w) > 2 and w not in {"where", "what", "are", "the", "for", "from", "find", "file", "files", "notes", "note", "resource", "resources", "please", "show", "give", "me"}]
        rows = []
        if search_terms:
            like = "%" + "%".join(search_terms[:4]) + "%"
            rows = con.execute(
                "SELECT id,title,resource_type,course,semester,subject,description,file_name FROM resources "
                "WHERE title LIKE ? OR course LIKE ? OR semester LIKE ? OR subject LIKE ? OR description LIKE ? "
                "ORDER BY id DESC LIMIT 8", (like,like,like,like,like)
            ).fetchall()
        if not rows:
            rows = con.execute("SELECT id,title,resource_type,course,semester,subject,description,file_name FROM resources ORDER BY id DESC LIMIT 8").fetchall()
        if not rows:
            drive = setting(con, "google_drive_url", DRIVE_URL)
            return f" I couldn't find a VYBE resource yet. Check Academics or the shared Google Drive: {drive}"
        lines = [" I found these VYBE resources:"]
        for r in rows[:5]:
            location = f"Open in VYBE: /resource/{r['id']}" if r['file_name'] else "Available through the configured Google Drive / link resource"
            lines.append(f"• {r['title']}  |  {r['course']} · {r['semester']} · {r['subject']}  |  {location}")
        return "\n".join(lines) + "\n\nYou can also open Academics → Search to find more notes and files."

    if any(x in q for x in ("community", "question", "questions", "solution", "solutions", "problem", "problems", "chat")):
        like = f"%{question.strip()[:80]}%"
        rows = con.execute("SELECT id,title,description,status FROM issues WHERE title LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT 5", (like,like)).fetchall()
        if rows:
            return " Matching community problems:\n" + "\n".join(f"• {r['title']}  |  {r['status']}  |  /community#problem-{r['id']}" for r in rows)
        count = con.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"]
        return f" VYBE has {count} campus problem(s) in Community. Open Community to view questions and solutions."

    results = _campus_search(con, question, 8)
    if results:
        website=[x for x in results if x['type']=='College Website']
        if website:
            return " From the official college website:\n" + "\n".join(f"• {x['title']}  |  {x['text']}\n  Source: {x['url']}" for x in website[:5])
        return " I found this in VYBE:\n" + "\n".join(f"• {x['title']}  |  {x['text']}" for x in results[:5])
    return "I could not find a verified answer in VYBE campus data. Try a more specific question or ask university administration."


@app.route("/announcements")
@student_required
def announcements():
    con=db(); rows=_active_announcements(con,30); con.close()
    cards=""
    for r in rows:
        badge=" "+esc(r["priority"]) if r["priority"] in ("High","Important") else " Announcement"
        cards += f'''<div class="card notice-card"><div class="badge">{badge}</div><h2>{esc(r["title"])}</h2><p class="muted" style="white-space:pre-wrap">{esc(r["message"])}</p><div class="small">{esc(r["created_at"])}</div></div>'''
    body=f'''<section class="section"><div class="badge">CAMPUS UPDATES</div><h1>Announcements.</h1><p class="muted">Important campus information, in one place.</p></section><section class="section" style="display:grid;gap:14px">{cards or '<div class="empty">No active announcements.</div>'}</section>'''
    return layout("Announcements",body)


@app.route("/events")
@student_required
def events():
    con=db(); rows=_upcoming_events(con,30); con.close()
    cards=""
    for r in rows:
        cards += f'''<div class="card"><div class="badge"> EVENT</div><div class="event-date">{esc(r["event_date"])}</div><h2>{esc(r["title"])}</h2><p class="small"> {esc(r["event_time"] or "Time TBA")} ·  {esc(r["location"] or "Location TBA")}</p><p class="muted" style="white-space:pre-wrap">{esc(r["description"])}</p></div>'''
    body=f'''<section class="section"><div class="badge">CAMPUS EVENTS</div><h1>What's happening.</h1><p class="muted">Upcoming events and activities around campus.</p></section><section class="section grid">{cards or '<div class="empty">No upcoming events.</div>'}</section>'''
    return layout("Events",body)


@app.route("/timetable")
@student_required
def timetable():
    con=db(); rows=_latest_timetables(con,30); con.close()
    cards=""
    for r in rows:
        suffix=Path(r["original_name"]).suffix.lower()
        if suffix in (".png",".jpg",".jpeg",".webp"):
            preview=f'<img src="/timetable-file/{r["id"]}" alt="{esc(r["title"])}" style="display:block;width:100%;max-height:720px;object-fit:contain;border-radius:18px;background:#08080a">'
        else:
            preview=f'<div class="notice"><strong> {esc(r["original_name"])}</strong><p class="small">This timetable is a document. Open it below.</p></div>'
        cards += f'<div class="card"><div class="badge"> TIMETABLE</div><h2>{esc(r["title"])}</h2><p class="small">Updated {esc(r["created_at"])}</p>{preview}<div class="actions"><a class="btn accent" href="/timetable-file/{r["id"]}" target="_blank" rel="noopener">Open / view timetable →</a></div></div>'
    body=f'<section class="section"><div class="badge">CAMPUS TIMETABLE</div><h1>Your timetable.</h1><p class="muted">The latest timetable posted by VYBE admin or an approved publisher.</p></section><section class="section" style="display:grid;gap:16px">{cards or "<div class=\"empty\">No timetable has been posted yet.</div>"}</section>'
    return layout("Timetable",body)


@app.route("/timetable-file/<int:tid>")
@student_required
def timetable_file(tid):
    con=db(); row=con.execute("SELECT file_name,original_name,file_data FROM timetables WHERE id=?",(tid,)).fetchone(); con.close()
    if not row: abort(404)
    if row["file_data"] is not None:
        return send_file(io.BytesIO(bytes(row["file_data"])), mimetype=mimetypes.guess_type(row["original_name"] or row["file_name"])[0] or "application/octet-stream", as_attachment=False, download_name=row["original_name"] or row["file_name"])
    path=UPLOAD_DIR/row["file_name"]
    if not path.is_file(): abort(404)
    return send_file(path, mimetype=mimetypes.guess_type(path.name)[0] or "application/octet-stream", as_attachment=False, download_name=row["original_name"])


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
    if request.method=="POST":
        action=request.form.get("action","profile")
        if action=="admit_card":
            f=request.files.get("admit_card")
            if not f or not f.filename: con.close(); flash("Choose an admit card file first."); return redirect(url_for("profile"))
            data=f.read()
            if not data or len(data)>15*1024*1024: con.close(); flash("Admit card must be a non-empty file up to 15 MB."); return redirect(url_for("profile"))
            original=Path(f.filename).name[:240]; mime=f.mimetype or "application/octet-stream"; stored=secrets.token_hex(16)+Path(original).suffix.lower()
            con.execute("UPDATE students SET admit_card_file_name=?,admit_card_original_name=?,admit_card_mime_type=?,admit_card_file_data=? WHERE id=?",(stored,original,mime,data,session["student_db_id"]))
            con.commit(); con.close(); flash("Admit card saved privately to your VYBE profile."); return redirect(url_for("profile"))
        bio=request.form.get("bio","").strip()[:300]; interests=request.form.get("interests","").strip()[:200]
        con.execute("UPDATE students SET bio=?,interests=? WHERE id=?",(bio,interests,session["student_db_id"])); con.commit(); con.close(); flash("Profile updated."); return redirect(url_for("profile"))
    st=con.execute("SELECT name,student_id,bio,interests,reputation_points,helpful_answers,accepted_solutions,admit_card_original_name FROM students WHERE id=?",(session["student_db_id"],)).fetchone()
    accepted=con.execute("SELECT issue_title,solution_text,solver_name,accepted_at FROM accepted_solutions WHERE student_id=? ORDER BY id DESC LIMIT 30",(session["student_db_id"],)).fetchall(); con.close()
    initials="".join(x[0] for x in st["name"].split()[:2]).upper() or "V"
    accepted_html="".join(f'<div class="feed-item"><strong>{esc(x["issue_title"])}</strong><p class="muted" style="white-space:pre-wrap">{esc(x["solution_text"])}</p><p class="small">Accepted from {esc(x["solver_name"])} · {esc(x["accepted_at"])}</p></div>' for x in accepted)
    card_label=esc(st["admit_card_original_name"]) if st["admit_card_original_name"] else "No admit card uploaded yet."
    body=f'''<section class="section"><div class="card"><div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap"><div class="profile-avatar">{esc(initials)}</div><div><div class="badge">VYBE PROFILE</div><h1 style="margin:9px 0 4px">{esc(st["name"])}</h1><p class="muted" style="margin:0">Student · Student ID stays private</p></div></div><div class="stat-row" style="margin-top:22px"><span class="stat-chip" id="points"> {st["reputation_points"]} VYBE points</span><span class="stat-chip" id="helpful"> {st["helpful_answers"]} helpful answers</span><span class="stat-chip"> {st["accepted_solutions"]} accepted solutions</span></div></div></section>
<section class="section grid2"><div class="card"><h2>About you.</h2><form class="form" method="post"><input type="hidden" name="action" value="profile"><textarea name="bio" maxlength="300" placeholder="A short bio">{esc(st["bio"])}</textarea><input name="interests" maxlength="200" value="{esc(st["interests"])}" placeholder="Interests · e.g. Coding, Design, Cricket"><button class="btn accent">Save profile →</button></form></div><div class="card"><h2> Password</h2><p class="muted">Change your student password from your profile area.</p><a class="btn dark" href="/account/password">Open password settings →</a></div></section>
<section class="section"><div class="card"><h2> Admit card</h2><p class="muted">Optional and private. Upload your admit card in any file format up to 15 MB.</p><p class="small">Current file: <strong>{card_label}</strong></p><form class="form" method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="admit_card"><input type="file" name="admit_card" required><button class="btn accent">Save admit card →</button></form></div></section>
<section class="section"><div class="card"><h2> Accepted solutions</h2><p class="muted">Solutions you personally accepted stay here even after their community chat is removed.</p><div class="feed-list">{accepted_html or '<div class="empty">No accepted solutions yet.</div>'}</div></div></section>'''
    return layout("Profile",body)

@app.route("/profile/admit-card")
@student_required
def profile_admit_card():
    con=db(); r=con.execute("SELECT admit_card_file_data,admit_card_mime_type,admit_card_original_name FROM students WHERE id=?",(session["student_db_id"],)).fetchone(); con.close()
    if not r or not r["admit_card_file_data"]: abort(404)
    return send_file(io.BytesIO(bytes(r["admit_card_file_data"])),mimetype=r["admit_card_mime_type"] or "application/octet-stream",as_attachment=True,download_name=r["admit_card_original_name"] or "admit-card")


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
    con.close()
    if not enabled:
        body = '''<section class="section"><div class="ai-box"><div class="badge"> ASK VYBE</div><h1 style="margin:15px 0 8px">Assistant is offline.</h1><p class="muted">The VYBE Assistant has been temporarily disabled by the administrator.</p></div></section>'''
        return layout("Ask VYBE", body)
    source_html="".join(f'<a class="feed-item" href="{esc(x["url"])}"><span class="pill">{esc(x["type"])}</span><strong style="display:block;margin-top:8px">{esc(x["title"])}</strong><span class="small">{esc(x["text"])}</span></a>' for x in sources)
    body=f'''<section class="section"><div class="ai-box"><div class="badge"> ASK VYBE · FREE</div><h1 style="margin:15px 0 8px">Your campus assistant.</h1><p class="muted">No AI API key required. Ask about announcements, updates, events, notes, files, resources, community questions, or the current date and time.</p><form class="form" method="post" style="margin-top:20px"><textarea name="question" maxlength="1000" placeholder="e.g. What are the latest announcements? Where are the Data Structures notes? What time is it?">{esc(question)}</textarea><button class="btn accent">Ask VYBE →</button></form></div></section>{f'<section class="section"><div class="card"><div class="badge">ANSWER</div><div class="ai-answer" style="margin-top:12px;white-space:pre-wrap">{esc(answer)}</div></div></section>' if answer else ''}{f'<section class="section"><h2>Related VYBE information.</h2><div class="feed-list">{source_html}</div></section>' if sources else ''}'''
    return layout("Ask VYBE",body)


@app.route("/dashboard")
@student_required
def dashboard():
    con = db()
    s = con.execute("SELECT name,reputation_points,helpful_answers,accepted_solutions FROM students WHERE id=?", (session["student_db_id"],)).fetchone()
    counts = {
        "resources": con.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"],
        "issues": con.execute("SELECT COUNT(*) AS c FROM issues WHERE student_id=?", (session["student_db_id"],)).fetchone()["c"],
        "solutions": con.execute("SELECT COUNT(*) AS c FROM solutions").fetchone()["c"],
    }
    drive = setting(con, "google_drive_url", DRIVE_URL)
    wa = setting(con, "whatsapp_link", "")
    anns = _active_announcements(con, 4)
    evs = _upcoming_events(con, 4)
    con.close()
    ann_html="".join(f'<a class="feed-item" href="/announcements"><span class="pill">{esc(a["priority"])}</span><strong style="display:block;margin-top:7px">{esc(a["title"])}</strong><span class="small">{esc(a["message"][:180])}</span></a>' for a in anns)
    event_html="".join(f'<a class="feed-item" href="/events"><span class="pill"> {esc(e["event_date"])}</span><strong style="display:block;margin-top:7px">{esc(e["title"])}</strong><span class="small"> {esc(e["event_time"] or "TBA")} ·  {esc(e["location"] or "TBA")}</span></a>' for e in evs)
    body = f'''<section class="section"><div class="badge">STUDENT SPACE</div><h1>Hey, {esc(s["name"])}.</h1><p class="muted">Your campus, your community, your space  |  now in one cleaner home.</p><div class="stat-row" style="margin-top:18px"><span class="stat-chip"> {s["reputation_points"]} VYBE points</span><span class="stat-chip"> {s["helpful_answers"]} helpful answers</span></div></section>
    <section class="grid"><a class="card" href="/academics"><div class="kpi">{counts["resources"]}</div><h3>Academics</h3><p class="muted">Notes, PYQs, syllabus & study material</p></a><a class="card" href="/timetable"><div class="kpi"></div><h3>Timetable</h3><p class="muted">Open the latest class timetable.</p></a><a class="card" href="/issues"><div class="kpi">{counts["issues"]}</div><h3>Campus</h3><p class="muted">Report problems and open Saved Reports.</p></a></section>
    <section class="section grid2"><div class="card"><div class="badge"> CAMPUS</div><h2>Latest announcements</h2><div class="feed-list" style="margin-top:12px">{ann_html or '<div class="empty">No active announcements.</div>'}</div><div class="actions"><a class="btn dark" href="/announcements">View all →</a></div></div>
    <div class="card"><div class="badge"> WHAT'S ON</div><h2>Upcoming events</h2><div class="feed-list" style="margin-top:12px">{event_html or '<div class="empty">No upcoming events.</div>'}</div><div class="actions"><a class="btn dark" href="/events">View events →</a></div></div></section>
    <section class="section grid2"><a class="community-launch" href="/chat"><div class="community-icon"></div><div class="community-copy"><h3>Community Chat</h3><p>Talk with your campus community · names only, Student IDs stay private.</p></div><div class="community-arrow">→</div></a><a class="community-launch" href="/assistant"><div class="community-icon"></div><div class="community-copy"><h3>Ask VYBE</h3><p>Ask questions about your campus information and get a quick answer.</p></div><div class="community-arrow">→</div></a></section>
    <section class="section grid2"><div class="card"><h2> Google Drive</h2><p class="muted">Open the live shared academic folder.</p><a class="btn accent" target="_blank" rel="noopener noreferrer" href="{esc(drive)}">Open Google Drive →</a></div><div class="card"><h2> WhatsApp Community</h2><p class="muted">Academic material shared through the configured community.</p>{f'<a class="btn dark" target="_blank" rel="noopener noreferrer" href="{esc(wa)}">Open WhatsApp →</a>' if valid_url(wa) else '<span class="pill">Not configured yet</span>'}</div></section>'''
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
    body = f'''<section class="section"><div class="badge">ACADEMICS</div><h1>Study smarter.</h1><p class="muted">Search by resource, course, semester or subject.</p><div class="card"><form class="form" method="get"><input name="q" value="{esc(q)}" placeholder="Search notes, PYQs, assignments..."><div class="two"><select name="course"><option value="">All courses</option>{''.join(f'<option {"selected" if x==course else ""}>{esc(x)}</option>' for x in courses)}</select><select name="semester"><option value="">All semesters</option>{''.join(f'<option {"selected" if x==semester else ""}>{esc(x)}</option>' for x in semesters)}</select></div><select name="subject"><option value="">All subjects</option>{''.join(f'<option {"selected" if x==subject else ""}>{esc(x)}</option>' for x in subjects)}</select><button class="btn accent">Search</button></form></div></section><section class="section grid">{cards or '<div class="empty">No matching resources.</div>'}</section><section class="section"><div class="card"><h2> Google Drive</h2><p class="muted">This is the live academic folder configured for VYBE.</p><a class="btn accent" target="_blank" rel="noopener noreferrer" href="{esc(drive)}">Open shared academic folder →</a></div></section>'''
    return layout("Academics", body)


@app.route("/resource/<int:rid>")
@student_required
def resource(rid):
    con = db(); r = con.execute("SELECT file_name, original_name, mime_type, file_data FROM resources WHERE id=?", (rid,)).fetchone(); con.close()
    if not r or (not r["file_name"] and not r["file_data"]): abort(404)
    # Prefer the database copy so a student can open material even when the
    # web process is on a different instance or the local upload directory
    # was reset during a deployment.
    data = r["file_data"]
    if data is not None:
        download_name = r["original_name"] or r["file_name"] or "resource-file"
        return send_file(io.BytesIO(bytes(data)), mimetype=r["mime_type"] or mimetypes.guess_type(download_name)[0] or "application/octet-stream", as_attachment=False, download_name=download_name)
    path = UPLOAD_DIR / r["file_name"]
    if not path.is_file(): abort(404)
    return send_file(path, mimetype=r["mime_type"] or mimetypes.guess_type(path.name)[0] or "application/octet-stream", as_attachment=False, download_name=r["original_name"] or path.name)


@app.route("/issues", methods=["GET","POST"])
@student_required
def issues():
    con=db()
    if request.method=="POST":
        title=request.form.get("title","").strip()[:120]; desc=request.form.get("description","").strip()[:2000]; cat=request.form.get("category","").strip()[:80]
        if not title or not desc: con.close(); flash("Please enter a title and description."); return redirect(url_for("issues"))
        con.execute("INSERT INTO issues(student_id,title,category,description,status,created_at) VALUES(?,?,?,?,?,?)",(session["student_db_id"],title,cat,desc,"open",now())); con.commit(); con.close(); flash("Your campus problem is now visible to students."); return redirect(url_for("community"))
    rows=con.execute("SELECT * FROM issues WHERE student_id=? ORDER BY id DESC",(session["student_db_id"],)).fetchall(); saved=con.execute("SELECT * FROM saved_reports WHERE student_id=? ORDER BY id DESC",(session["student_db_id"],)).fetchall(); con.close()
    cards="".join(f'<div class="card"><span class="pill">{esc(x["status"])}</span><h3>{esc(x["title"])}</h3><p class="small">{esc(x["category"])} · {esc(x["created_at"])}</p><p class="muted">{esc(x["description"])}</p><a class="btn dark" href="/community#problem-{x["id"]}">Open community chat →</a></div>' for x in rows)
    saved_cards="".join(f'<div class="feed-item"><strong>{esc(x["issue_title"])}</strong><p class="muted">{esc(x["issue_description"])}</p><p class="small">Accepted solution: {esc(x["solution_text"])} · from {esc(x["solver_name"])} · {esc(x["saved_at"])}</p></div>' for x in saved)
    body=f'''<section class="section"><div class="badge">CAMPUS</div><h1>Fix what matters.</h1><p class="muted">Report Wi-Fi, systems, classrooms, electricity, facilities or anything else.</p><div class="two"><div class="card"><h2>Report a problem</h2><form class="form" method="post"><select name="category">{"".join(f'<option>{esc(c)}</option>' for c in CATEGORIES)}</select><input name="title" maxlength="120" placeholder="Short problem title" required><textarea name="description" maxlength="2000" placeholder="What is happening?" required></textarea><button class="btn accent">Submit report</button></form></div><div><h2>My reports</h2>{cards or '<div class="empty">No active reports yet.</div>'}</div></div></section><section class="section" id="saved-reports"><div class="card"><h2> Saved Reports</h2><p class="muted">When you accept a solution, VYBE saves the report and accepted solution here.</p><div class="feed-list">{saved_cards or '<div class="empty">No saved reports yet.</div>'}</div></div></section>'''
    return layout("Campus",body)



def _render_solution_card(row,my_student_id):
    button="" if row["student_id"]==my_student_id else f"<form method=\"post\" action=\"/community/solution/{row['id']}/helpful\" style=\"margin-top:9px\"><button class=\"btn dark\" type=\"submit\"> Helpful answer</button></form>"
    return f'<div class="bubble"><strong>{esc(row["author_name"])}</strong><div>{esc(row["text"])}</div><div class="small">{esc(row["created_at"])}</div>{button}</div>'

@app.route("/community", methods=["GET", "POST"])
@student_required
def community():
    con = db()
    if request.method == "POST":
        try:
            iid = int(request.form.get("issue_id", "0"))
        except (TypeError, ValueError):
            iid = 0
        text = request.form.get("text", "").strip()[:1500]
        if iid <= 0 or not text:
            con.close(); flash("Please enter a valid solution."); return redirect(url_for("community"))
        try:
            # Any approved student may solve any other student's problem.
            issue = con.execute("SELECT id, student_id FROM issues WHERE id=?", (iid,)).fetchone()
            if not issue:
                con.rollback(); con.close(); flash("That problem is no longer available."); return redirect(url_for("community"))
            if issue["student_id"] == session["student_db_id"]:
                con.rollback(); con.close(); flash("You cannot post a solution to your own problem."); return redirect(url_for("community"))
            con.execute("INSERT INTO solutions(issue_id,student_id,text,created_at) VALUES(?,?,?,?)", (iid, session["student_db_id"], text, now()))
            con.commit()
            con.close()
            flash("Solution posted successfully.")
            return redirect(url_for("community") + f"#problem-{iid}")
        except Exception:
            con.rollback()
            con.close()
            app.logger.exception("Community solution post failed")
            flash("We couldn't post that solution right now. Please try again.")
            return redirect(url_for("community"))
    issues_rows = con.execute("SELECT i.*, s.name AS reporter_name FROM issues i JOIN students s ON s.id=i.student_id ORDER BY i.id DESC LIMIT 80").fetchall()
    solutions = con.execute("SELECT so.*, s.name AS author_name FROM solutions so JOIN students s ON s.id=so.student_id ORDER BY so.id ASC").fetchall()
    by_issue = {}
    for s in solutions: by_issue.setdefault(s["issue_id"], []).append(s)
    blocks = ""
    for i in issues_rows:
        sols = by_issue.get(i["id"], [])
        sol_html = "".join(_render_solution_card(s, session["student_db_id"]) for s in sols)
        other_solution = any(s["student_id"] != session["student_db_id"] for s in sols)
        accept = ""
        if i["student_id"] == session["student_db_id"] and other_solution:
            accept = f'<form method="post" action="/community/problem/{i["id"]}/accept" onsubmit="return confirm(\'Accept a solution? This deletes the problem and its entire chat.\')"><button class="btn good"> Accept solution &amp; delete chat</button></form>'
        blocks += f'''<div class="card" id="problem-{i["id"]}"><div class="resource-meta"><span class="pill">{esc(i["category"])}</span><span class="pill">{esc(i["status"])}</span></div><h2>{esc(i["title"])}</h2><p class="muted">{esc(i["description"])}</p><p class="small">Reported by {esc(i["reporter_name"])} · {esc(i["created_at"])}</p><div class="chat">{sol_html or '<div class="empty">No solutions yet. Be the first to help.</div>'}</div><form class="form" method="post" style="margin-top:14px"><input type="hidden" name="issue_id" value="{i["id"]}"><textarea name="text" maxlength="1500" placeholder="Suggest a practical solution..." required></textarea><button class="btn dark">Post solution</button></form>{accept}</div>'''
    con.close()
    body = f'''<section class="section"><div class="badge">COMMUNITY</div><h1>Students solve together.</h1><p class="muted">Solutions are visible immediately. There is no admin moderation. Only the original reporter can accept a solution, and the accept button appears after another student has contributed.</p></section><section class="section" style="display:grid;gap:16px">{blocks or '<div class="empty">No campus problems have been reported yet.</div>'}</section>'''
    return layout("Community", body)


@app.route("/community/solution/<int:solution_id>/helpful", methods=["POST"])
@student_required
def mark_solution_helpful(solution_id):
    con=db()
    try:
        sol=con.execute("SELECT student_id FROM solutions WHERE id=?",(solution_id,)).fetchone()
        if not sol: con.close(); flash("That solution is no longer available."); return redirect(url_for("community"))
        if sol["student_id"]==session["student_db_id"]: con.close(); flash("You cannot mark your own answer helpful."); return redirect(url_for("community"))
        con.execute("INSERT INTO helpful_votes(solution_id,voter_id,created_at) VALUES(?,?,?)",(solution_id,session["student_db_id"],now()))
        con.execute("UPDATE students SET reputation_points=COALESCE(reputation_points,0)+5,helpful_answers=COALESCE(helpful_answers,0)+1 WHERE id=?",(sol["student_id"],))
        con.commit(); flash("Marked as helpful. +5 VYBE points to the helper.")
    except Exception:
        con.rollback(); flash("You already marked this answer helpful, or it is no longer available.")
    finally: con.close()
    return redirect(url_for("community"))


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
            con.close(); flash("A solution from another student is required first."); return redirect(url_for("community") + f"#problem-{iid}")
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
        return redirect(url_for("community"))
    except Exception:
        try: con.rollback()
        except Exception: pass
        try: con.close()
        except Exception: pass
        app.logger.exception("Accept solution failed for issue %s", iid)
        flash("We couldn't accept that solution right now. Please try again.")
        return redirect(url_for("community") + f"#problem-{iid}")


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
        con.commit()
        con.close()
        if not ok:
            flash("Incorrect admin password.")
            return redirect(url_for("admin_login"))

        session.clear()
        session["admin_authenticated"] = True
        session["admin_password_verified"] = True
        session["passkey_verified"] = False

        if passkey_count == 0:
            flash("Password accepted. Register your first admin passkey before using the dashboard.")
            return redirect(url_for("admin_password"))
        return redirect(url_for("admin_verify"))

    body = f"""<div class=\"auth\"><div class=\"card authbox\"><div class=\"badge\">PRIVATE CONTROL CENTER</div>
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
        <input type=\"password\" name=\"password\" required autocomplete=\"current-password\" placeholder=\"Admin password\">
        <button class=\"btn dark\" type=\"submit\">Use Password →</button>
      </form>
    </div></div></div><script>{WEBAUTHN_JS}</script>"""
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
        session["admin_authenticated"] = True
        session["passkey_verified"] = True
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


@app.route("/admin/login-history")
@admin_required
def admin_login_history():
    con = db()
    rows = con.execute("SELECT logged_at_ist,success,event,ip_address,user_agent FROM admin_login_logs ORDER BY id DESC LIMIT 100").fetchall()
    con.close()
    items = ""
    for r in rows:
        state = '<span class="pill status-good">Success</span>' if r["success"] else '<span class="pill status-bad">Failed</span>'
        items += f'''<tr><td>{esc(r["logged_at_ist"])}</td><td>{state}</td><td>{esc(r["event"])}</td><td>{esc(r["ip_address"] or " | ")}</td><td class="small">{esc(r["user_agent"] or " | ")}</td></tr>'''
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
        "community_messages": con.execute("SELECT COUNT(*) AS c FROM community_messages").fetchone()["c"],
        "announcements": con.execute("SELECT COUNT(*) AS c FROM announcements").fetchone()["c"],
        "events": con.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],
    }
    assistant_enabled = setting(con, "vybe_assistant_enabled", "1") == "1"
    online = setting(con, "vybe_online", "1") == "1"
    con.close()
    body = f'''<section class="section"><div class="badge">PRIVATE VYBE CONTROL CENTER</div><h1>Admin dashboard.</h1>
    <div class="grid">
      <a class="card" href="/admin/students"><div class="kpi">{stats["students"]}</div><h3>Students</h3><p class="muted">Manage all student accounts.</p></a>
      <a class="card" href="/admin/students#pending"><div class="kpi">{stats["pending"]}</div><h3>Pending</h3><p class="muted">Entry requests waiting for approval.</p></a>
      <a class="card" href="/admin/problems"><div class="kpi">{stats["issues"]}</div><h3>Problems</h3><p class="muted">View reports and update status.</p></a>
      <a class="card" href="/admin/resources"><div class="kpi">{stats["resources"]}</div><h3>Resources</h3><p class="muted">Add and remove academic material.</p></a>
      <a class="card" href="/admin/announcements"><div class="kpi">{stats["announcements"]}</div><h3>Announcements</h3><p class="muted">Publish campus-wide updates.</p></a>
      <a class="card" href="/admin/events"><div class="kpi">{stats["events"]}</div><h3>Events</h3><p class="muted">Create and manage campus events.</p></a>
      <a class="card" href="/admin/chats"><div class="kpi">{stats["chats"]}</div><h3>Problem chats</h3><p class="muted">Saved problem and solution history.</p></a>
      <a class="card" href="/admin/community-chat"><div class="kpi">{stats["community_messages"]}</div><h3>Community Chat</h3><p class="muted">Moderate the live student community chat.</p></a><a class="card" href="/admin/analytics"><div class="kpi">↗</div><h3>Analytics</h3><p class="muted">See campus usage and community activity.</p></a>
    </div>
    <section class="section grid2">
      <div class="card"><h2> VYBE Assistant</h2><p class="small">Status: <strong>{" ON" if assistant_enabled else " OFF"}</strong></p><p class="muted">Free built-in assistant. No OpenAI API key or paid AI service is required. It answers from VYBE's live campus data plus the current IST date/time.</p><form method="post" action="/admin/assistant"><button class="btn {"danger" if assistant_enabled else "good"}">{" Turn Assistant OFF" if assistant_enabled else " Turn Assistant ON"}</button></form></div>
      <div class="card"><h2> What it can answer</h2><p class="muted">Announcements, new updates, events, notes/files, resources, community questions and solutions, plus current date and time.</p><span class="pill">No API key needed</span></div>
    </section>
    <section class="section grid2">
      <div class="card"><h2> VYBE Public Status</h2><p class="{"online" if online else "offline"}"><strong>{" ONLINE" if online else " OFFLINE"}</strong></p>
      <p class="muted">When offline, student/public routes are blocked while admin routes remain accessible.</p>
      <form method="post" action="/admin/status">{('<button class="btn danger"> Take VYBE Offline</button>' if online else '<button class="btn good"> Bring VYBE Online</button>')}</form></div>
      <div class="card"><h2> Security</h2><p class="muted">Admin login requires password + passkey. Manage credentials and password-change approvals here.</p><div class="actions"><a class="btn dark" href="/admin/password">Security center →</a><a class="btn dark" href="/admin/password-requests">Password requests →</a></div></div>
    </section></section>'''
    return layout("Admin", body, admin=True)


@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    con=db()
    stats={"students":con.execute("SELECT COUNT(*) AS c FROM students WHERE status='approved'").fetchone()["c"],"pending":con.execute("SELECT COUNT(*) AS c FROM students WHERE status='pending'").fetchone()["c"],"resources":con.execute("SELECT COUNT(*) AS c FROM resources").fetchone()["c"],"announcements":con.execute("SELECT COUNT(*) AS c FROM announcements").fetchone()["c"],"events":con.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],"problems":con.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"],"solutions":con.execute("SELECT COUNT(*) AS c FROM solutions").fetchone()["c"],"saved":con.execute("SELECT COUNT(*) AS c FROM saved_reports").fetchone()["c"],"helpful":con.execute("SELECT COUNT(*) AS c FROM helpful_votes").fetchone()["c"],"website_pages":con.execute("SELECT COUNT(*) AS c FROM campus_pages").fetchone()["c"]}
    top=con.execute("SELECT name,reputation_points,helpful_answers,accepted_solutions FROM students WHERE status='approved' ORDER BY reputation_points DESC,helpful_answers DESC LIMIT 10").fetchall(); con.close()
    rows="".join(f'<tr><td>{esc(x["name"])}</td><td>{x["reputation_points"]}</td><td>{x["helpful_answers"]}</td><td>{x["accepted_solutions"]}</td></tr>' for x in top)
    body=f'''<section class="section"><div class="badge">ADMIN ANALYTICS</div><h1>Campus analytics.</h1><p class="muted">Operational counts from VYBE's own database. No external analytics service is required.</p><section class="grid"><div class="card"><div class="kpi">{stats["students"]}</div><h3>Approved students</h3></div><div class="card"><div class="kpi">{stats["resources"]}</div><h3>Resources</h3></div><div class="card"><div class="kpi">{stats["problems"]}</div><h3>Campus problems</h3></div><div class="card"><div class="kpi">{stats["solutions"]}</div><h3>Open solutions</h3></div><div class="card"><div class="kpi">{stats["helpful"]}</div><h3>Helpful votes</h3></div><div class="card"><div class="kpi">{stats["saved"]}</div><h3>Saved reports</h3></div><div class="card"><div class="kpi">{stats["website_pages"]}</div><h3>Website pages synced</h3></div><div class="card"><div class="kpi">{stats["pending"]}</div><h3>Pending students</h3></div></section><section class="section"><div class="card tablewrap"><h2>Top VYBE contributors</h2><table><tr><th>Student</th><th>Points</th><th>Helpful answers</th><th>Accepted solutions</th></tr>{rows or '<tr><td colspan="4">No contributor data yet.</td></tr>'}</table></div></section></section>'''
    return layout("Analytics",body,admin=True)


@app.route("/admin/assistant", methods=["POST"])
@admin_required
def admin_assistant():
    con = db()
    current = setting(con, "vybe_assistant_enabled", "1") == "1"
    set_setting(con, "vybe_assistant_enabled", "0" if current else "1")
    con.commit()
    con.close()
    flash("VYBE Assistant disabled." if current else "VYBE Assistant enabled.")
    return redirect(url_for("admin_panel"))


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
        access_con = db(); access_row = access_con.execute("SELECT value FROM settings WHERE key=?", (f"content_manager_{sid_num}",)).fetchone(); access_con.close()
        publisher = bool(access_row and access_row["value"] == "1")
        if s["status"] == "approved":
            access_action = (f'<form method="post" action="/admin/content-access/{sid_num}/revoke"><button class="btn" onclick="return confirm(\'Remove publisher access from this student?\')">Revoke publisher</button></form>' if publisher else f'<form method="post" action="/admin/content-access/{sid_num}/grant"><button class="btn accent">Give publisher access</button></form>')
        else:
            access_action = '<span class="small muted">Approve first</span>'
        access_label = '<span class="pill">Publisher</span>' if publisher else '<span class="small muted">Student</span>'
        rows += f'<tr><td><span class="student-presence">{presence}{student_name}</span></td><td>{student_sid}</td><td><span class="pill">{student_status}</span></td><td>{created_at}</td><td><div class="actions">{action}{access_action}<a class="btn danger" href="/admin/student/{sid_num}/delete" onclick="return confirm(&quot;Delete this student and all dependent records?&quot;)">Delete</a></div><div style="margin-top:6px">{access_label}</div></td></tr>'
    body = f'''<section class="section" id="pending"><h1>Students.</h1><p class="muted">Approve or block students, or give a trusted student limited Publisher access. Publisher access allows creating announcements and upcoming events only; deleting them remains admin-only.</p><div class="actions"><form method="post" action="/admin/students/delete-all" onsubmit="return confirm('Delete ALL students and their dependent records?')"><button class="btn danger">Delete all students</button></form></div><div class="card tablewrap"><table><thead><tr><th>Name / Presence</th><th>Student ID</th><th>Status</th><th>Registered</th><th>Actions</th></tr></thead><tbody>{rows or '<tr><td colspan="5">No students.</td></tr>'}</tbody></table></div></section>'''
    return layout("Students", body, admin=True)

@app.route("/admin/student/<int:sid>/<action>")
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
    if request.method == "POST":
        kind = request.form.get("kind", "").strip()
        con = db()
        try:
            if kind == "announcement":
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
            elif kind == "timetable":
                title = request.form.get("timetable_title", "").strip()[:160]
                f = request.files.get("timetable_file")
                if not title or not f or not f.filename:
                    flash("Timetable title and file are required.")
                else:
                    suffix=Path(f.filename).suffix.lower()
                    allowed={".pdf",".doc",".docx",".png",".jpg",".jpeg",".webp"}
                    if suffix not in allowed:
                        flash("Timetable must be a PDF, Word document or image file.")
                    else:
                        filename=secrets.token_hex(16)+suffix
                        file_data=f.read()
                        f.stream.seek(0); f.save(UPLOAD_DIR/filename)
                        con.execute("INSERT INTO timetables(title,file_name,original_name,created_at,file_data) VALUES(?,?,?,?,?)",(title,filename,Path(f.filename).name[:240],now(),file_data))
                        con.commit(); flash("Timetable posted to VYBE.")
            elif kind == "event":
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
            else:
                flash("Invalid publisher action.")
        except Exception:
            con.rollback(); app.logger.exception("Publisher action failed")
            flash("Could not publish right now. Please try again.")
        finally:
            con.close()
        return redirect(url_for("publisher"))
    body = """<section class="section"><div class="badge">LIMITED PUBLISHER ACCESS</div><h1>Publish.</h1><p class="muted">You can add new announcements, upcoming events and timetable versions. You cannot delete or edit existing posts.</p></section><section class="section grid2"><div class="card"><h2>New announcement</h2><form class="form" method="post"><input type="hidden" name="kind" value="announcement"><input name="title" maxlength="160" placeholder="Announcement title" required><select name="priority"><option>Normal</option><option>Important</option><option>High</option></select><textarea name="message" maxlength="3000" placeholder="Write the campus update..." required></textarea><input type="datetime-local" name="expires_at"><button class="btn accent">Publish announcement →</button></form></div><div class="card"><h2>New upcoming event</h2><form class="form" method="post"><input type="hidden" name="kind" value="event"><input name="event_title" maxlength="160" placeholder="Event name" required><div class="two"><input type="date" name="event_date" required><input type="time" name="event_time"></div><input name="location" maxlength="160" placeholder="Location"><textarea name="description" maxlength="1500" placeholder="Event details"></textarea><button class="btn accent">Create event →</button></form></div><div class="card"><h2>New timetable</h2><form class="form" method="post" enctype="multipart/form-data"><input type="hidden" name="kind" value="timetable"><input name="timetable_title" maxlength="160" placeholder="e.g. Semester 5 Timetable" required><input type="file" name="timetable_file" accept=".pdf,.doc,.docx,.png,.jpg,.jpeg,.webp" required><div class="small">Upload a PDF, Word file or image. Posting a new timetable creates a new version; deletion stays admin-only.</div><button class="btn accent">Post timetable →</button></form></div></section><section class="section"><div class="card"><h2>Permissions</h2><p class="muted">Your publisher permission is limited to creating new announcements, upcoming events and timetable versions. Delete, edit, student management, settings and other admin controls remain unavailable.</p></div></section>"""
    return layout("Publisher", body)


@app.route("/admin/announcements", methods=["GET","POST"])
@admin_required
def admin_announcements():
    con=db()
    if request.method=="POST":
        title=request.form.get("title","").strip()[:160]
        message=request.form.get("message","").strip()[:3000]
        priority=request.form.get("priority","Normal").strip()
        expires=request.form.get("expires_at","").strip()[:40]
        if priority not in ("Normal","Important","High"): priority="Normal"
        if not title or not message:
            con.close(); flash("Title and announcement message are required."); return redirect(url_for("admin_announcements"))
        con.execute("INSERT INTO announcements(title,message,priority,created_at,expires_at) VALUES(?,?,?,?,?)", (title,message,priority,now(),expires or None))
        con.commit(); con.close()
        flash("Announcement published to VYBE.")
        return redirect(url_for("admin_announcements"))
    rows=con.execute("SELECT * FROM announcements ORDER BY id DESC").fetchall()
    con.close()
    html_rows="".join(f'''<tr><td><span class="pill">{esc(r["priority"])}</span></td><td><strong>{esc(r["title"])}</strong><br><span class="small">{esc(r["message"][:220])}</span></td><td>{esc(r["created_at"])}</td><td>{esc(r["expires_at"] or "No expiry")}</td><td><form method="post" action="/admin/announcement/{r["id"]}/delete" onsubmit="return confirm('Delete this announcement?')"><button class="btn danger">Delete</button></form></td></tr>''' for r in rows)
    body=f'''<section class="section"><div class="badge">CAMPUS ANNOUNCEMENTS</div><h1>Announcements.</h1><div class="grid2"><div class="card"><h2>Publish update</h2><form class="form" method="post"><input name="title" maxlength="160" placeholder="Announcement title" required><select name="priority"><option>Normal</option><option>Important</option><option>High</option></select><textarea name="message" maxlength="3000" placeholder="Write the campus update..." required></textarea><input type="datetime-local" name="expires_at"><div class="small">Expiry is optional. Students see active announcements on their dashboard.</div><button class="btn accent">Publish announcement →</button></form></div><div class="card"><h2>How it works</h2><p class="muted">Published announcements appear on student dashboards, the Announcements page, search and Ask VYBE context.</p></div></div><section class="section"><div class="card tablewrap"><table><tr><th>Priority</th><th>Announcement</th><th>Created</th><th>Expires</th><th>Action</th></tr>{html_rows or '<tr><td colspan="5">No announcements yet.</td></tr>'}</table></div></section></section>'''
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
        location=request.form.get("location","").strip()[:160]
        description=request.form.get("description","").strip()[:1500]
        if not title or not event_date:
            con.close(); flash("Event title and date are required."); return redirect(url_for("admin_events"))
        con.execute("INSERT INTO events(title,event_date,event_time,location,description,created_at) VALUES(?,?,?,?,?,?)", (title,event_date,event_time,location,description,now()))
        con.commit(); con.close()
        flash("Event added to VYBE.")
        return redirect(url_for("admin_events"))
    rows=con.execute("SELECT * FROM events ORDER BY event_date ASC,event_time ASC,id DESC").fetchall()
    con.close()
    html_rows="".join(f'''<tr><td>{esc(r["event_date"])}</td><td><strong>{esc(r["title"])}</strong><br><span class="small"> {esc(r["event_time"] or "TBA")} ·  {esc(r["location"] or "TBA")}</span></td><td>{esc(r["description"][:180])}</td><td><form method="post" action="/admin/event/{r["id"]}/delete" onsubmit="return confirm('Delete this event?')"><button class="btn danger">Delete</button></form></td></tr>''' for r in rows)
    body=f'''<section class="section"><div class="badge">CAMPUS EVENTS</div><h1>Events.</h1><div class="grid2"><div class="card"><h2>Create event</h2><form class="form" method="post"><input name="title" maxlength="160" placeholder="Event name" required><div class="two"><input type="date" name="event_date" required><input type="time" name="event_time"></div><input name="location" maxlength="160" placeholder="Location"><textarea name="description" maxlength="1500" placeholder="Event details"></textarea><button class="btn accent">Create event →</button></form></div><div class="card"><h2>Student experience</h2><p class="muted">Events appear on dashboards, the Events page, search and Ask VYBE context.</p></div></div><section class="section"><div class="card tablewrap"><table><tr><th>Date</th><th>Event</th><th>Details</th><th>Action</th></tr>{html_rows or '<tr><td colspan="4">No events yet.</td></tr>'}</table></div></section></section>'''
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
        con.close(); flash("Student not found."); return redirect(url_for("admin_students"))
    if action == "grant":
        if student["status"] != "approved":
            con.close(); flash("Only approved students can receive publisher access."); return redirect(url_for("admin_students"))
        set_setting(con, f"content_manager_{sid}", "1")
        flash(f"Publisher access granted to {student['name']}.")
    else:
        set_setting(con, f"content_manager_{sid}", "0")
        flash(f"Publisher access revoked from {student['name']}.")
    con.commit(); con.close()
    return redirect(url_for("admin_students"))


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
        allowed={".pdf",".doc",".docx",".png",".jpg",".jpeg",".webp"}
        if suffix not in allowed:
            con.close(); flash("Timetable must be a PDF, Word document or image file."); return redirect(url_for("admin_timetable"))
        filename=secrets.token_hex(16)+suffix
        try:
            file_data=f.read()
            f.stream.seek(0); f.save(UPLOAD_DIR/filename)
            con.execute("INSERT INTO timetables(title,file_name,original_name,created_at,file_data) VALUES(?,?,?,?,?)",(title,filename,Path(f.filename).name[:240],now(),file_data))
            con.commit(); flash("Timetable posted to VYBE.")
        except Exception:
            con.rollback(); flash("Could not save the timetable. Please try again.")
        finally: con.close()
        return redirect(url_for("admin_timetable"))
    rows=con.execute("SELECT * FROM timetables ORDER BY id DESC").fetchall(); con.close()
    html_rows="".join(f'''<tr><td><strong>{esc(r["title"])}</strong><br><span class="small">{esc(r["original_name"])}</span></td><td>{esc(r["created_at"])}</td><td><a class="btn dark" href="/timetable-file/{r["id"]}" target="_blank" rel="noopener">View</a> <form style="display:inline" method="post" action="/admin/timetable/{r["id"]}/delete" onsubmit="return confirm('Delete this timetable?')"><button class="btn danger">Delete</button></form></td></tr>''' for r in rows)
    body=f'''<section class="section"><div class="badge">CAMPUS TIMETABLE</div><h1>Timetable.</h1><div class="grid2"><div class="card"><h2>Post timetable</h2><form class="form" method="post" enctype="multipart/form-data"><input name="title" maxlength="160" placeholder="Timetable title" required><input type="file" name="file" accept=".pdf,.doc,.docx,.png,.jpg,.jpeg,.webp" required><div class="small">PDF, Word (.doc/.docx) or image (.png/.jpg/.jpeg/.webp).</div><button class="btn accent">Post timetable →</button></form></div><div class="card"><h2>Student access</h2><p class="muted">Students can open the latest timetable from the Timetable button. Approved Publishers can also post new timetable versions, but only admins can delete them.</p></div></div></section><section class="section"><div class="card tablewrap"><table><tr><th>Timetable</th><th>Posted</th><th>Actions</th></tr>{html_rows or '<tr><td colspan="3">No timetables posted yet.</td></tr>'}</table></div></section>'''
    return layout("Timetable",body,admin=True)


@app.route("/admin/timetable/<int:tid>/delete", methods=["POST"])
@admin_required
def delete_timetable(tid):
    con=db(); row=con.execute("SELECT file_name FROM timetables WHERE id=?",(tid,)).fetchone()
    if row:
        try: (UPLOAD_DIR/row["file_name"]).unlink(missing_ok=True)
        except Exception: pass
        con.execute("DELETE FROM timetables WHERE id=?",(tid,)); con.commit(); flash("Timetable deleted.")
    else: flash("Timetable not found.")
    con.close(); return redirect(url_for("admin_timetable"))


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
    f=request.files.get("file"); filename=None; original_name=None; mime_type=None; file_data=None
    if f and f.filename:
        suffix=Path(f.filename).suffix.lower()
        if suffix not in ALLOWED_EXT: flash("That file type is not allowed."); return redirect(url_for("admin_resources"))
        original_name=Path(f.filename).name[:240]
        filename=secrets.token_hex(16)+suffix
        mime_type=f.mimetype or mimetypes.guess_type(original_name)[0] or "application/octet-stream"
        file_data=f.read()
        # Keep a local copy for compatibility, while also storing the bytes in the DB
        # so uploads survive multi-instance deployments/restarts.
        f.stream.seek(0); f.save(UPLOAD_DIR/filename)
    con=db(); con.execute("INSERT INTO resources(title,resource_type,course,semester,subject,description,file_name,original_name,mime_type,file_data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(title,typ,course,sem,subject,desc,filename,original_name,mime_type,file_data,now())); con.commit(); con.close(); flash("Resource added."); return redirect(url_for("admin_resources"))


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


@app.route("/admin/assistant/website-sync")
@admin_required
def admin_website_sync_disabled():
    abort(404)

@app.route("/admin/settings", methods=["GET","POST"])
@admin_required
def admin_settings():
    con = db()
    if request.method == "POST":
        website = _normalize_public_url(request.form.get("college_website_url","").strip()[:500])
        wa = request.form.get("whatsapp_link", "").strip()[:500]
        drive = request.form.get("google_drive_url", "").strip()[:500]
        wa_version = request.form.get("whatsapp_api_version", "v23.0").strip()[:30] or "v23.0"
        wa_phone_id = request.form.get("whatsapp_phone_number_id", "").strip()[:100]
        wa_token = request.form.get("whatsapp_access_token", "").strip()[:1000]
        wa_admin = request.form.get("whatsapp_admin_number", "").strip()[:30]
        chat_enabled = "1" if request.form.get("community_chat_enabled") == "1" else "0"
        if request.form.get("save_website")=="1" and request.form.get("college_website_url","").strip() and not website:
            flash("Official college website must be a valid http(s) URL.")
        elif wa and not valid_url(wa):
            flash("WhatsApp community link must be a valid URL.")
        elif drive and not valid_url(drive):
            flash("Google Drive URL must be a valid URL.")
        else:
            if request.form.get("save_website")=="1": set_setting(con,"college_website_url",website)
            set_setting(con, "whatsapp_link", wa)
            set_setting(con, "google_drive_url", drive or DRIVE_URL)
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
    wa_version = setting(con, "whatsapp_api_version", "v23.0")
    wa_phone_id = setting(con, "whatsapp_phone_number_id", "")
    wa_admin = setting(con, "whatsapp_admin_number", "")
    chat_enabled = setting(con, "community_chat_enabled", "1") == "1"
    website_url = setting(con, "college_website_url", "")
    website_sync = setting(con, "college_website_last_sync", "Never")
    con.close()
    body = f'''<section class="section"><h1>Settings.</h1>
    <div class="grid2">
      <div class="card"><h2> Google Drive</h2><form class="form" method="post">
        <input name="google_drive_url" value="{esc(drive)}" required>
        <div class="small">Students can only see this link after login.</div>
        <h2 style="margin-top:18px"> WhatsApp Community</h2>
        <input name="whatsapp_link" value="{esc(wa)}" placeholder="https://chat.whatsapp.com/...">
        <button class="btn accent">Save configuration</button></form></div>
      <div class="card"><h2> Student Community Chat</h2><p class="small">Status: <strong>{" ON" if chat_enabled else " OFF"}</strong></p><p class="small">Students see each other's messages and registered names only. Student IDs remain hidden from the public chat.</p><a class="btn dark" href="/admin/community-chat">Open chat controls →</a></div><div class="card"><h2>Campus data sources</h2><p class="muted">VYBE uses university-managed uploads, announcements, events and resources. External college-site ingestion is disabled.</p></div>
      <div class="card"><h2> Public status</h2><p class="{"online" if online else "offline"}"><strong>{" ONLINE" if online else " OFFLINE"}</strong></p>
        <form method="post" action="/admin/status"><button class="btn {"danger" if online else "good"}">{" Take VYBE Offline" if online else " Bring VYBE Online"}</button></form>
        <h2 style="margin-top:22px"> Phone passkey</h2><p class="muted">Registered credentials: {pk}</p><a class="btn dark" href="/admin/password">Security center →</a>
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
          <div style="position:relative"><input id="newPassword" type="password" name="new_password" placeholder="New password (12+ chars)" minlength="12" required autocomplete="new-password"><button type="button" class="btn dark toggle-password" data-target="newPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div>
          <div style="position:relative"><input id="confirmPassword" type="password" name="confirm_password" placeholder="Confirm new password" minlength="12" required autocomplete="new-password"><button type="button" class="btn dark toggle-password" data-target="confirmPassword" style="position:absolute;right:7px;top:7px;padding:7px 10px">View</button></div>
          <button class="btn accent" {"disabled" if not session.get("passkey_verified") else ""}>Change Password</button>
        </form>
        <div class="small">{"Current passkey verified " if session.get("passkey_verified") else "Verify current passkey above before changing the password."}</div>
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
        html_rows.append(f'''<tr><td>{esc(r["requested_at"])}</td><td><strong>{esc(r["student_name"])}</strong><br><span class="small">{esc(r["student_sid"])}</span></td><td><span class="pill">{esc(r["status"])}</span></td><td>{esc(r["approved_at"] or ' | ')}<br><span class="small">{esc(r["expires_at"] or '')}</span></td><td>{action}</td></tr>''')
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
    expires = None
    con.execute("UPDATE password_reset_requests SET status='approved', approved_at=?, approval_code_hash=NULL, approval_code_token=NULL, expires_at=NULL WHERE id=?", (approved, rid))
    con.commit(); con.close()
    flash("Approved. The student can now set a new password directly on their recovery page for the next 15 minutes.")
    return redirect(url_for("admin_password_requests"))


@app.route('/faculty/login', methods=['GET','POST'])
def faculty_login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        con=db(); row=con.execute('SELECT id,password_hash,status FROM faculty WHERE email=?',(email,)).fetchone()
        if row and row['status']=='active' and check_password(password,row['password_hash']):
            con.execute('UPDATE faculty SET last_login=? WHERE id=?',(now(),row['id'])); con.commit(); con.close(); session.clear(); session['faculty_id']=row['id']; return redirect(url_for('faculty_dashboard'))
        con.close(); flash('Faculty email or password is incorrect.')
    return layout('Faculty Login','<div class="auth"><div class="card authbox"><div class="badge">FACULTY</div><h1>Faculty login.</h1><p class="muted">Sign in to manage classes, resources and campus communication.</p><form class="form" method="post"><input type="email" name="email" required placeholder="Faculty email"><input type="password" name="password" required placeholder="Password"><button class="btn accent">Sign in</button></form><p class="small">Faculty accounts are created by university administration.</p></div></div>')

@app.route('/faculty')
@faculty_required
def faculty_dashboard():
    con=db(); f=con.execute('SELECT name,email,department FROM faculty WHERE id=?',(session['faculty_id'],)).fetchone(); con.close()
    body=f'<section class="section"><div class="badge">FACULTY PORTAL</div><h1>Welcome, {esc(f["name"])}.</h1><p class="muted">{esc(f["department"] or "Faculty")} | {esc(f["email"])}</p><div class="grid"><a class="card" href="/faculty/resources"><div class="eyebrow">RESOURCES</div><h2>Class resources</h2><p class="muted">Upload material for students.</p></a><a class="card" href="/calendar"><div class="eyebrow">CALENDAR</div><h2>Campus calendar</h2><p class="muted">Review upcoming events.</p></a><a class="card" href="/faculty/logout"><div class="eyebrow">ACCOUNT</div><h2>Sign out</h2><p class="muted">End the faculty session.</p></a></div></section>'
    return layout('Faculty',body)

@app.route('/faculty/logout')
def faculty_logout():
    session.pop('faculty_id',None); return redirect(url_for('faculty_login'))

@app.route('/faculty/resources',methods=['GET','POST'])
@faculty_required
def faculty_resources():
    if request.method=='POST':
        title=request.form.get('title','').strip()[:160]; course=request.form.get('course','').strip()[:100]; semester=request.form.get('semester','').strip()[:100]; subject=request.form.get('subject','').strip()[:100]; desc=request.form.get('description','').strip()[:1200]; f=request.files.get('file')
        if not title or not course or not semester or not subject or not f or not f.filename: flash('Title, course, semester, subject and file are required.')
        else:
            data=f.read()
            if len(data)>20*1024*1024: flash('File is too large.')
            else:
                con=db(); con.execute('INSERT INTO resources(title,resource_type,course,semester,subject,description,file_name,original_name,mime_type,file_data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(title,'Faculty material',course,semester,subject,desc,secrets.token_hex(12)+Path(f.filename).suffix.lower(),f.filename[:200],f.mimetype or 'application/octet-stream',data,now())); con.commit(); con.close(); flash('Resource uploaded.')
        return redirect(url_for('faculty_resources'))
    return layout('Faculty Resources','<section class="section"><div class="badge">FACULTY RESOURCES</div><h1>Class resources.</h1><div class="card"><form class="form" method="post" enctype="multipart/form-data"><input name="title" required maxlength="160" placeholder="Resource title"><div class="two"><input name="course" required placeholder="Course"><input name="semester" required placeholder="Semester"></div><input name="subject" required placeholder="Subject"><textarea name="description" maxlength="1200" placeholder="Description"></textarea><input type="file" name="file" required><button class="btn accent">Upload resource</button></form></div></section>')

@app.route('/helpdesk',methods=['GET','POST'])
@student_required
def helpdesk():
    if request.method=='POST':
        category=request.form.get('category','General').strip()[:80]; subject=request.form.get('subject','').strip()[:160]; desc=request.form.get('description','').strip()[:3000]
        if not subject or not desc: flash('Subject and description are required.')
        else:
            con=db(); con.execute('INSERT INTO helpdesk_tickets(student_id,category,subject,description,status,assigned_to,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(session['student_db_id'],category,subject,desc,'Open','',now(),now())); con.commit(); con.close(); flash('Help desk ticket submitted.')
        return redirect(url_for('helpdesk'))
    con=db(); rows=con.execute('SELECT id,category,subject,status,created_at FROM helpdesk_tickets WHERE student_id=? ORDER BY id DESC',(session['student_db_id'],)).fetchall(); con.close()
    items=''.join(f'<div class="feed-item"><strong>#{r["id"]} {esc(r["subject"])}</strong><div class="small">{esc(r["category"])} | {esc(r["status"])} | {esc(r["created_at"])}</div></div>' for r in rows)
    return layout('Help Desk',f'<section class="section"><div class="badge">HELP DESK</div><h1>Get campus support.</h1><p class="muted">Send a request to the appropriate university team and track its status.</p><div class="grid2"><div class="card"><form class="form" method="post"><select name="category"><option>Academic</option><option>Examination</option><option>Fees</option><option>Hostel</option><option>Transport</option><option>Library</option><option>IT Support</option><option>Facilities</option><option>General</option></select><input name="subject" maxlength="160" required placeholder="What do you need help with?"><textarea name="description" maxlength="3000" required placeholder="Describe the issue clearly."></textarea><button class="btn accent">Submit ticket</button></form></div><div class="card"><h2>Your tickets</h2><div class="feed-list">{items or "<div class=empty>No tickets yet.</div>"}</div></div></div></section>')

@app.route('/admin/helpdesk')
@admin_required
def admin_helpdesk():
    con=db(); rows=con.execute('SELECT h.*,s.name FROM helpdesk_tickets h JOIN students s ON s.id=h.student_id ORDER BY h.id DESC').fetchall(); con.close()
    trs=''.join(f'<tr><td>#{r["id"]}</td><td>{esc(r["name"])}</td><td>{esc(r["category"])}</td><td>{esc(r["subject"])}</td><td>{esc(r["status"])}</td><td><form method="post" action="/admin/helpdesk/{r["id"]}/status"><select name="status"><option>Open</option><option>In progress</option><option>Resolved</option></select><button class="btn dark">Update</button></form></td></tr>' for r in rows)
    return layout('Help Desk',f'<section class="section"><div class="badge">ADMIN SUPPORT</div><h1>Help desk.</h1><div class="card tablewrap"><table><tr><th>ID</th><th>Student</th><th>Category</th><th>Subject</th><th>Status</th><th>Action</th></tr>{trs or "<tr><td colspan=6>No tickets.</td></tr>"}</table></div></section>',admin=True)

@app.route('/admin/helpdesk/<int:tid>/status',methods=['POST'])
@admin_required
def admin_helpdesk_status(tid):
    status=request.form.get('status','Open')
    if status not in ('Open','In progress','Resolved'): abort(400)
    con=db(); con.execute('UPDATE helpdesk_tickets SET status=?,updated_at=? WHERE id=?',(status,now(),tid)); con.commit(); con.close(); flash('Help desk ticket updated.'); return redirect(url_for('admin_helpdesk'))

@app.route('/clubs')
@student_required
def clubs():
    con=db(); rows=con.execute('SELECT c.id,c.name,c.description,c.category,(SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id) AS members,(SELECT COUNT(*) FROM club_members m WHERE m.club_id=c.id AND m.student_id=?) AS joined FROM clubs c ORDER BY c.name',(session['student_db_id'],)).fetchall(); con.close()
    cards=''.join(f'<div class="card"><div class="eyebrow">{esc(r["category"])}</div><h2>{esc(r["name"])}</h2><p class="muted">{esc(r["description"])}</p><p class="small">{r["members"]} members</p><form method="post" action="/clubs/{r["id"]}/join"><button class="btn {"good" if r["joined"] else "dark"}" {"disabled" if r["joined"] else ""}>{"Member" if r["joined"] else "Join club"}</button></form></div>' for r in rows)
    return layout('Clubs',f'<section class="section"><div class="badge">CAMPUS CLUBS</div><h1>Find your community.</h1><div class="grid">{cards or "<div class=empty>No clubs have been added yet.</div>"}</div></section>')

@app.route('/clubs/<int:cid>/join',methods=['POST'])
@student_required
def club_join(cid):
    con=db()
    try: con.execute('INSERT INTO club_members(club_id,student_id,joined_at) VALUES(?,?,?)',(cid,session['student_db_id'],now())); con.commit(); flash('You joined the club.')
    except Exception: con.rollback(); flash('You are already a member or the club is unavailable.')
    con.close(); return redirect(url_for('clubs'))

@app.route('/admin/clubs',methods=['GET','POST'])
@admin_required
def admin_clubs():
    con=db()
    if request.method=='POST':
        name=request.form.get('name','').strip()[:120]; category=request.form.get('category','General').strip()[:80]; desc=request.form.get('description','').strip()[:1000]
        if name:
            try: con.execute('INSERT INTO clubs(name,description,category,created_at) VALUES(?,?,?,?)',(name,desc,category,now())); con.commit(); flash('Club created.')
            except Exception: con.rollback(); flash('That club already exists.')
        else: flash('Club name is required.')
    rows=con.execute('SELECT id,name,category,description FROM clubs ORDER BY name').fetchall(); con.close()
    trs=''.join(f'<tr><td>{esc(r["name"])}</td><td>{esc(r["category"])}</td><td>{esc(r["description"])}</td></tr>' for r in rows)
    return layout('Club Management',f'<section class="section"><div class="badge">ADMIN CLUBS</div><h1>Clubs.</h1><div class="grid2"><div class="card"><form class="form" method="post"><input name="name" required placeholder="Club name"><input name="category" placeholder="Category"><textarea name="description" placeholder="Description"></textarea><button class="btn accent">Create club</button></form></div><div class="card tablewrap"><table><tr><th>Name</th><th>Category</th><th>Description</th></tr>{trs}</table></div></div></section>',admin=True)

@app.route('/calendar')
@student_required
def calendar():
    con=db(); events=con.execute('SELECT title,event_date,event_time,location,description FROM events ORDER BY event_date,event_time,id').fetchall(); alerts=con.execute('SELECT title,message,created_at FROM emergency_alerts WHERE active=1 ORDER BY id DESC').fetchall(); con.close()
    ev=''.join(f'<div class="feed-item"><div class="eyebrow">{esc(e["event_date"])} {esc(e["event_time"])}</div><strong>{esc(e["title"])}</strong><div class="small">{esc(e["location"])}</div><p class="muted">{esc(e["description"])}</p></div>' for e in events)
    al=''.join(f'<div class="card alert-card"><div class="eyebrow">URGENT CAMPUS ALERT</div><h2>{esc(a["title"])}</h2><p class="muted">{esc(a["message"])}</p></div>' for a in alerts)
    return layout('Campus Calendar',f'<section class="section">{al}<div class="badge">CAMPUS CALENDAR</div><h1>What is happening.</h1><div class="feed-list">{ev or "<div class=empty>No upcoming events.</div>"}</div></section>')

@app.route('/admin/emergency',methods=['GET','POST'])
@admin_required
def admin_emergency():
    con=db()
    if request.method=='POST':
        title=request.form.get('title','').strip()[:160]; msg=request.form.get('message','').strip()[:2000]
        if title and msg: con.execute('INSERT INTO emergency_alerts(title,message,active,created_at) VALUES(?,?,1,?)',(title,msg,now())); con.commit(); flash('Emergency alert published.')
        else: flash('Title and message are required.')
    rows=con.execute('SELECT id,title,active,created_at FROM emergency_alerts ORDER BY id DESC').fetchall(); con.close()
    trs=''.join(f'<tr><td>{esc(r["title"])}</td><td>{"Active" if r["active"] else "Inactive"}</td><td><form method="post" action="/admin/emergency/{r["id"]}/toggle"><button class="btn dark">Toggle</button></form></td></tr>' for r in rows)
    return layout('Emergency Alerts',f'<section class="section"><div class="badge">EMERGENCY COMMUNICATION</div><h1>Campus alerts.</h1><div class="grid2"><div class="card"><form class="form" method="post"><input name="title" required placeholder="Alert title"><textarea name="message" required placeholder="Emergency information"></textarea><button class="btn danger">Publish alert</button></form></div><div class="card tablewrap"><table><tr><th>Title</th><th>Status</th><th>Action</th></tr>{trs}</table></div></div></section>',admin=True)

@app.route('/admin/emergency/<int:aid>/toggle',methods=['POST'])
@admin_required
def admin_emergency_toggle(aid):
    con=db(); con.execute('UPDATE emergency_alerts SET active=CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?',(aid,)); con.commit(); con.close(); return redirect(url_for('admin_emergency'))

@app.route('/security')
@student_required
def student_security():
    token=session.get('student_session_token','')
    con=db(); rows=con.execute('SELECT session_token,created_at,last_seen,user_agent,ip_address,revoked FROM student_sessions WHERE student_id=? ORDER BY id DESC LIMIT 20',(session['student_db_id'],)).fetchall(); con.close()
    items=''.join(f'<div class="feed-item"><strong>{"Current session" if r["session_token"]==token else "Session"}</strong><div class="small">Started {esc(r["created_at"])} | Last seen {esc(r["last_seen"])} | {esc(r["user_agent"])}</div></div>' for r in rows)
    return layout('Security',f'<section class="section"><div class="badge">ACCOUNT SECURITY</div><h1>Your sessions.</h1><p class="muted">Review recent browser sessions and keep your account credentials private.</p><div class="feed-list">{items or "<div class=empty>No session history yet.</div>"}</div></section>')

@app.route('/admin/faculty',methods=['GET','POST'])
@admin_required
def admin_faculty():
    con=db()
    if request.method=='POST':
        name=request.form.get('name','').strip()[:100]; email=request.form.get('email','').strip().lower()[:160]; dept=request.form.get('department','').strip()[:120]; pw=request.form.get('password','')
        if len(name)<2 or '@' not in email or len(pw)<8: flash('Enter a name, valid email and password of at least 8 characters.')
        else:
            try: con.execute('INSERT INTO faculty(name,email,password_hash,department,status,created_at) VALUES(?,?,?,?,?,?)',(name,email,hash_password(pw),dept,'active',now())); con.commit(); flash('Faculty account created.')
            except Exception: con.rollback(); flash('That faculty email is already in use.')
    rows=con.execute('SELECT id,name,email,department,status FROM faculty ORDER BY name').fetchall(); con.close()
    trs=''.join(f'<tr><td>{esc(r["name"])}</td><td>{esc(r["email"])}</td><td>{esc(r["department"])}</td><td>{esc(r["status"])}</td></tr>' for r in rows)
    return layout('Faculty Management',f'<section class="section"><div class="badge">FACULTY MANAGEMENT</div><h1>Faculty accounts.</h1><div class="grid2"><div class="card"><form class="form" method="post"><input name="name" required placeholder="Full name"><input name="email" type="email" required placeholder="Email"><input name="department" placeholder="Department"><input name="password" type="password" minlength="8" required placeholder="Temporary password"><button class="btn accent">Create faculty account</button></form></div><div class="card tablewrap"><table><tr><th>Name</th><th>Email</th><th>Department</th><th>Status</th></tr>{trs}</table></div></div></section>',admin=True)

WEBAUTHN_JS = r'''
function b64ToBuf(v){v=v.replace(/-/g,"+").replace(/_/g,"/");while(v.length%4)v+="=";return Uint8Array.from(atob(v),c=>c.charCodeAt(0)).buffer}
function bufToB64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function decodeCreation(o){o.challenge=b64ToBuf(o.challenge);o.user.id=b64ToBuf(o.user.id);(o.excludeCredentials||[]).forEach(x=>x.id=b64ToBuf(x.id));const host=location.hostname.toLowerCase();if(!o.rp||!o.rp.id)throw new Error("WebAuthn RP ID is missing from the server response.");const rp=o.rp.id.toLowerCase();if(host!==rp&&!host.endsWith("."+rp))throw new Error("This passkey is configured for a different domain. Open VYBE on its configured HTTPS domain.");window.VYBE_RP_ID=o.rp.id;return o}
function decodeRequest(o){o.challenge=b64ToBuf(o.challenge);(o.allowCredentials||[]).forEach(x=>x.id=b64ToBuf(x.id));return o}
function serializeCredential(c){return {id:c.id,rawId:bufToB64(c.rawId),type:c.type,response:{clientDataJSON:bufToB64(c.response.clientDataJSON),attestationObject:c.response.attestationObject?bufToB64(c.response.attestationObject):undefined,authenticatorData:c.response.authenticatorData?bufToB64(c.response.authenticatorData):undefined,signature:c.response.signature?bufToB64(c.response.signature):undefined,userHandle:c.response.userHandle?bufToB64(c.response.userHandle):undefined},clientExtensionResults:c.getClientExtensionResults?c.getClientExtensionResults():{}}}
async function postJSON(url,payload){let r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},credentials:"same-origin",body:JSON.stringify(payload)});let j={};try{j=await r.json()}catch(_){throw new Error("Server returned an invalid response.")}if(!r.ok)throw new Error(j.error||"Request failed");return j}
function pkError(e){if(e&&e.name==="NotAllowedError")return "Passkey request was cancelled or timed out. Try again and choose your phone/device.";if(e&&e.name==="InvalidStateError")return "This passkey is already registered on this device.";if(e&&e.name==="SecurityError")return "WebAuthn SecurityError. Open VYBE using HTTPS on its configured domain.";return (e&&e.name?e.name+": ":"")+(e&&e.message)||"Passkey operation failed."}
const loginPk=document.getElementById("loginPasskey");
if(loginPk)loginPk.onclick=async()=>{const msg=document.getElementById("loginPkMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys. Try current Chrome, Edge, Safari or Firefox.");loginPk.disabled=true;loginPk.textContent="Waiting for device...";msg.textContent="Approve the passkey on your phone/device.";let o=await postJSON("/admin/login-passkey/options",{});o=decodeRequest(o);let c=await navigator.credentials.get({publicKey:o});if(!c)throw new Error("No passkey was selected.");await postJSON("/admin/login-passkey/verify",serializeCredential(c));msg.textContent="Passkey verified. Opening admin panel...";setTimeout(()=>location.href="/admin/panel",250)}catch(e){msg.textContent=pkError(e);loginPk.disabled=false;loginPk.textContent="Continue with Passkey →"}}
const reg=document.getElementById("registerPasskey");
if(reg)reg.onclick=async()=>{const msg=document.getElementById("pkMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys. Try current Chrome, Edge, Safari or Firefox.");reg.disabled=true;reg.textContent="Waiting for device...";msg.textContent="Choose your phone or another passkey device when your browser asks.";let o=await postJSON("/passkey/register/options",{});o=decodeCreation(o);let c=await navigator.credentials.create({publicKey:o});if(!c)throw new Error("No passkey was created.");await postJSON("/passkey/register/verify",serializeCredential(c));msg.textContent="Phone passkey registered successfully.";setTimeout(()=>location.reload(),500)}catch(e){msg.textContent=pkError(e);reg.disabled=false;reg.textContent="Register New Passkey"}}
const ver=document.getElementById("verifyPasskey");
if(ver)ver.onclick=async()=>{const msg=document.getElementById("authMsg");try{if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support passkeys.");ver.disabled=true;ver.textContent="Waiting for device...";let o=await postJSON("/passkey/auth/options",{});o=decodeRequest(o);let c=await navigator.credentials.get({publicKey:o});if(!c)throw new Error("No passkey was selected.");await postJSON("/passkey/auth/verify",serializeCredential(c));msg.textContent="Phone passkey verified.";ver.textContent="Passkey verified ";if(location.pathname==="/admin/verify")setTimeout(()=>location.href="/admin/panel",400)}catch(e){msg.textContent=pkError(e);ver.disabled=false;ver.textContent="Verify Current Passkey"}}
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

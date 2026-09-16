"""
VYBE V2 — single-file student campus portal
Run locally:
    py -m pip install -r requirements.txt
    py VYBE_PUBLIC.py

For public deployment, set environment variables:
    VYBE_SECRET_KEY
    VYBE_ADMIN_PASSWORD
    DATABASE_URL
    PORT

Important:
- This is a deployable foundation, not a substitute for a college's official
  authentication system.
- New student accounts are PENDING until the admin approves them.
- WhatsApp is integration-ready, but this app does not scrape WhatsApp
  Communities or private chat history.
"""

import os
import psycopg
from psycopg.rows import dict_row
import secrets
import hashlib
import html
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session, flash,
    render_template_string, abort, Response
)

APP_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("VYBE_SECRET_KEY", "change-this-vybe-secret")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

ADMIN_PASSWORD = os.environ.get("VYBE_ADMIN_PASSWORD", "vybe-admin-change-me")

# Google Drive folder used by the student-facing Academics area.
# Override with VYBE_DRIVE_URL in the deployment environment if needed.
VYBE_DRIVE_URL = os.environ.get(
    "VYBE_DRIVE_URL",
    "https://drive.google.com/drive/folders/1xHRB6-j6UI8F_-q_E9w6GDlmeXWxKkc_?usp=sharing"
)

ALLOWED_EXT = {
    ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".txt",
    ".png", ".jpg", ".jpeg", ".webp", ".zip"
}


class DBConn:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=None):
        # Keep the existing VYBE SQL readable while adapting SQLite-style ?
        # placeholders to PostgreSQL %s placeholders.
        sql = sql.replace("?", "%s")
        return self.conn.execute(sql, params or ())

    def commit(self):
        return self.conn.commit()

    def close(self):
        return self.conn.close()


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return DBConn(psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10))


def init_db():
    con = db()
    statements = [
        """CREATE TABLE IF NOT EXISTS students (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            student_id TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            last_login TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS resources (
            id BIGSERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            course TEXT NOT NULL,
            semester TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT DEFAULT '',
            file_name TEXT,
            file_data BYTEA,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS issues (
            id BIGSERIAL PRIMARY KEY,
            student_id BIGINT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL,
            FOREIGN KEY(student_id) REFERENCES students(id)
        )""",
        """CREATE TABLE IF NOT EXISTS solutions (
            id BIGSERIAL PRIMARY KEY,
            issue_id BIGINT NOT NULL,
            student_id BIGINT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            approved INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(issue_id) REFERENCES issues(id),
            FOREIGN KEY(student_id) REFERENCES students(id)
        )""",
        """CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
    ]
    for statement in statements:
        con.execute(statement)
    # Existing databases keep their data; add file_data when upgrading.
    con.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS file_data BYTEA")
    if con.execute("SELECT 1 FROM settings WHERE key='whatsapp_link'").fetchone() is None:
        con.execute("INSERT INTO settings(key,value) VALUES('whatsapp_link','')")
    con.commit()
    con.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_password(p):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, 180_000)
    return salt.hex() + "$" + digest.hex()


def check_password(p, stored):
    try:
        salt, digest = stored.split("$", 1)
        test = hashlib.pbkdf2_hmac(
            "sha256", p.encode(), bytes.fromhex(salt), 180_000
        ).hex()
        return secrets.compare_digest(test, digest)
    except Exception:
        return False


def student_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("student_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def esc(v):
    return html.escape(str(v or ""))


BASE_CSS = r"""
:root{
 --bg:#090a0d;--panel:#111318;--panel2:#171a20;--line:#282c34;
 --text:#f5f7fb;--muted:#9ca3af;--accent:#9b8cff;--accent2:#5f8cff;
 --good:#55d68a;--warn:#ffd166;--bad:#ff6b6b;
}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:
 radial-gradient(circle at 20% 0%,rgba(155,140,255,.12),transparent 32%),
 radial-gradient(circle at 90% 10%,rgba(95,140,255,.10),transparent 28%),var(--bg);
 color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",
 "Segoe UI",sans-serif;min-height:100vh}
a{color:inherit;text-decoration:none}.wrap{max-width:1180px;margin:auto;padding:22px}
.nav{position:sticky;top:0;z-index:20;background:rgba(9,10,13,.78);
 backdrop-filter:blur(18px);border-bottom:1px solid rgba(255,255,255,.06)}
.navin{max-width:1180px;margin:auto;padding:14px 22px;display:flex;align-items:center;
 justify-content:space-between;gap:14px}.brand{font-weight:900;letter-spacing:-.05em;font-size:25px}
.brand span{opacity:.55}.navlinks{display:flex;gap:8px;flex-wrap:wrap}
.navlinks a{padding:9px 12px;border-radius:12px;color:#c8ccd5}.navlinks a:hover{background:#1a1d23;color:#fff}
.hero{padding:80px 0 55px;text-align:center}.hero h1{font-size:clamp(52px,9vw,104px);
 margin:0;letter-spacing:-.075em;line-height:.9}.hero p{max-width:680px;margin:22px auto;color:var(--muted);
 font-size:18px;line-height:1.6}.badge{display:inline-block;border:1px solid var(--line);
 background:rgba(255,255,255,.04);padding:8px 13px;border-radius:999px;color:#cbd0db}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.grid2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.card{background:linear-gradient(145deg,rgba(255,255,255,.065),rgba(255,255,255,.025));
 border:1px solid rgba(255,255,255,.09);border-radius:24px;padding:22px;
 box-shadow:0 18px 60px rgba(0,0,0,.22);transition:.25s transform,.25s border-color}
.card:hover{transform:translateY(-3px);border-color:rgba(155,140,255,.3)}
.card h2,.card h3{margin:0 0 8px}.muted{color:var(--muted)}.small{font-size:13px;color:var(--muted)}
.btn{display:inline-flex;align-items:center;justify-content:center;border:0;cursor:pointer;
 padding:11px 15px;border-radius:13px;background:#f5f7fb;color:#090a0d;font-weight:800}
.btn.dark{background:#1a1d23;color:#fff;border:1px solid var(--line)}.btn.accent{background:linear-gradient(135deg,var(--accent),var(--accent2));color:white}
.btn.danger{background:#35181b;color:#ffb5b5;border:1px solid #572428}.btn.good{background:#123122;color:#9cf0bd}
.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:15px}.section{padding:35px 0}
input,textarea,select{width:100%;padding:12px 13px;background:#0d0f13;color:#fff;border:1px solid #2a2e36;
 border-radius:13px;outline:none}input:focus,textarea:focus,select:focus{border-color:var(--accent)}
textarea{min-height:130px;resize:vertical}.form{display:grid;gap:13px}.label{font-size:13px;color:#aeb4c0;margin-bottom:5px}
.flash{padding:12px 14px;border:1px solid #30343d;background:#171a20;border-radius:13px;margin:10px 0}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid #272b32;vertical-align:top}
.pill{display:inline-block;padding:5px 9px;border-radius:999px;background:#1d2027;color:#cbd0db;font-size:12px}
.pill.good{background:#123122;color:#9cf0bd}.pill.warn{background:#332b12;color:#ffe39a}.pill.bad{background:#35181b;color:#ffb5b5}
.search{margin-bottom:18px}.empty{text-align:center;padding:45px;color:var(--muted)}
.footer{padding:45px 0;color:#777;text-align:center}.hide-id{color:#8f96a3}
.auth{min-height:82vh;display:grid;place-items:center}.authbox{width:min(440px,100%);padding:30px}
.adminmark{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:#a9a0ff}
.kpi{font-size:38px;font-weight:900;letter-spacing:-.05em}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:800px){.grid,.grid2,.two{grid-template-columns:1fr}.navlinks{display:none}.wrap{padding:15px}.hero{padding:55px 0 35px}.hero h1{font-size:65px}table{display:block;overflow:auto}}
"""

def layout(title, body, nav=True):
    links = ""
    if nav:
        if session.get("student_id"):
            links += '<a href="/dashboard">Home</a><a href="/academics">Academics</a><a href="/issues">Campus</a><a href="/community">Community</a><a href="/logout">Logout</a>'
        elif session.get("admin"):
            links += '<a href="/admin/panel">Admin</a><a href="/admin/logout">Logout</a>'
        else:
            links += '<a href="/login">Student Login</a><a href="/admin">Admin</a>'
    flashes = "".join(f'<div class="flash">{esc(m)}</div>' for m in session.pop("_flashes", []))
    return f"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{esc(title)} · VYBE</title><style>{BASE_CSS}</style></head><body>
    <div class="nav"><div class="navin"><a class="brand" href="/">VYBE<span>.</span></a>
    <div class="navlinks">{links}</div></div></div><main class="wrap">{flashes}{body}</main>
    <footer class="footer">VYBE · Your Campus. Your Community. Your Space.</footer></body></html>"""


@app.route("/")
def home():
    if session.get("student_id"):
        return redirect(url_for("dashboard"))
    if session.get("admin"):
        return redirect(url_for("admin_panel"))
    body = """
    <section class="hero">
      <div class="badge">A student-built campus space</div>
      <h1>VYBE</h1>
      <p>Academics, campus problems and student community — brought together in one private space for your campus.</p>
      <div class="actions" style="justify-content:center">
        <a class="btn accent" href="/login">Enter VYBE</a>
        <a class="btn dark" href="/admin">Admin</a>
      </div>
    </section>
    <section class="grid">
      <div class="card"><h2>📚 Academics</h2><p class="muted">Notes, PYQs, syllabus and resources organised by semester and subject.</p></div>
      <div class="card"><h2>🏫 Campus</h2><p class="muted">Report Wi‑Fi, classroom, system and facility problems and track their status.</p></div>
      <div class="card"><h2>💬 Community</h2><p class="muted">Students can share practical solutions and help each other.</p></div>
    </section>
    """
    return layout("Welcome", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        sid = request.form.get("student_id","").strip()
        con = db()
        s = con.execute(
            "SELECT * FROM students WHERE name=? AND student_id=?",
            (name, sid)
        ).fetchone()
        if s:
            if s["status"] != "approved":
                con.close()
                flash("Your account is awaiting admin approval.")
                return redirect(url_for("login"))
            con.execute("UPDATE students SET last_login=? WHERE id=?", (now(),s["id"]))
            con.commit(); con.close()
            session.clear(); session["student_id"] = s["id"]
            return redirect(url_for("dashboard"))
        con.close()
        flash("Invalid Student ID or password.")
    body = """
    <div class="auth"><div class="card authbox">
      <div class="adminmark">VYBE STUDENT ACCESS</div><h1>Welcome back.</h1>
      <p class="muted">Sign in with your registered name and student ID.</p>
      <form class="form" method="post">
        <div><div class="label">Name</div><input name="name" required autocomplete="name"></div>
        <div><div class="label">Student ID</div><input name="student_id" required autocomplete="username"></div>
        <button class="btn accent" type="submit">Sign in</button>
      </form>
      <p class="small">New here? <a href="/register" style="color:#b8adff">Request access →</a></p>
    </div></div>"""
    return layout("Student Login", body)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()[:80]
        sid = request.form.get("student_id","").strip()[:80]
        password = request.form.get("password","")
        if len(name) < 2 or len(sid) < 2 or len(password) < 6:
            flash("Enter a valid name, student ID and a password of at least 6 characters.")
            return redirect(url_for("register"))
        con = db()
        try:
            con.execute("""INSERT INTO students(name,student_id,password_hash,status,created_at)
                           VALUES(?,?,?,?,?)""",
                        (name,sid,hash_password(password),"pending",now()))
            con.commit()
            flash("Access request submitted. Wait for admin approval.")
        except psycopg.IntegrityError:
            flash("That Student ID is already registered.")
        finally:
            con.close()
        return redirect(url_for("login"))
    body = """
    <div class="auth"><div class="card authbox">
      <div class="adminmark">REQUEST ACCESS</div><h1>Join VYBE.</h1>
      <p class="muted">Your request will be reviewed by the VYBE admin before you can enter.</p>
      <form class="form" method="post">
        <div><div class="label">Display name</div><input name="name" placeholder="e.g. Satyam" required></div>
        <div><div class="label">Student ID</div><input name="student_id" required></div>
        <div><div class="label">Password</div><input type="password" name="password" minlength="6" required></div>
        <button class="btn accent">Request access</button>
      </form>
    </div></div>"""
    return layout("Request Access", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@student_required
def dashboard():
    con=db()
    s=con.execute("SELECT name FROM students WHERE id=?",(session["student_id"],)).fetchone()
    counts={
      "resources":con.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"],
      "issues":con.execute("SELECT COUNT(*) c FROM issues WHERE student_id=?",(session["student_id"],)).fetchone()["c"],
      "community":con.execute("SELECT COUNT(*) c FROM solutions WHERE approved=1").fetchone()["c"]
    }
    con.close()
    body=f"""
    <section class="section"><div class="badge">Student space</div><h1>Hey, {esc(s["name"])}.</h1>
    <p class="muted">Welcome to your campus VYBE.</p></section>
    <section class="grid">
      <a class="card" href="/academics"><div class="kpi">{counts["resources"]}</div><h3>Resources</h3><p class="muted">Notes, PYQs & study material</p></a>
      <a class="card" href="/issues"><div class="kpi">{counts["issues"]}</div><h3>My campus reports</h3><p class="muted">Track problems you reported</p></a>
      <a class="card" href="/community"><div class="kpi">{counts["community"]}</div><h3>Community solutions</h3><p class="muted">See approved student solutions</p></a>
      <a class="card" href="/drive"><div class="kpi">☁️</div><h3>Google Drive</h3><p class="muted">Open the shared academic folder</p></a>
    </section>"""
    return layout("Dashboard",body)


@app.route("/academics")
@student_required
def academics():
    q=request.args.get("q","").strip()
    con=db()
    if q:
        rows=con.execute("""SELECT * FROM resources WHERE title LIKE ? OR subject LIKE ? OR course LIKE ?
                            ORDER BY id DESC""",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    else:
        rows=con.execute("SELECT * FROM resources ORDER BY id DESC").fetchall()
    con.close()
    cards=""
    for r in rows:
        file_link=f'<a class="btn dark" href="/resource/{r["id"]}">Open file</a>' if r["file_name"] else ""
        cards+=f"""<div class="card"><span class="pill">{esc(r["semester"])}</span>
        <h3>{esc(r["title"])}</h3><p class="small">{esc(r["course"])} · {esc(r["subject"])}</p>
        <p class="muted">{esc(r["description"])}</p>{file_link}</div>"""
    if not cards: cards='<div class="empty">No resources found.</div>'
    body=f"""<section class="section"><h1>Academics</h1><p class="muted">Your campus library.</p>
    <div class="card" style="margin-bottom:18px">
      <h2>☁️ Google Drive</h2>
      <p class="muted">Open the shared VYBE academic folder for additional study material.</p>
      <div class="actions"><a class="btn accent" href="/drive">Open Google Drive →</a></div>
    </div>
    <form class="search"><input name="q" value="{esc(q)}" placeholder="Search notes, subjects, PYQs..."></form>
    <div class="grid">{cards}</div></section>"""
    return layout("Academics",body)


@app.route("/drive")
@student_required
def drive():
    return redirect(VYBE_DRIVE_URL)


@app.route("/resource/<int:rid>")
@student_required
def resource(rid):
    con=db(); r=con.execute("SELECT * FROM resources WHERE id=?",(rid,)).fetchone(); con.close()
    if not r or not r["file_name"] or r.get("file_data") is None: abort(404)
    suffix=Path(r["file_name"]).suffix.lower()
    mime={".pdf":"application/pdf",".txt":"text/plain",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",".doc":"application/msword",".docx":"application/vnd.openxmlformats-officedocument.wordprocessingml.document",".ppt":"application/vnd.ms-powerpoint",".pptx":"application/vnd.openxmlformats-officedocument.presentationml.presentation",".zip":"application/zip"}.get(suffix,"application/octet-stream")
    return Response(bytes(r["file_data"]), mimetype=mime, headers={"Content-Disposition": f'inline; filename="{r["file_name"]}"'})


@app.route("/issues", methods=["GET","POST"])
@student_required
def issues():
    con=db()
    if request.method=="POST":
        cat=request.form.get("category","Other")[:50]
        title=request.form.get("title","").strip()[:120]
        desc=request.form.get("description","").strip()[:2000]
        if title and desc:
            con.execute("""INSERT INTO issues(student_id,category,title,description,status,created_at)
                           VALUES(?,?,?,?,?,?)""",(session["student_id"],cat,title,desc,"Open",now()))
            con.commit(); flash("Campus report submitted.")
        else: flash("Please complete the report.")
        con.close(); return redirect(url_for("issues"))
    rows=con.execute("""SELECT * FROM issues WHERE student_id=? ORDER BY id DESC""",(session["student_id"],)).fetchall()
    con.close()
    cards=""
    for x in rows:
        cls="good" if x["status"]=="Resolved" else ("warn" if x["status"]=="In progress" else "")
        cards+=f"""<div class="card"><span class="pill {cls}">{esc(x["status"])}</span>
        <h3>{esc(x["title"])}</h3><p class="small">{esc(x["category"])} · {esc(x["created_at"])}</p>
        <p class="muted">{esc(x["description"])}</p></div>"""
    body=f"""<section class="section"><h1>Campus</h1><p class="muted">Report a problem and track it.</p>
    <div class="two"><div class="card"><h2>Report a problem</h2><form class="form" method="post">
      <div><div class="label">Category</div><select name="category"><option>Wi-Fi</option><option>Systems</option><option>Classroom</option><option>Electricity</option><option>Facilities</option><option>Other</option></select></div>
      <div><div class="label">Title</div><input name="title" required></div>
      <div><div class="label">Details</div><textarea name="description" required></textarea></div>
      <button class="btn accent">Submit report</button></form></div>
      <div><h2>My reports</h2>{cards or '<div class="empty">No reports yet.</div>'}</div></div></section>"""
    return layout("Campus",body)


@app.route("/community", methods=["GET","POST"])
@student_required
def community():
    con=db()
    if request.method=="POST":
        iid=request.form.get("issue_id")
        text=request.form.get("text","").strip()[:1500]
        if iid and text:
            con.execute("""INSERT INTO solutions(issue_id,student_id,text,created_at,approved)
                           VALUES(?,?,?,?,1)""",(iid,session["student_id"],text,now()))
            con.commit(); flash("Solution shared with all students.")
        con.close(); return redirect(url_for("community"))
    issues_rows=con.execute("SELECT * FROM issues ORDER BY id DESC LIMIT 50").fetchall()
    sol=con.execute("""SELECT s.*, i.title FROM solutions s JOIN issues i ON i.id=s.issue_id
                       WHERE s.approved=1 ORDER BY s.id DESC LIMIT 80""").fetchall()
    solution_counts={}
    for srow in sol:
        solution_counts[srow["issue_id"]]=solution_counts.get(srow["issue_id"],0)+1
    con.close()
    issue_html=""
    for i in issues_rows:
        issue_html+=f"""<div class="card"><span class="pill">{esc(i["category"])}</span><h3>{esc(i["title"])}</h3>
        <p class="muted">{esc(i["description"])}</p>
        <form class="form" method="post"><input type="hidden" name="issue_id" value="{i["id"]}">
        <textarea name="text" placeholder="Suggest a solution..." required></textarea>
        <button class="btn dark">Send solution</button></form>
        {(f'<form method="post" action="/community/issue/{i["id"]}/resolve" style="margin-top:10px"><button class="btn good" onclick="return confirm(\'Accept solution and delete this problem chat?\')">✓ Accept solution & delete chat</button></form>' if i["student_id"]==session["student_id"] and solution_counts.get(i["id"],0)>0 else '')}
        </div>"""
    sol_html=""
    for s in sol:
        sol_html+=f"""<div class="card"><span class="pill good">Community solution</span>
        <h3>{esc(s["title"])}</h3><p>{esc(s["text"])}</p><p class="small">{esc(s["created_at"])}</p></div>"""
    body=f"""<section class="section"><h1>Community</h1><p class="muted">Help solve campus problems. Solutions are shared directly with all students.</p>
    <h2>Campus problems</h2><div class="grid">{issue_html or '<div class="empty">No problems yet.</div>'}</div>
    <div class="section"><h2>Approved solutions</h2><div class="grid">{sol_html or '<div class="empty">No approved solutions yet.</div>'}</div></div></section>"""
    return layout("Community",body)


@app.route("/community/issue/<int:iid>/resolve", methods=["POST"])
@student_required
def resolve_community_issue(iid):
    con=db()
    row=con.execute("SELECT id FROM issues WHERE id=? AND student_id=?",(iid,session["student_id"])).fetchone()
    if not row:
        con.close(); abort(403)
    con.execute("DELETE FROM solutions WHERE issue_id=?",(iid,))
    con.execute("DELETE FROM issues WHERE id=?",(iid,))
    con.commit(); con.close()
    flash("Problem solved. The problem chat was deleted.")
    return redirect(url_for("community"))


@app.route("/admin", methods=["GET","POST"])
def admin_login():
    if request.method=="POST":
        if secrets.compare_digest(request.form.get("password",""), ADMIN_PASSWORD):
            session.clear(); session["admin"]=True
            return redirect(url_for("admin_panel"))
        flash("Incorrect admin password.")
    body="""<div class="auth"><div class="card authbox">
      <div class="adminmark">PRIVATE CONTROL CENTER</div><h1>Admin login.</h1>
      <p class="muted">This area is only for the VYBE owner/admin.</p>
      <form class="form" method="post"><div class="label">Admin password</div>
      <input type="password" name="password" required autocomplete="current-password">
      <button class="btn accent">Enter control center</button></form>
    </div></div>"""
    return layout("Admin Login",body)


@app.route("/admin/logout")
def admin_logout():
    session.clear(); return redirect(url_for("home"))


@app.route("/admin/panel")
@admin_required
def admin_panel():
    con=db()
    stats={
      "students":con.execute("SELECT COUNT(*) c FROM students").fetchone()["c"],
      "pending":con.execute("SELECT COUNT(*) c FROM students WHERE status='pending'").fetchone()["c"],
      "issues":con.execute("SELECT COUNT(*) c FROM issues").fetchone()["c"],
      "resources":con.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"],
      "solutions":con.execute("SELECT COUNT(*) c FROM solutions").fetchone()["c"]
    }
    students=con.execute("SELECT * FROM students ORDER BY id DESC").fetchall()
    issues_rows=con.execute("""SELECT i.*,s.name,s.student_id FROM issues i JOIN students s ON s.id=i.student_id
                               ORDER BY i.id DESC""").fetchall()
    solutions=con.execute("""SELECT so.*,i.title,s.name FROM solutions so
                              JOIN issues i ON i.id=so.issue_id JOIN students s ON s.id=so.student_id
                              ORDER BY so.id DESC LIMIT 80""").fetchall()
    con.close()
    stu=""
    for s in students:
        act=""
        if s["status"]=="pending":
            act=f'<a class="btn good" href="/admin/student/{s["id"]}/approve">Approve</a>'
        elif s["status"]=="approved":
            act=f'<a class="btn danger" href="/admin/student/{s["id"]}/block">Block</a>'
        else:
            act=f'<a class="btn good" href="/admin/student/{s["id"]}/approve">Unblock</a>'
        act += f' <a class="btn danger" href="/admin/student/{s["id"]}/delete" onclick="return confirm(\'Delete this student?\')">Delete</a>'
        stu+=f"""<tr><td>{esc(s["name"])}</td><td>{esc(s["student_id"])}</td>
        <td><span class="pill">{esc(s["status"])}</span></td><td>{act}</td></tr>"""
    iss=""
    for i in issues_rows:
        iss+=f"""<tr><td>#{i["id"]}</td><td>{esc(i["name"])}</td><td>{esc(i["student_id"])}</td>
        <td>{esc(i["title"])}<br><span class="small">{esc(i["description"])}</span></td><td>{esc(i["status"])}</td>
        <td><a class="btn dark" href="/admin/issue/{i["id"]}/next">Next status</a></td></tr>"""
    sol=""
    for s in solutions:
        sol+=f"""<tr><td>{esc(s["title"])}</td><td>{esc(s["name"])}</td><td>{esc(s["text"])}</td>
        </tr>"""
    body=f"""<section class="section"><div class="adminmark">PRIVATE VYBE CONTROL CENTER</div><h1>Admin dashboard.</h1>
    <div class="grid">
      <div class="card"><div class="kpi">{stats["students"]}</div><div class="muted">Students</div></div>
      <div class="card"><div class="kpi">{stats["pending"]}</div><div class="muted">Pending approvals</div></div>
      <div class="card"><div class="kpi">{stats["issues"]}</div><div class="muted">Campus reports</div></div>
      <div class="card"><div class="kpi">{stats["resources"]}</div><div class="muted">Resources</div></div>
      <div class="card"><div class="kpi">{stats["solutions"]}</div><div class="muted">Community solutions</div></div>
    </div>
    <div class="section"><div class="card"><h2>Students</h2><div class="actions"><a class="btn danger" href="/admin/students/delete-all" onclick="return confirm(\'DELETE ALL STUDENT DATA?\')">Delete All Students</a></div><div style="overflow:auto"><table><tr><th>Name</th><th>Private Student ID</th><th>Status</th><th>Action</th></tr>{stu or '<tr><td colspan=4>No students.</td></tr>'}</table></div></div></div>
    <div class="section"><div class="card"><h2>Campus reports</h2><div style="overflow:auto"><table><tr><th>#</th><th>Student</th><th>Private ID</th><th>Report</th><th>Status</th><th>Action</th></tr>{iss or '<tr><td colspan=6>No reports.</td></tr>'}</table></div></div></div>
    <div class="section"><div class="card"><h2>Community solutions</h2><p class="muted">Solutions are visible to students immediately. There is no admin moderation step.</p><div style="overflow:auto"><table><tr><th>Issue</th><th>Student</th><th>Solution</th></tr>{sol or '<tr><td colspan=3>No solutions yet.</td></tr>'}</table></div></div></div>
    <div class="section"><div class="card"><h2>Resources + WhatsApp</h2>
      <p class="muted">Add study resources and keep your WhatsApp Community link available to students.</p>
      <form class="form" method="post" action="/admin/resource" enctype="multipart/form-data">
        <input name="title" placeholder="Resource title" required><div class="two">
        <input name="course" placeholder="Course" required><input name="semester" placeholder="Semester" required></div>
        <input name="subject" placeholder="Subject" required><textarea name="description" placeholder="Description"></textarea>
        <input type="file" name="file"><button class="btn accent">Add resource</button>
      </form>
      <form class="form" method="post" action="/admin/whatsapp" style="margin-top:20px">
        <input name="link" placeholder="Official WhatsApp Community invite/link">
        <button class="btn dark">Save WhatsApp link</button>
      </form>
    </div></div>
    </section>"""
    return layout("Admin",body)


@app.route("/admin/student/<int:sid>/<action>")
@admin_required
def student_action(sid,action):
    if action not in ("approve","block"): abort(400)
    con=db()
    status="approved" if action=="approve" else "blocked"
    con.execute("UPDATE students SET status=? WHERE id=?",(status,sid)); con.commit(); con.close()
    flash(f"Student {action}d.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/student/<int:sid>/delete")
@admin_required
def delete_student(sid):
    con=db()
    ids=[r["id"] for r in con.execute("SELECT id FROM issues WHERE student_id=?",(sid,)).fetchall()]
    for iid in ids: con.execute("DELETE FROM solutions WHERE issue_id=?",(iid,))
    con.execute("DELETE FROM solutions WHERE student_id=?",(sid,))
    con.execute("DELETE FROM issues WHERE student_id=?",(sid,))
    con.execute("DELETE FROM students WHERE id=?",(sid,))
    con.commit(); con.close(); flash("Student data deleted.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/students/delete-all")
@admin_required
def delete_all_students():
    con=db(); con.execute("DELETE FROM solutions"); con.execute("DELETE FROM issues"); con.execute("DELETE FROM students"); con.commit(); con.close()
    flash("All student data deleted.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/issue/<int:iid>/next")
@admin_required
def next_issue(iid):
    con=db(); row=con.execute("SELECT status FROM issues WHERE id=?",(iid,)).fetchone()
    if row:
        order=["Open","In progress","Resolved"]
        status=order[(order.index(row["status"])+1)%len(order)] if row["status"] in order else "Open"
        con.execute("UPDATE issues SET status=? WHERE id=?",(status,iid)); con.commit()
    con.close(); return redirect(url_for("admin_panel"))


@app.route("/admin/resource", methods=["POST"])
@admin_required
def add_resource():
    title=request.form.get("title","").strip()[:150]
    course=request.form.get("course","").strip()[:100]
    sem=request.form.get("semester","").strip()[:100]
    subject=request.form.get("subject","").strip()[:100]
    desc=request.form.get("description","").strip()[:1000]
    f=request.files.get("file")
    filename=None
    file_data=None
    if f and f.filename:
        suffix=Path(f.filename).suffix.lower()
        if suffix not in ALLOWED_EXT:
            flash("That file type is not allowed."); return redirect(url_for("admin_panel"))
        filename=Path(f.filename).name[:200]
        file_data=f.read()
    con=db()
    con.execute("""INSERT INTO resources(title,course,semester,subject,description,file_name,file_data,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",(title,course,sem,subject,desc,filename,file_data,now()))
    con.commit(); con.close()
    flash("Resource added.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/whatsapp", methods=["POST"])
@admin_required
def whatsapp():
    link=request.form.get("link","").strip()[:500]
    con=db(); con.execute("UPDATE settings SET value=? WHERE key='whatsapp_link'",(link,)); con.commit(); con.close()
    flash("WhatsApp Community link saved.")
    return redirect(url_for("admin_panel"))


@app.route("/whatsapp")
@student_required
def whatsapp_link():
    con=db(); row=con.execute("SELECT value FROM settings WHERE key='whatsapp_link'").fetchone(); con.close()
    if row and row["value"]:
        return redirect(row["value"])
    flash("The WhatsApp Community link has not been configured yet.")
    return redirect(url_for("dashboard"))


init_db()

if __name__ == "__main__":
    port=int(os.environ.get("PORT","5000"))
    app.run(host="0.0.0.0",port=port,debug=False)

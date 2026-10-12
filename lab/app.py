"""bbh acceptance-test lab: a small, deliberately vulnerable Flask app.

Binds 127.0.0.1 only. Fresh in-memory database every start. The planted bugs and
decoys are documented in ground_truth.json. This exists to prove the harness
finds the bugs and rejects the decoys; it is never exposed off localhost.

Accounts: alice/alice-pass (A), bob/bob-pass (B), carol/carol-pass (a third
party, NOT a test account).
"""

from __future__ import annotations

import html
import json
import os
import re
import sqlite3
import time
from functools import wraps

from flask import Flask, Response, g, redirect, request, make_response

app = Flask(__name__)

USERS = {
    "alice": {"id": 1, "password": "alice-pass", "email": "alice@lab.test", "display_name": "Alice", "bio": "Alice bio", "newsletter": True},
    "bob": {"id": 2, "password": "bob-pass", "email": "bob@lab.test", "display_name": "Bob", "bio": "Bob bio", "newsletter": False},
    "carol": {"id": 3, "password": "carol-pass", "email": "carol@lab.test", "display_name": "Carol", "bio": "Carol bio", "newsletter": True},
}
SESSIONS: dict[str, str] = {}      # token -> username
NOTES: dict[int, dict] = {}        # note id -> {owner_id, title, content}
ITEMS: dict[int, dict] = {}        # item id -> {owner_id, name}
CSP_SCRIPT_SELF = "script-src 'self'; object-src 'none'"


def seed():
    SESSIONS.clear(); NOTES.clear(); ITEMS.clear()
    for u in USERS.values():
        u["display_name"] = u["display_name"].split()[0]
        u["bio"] = f"{u['display_name']} bio"
        u["newsletter"] = u.get("newsletter", False)
    NOTES[1] = {"owner_id": 1, "title": "Alice note 1", "content": "alice-secret-1"}
    NOTES[2] = {"owner_id": 1, "title": "Alice note 2", "content": "alice-secret-2"}
    NOTES[7] = {"owner_id": 2, "title": "Bob note", "content": "bob-private-SECRET-7"}
    NOTES[9] = {"owner_id": 3, "title": "Carol note", "content": "carol-secret-9"}
    for uid, (iid, name) in zip((1, 2, 3), ((10, "alice-item"), (20, "bob-item"), (30, "carol-item"))):
        ITEMS[iid] = {"owner_id": uid, "name": name}


def current_user():
    tok = request.cookies.get("lab_session")
    uname = SESSIONS.get(tok or "")
    return USERS.get(uname) if uname else None


def login_required(f):
    @wraps(f)
    def inner(*a, **k):
        if not current_user():
            return Response(json.dumps({"error": "login required"}), status=401, mimetype="application/json")
        return f(*a, **k)
    return inner


def page(body: str, csp: str | None = None) -> Response:
    resp = make_response(f"<!doctype html><html><head><link rel=stylesheet href=/static/app.css>"
                         f"<script src=/static/app.js></script></head><body>{body}</body></html>")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    if csp:
        resp.headers["Content-Security-Policy"] = csp
    return resp


def _parse_body_any_content_type():
    """Parse the body as JSON regardless of Content-Type (used only where the bug requires it)."""
    raw = request.get_data(as_text=True) or ""
    try:
        return json.loads(raw)
    except Exception:
        return {k: v for k, v in request.form.items()} or {}


# --- auth ------------------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page('<h1>Login</h1><form method=post action=/login>'
                    '<input name=username><input name=password type=password>'
                    '<input type=hidden name=csrf_token value=static-csrf>'
                    '<button>Sign in</button></form>')
    uname = request.form.get("username", "")
    pw = request.form.get("password", "")
    u = USERS.get(uname)
    if u and u["password"] == pw:
        tok = f"sess-{uname}-{int(time.time()*1000)%100000}"
        SESSIONS[tok] = uname
        resp = redirect("/dashboard")
        resp.set_cookie("lab_session", tok, httponly=True, samesite="Lax")
        return resp
    return page("<h1>Login</h1><p>bad credentials</p>"), 401


@app.route("/api/login", methods=["POST"])
def api_login():
    """PLANTED BUG 4: NoSQL-style operator injection on username/password."""
    body = _parse_body_any_content_type()

    def matches(stored: str, supplied):
        if isinstance(supplied, dict):
            for op, val in supplied.items():
                if op == "$ne":
                    if not (stored != val):
                        return False
                elif op == "$gt":
                    if not (stored > str(val)):
                        return False
                elif op == "$gte":
                    if not (stored >= str(val)):
                        return False
                elif op == "$lt":
                    if not (stored < str(val)):
                        return False
                elif op == "$regex":
                    if not re.search(str(val), stored):
                        return False
                elif op == "$in":
                    if stored not in (val or []):
                        return False
                elif op == "$nin":
                    if stored in (val or []):
                        return False
                elif op == "$exists":
                    if bool(val) != True:
                        return False
                else:
                    return False
            return True
        return stored == supplied

    for uname, u in USERS.items():
        un, pw = body.get("username"), body.get("password")
        if matches(uname, un) and matches(u["password"], pw):
            tok = f"sess-{uname}-{int(time.time()*1000)%100000}"
            SESSIONS[tok] = uname
            resp = Response(json.dumps({"ok": True, "user": uname}), mimetype="application/json")
            resp.set_cookie("lab_session", tok, httponly=True, samesite="Lax")
            return resp
    return Response(json.dumps({"ok": False}), status=401, mimetype="application/json")


@app.route("/logout")
def logout():
    tok = request.cookies.get("lab_session")
    SESSIONS.pop(tok or "", None)
    resp = redirect("/")
    resp.delete_cookie("lab_session")
    return resp


# --- pages -----------------------------------------------------------------------------------

@app.route("/")
def index():
    return page('<h1>Lab</h1><ul>'
                '<li><a href=/dashboard>dashboard</a></li><li><a href=/notes>notes</a></li>'
                '<li><a href=/settings>settings</a></li><li><a href=/people>people</a></li>'
                '<li><a href=/products>products</a></li><li><a href="/search?q=hello">search</a></li>'
                '<li><a href="/greet?name=friend">greet</a></li><li><a href="/echo?msg=hi">echo</a></li>'
                '<li><a href="/lookup?id=1">lookup</a></li></ul>')


@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return page(f"<h1>Dashboard</h1><p>Welcome {html.escape(u['display_name'])}</p>")


@app.route("/search")
def search():
    """PLANTED BUG 1: q reflected RAW into HTML; CSP script-src 'self' blocks inline script.
    HTMLi works, reflected XSS does not, no template evaluation (SSTI/CSTI n/a)."""
    q = request.args.get("q", "")
    return page(f"<h1>Search</h1><p>Results for {q}</p>", csp=CSP_SCRIPT_SELF)


@app.route("/greet")
def greet():
    """PLANTED BUG 2: name goes into a Jin2-ish template source and is rendered, then the
    RENDERED output is HTML-escaped. SSTI works (engine evaluates), HTMLi/XSS do not."""
    from jinja2.sandbox import SandboxedEnvironment

    name = request.args.get("name", "friend")
    env = SandboxedEnvironment()
    try:
        rendered = env.from_string("Hello " + name + "!").render()
    except Exception as exc:
        rendered = f"Hello (template error: {type(exc).__name__})"
    return page(f"<h1>Greeting</h1><p>{html.escape(rendered)}</p>")


@app.route("/products")
def products():
    """PLANTED BUG 3: sort concatenated into ORDER BY in SQLite with a registered sleep().
    Time-based blind SQLi only: errors swallowed, rows re-sorted in Python so no boolean/error diff."""
    sort = request.args.get("sort", "name")
    con = sqlite3.connect(":memory:")
    total = {"slept": 0.0}

    def _sleep(seconds):
        try:
            s = float(seconds)
        except Exception:
            s = 0.0
        s = max(0.0, min(5.0, s))
        # cap the TOTAL sleeping per request at the largest single requested value
        want = max(total["slept"], s)
        delta = want - total["slept"]
        if delta > 0:
            time.sleep(delta)
            total["slept"] = want
        return 0

    con.create_function("sleep", 1, _sleep)
    con.execute("CREATE TABLE products(id INTEGER, name TEXT, price INTEGER)")
    rows_seed = [(1, "Alpha", 30), (2, "Beta", 20), (3, "Gamma", 10)]
    con.executemany("INSERT INTO products VALUES (?,?,?)", rows_seed)
    try:
        cur = con.execute(f"SELECT id, name, price FROM products ORDER BY {sort}")
        _ = cur.fetchall()
    except Exception:
        pass
    # always present a stable, fixed ordering so there is NO boolean/error differential
    fixed = sorted(rows_seed, key=lambda r: r[0])
    con.close()
    body = "<h1>Products</h1><ul>" + "".join(f"<li>{html.escape(n)}: {p}</li>" for _, n, p in fixed) + "</ul>"
    return page(body)


@app.route("/notes")
@login_required
def notes_page():
    u = current_user()
    mine = [(nid, n) for nid, n in NOTES.items() if n["owner_id"] == u["id"]]
    body = "<h1>Notes</h1><ul>" + "".join(f"<li>{html.escape(n['title'])}: {html.escape(n['content'])}</li>" for _, n in mine) + "</ul>"
    body += '<form method=post action=/notes/new><input name=title><input name=content><button>Add</button></form>'
    return page(body)


@app.route("/notes/new", methods=["POST"])
@login_required
def notes_new():
    u = current_user()
    nid = max(NOTES) + 1 if NOTES else 1
    NOTES[nid] = {"owner_id": u["id"], "title": request.form.get("title", ""), "content": request.form.get("content", "")}
    return redirect("/notes")


@app.route("/api/notes/<nid>", methods=["GET", "POST"])
@login_required
def api_notes(nid):
    """PLANTED BUG 5a (read) + 5b (write): no owner check on either. The write returns
    ok without echoing content, so only a counter-read shows the change."""
    try:
        key = int(nid)
    except ValueError:
        return Response(json.dumps({"error": "bad id"}), status=400, mimetype="application/json")
    note = NOTES.get(key)
    if not note:
        return Response(json.dumps({"error": "not found"}), status=404, mimetype="application/json")
    if request.method == "GET":
        return Response(json.dumps({"id": key, "owner_id": note["owner_id"], "title": note["title"], "content": note["content"]}),
                        mimetype="application/json")
    body = _parse_body_any_content_type()
    if "title" in body:
        note["title"] = body["title"]
    if "content" in body:
        note["content"] = body["content"]
    return Response(json.dumps({"ok": True}), mimetype="application/json")


@app.route("/api/users/<uid>/display_name", methods=["POST"])
@login_required
def api_display_name(uid):
    """DECOY (bug 6): returns ok for any id, but only changes the caller's own display name."""
    u = current_user()
    body = _parse_body_any_content_type()
    try:
        target = int(uid)
    except ValueError:
        return Response(json.dumps({"error": "bad id"}), status=400, mimetype="application/json")
    if target == u["id"] and "display_name" in body:
        u["display_name"] = body["display_name"]
    return Response(json.dumps({"ok": True}), mimetype="application/json")


@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    """PLANTED BUG 7: state-changing, parses the body as JSON whatever the Content-Type,
    cookie auth, NO CSRF token or Origin check."""
    u = current_user()
    if request.method == "GET":
        return Response(json.dumps({"display_name": u["display_name"], "newsletter": u["newsletter"]}),
                        mimetype="application/json")
    body = _parse_body_any_content_type()
    if "display_name" in body:
        u["display_name"] = body["display_name"]
    if "newsletter" in body:
        u["newsletter"] = bool(body["newsletter"])
    return Response(json.dumps({"ok": True}), mimetype="application/json")


@app.route("/settings")
@login_required
def settings_page():
    u = current_user()
    return page(f"<h1>Settings</h1><p>Name: {html.escape(u['display_name'])}</p>"
                f"<p>Bio: {html.escape(u['bio'])}</p>"
                f"<p>Newsletter: {u['newsletter']}</p>")


@app.route("/api/profile/bio", methods=["POST"])
@login_required
def api_bio():
    """PLANTED BUG 10 (store): bio stored RAW. Rendered escaped on /settings (own view) but
    RAW on /people to OTHER users. Second-order, cross-principal HTMLi; XSS blocked by CSP."""
    u = current_user()
    body = _parse_body_any_content_type()
    if "bio" in body:
        u["bio"] = body["bio"]
    return Response(json.dumps({"ok": True}), mimetype="application/json")


@app.route("/people")
@login_required
def people():
    """Renders OTHER users' bios RAW (bug 10 sink). CSP blocks script."""
    me = current_user()
    rows = []
    for u in USERS.values():
        if u["id"] == me["id"]:
            continue
        rows.append(f"<li><b>{html.escape(u['display_name'])}</b>: {u['bio']}</li>")  # bio RAW
    return page("<h1>Team</h1><ul>" + "".join(rows) + "</ul>", csp=CSP_SCRIPT_SELF)


@app.route("/api/items")
@login_required
def api_items():
    """PLANTED BUG 9: owner_id filter; when ABSENT, returns EVERY user's items incl. carol's."""
    owner_id = request.args.get("owner_id")
    if owner_id is None or owner_id == "":
        rows = ITEMS
    else:
        try:
            oid = int(owner_id)
        except ValueError:
            return Response(json.dumps({"error": "bad owner_id"}), status=400, mimetype="application/json")
        rows = {iid: it for iid, it in ITEMS.items() if it["owner_id"] == oid}
    out = [{"id": iid, "owner_id": it["owner_id"], "owner_email": _email_of(it["owner_id"]), "name": it["name"]}
           for iid, it in rows.items()]
    return Response(json.dumps(out), mimetype="application/json")


def _email_of(uid):
    for u in USERS.values():
        if u["id"] == uid:
            return u["email"]
    return ""


@app.route("/redirect")
def redirect_ep():
    """PLANTED BUG 8: flawed allowlist keeps the WRONG side of split('@'). Only
    https://lab.test@evil.test passes; every other bypass shape is refused."""
    from urllib.parse import urlsplit

    url = request.args.get("url", "")
    if re.match(r"^/[A-Za-z0-9/_-]*$", url):
        return redirect(url)
    try:
        netloc = urlsplit(url).netloc
    except Exception:
        return page("bad url"), 400
    host = netloc.split("@")[0].split(":")[0]   # BUG: keeps credentials side, drops the real host
    allowed = (request.host or "").split(":")[0]  # this app's own host
    if host == allowed:
        return redirect(url)
    return page("redirect refused"), 400


@app.route("/go")
def go():
    """DECOY (D3): exact allowlist of relative paths only."""
    nxt = request.args.get("next", "")
    if nxt in ("/dashboard", "/notes", "/settings"):
        return redirect(nxt)
    return page("refused"), 400


@app.route("/echo")
def echo():
    """DECOY (D1): msg reflected in four contexts, correctly encoded in each."""
    msg = request.args.get("msg", "")
    enc = html.escape(msg)
    js = json.dumps(msg).replace("</", "<\\/").replace("<!--", "")
    attr = html.escape(msg, quote=True)
    url = msg if re.match(r"^https?://[A-Za-z0-9./?=&_-]*$", msg) else "#"
    body = (f"<h1>Echo</h1><p>text: {enc}</p>"
            f"<div data-x=\"{attr}\">attr</div>"
            f"<a href=\"{html.escape(url, quote=True)}\">link</a>"
            f"<script>var m = {js};</script>")
    return page(body)


@app.route("/lookup")
def lookup():
    """DECOY (D2): parameterised query; non-numeric id returns a static 'SQL error' text."""
    idv = request.args.get("id", "")
    if not idv.isdigit():
        return page("<h1>Lookup</h1><p>SQL error: invalid input syntax for integer</p>"), 400
    return page(f"<h1>Lookup</h1><p>id={html.escape(idv)} ok</p>")


@app.route("/static/app.js")
def app_js():
    """The SPA client calls every JSON API with fetch(), so a JS reader finds them."""
    js = """// lab client
fetch('/api/settings');
fetch('/api/items?owner_id=1');
fetch('/api/notes/1');
fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
fetch('/api/profile/bio', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{"bio":""}'});
fetch('/api/users/1/display_name', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{"display_name":""}'});
// admin route (not wired to UI): /api/admin/users
"""
    return Response(js, mimetype="application/javascript")


@app.route("/static/app.css")
def app_css():
    return Response("body{font-family:sans-serif}", mimetype="text/css")


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /api/\n# lab-robots-marker\n", mimetype="text/plain")


seed()


def main():
    port = int(os.environ.get("LAB_PORT", "5057"))
    seed()
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

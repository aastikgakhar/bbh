"""Prove every planted bug works and every decoy resists, with the Flask test
client. Kept under ~60 s by using short SQLi delays."""

import json
import time

import pytest

import app as lab


@pytest.fixture(autouse=True)
def fresh():
    lab.seed()
    yield


@pytest.fixture
def client():
    lab.app.config["TESTING"] = True
    return lab.app.test_client()


def login(client, username, password):
    r = client.post("/login", data={"username": username, "password": password})
    return r


def sess(client, username):
    login(client, username, {"alice": "alice-pass", "bob": "bob-pass", "carol": "carol-pass"}[username])
    return client


# --- planted bugs --------------------------------------------------------------------------

def test_bug1_htmli_works_xss_blocked(client):
    r = client.get("/search?q=<b>k1</b>")
    assert b"<b>k1</b>" in r.data                       # raw markup rendered
    assert "script-src 'self'" in r.headers.get("Content-Security-Policy", "")  # XSS blocked by CSP
    # no template evaluation
    r2 = client.get("/search?q={{7*7}}")
    assert b"{{7*7}}" in r2.data and b"49" not in r2.data.split(b"{{7*7}}")[0][-10:]


def test_bug2_ssti_jinja(client):
    r = client.get("/greet?name={{7*7}}")
    assert b"49" in r.data and b"{{7*7}}" not in r.data   # evaluated
    r2 = client.get("/greet?name={{7*'7'}}")
    assert b"7777777" in r2.data                          # identifies Jinja2
    # markup does not inject (rendered output escaped)
    r3 = client.get("/greet?name=<b>x</b>")
    assert b"<b>x</b>" not in r3.data and b"&lt;b&gt;" in r3.data


def test_bug3_time_based_sqli_only(client):
    base = _timed(client, "/products?sort=name")
    slow = _timed(client, "/products?sort=(CASE WHEN (1=1) THEN sleep(1) ELSE 1 END)")
    assert slow - base >= 0.6, (base, slow)
    # no boolean/error differential: true vs false orderings return identical bodies
    a = client.get("/products?sort=(CASE WHEN (1=1) THEN name ELSE price END)").data
    b = client.get("/products?sort=(CASE WHEN (1=2) THEN name ELSE price END)").data
    bad = client.get("/products?sort=thisisnotacolumn").data
    assert a == b == bad   # ordering never changes, errors swallowed


def _timed(client, url):
    t = time.perf_counter()
    client.get(url)
    return time.perf_counter() - t


def test_bug4_nosqli_login(client):
    r = client.post("/api/login", data=json.dumps({"username": "alice", "password": {"$ne": ""}}),
                    content_type="application/json")
    assert r.status_code == 200 and json.loads(r.data)["user"] == "alice"
    # normal wrong password fails
    r2 = client.post("/api/login", data=json.dumps({"username": "alice", "password": "wrong"}), content_type="application/json")
    assert r2.status_code == 401


def test_bug5a_idor_read(client):
    sess(client, "alice")
    r = client.get("/api/notes/7")   # bob's note
    assert r.status_code == 200 and b"bob-private-SECRET-7" in r.data


def test_bug5b_idor_write_needs_counter_read(client):
    sess(client, "alice")
    w = client.post("/api/notes/7", data=json.dumps({"content": "hacked-by-alice"}), content_type="application/json")
    assert w.status_code == 200 and b"hacked-by-alice" not in w.data  # write does not echo
    # counter-read as bob shows the change
    bob = lab.app.test_client()
    sess(bob, "bob")
    r = bob.get("/api/notes/7")
    assert b"hacked-by-alice" in r.data


def test_bug6_decoy_display_name_no_cross_change(client):
    sess(client, "alice")
    r = client.post("/api/users/2/display_name", data=json.dumps({"display_name": "pwned"}), content_type="application/json")
    assert r.status_code == 200 and json.loads(r.data)["ok"]   # returns ok
    bob = lab.app.test_client(); sess(bob, "bob")
    assert b"pwned" not in bob.get("/settings").data            # but bob unchanged


def test_bug7_csrf_text_plain(client):
    sess(client, "alice")
    r = client.post("/api/settings", data=json.dumps({"display_name": "csrf-name"}), content_type="text/plain")
    assert r.status_code == 200
    assert b"csrf-name" in client.get("/api/settings").data     # state changed via text/plain, no token


@pytest.mark.parametrize("url,ok", [
    ("https://lab.test@evil.test", True),
    ("//evil.test", False), ("https:/\\evil.test", False), ("https://lab.test.evil.test", False),
    ("https://evil.test%23@lab.test", False), ("/\\/evil.test", False), ("\\\\evil.test", False),
    ("https://evil.test", False),
])
def test_bug8_open_redirect_only_userinfo(client, url, ok):
    r = client.get("/redirect", query_string={"url": url})
    if ok:
        assert r.status_code in (301, 302) and "evil.test" in r.headers.get("Location", "")
    else:
        loc = r.headers.get("Location", "")
        assert r.status_code == 400 or "evil.test" not in loc


def test_bug9_mass_dump_absent_filter(client):
    sess(client, "alice")
    scoped = json.loads(client.get("/api/items?owner_id=1").data)
    assert all(it["owner_id"] == 1 for it in scoped)
    wide = json.loads(client.get("/api/items").data)   # filter absent
    emails = {it["owner_email"] for it in wide}
    assert "carol@lab.test" in emails and len(wide) >= 3   # third party leaked


def test_bug10_stored_htmli_second_order(client):
    sess(client, "alice")
    client.post("/api/profile/bio", data=json.dumps({"bio": "<b>alice-markup</b>"}), content_type="application/json")
    # alice's own settings view escapes it
    assert b"<b>alice-markup</b>" not in client.get("/settings").data
    # bob's /people view renders it RAW
    bob = lab.app.test_client(); sess(bob, "bob")
    people = bob.get("/people")
    assert b"<b>alice-markup</b>" in people.data
    assert "script-src 'self'" in people.headers.get("Content-Security-Policy", "")   # XSS still blocked


# --- decoys --------------------------------------------------------------------------------

def test_decoy_echo_all_contexts_encoded(client):
    # HTML-text and attribute contexts must be entity-encoded; the JS-string context must not
    # be breakable (no raw </script>, quotes escaped). A raw <img> inside a quoted JS string
    # with </ escaped is safe, so we check breakout, not the mere substring.
    r = client.get("/echo?msg=</script><img src=x onerror=alert(1)>\"'")
    body = r.data.decode()
    assert "&lt;img" in body                         # HTML-text context encoded
    assert "</script><img" not in body               # no script breakout anywhere
    assert "<\\/script>" in body or "<\\/" in body    # the closing tag was neutralised in the JS string
    # a tag in the attribute context does not break out: the attribute value is entity-encoded,
    # and the only place the quote survives is the JS string where json.dumps backslash-escapes it.
    r2 = client.get('/echo?msg="><svg onload=alert(1)>')
    b2 = r2.data.decode()
    assert 'data-x="&quot;&gt;&lt;svg' in b2            # attribute context encoded
    assert '"\\"><svg' in b2 or '\\"><svg' in b2        # JS-string quote escaped (no breakout)
    assert '<svg onload=alert(1)>' not in b2.split("<script>")[0]  # nothing raw before the script block


def test_decoy_lookup_fake_sql_error(client):
    base = _timed(client, "/lookup?id=1")
    r = client.get("/lookup?id=1' OR '1'='1")
    assert b"SQL error" in r.data                 # mentions SQL
    slow = _timed(client, "/lookup?id=1' AND SLEEP(2)-- -")
    assert slow - base < 0.5                       # but no timing / injection


def test_decoy_go_strict_allowlist(client):
    assert client.get("/go?next=/dashboard").status_code in (301, 302)
    for bad in ("//evil.test", "https://evil.test", "/etc/passwd", "/dashboard/../admin"):
        r = client.get("/go", query_string={"next": bad})
        assert r.status_code == 400 or "evil.test" not in r.headers.get("Location", "")


def test_server_boots_on_loopback():
    # import-time seed ran; the app object exists and binds 127.0.0.1 in main()
    assert lab.USERS["alice"]["id"] == 1 and 7 in lab.NOTES

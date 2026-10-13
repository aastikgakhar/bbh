"""Request normalisation: path templates, families, input extraction, value typing,
endpoint flags. Stdlib only."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from .httpraw import Request

_UUID = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_B64 = re.compile(r"^[A-Za-z0-9_\-+/=]{16,}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_EMAIL = re.compile(r"^[^@/\s]+@[^@/\s]+\.[a-z]{2,}$", re.I)
_NUM = re.compile(r"^-?\d+$")

MUTATING_VERBS = {
    "delete", "remove", "destroy", "update", "set", "toggle", "enable", "disable", "approve", "accept", "reject",
    "confirm", "unsubscribe", "subscribe", "logout", "signout", "revoke", "cancel", "archive", "publish", "follow",
    "unfollow", "like", "unlike", "vote", "transfer", "redeem", "apply", "claim", "reset", "verify", "activate",
    "deactivate", "invite", "join", "leave", "share", "unshare", "rename", "move", "restore", "purge",
}
LIST_WORDS = {"search", "list", "export", "sync", "batch", "feed", "items", "all", "query", "find", "browse", "report", "reports", "download"}
REDIRECT_NAMES = {"url", "next", "redirect", "redirect_uri", "redirect_url", "return_to", "returnto", "returnurl", "return_url",
                  "return", "continue", "callback", "callback_url", "dest", "destination", "goto", "go", "u", "r", "target",
                  "to", "out", "link", "forward", "redir", "uri", "path", "image_url", "img", "src", "webhook", "feed", "host", "domain"}
SORT_NAMES = {"sort", "sortby", "sort_by", "order", "orderby", "order_by", "column", "col", "dir", "direction", "sortfield", "sort_field", "field", "fields"}
DATASTORE_NAMES = {"id", "q", "query", "search", "filter", "term", "keyword", "keywords", "name", "email", "user", "username",
                   "category", "type", "status", "limit", "offset", "page", "per_page", "count", "from", "to", "start", "end"}
LIMIT_NAMES = {"coupon", "code", "promo", "voucher", "redeem", "invite", "token", "otp", "vote", "like", "credit", "credits",
               "quota", "limit", "claim", "transfer", "amount", "seat", "seats", "gift", "referral"}
FILE_NAMES = {"file", "filename", "path", "dir", "folder", "template", "page", "include", "doc", "document", "download", "attachment", "name", "image", "img"}
# Inputs whose name suggests the value reaches an OS command (a ping/dig/convert/backup backend).
# Tight on purpose: command_injection is otherwise opened only by the 500-escalation, to keep cost down.
COMMAND_NAMES = {"cmd", "command", "exec", "execute", "run", "ping", "host", "hostname", "domain",
                 "dns", "nslookup", "lookup", "shell", "process", "jobname", "script", "target", "action"}
BROWSER_HEADERS = {
    "host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "content-length", "content-type",
    "cookie", "authorization", "origin", "referer", "upgrade-insecure-requests", "cache-control", "pragma", "te",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "sec-gpc", "dnt", "priority", "if-none-match", "if-modified-since", "range", "x-requested-with",
    "content-encoding", "keep-alive", "purpose", "sec-purpose", "x-forwarded-for",
}


def classify_segment(seg: str) -> str | None:
    if not seg:
        return None
    if _NUM.match(seg) or _UUID.match(seg) or _HEX.match(seg) or _EMAIL.match(seg):
        return "{id}"
    if _DATE.match(seg):
        return "{date}"
    if len(seg) >= 16 and _B64.match(seg) and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg):
        return "{id}"
    if len(seg) >= 12 and re.search(r"\d", seg) and re.search(r"[a-z]", seg, re.I) and re.match(r"^[A-Za-z0-9_-]+$", seg) \
            and sum(ch.isdigit() for ch in seg) >= 3:
        return "{id}"
    return None


def path_template(path: str) -> tuple[str, list[tuple[int, str]]]:
    """'/api/notes/7/edit' -> ('/api/notes/{id}/edit', [(2, '7')])  (index among segments)."""
    segs = (path or "/").split("/")
    out, params = [], []
    for i, seg in enumerate(segs):
        repl = classify_segment(seg)
        if repl:
            out.append(repl)
            params.append((i - 1, seg))  # index among segments after the leading ""
        else:
            out.append(seg)
    tpl = "/".join(out) or "/"
    return (tpl if tpl.startswith("/") else "/" + tpl), params


def family_of(path_tpl: str) -> str:
    segs = [s for s in path_tpl.split("/") if s]
    while segs and segs[-1].startswith("{"):
        segs.pop()
    segs = [s for s in segs if not s.startswith("{")][:3]
    return "/" + "/".join(segs)


def feature_of(path_tpl: str) -> str:
    for s in [s for s in path_tpl.split("/") if s and not s.startswith("{")]:
        if s.lower() in ("api", "rest", "rpc", "internal", "public", "v1", "v2", "v3", "v4") or re.match(r"^v\d+$", s, re.I):
            continue
        return re.sub(r"[^a-z0-9_-]", "", s.lower())[:40] or "root"
    return "home"


def value_type(value: str | None) -> str:
    if value is None or value == "":
        return "empty"
    v = str(value)
    if v.lower() in ("true", "false"):
        return "bool"
    if _NUM.match(v):
        return "int"
    if _UUID.match(v):
        return "uuid"
    if _EMAIL.match(v):
        return "email"
    if re.match(r"^(https?:)?//", v, re.I) or re.match(r"^https?%3a", v, re.I):
        return "url"
    if re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?$", v, re.I) and not re.match(r"^[\d.]+$", v):
        return "host"
    if v.startswith("/") or re.search(r"[\\/]", v) or re.match(r"^[\w.-]+\.(pdf|png|jpe?g|gif|svg|txt|csv|json|xml|html?|docx?|xlsx?|zip|js|css|md)$", v, re.I):
        return "path"
    if v[:1] in "[{":
        try:
            json.loads(v)
            return "json"
        except ValueError:
            pass
    if len(v) >= 16 and _B64.match(v):
        try:
            base64.b64decode(v + "=" * (-len(v) % 4), validate=False)
            return "base64"
        except (binascii.Error, ValueError):
            pass
    return "string"


@dataclass
class InputSpec:
    name: str
    location: str
    sample: str | None
    json_path: str | None = None
    vtype: str = "string"
    path_index: int | None = None


@dataclass
class Normalised:
    origin: str
    host: str
    method: str
    path_template: str
    family: str
    feature: str
    inputs: list[InputSpec] = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    content_type: str | None = None
    body_kind: str = "none"


def _flatten_json(obj, prefix: str = "", depth: int = 0, out: list | None = None) -> list[tuple[str, object]]:
    out = [] if out is None else out
    if len(out) >= 60 or depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten_json(v, f"{prefix}.{k}" if prefix else str(k), depth + 1, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            _flatten_json(v, f"{prefix}[{i}]", depth + 1, out)
    else:
        out.append((prefix or "$", obj))
    return out


def _multipart_fields(body: bytes, content_type_header: str) -> list[tuple[str, str | None, str]]:
    """[(field_name, filename_or_None, value_preview)]"""
    m = re.search(r'boundary="?([^";]+)"?', content_type_header or "", re.I)
    if not m:
        return []
    boundary = ("--" + m.group(1)).encode()
    out = []
    for part in body.split(boundary):
        head, _, val = part.partition(b"\r\n\r\n")
        disp = re.search(rb'name="([^"]*)"(?:;\s*filename="([^"]*)")?', head)
        if not disp:
            continue
        name = disp.group(1).decode("latin-1")
        fname = disp.group(2).decode("latin-1") if disp.group(2) is not None else None
        out.append((name, fname, val.rstrip(b"\r\n-")[:200].decode("utf-8", "replace")))
    return out


def body_kind_of(req: Request) -> str:
    ct = req.content_type
    if not req.body:
        return "none"
    if "json" in ct:
        return "json"
    if "x-www-form-urlencoded" in ct:
        return "form"
    if "multipart" in ct:
        return "multipart"
    if "xml" in ct:
        return "xml"
    stripped = req.body.lstrip()[:1]
    if stripped in (b"{", b"["):
        return "json"
    if stripped == b"<":
        return "xml"
    return "text"


def is_graphql(req: Request) -> bool:
    if "graphql" in urlsplit(req.url).path.lower():
        return True
    if body_kind_of(req) == "json":
        try:
            d = json.loads(req.body)
        except ValueError:
            return False
        items = d if isinstance(d, list) else [d]
        return any(isinstance(x, dict) and isinstance(x.get("query"), str) and re.match(r"^\s*(query|mutation|subscription|\{)", x["query"]) for x in items)
    return False


def normalise(req: Request, *, auth_header_names: set[str] | None = None, auth_cookie_names: set[str] | None = None) -> Normalised:
    parts = urlsplit(req.url)
    host = (parts.hostname or "").lower()
    origin = f"{parts.scheme}://{parts.netloc.split('@')[-1]}"
    tpl, path_params = path_template(parts.path or "/")
    method = req.method.upper()
    n = Normalised(origin=origin, host=host, method=method, path_template=tpl, family=family_of(tpl),
                   feature=feature_of(tpl), content_type=req.content_type or None, body_kind=body_kind_of(req))
    auth_header_names = {h.lower() for h in (auth_header_names or set())} | {"authorization", "cookie"}
    auth_cookie_names = set(auth_cookie_names or set())

    for idx, (seg_index, value) in enumerate(path_params):
        n.inputs.append(InputSpec(name="id" if idx == 0 else f"id{idx + 1}", location="path", sample=value,
                                  vtype=value_type(value), path_index=seg_index))
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if not any(i.location == "query" and i.name == k for i in n.inputs):
            n.inputs.append(InputSpec(name=k, location="query", sample=v, vtype=value_type(v)))
    kind = n.body_kind
    if kind == "form":
        for k, v in parse_qsl(req.body.decode("utf-8", "replace"), keep_blank_values=True):
            if not any(i.location == "form" and i.name == k for i in n.inputs):
                n.inputs.append(InputSpec(name=k, location="form", sample=v, vtype=value_type(v)))
    elif kind == "json":
        try:
            data = json.loads(req.body)
        except ValueError:
            data = None
        if data is not None:
            for path, v in _flatten_json(data):
                sv = json.dumps(v) if not isinstance(v, str) else v
                n.inputs.append(InputSpec(name=path, location="json", json_path=path, sample=sv,
                                          vtype=value_type(sv) if isinstance(v, str) else ("int" if isinstance(v, int) and not isinstance(v, bool) else "json")))
    elif kind == "multipart":
        for name, fname, preview in _multipart_fields(req.body, req.header("Content-Type") or ""):
            if fname is not None:
                n.inputs.append(InputSpec(name=name, location="filename", sample=fname, vtype="path"))
            else:
                n.inputs.append(InputSpec(name=name, location="multipart", sample=preview, vtype=value_type(preview)))
    cookie = req.header("Cookie") or ""
    for chunk in cookie.split(";"):
        if "=" in chunk:
            k, _, v = chunk.strip().partition("=")
            if k and k not in auth_cookie_names and not re.search(r"sess|auth|token|jwt|sid|csrf|xsrf", k, re.I):
                n.inputs.append(InputSpec(name=k, location="cookie", sample=v, vtype=value_type(v)))
    for k, v in req.headers:
        kl = k.lower()
        if kl in BROWSER_HEADERS or kl in auth_header_names or kl.startswith(("sec-", "x-csrf", "x-xsrf")):
            continue
        n.inputs.append(InputSpec(name=k, location="header", sample=v, vtype=value_type(v)))

    path_words = {w for w in re.split(r"[/_.\-]", tpl.lower()) if w}
    last_static = next((s for s in reversed(tpl.split("/")) if s and not s.startswith("{")), "")
    state_changing = method not in ("GET", "HEAD", "OPTIONS") or bool(path_words & MUTATING_VERBS)
    n.flags = {
        "state_changing": state_changing,
        "mutating_get": method == "GET" and bool(path_words & MUTATING_VERBS),
        "list_endpoint": (method in ("GET", "POST") and (bool(path_words & LIST_WORDS) or (last_static.endswith("s") and not tpl.rstrip("/").endswith("}")))),
        "graphql": is_graphql(req),
        "upload": any(i.location == "filename" for i in n.inputs),
        "xml_body": kind == "xml",
        "json_body": kind == "json",
        "login": bool(path_words & {"login", "signin", "sign-in", "session", "sessions", "authenticate", "token"}) and method == "POST",
        "logout": bool(path_words & {"logout", "signout", "sign-out", "logoff"}),
        "auth_required": bool(req.header("Cookie") or req.header("Authorization")),
        "static_asset": bool(re.search(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp|mp4|pdf)$", tpl, re.I)),
        "limit": bool(path_words & LIMIT_NAMES),
    }
    return n


def input_roles(spec: InputSpec) -> set[str]:
    """Rule signals for one input (used by the planner)."""
    name = spec.name.lower().split(".")[-1].split("[")[0]
    roles: set[str] = set()
    if spec.vtype in ("url", "host") or name in REDIRECT_NAMES:
        roles.add("url_like")
    if name in SORT_NAMES:
        roles.add("orderby")
    if spec.vtype in ("int", "uuid", "base64") or name in ("id", "uid", "user_id", "userid") or name.endswith(("_id", "id")):
        roles.add("object_id")
    if spec.location in ("query", "form", "json", "multipart", "header", "path", "cookie") and (
            spec.vtype in ("int", "uuid") or name in DATASTORE_NAMES or name in SORT_NAMES or spec.location == "json"
            or name.endswith(("_id", "id")) or spec.vtype == "string"):
        roles.add("datastore")
    if spec.location == "filename" or name in FILE_NAMES or (spec.vtype == "path" and spec.location != "path"):
        roles.add("file_like")
    if name in LIMIT_NAMES:
        roles.add("limit_like")
    if name in COMMAND_NAMES:
        roles.add("command_like")
    return roles

"""Apply a case's mutation ops to a copy of the base request. Stdlib only.

Value encoding: values are DECODED strings. For query, form, path and cookie
locations they are percent-encoded on the way out, except that %XX sequences
already present are preserved, so "%0d%0a" and double-encoded "%253C" payloads
reach the wire exactly as written. An op with "raw": true is inserted verbatim
(only space, '#', CR and LF are escaped in URLs, because they cannot travel raw).
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from .httpraw import Request
from .normalise import body_kind_of

_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
UNRESERVED = "-._~"


class MutationError(ValueError):
    pass


@dataclass
class InputRef:
    name: str | None
    location: str | None
    json_path: str | None = None
    path_index: int | None = None


def quote_value(value: str, *, raw: bool = False, safe: str = "") -> str:
    """Percent-encode a decoded value, preserving existing %XX escapes."""
    if raw:
        return value.replace(" ", "%20").replace("#", "%23").replace("\r", "%0D").replace("\n", "%0A")
    out, i = [], 0
    while i < len(value):
        m = _PCT.match(value, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        out.append(quote(value[i], safe=UNRESERVED + safe))
        i += 1
    return "".join(out)


def _wire_pairs(qs: str) -> list[list[str]]:
    """Split a query/form string into [decoded_name, wire_name, wire_value] keeping wire text."""
    from urllib.parse import unquote_plus

    out = []
    for chunk in qs.split("&") if qs else []:
        if not chunk:
            continue
        k, sep, v = chunk.partition("=")
        out.append([unquote_plus(k), k, v if sep else ""])
    return out


def _apply_pairs(pairs: list[list[str]], name: str, value, raw: bool, mode: str) -> list[list[str]]:
    wire_v = None if value is None else quote_value(str(value), raw=raw)
    new, done = [], False
    for dn, wn, wv in pairs:
        if dn == name and mode == "remove":
            continue
        if dn == name and not done:
            done = True
            if mode == "set":
                new.append([dn, wn, wire_v])
            elif mode == "duplicate_after":
                new += [[dn, wn, wv], [dn, wn, wire_v]]
            elif mode == "duplicate_before":
                new += [[dn, wn, wire_v], [dn, wn, wv]]
            continue
        new.append([dn, wn, wv])
    if not done and mode != "remove":
        new.append([name, quote_value(name, safe="[]$"), wire_v])
    return new


def _join_pairs(pairs: list[list[str]]) -> str:
    return "&".join(f"{wn}={wv}" for _, wn, wv in pairs)


def _json_get_set(data: Any, path: str, value: Any = None, *, mode: str = "set") -> Any:
    tokens = re.findall(r"[^.\[\]]+|\[\d+\]", path)
    if path in ("$", ""):
        return value if mode == "set" else data
    cur = data
    for i, tok in enumerate(tokens):
        last = i == len(tokens) - 1
        key: Any = int(tok[1:-1]) if tok.startswith("[") else tok
        if last:
            if mode == "set":
                cur[key] = value
            elif mode == "get":
                return cur[key]
            elif mode == "del":
                del cur[key]
            return data
        cur = cur[key]
    return data


def _body_as_dict(req: Request) -> dict:
    kind = body_kind_of(req)
    if kind == "json":
        try:
            d = json.loads(req.body)
            return d if isinstance(d, dict) else {"data": d}
        except ValueError:
            return {}
    if kind in ("form", "text") and req.body:
        return {k: v for k, v in parse_qsl(req.body.decode("utf-8", "replace"), keep_blank_values=True)}
    if kind == "multipart":
        from .normalise import _multipart_fields

        return {n: v for n, f, v in _multipart_fields(req.body, req.header("Content-Type") or "") if f is None}
    return {}


def _multipart(fields: dict, files: dict | None = None) -> tuple[bytes, str]:
    boundary = "----" + secrets.token_hex(12)
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, (fname, ctype, content) in (files or {}).items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{fname}"\r\nContent-Type: {ctype}\r\n\r\n'.encode()
                     + (content if isinstance(content, bytes) else str(content).encode()) + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _set_cookie(req: Request, name: str, value: str | None) -> None:
    jar = []
    for chunk in (req.header("Cookie") or "").split(";"):
        if "=" in chunk:
            k, _, v = chunk.strip().partition("=")
            if k != name:
                jar.append(f"{k}={v}")
    if value is not None:
        jar.append(f"{name}={quote_value(value, safe='=/+')}")
    if jar:
        req.set_header("Cookie", "; ".join(jar))
    else:
        req.remove_header("Cookie")


def _set_location(req: Request, loc: str, name: str, value: Any, *, raw: bool = False, json_value: bool = False,
                  ref: InputRef | None = None, mode: str = "set") -> None:
    """mode: set | remove | duplicate_after | duplicate_before"""
    parts = urlsplit(req.url)
    if loc == "query":
        pairs = _apply_pairs(_wire_pairs(parts.query), name, value, raw, mode)
        req.url = urlunsplit((parts.scheme, parts.netloc, parts.path, _join_pairs(pairs), parts.fragment))
    elif loc == "form":
        pairs = _apply_pairs(_wire_pairs(req.body.decode("latin-1") if req.body else ""), name, value, raw, mode)
        req.body = _join_pairs(pairs).encode("latin-1", "replace")
        if not req.content_type:
            req.set_header("Content-Type", "application/x-www-form-urlencoded")
    elif loc == "json":
        try:
            data = json.loads(req.body) if req.body else {}
        except ValueError:
            data = {}
        path = (ref.json_path if ref and ref.name == name and ref.json_path else None) or name
        if mode == "remove":
            try:
                _json_get_set(data, path, mode="del")
            except (KeyError, IndexError, TypeError):
                pass
        elif mode.startswith("duplicate"):
            # JSON has no duplicate keys in a dict model: write raw text with the key twice
            body = json.dumps(data)
            dup = json.dumps({path.split(".")[-1]: value if json_value else str(value)})[1:-1]
            req.body = (body[:-1] + (", " if len(body) > 2 else "") + dup + "}").encode() if body.endswith("}") else body.encode()
            req.set_header("Content-Type", "application/json")
            return
        else:
            v = value if json_value else str(value)
            try:
                _json_get_set(data, path, v)
            except (KeyError, IndexError, TypeError):
                if isinstance(data, dict):
                    data[path] = v
        req.body = json.dumps(data).encode()
        req.set_header("Content-Type", "application/json")
    elif loc == "header":
        if mode == "remove":
            req.remove_header(name)
        elif mode.startswith("duplicate"):
            req.headers.append((name, str(value)))
        else:
            req.set_header(name, str(value))
    elif loc == "cookie":
        _set_cookie(req, name, None if mode == "remove" else str(value))
    elif loc == "path":
        segs = (parts.path or "/").split("/")
        idx = (ref.path_index if ref and ref.path_index is not None else None)
        if idx is None:
            raise MutationError("path input has no segment index")
        real = idx + 1  # account for the leading ""
        if real >= len(segs):
            raise MutationError(f"path segment {idx} does not exist in {parts.path}")
        if mode == "remove":
            del segs[real]
        else:
            segs[real] = str(value) if raw else quote_value(str(value), safe="")
        req.url = urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, parts.fragment))
    elif loc in ("multipart", "filename"):
        fields = _body_as_dict(req)
        files: dict = {}
        # keep original file parts
        from .normalise import _multipart_fields

        for n, fname, prev in _multipart_fields(req.body, req.header("Content-Type") or ""):
            if fname is not None:
                files[n] = (fname, "application/octet-stream", prev)
        if loc == "multipart":
            if mode == "remove":
                fields.pop(name, None)
            else:
                fields[name] = str(value)
        else:
            old = files.get(name, ("upload.bin", "application/octet-stream", b""))
            if mode == "remove":
                files.pop(name, None)
            else:
                files[name] = (str(value), old[1], old[2])
        req.body, ctype = _multipart(fields, files)
        req.set_header("Content-Type", ctype)
    else:
        raise MutationError(f"unknown location {loc!r}")


def _current_value(req: Request, ref: InputRef) -> str:
    parts = urlsplit(req.url)
    if ref.location == "query":
        return next((v for k, v in parse_qsl(parts.query, keep_blank_values=True) if k == ref.name), "")
    if ref.location == "form":
        return next((v for k, v in parse_qsl(req.body.decode("utf-8", "replace"), keep_blank_values=True) if k == ref.name), "")
    if ref.location == "json":
        try:
            v = _json_get_set(json.loads(req.body), ref.json_path or ref.name or "$", mode="get")
            return v if isinstance(v, str) else json.dumps(v)
        except (ValueError, KeyError, IndexError, TypeError):
            return ""
    if ref.location == "header":
        return req.header(ref.name or "") or ""
    if ref.location == "cookie":
        for chunk in (req.header("Cookie") or "").split(";"):
            k, _, v = chunk.strip().partition("=")
            if k == ref.name:
                return v
        return ""
    if ref.location == "path" and ref.path_index is not None:
        segs = (parts.path or "/").split("/")
        return segs[ref.path_index + 1] if ref.path_index + 1 < len(segs) else ""
    if ref.location in ("multipart", "filename"):
        from .normalise import _multipart_fields

        for n, fname, prev in _multipart_fields(req.body, req.header("Content-Type") or ""):
            if n == ref.name:
                return fname if ref.location == "filename" else prev
    return ""


def reencode_body(req: Request, content_type: str) -> None:
    fields = _body_as_dict(req)
    ct = content_type.lower()
    if ct.startswith("application/json"):
        req.body = json.dumps(fields).encode()
    elif ct.startswith("application/x-www-form-urlencoded"):
        req.body = "&".join(f"{quote_value(str(k))}={quote_value(str(v) if not isinstance(v, (dict, list)) else json.dumps(v))}" for k, v in fields.items()).encode()
    elif ct.startswith("multipart/form-data"):
        req.body, content_type = _multipart({k: (v if isinstance(v, str) else json.dumps(v)) for k, v in fields.items()})
    elif ct.startswith("text/plain"):
        # the classic CSRF shape: keep a JSON body but label it text/plain
        if body_kind_of(req) != "json":
            req.body = json.dumps(fields).encode()
    elif "xml" in ct:
        inner = "".join(f"<{k}>{_xml_escape(v if isinstance(v, str) else json.dumps(v))}</{k}>" for k, v in fields.items())
        req.body = f'<?xml version="1.0" encoding="UTF-8"?><root>{inner}</root>'.encode()
    req.set_header("Content-Type", content_type)


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def apply(base: Request, ops: list[dict], ref: InputRef, *, substitute: Callable[[Any], Any] | None = None,
          strip_auth: Callable[[Request], None] | None = None) -> tuple[Request, str | None]:
    """Return (mutated request, principal override or None)."""
    req = base.copy()
    sub = substitute or (lambda v: v)
    principal = None
    for op in ops:
        name = op.get("op")
        raw = bool(op.get("raw"))
        if name in ("set_input", "append_input", "prepend_input", "remove_input", "duplicate_input", "set_input_json", "move_input"):
            if not ref.location:
                raise MutationError(f"{name} needs an input-level cell")
        if name == "set_input":
            _set_location(req, ref.location, ref.name, sub(op["value"]), raw=raw, ref=ref)
        elif name == "set_input_json":
            if ref.location != "json":
                # operator injection on non-JSON inputs travels as bracketed keys
                val = sub(op["value"])
                if isinstance(val, dict):
                    for k, v in val.items():
                        _set_location(req, ref.location, ref.name, None, ref=ref, mode="remove")
                        _set_location(req, ref.location, f"{ref.name}[{k}]", json.dumps(v) if not isinstance(v, str) else v, raw=raw, ref=ref)
                elif isinstance(val, list):
                    _set_location(req, ref.location, ref.name, None, ref=ref, mode="remove")
                    for v in val:
                        _set_location(req, ref.location, f"{ref.name}[]", str(v), raw=raw, ref=ref, mode="duplicate_after")
                else:
                    _set_location(req, ref.location, ref.name, json.dumps(val) if not isinstance(val, str) else val, raw=raw, ref=ref)
            else:
                _set_location(req, "json", ref.name, sub(op["value"]), json_value=True, ref=ref)
        elif name == "append_input":
            _set_location(req, ref.location, ref.name, _current_value(base, ref) + sub(op["value"]), raw=raw, ref=ref)
        elif name == "prepend_input":
            _set_location(req, ref.location, ref.name, sub(op["value"]) + _current_value(base, ref), raw=raw, ref=ref)
        elif name == "remove_input":
            _set_location(req, ref.location, ref.name, None, ref=ref, mode="remove")
        elif name == "duplicate_input":
            pos = op.get("position", "after")
            _set_location(req, ref.location, ref.name, sub(op["value"]), raw=raw, ref=ref,
                          mode="duplicate_before" if pos == "before" else "duplicate_after")
        elif name == "move_input":
            value = sub(op["value"]) if "value" in op else _current_value(req, ref)
            _set_location(req, ref.location, ref.name, None, ref=ref, mode="remove")
            to = op["to"]
            if to == "json" and body_kind_of(req) != "json":
                fields = _body_as_dict(req)
                fields[ref.name] = value
                req.body = json.dumps(fields).encode()
                req.set_header("Content-Type", "application/json")
            elif to == "form" and body_kind_of(req) not in ("form", "none"):
                fields = _body_as_dict(req)
                fields[ref.name] = value
                req.body = "&".join(f"{quote_value(str(k))}={quote_value(str(v))}" for k, v in fields.items()).encode()
                req.set_header("Content-Type", "application/x-www-form-urlencoded")
            else:
                _set_location(req, to, ref.name, value, raw=raw, ref=InputRef(ref.name, to))
            if to in ("form", "json") and req.method in ("GET", "HEAD"):
                req.method = "POST"
        elif name == "set_param":
            val = sub(op["value"])
            loc = op["location"]
            if loc == "json":
                _set_location(req, "json", op["name"], val, json_value=not isinstance(val, str), ref=InputRef(op["name"], "json", op["name"]))
            else:
                _set_location(req, loc, op["name"], val if isinstance(val, str) else json.dumps(val), raw=raw, ref=InputRef(op["name"], loc))
        elif name == "remove_param":
            _set_location(req, op["location"], op["name"], None, ref=InputRef(op["name"], op["location"], op["name"]), mode="remove")
        elif name == "set_header":
            req.set_header(op["name"], str(sub(op["value"])))
        elif name == "remove_header":
            req.remove_header(op["name"])
        elif name == "set_method":
            req.method = str(op["method"]).upper()
        elif name == "set_content_type":
            if op.get("reencode", True):
                reencode_body(req, op["value"])
            else:
                req.set_header("Content-Type", op["value"])
        elif name == "replace_body":
            body = sub(op["body"])
            req.body = body.encode() if isinstance(body, str) else bytes(body)
            if op.get("content_type"):
                req.set_header("Content-Type", op["content_type"])
        elif name in ("set_path", "append_path", "set_path_segment", "set_query_raw"):
            p = urlsplit(req.url)
            path, query = p.path or "/", p.query
            if name == "set_path":
                path = sub(op["path"])
            elif name == "append_path":
                path = path.rstrip("/") + sub(op["suffix"]) if not sub(op["suffix"]).startswith(";") else path + sub(op["suffix"])
            elif name == "set_path_segment":
                segs = path.split("/")
                i = int(op["index"]) + 1
                if i >= len(segs):
                    raise MutationError(f"path has no segment {op['index']}")
                segs[i] = sub(op["value"])
                path = "/".join(segs)
            else:
                query = sub(op["query"])
            req.url = urlunsplit((p.scheme, p.netloc, path, query, p.fragment))
        elif name == "as_principal":
            principal = op["principal"]
        elif name == "strip_auth":
            if strip_auth:
                strip_auth(req)
            else:
                req.remove_header("Cookie")
                req.remove_header("Authorization")
            principal = "unauth"
        elif name == "set_cookie":
            _set_cookie(req, op["name"], str(sub(op["value"])))
        elif name == "remove_cookie":
            _set_cookie(req, op["name"], None)
        else:
            raise MutationError(f"unknown op {name!r}")
    if req.method in ("GET", "HEAD") and req.body and not any(o.get("op") in ("replace_body",) for o in ops):
        # a moved-away body on a GET stays empty unless the case set one explicitly
        pass
    return req, principal

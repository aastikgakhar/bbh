"""Principal session material in captures/session-<label>.txt. Stdlib only.

Format: one "Header-Name: value" per line (Cookie, Authorization, X-CSRF-Token,
any app-specific auth header). Lines starting with '#' are comments. The file is
re-read on every send so a refreshed session is picked up immediately and
verification always uses fresh material.
"""

from __future__ import annotations

import re
import time
from http.cookies import SimpleCookie
from pathlib import Path

AUTH_HEADER_HINT = re.compile(r"^(cookie|authorization|x-(csrf|xsrf)[-\w]*|x-auth[-\w]*|x-api-key|x-access-token|x-session[-\w]*|x-user-token)$", re.I)


def read(path: Path) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out.append((k.strip(), v.strip()))
    return out


def write(path: Path, headers: list[tuple[str, str]], *, note: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# session material written {time.strftime('%Y-%m-%d %H:%M:%S')} {note}".rstrip()]
    lines += [f"{k}: {v}" for k, v in headers]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def from_request_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(k, v) for k, v in headers if AUTH_HEADER_HINT.match(k)]


def from_set_cookie(set_cookie_values: list[str], existing_cookie: str | None = None) -> str:
    """Merge Set-Cookie values into a Cookie header value."""
    jar: dict[str, str] = {}
    for chunk in (existing_cookie or "").split(";"):
        if "=" in chunk:
            k, _, v = chunk.strip().partition("=")
            jar[k] = v
    for sc in set_cookie_values:
        c = SimpleCookie()
        try:
            c.load(sc)
        except Exception:  # noqa: BLE001 - malformed cookie headers are skipped
            m = re.match(r"\s*([^=;\s]+)=([^;]*)", sc)
            if m:
                jar[m.group(1)] = m.group(2)
            continue
        for k, morsel in c.items():
            if morsel.get("max-age") == "0" or (morsel.get("expires") and "1970" in morsel.get("expires")):
                jar.pop(k, None)
            else:
                jar[k] = morsel.value
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def all_auth_header_names(files: list[Path]) -> set[str]:
    names = {"cookie", "authorization"}
    for f in files:
        names |= {k.lower() for k, _ in read(f)}
    return names


def cookie_names(headers: list[tuple[str, str]]) -> set[str]:
    out = set()
    for k, v in headers:
        if k.lower() == "cookie":
            for chunk in v.split(";"):
                if "=" in chunk:
                    out.add(chunk.strip().split("=", 1)[0])
    return out

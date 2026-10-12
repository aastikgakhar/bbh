"""PostToolUse: record owned tabs, ingest Burp tool responses inline, spawn a
throttled detached ingest worker, inject up-to-15-line side guidance when there
is something new, and drop a red-team line after a cell closes negative."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

import _hooklib as h

BURP_HISTORY = ("mcp__burp__get_proxy_http_history", "mcp__burp__get_proxy_http_history_regex")
WORKER_THROTTLE_S = 30


def body(data, root):
    tool = data.get("tool_name", "")
    resp = data.get("tool_response")
    led = None

    # 1. owned-tab ledger: record tab ids the session created
    if tool.endswith(("__tabs_create_mcp", "__browser_create_tab", "__browser_navigate", "__navigate", "__browser_get_new_tab")):
        _record_tab(root, resp)

    try:
        led = h.open_ledger(root)
    except Exception:  # noqa: BLE001
        return
    if not led.engagement().get("configured"):
        return

    lines = []

    # 2. red-team line after a negative close
    if tool.endswith("__close_cell"):
        info = _parse_response(resp)
        cell = (info.get("cell") or {})
        if cell.get("state") == "negative":
            from bbh import classes as C

            prompts_seen = led.kv_get("redteam_counter", 0) or 0
            line = C.redteam_prompt(cell.get("vuln_class", ""), prompts_seen)
            led.kv_set("redteam_counter", prompts_seen + 1)
            lines.append(f"Red-team that negative before moving on: {line}")

    # 3. inline-ingest Burp history responses (already in tool_response, no network)
    if tool in BURP_HISTORY:
        n = _ingest_inline(led, resp)
        if n:
            lines.append(f"Ingested {n} new in-scope request(s) from that Burp page.")

    # 4. throttled detached worker: sync Burp + plan, write guidance for the next PostToolUse
    if tool.startswith(("mcp__burp__", "mcp__browser-mcp__", "mcp__claudecodebrowser__", "mcp__claude-in-chrome__")):
        _maybe_spawn_worker(led, root)

    # 5. consume guidance the previous worker produced, if the agent has not seen it
    g = _fresh_guidance(led, root)
    if g:
        if g.get("new_endpoints"):
            lines.append(f"New endpoints since last check: {len(g['new_endpoints'])} (ids {g['new_endpoints'][:8]}).")
        if g.get("cells_opened"):
            opened = ", ".join(f"{k}:{v}" for k, v in sorted(g["cells_opened"].items()))
            lines.append(f"Cells opened: {opened}.")
        if g.get("foreign_skipped"):
            lines.append(f"({g['foreign_skipped']} out-of-scope requests skipped.)")
        if g.get("top_tasks"):
            lines.append("Top next tasks: " + "; ".join(g["top_tasks"][:3]))

    if lines:
        # throttle generic guidance to once per 30s, but always show a red-team line
        last = led.kv_get("post_guidance_ts", 0) or 0
        is_redteam = any(x.startswith("Red-team") for x in lines)
        if is_redteam or (time.time() - last) >= WORKER_THROTTLE_S:
            led.kv_set("post_guidance_ts", time.time())
            text = "bbh: " + " ".join(lines[:6])
            h.post_context(text[:1500])


def _record_tab(root, resp):
    try:
        info = _parse_response(resp)
        tab = info.get("tab") or info
        tid = tab.get("id") or tab.get("tab_id") or tab.get("tabId")
        if tid is None:
            return
        import json as _j
        from pathlib import Path

        f = Path(root) / ".bbh" / "owned_tabs.json"
        owned = []
        if f.exists():
            owned = _j.loads(f.read_text(encoding="utf-8") or "[]")
        if tid not in owned:
            owned.append(tid)
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(_j.dumps(owned), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def _parse_response(resp):
    if isinstance(resp, dict):
        # MCP tool_response: often {"content":[{"type":"text","text":"{...}"}]}
        if "content" in resp and isinstance(resp["content"], list):
            for c in resp["content"]:
                if isinstance(c, dict) and c.get("type") == "text":
                    try:
                        return json.loads(c["text"])
                    except Exception:  # noqa: BLE001
                        return {}
        return resp
    if isinstance(resp, str):
        try:
            return json.loads(resp)
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _ingest_inline(led, resp):
    text = ""
    if isinstance(resp, dict) and isinstance(resp.get("content"), list):
        text = "".join(c.get("text", "") for c in resp["content"] if isinstance(c, dict))
    elif isinstance(resp, str):
        text = resp
    if not text or "{\"request\":\"" not in text:
        return 0
    from bbh.ingest import IngestReport, parse_record, split_records, infer_scheme, record_exchange
    from bbh.httpraw import Exchange, parse_request, parse_response

    scope = led.scope()
    rep = IngestReport("burp")
    for rec in split_records(text):
        try:
            raw_req, raw_resp, trunc = parse_record(rec)
            scheme = infer_scheme(raw_req, scope)
            req = parse_request(raw_req.encode("utf-8", "surrogateescape"), default_scheme=scheme)
            r = None
            if raw_resp:
                try:
                    r = parse_response(raw_resp.encode("utf-8", "surrogateescape"))
                except Exception:  # noqa: BLE001
                    r = None
            record_exchange(led, Exchange(request=req, response=r), source="burp", truncated=trunc or r is None, report=rep)
        except Exception:  # noqa: BLE001
            continue
    for eid in rep.new_endpoints:
        try:
            from bbh.planner import plan

            plan(led, eid)
        except Exception:  # noqa: BLE001
            pass
    return len(rep.request_ids)


def _maybe_spawn_worker(led, root):
    last = led.kv_get("worker_spawn_ts", 0) or 0
    if time.time() - last < WORKER_THROTTLE_S:
        return
    if (root / ".bbh" / "STOP").exists():
        return
    if not led.engagement().get("burp_mcp_url"):
        return
    led.kv_set("worker_spawn_ts", time.time())
    try:
        server = os.path.join(os.environ.get("CLAUDE_PLUGIN_ROOT", ""), "server")
        env = dict(os.environ)
        env["BBH_ENGAGEMENT_DIR"] = str(root)
        env["PYTHONPATH"] = server + os.pathsep + env.get("PYTHONPATH", "")
        kwargs = {}
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([sys.executable, "-m", "bbh.worker", "ingest"], cwd=str(root), env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, **kwargs)
    except Exception:  # noqa: BLE001
        pass


def _fresh_guidance(led, root):
    f = root / ".bbh" / "guidance.json"
    if not f.exists():
        return None
    try:
        g = json.loads(f.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    seen = led.kv_get("guidance_seen_ts", 0) or 0
    if g.get("ts", 0) <= seen:
        return None
    led.kv_set("guidance_seen_ts", g.get("ts", time.time()))
    if not (g.get("new_endpoints") or g.get("cells_opened")):
        return None
    return g


h.run("post_tool_ingest", body)

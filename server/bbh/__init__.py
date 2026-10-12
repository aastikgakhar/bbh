"""bbh: a discipline harness for authorized bug bounty testing.

Modules imported by hooks must stay stdlib-only: paths, config, scope, hedge,
classes, ledger, tasks, lint, render. Network code (sender, ingest, verify,
browser, oob) may use httpx / mcp / websocket-client.
"""

__version__ = "0.1.0"

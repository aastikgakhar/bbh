# Extending bbh

This is for anyone, human or a fresh AI instance, who wants to make bbh stronger: a new vulnerability class, a new planner rule, a new MCP tool, a new hook, or a new condition/mutation op. It gives the architecture, the exact files to touch, the contract each new piece must meet, the invariants you must not break, and how to run everything.

Read `docs/design.md` for *why* each mechanism exists; this file is the *how*. All paths below are relative to the repo root `C:/Tools/burp-mcp/bbh`. The Python package lives under `server/bbh/`.

---

## Architecture in one pass

Data flows left to right; each stage has one home in the code:

```
prompt.md ──(config.py)──► engagement row
Burp / HAR / browser ──(ingest.py)──► requests ──(normalise.py)──► endpoints + inputs
                                                        │
                                                        ▼
                                              planner.py  ── opens one cell per (endpoint, input, class)
                                                        │          from request/response shape (deterministic rules)
                                                        ▼
                      cases/ generators ── generate(ctx) ──► 10+ cases (control first) per cell
                                                        │          contract in cases/base.py
                                                        ▼
                      runner.py ── builds Ctx, runs each case through ──► sender.py (the ONLY path to the network:
                                                        │                   scope + Rule 0 + kill switch + rate limit + capture)
                                                        ▼
                      evaluate.py ── scores each case's `positive` condition ──► ledger.py (THE source of truth: SQLite/WAL,
                                                        │                            every transition, append-only events)
                                                        ▼
                      verify.py ── replays a finding's assertion twice from a clean state ──► finding `verified`, cell `confirmed`
                                                        │
                                                        ▼
                      render.py ── report-N.md + repro/finding-N.{sh,json} + state.csv / feature-matrix.md / findings-summary.md

Cross-cutting:
  server.py   — 29 MCP tools, thin wrappers over ledger.py / the modules above. Never writes SQL itself.
  tasks.py    — next_task() priority order, open-work counting, depth-queue refill.
  classes.py  — the vuln-class registry: ladders, evidence minimums, n_a reasons, recipes, red-team prompts.
  hooks/      — stdlib-only scripts: inject tasks, guard scope, lint reports, gate Stop. Fail open except scope + kill switch.
```

The one rule that shapes everything: **state lives only in the ledger, and only `ledger.py` writes SQL.** Every other module asks the ledger to make a transition; the ledger refuses invalid ones and reports what is missing.

---

## Recipe 1: add a new vulnerability class

A class is one column in every cell's verdict. Adding one is four edits plus a test.

**1. Register it in `server/bbh/classes.py`.** Add a `_c(...)` entry to the `CLASSES` list:

```python
_c("csp_bypass", "XSS", "endpoint",
   ["directive_relaxed", "inline_executes"], "inline_executes",
   "xss", "CWE-693", ("static_asset", "no_render_path"),
   "Did you read the actual CSP header before theorising, and try every source expression?",
   base_priority=50, description="Content-Security-Policy weakness"),
```

The positional args are `name, column, level, ladder, min_rung, recipe, cwe, na_reasons, redteam`, then keywords. Constraints the tests enforce (`tests/test_scope_planner.py::test_every_class_has_a_recipe_and_na_reasons`):

- `column` must be one of `COLUMNS` (top of the file). Reuse one, or add a new column there (it becomes a matrix column via `column_classes()`).
- `level` is `"input"`, `"endpoint"`, or `"family"` (how the planner opens the cell).
- `ladder` is the rungs in climbing order; `min_rung` must be in `ladder` (the minimum reportable rung).
- `recipe` must be a key in `RECIPES` (which points at a heading in `skills/coverage-matrix/references/classes.md`).
- `na_reasons` must be keys of `NA_REASONS`; add a new reason there first if none fits.
- Optional: `min_cases` (default 10) and `min_techniques` (default 5) to raise the floor; `cross_principal=True` if it needs a second principal; `needs_oob=True` if it can only confirm by out-of-band callback.

If a negative must include specific technique families, add them to `REQUIRED_FAMILIES` (e.g. `"sqli": ("bool", "time")`); for a required passing control family, `REQUIRED_CONTROLS`; if cross-principal writes only count with a counter-read, add the class to `COUNTER_READ_CLASSES`.

**2. Write the generator** in a module under `server/bbh/cases/`. Follow the pattern in `cases/redirect.py` (short and complete):

```python
from .base import Ctx, TestCase
GENERATORS: dict = {}
def _gen(name):
    def deco(fn): GENERATORS[name] = fn; return fn
    return deco

@_gen("csp_bypass")
def gen_csp_bypass(ctx: Ctx) -> list[TestCase]:
    cases = [TestCase(case_no=0, technique="csp_bypass.control.baseline", payload=ctx.sample_value or "x",
                      mutation=[{"op": "set_input", "value": ctx.sample_value or "x"}], is_control=True,
                      positive={"type": "matches_base", "max_len_ratio": 0.5},
                      negative="the unmodified request does not return the baseline, so the tooling is broken")]
    # ... >= 10 non-control cases over >= 5 technique ids ...
    return cases
```

The contract is defined and checked by `cases/base.py::check_contract` (and the module docstring lists every mutation op, condition type, route, and placeholder). It requires:

- case 0 is the control (`is_control=True`), then cases numbered `1..n` with no gaps;
- at least 10 non-control cases spanning at least 5 distinct technique ids, where a technique string is `"<class>.<family>.<variant>"` and the id is `"<class>.<family>"`;
- every required family from `REQUIRED_FAMILIES` (plus `orderby`/`attr`/`js` when the context calls for them) appears;
- every case has a machine-checkable `positive` condition (at most 2 may be `manual`);
- every payload passes `screen_payload` (non-destructive, no stable marker — see invariants);
- **generation is deterministic for a given `ctx.salt`**: build payloads from `ctx.token(n)` / `ctx.number(n)`, never from `random`/`secrets`.

Routes that need extra data: `counter_read` and `race` cases need `extra["counter_read"]` (a request spec); `oob` cases use the `{{OOB}}` placeholder; `browser` cases set `extra["browser"]`. XSS-style script-execution rungs prove execution via `browser_marker` on the `browser` route, not raw reflection.

**3. Wire the module into `server/bbh/cases/__init__.py`.** Add its filename to `FAMILY_MODULES`. `registry()` imports each listed module and merges its `GENERATORS`; **a name with no matching file is silently skipped.** (That is why the current `"template"` entry maps to nothing and `markup.py` actually supplies the `ssti`/`csti` generators — see the inaccuracy note at the end. If you add generators to an existing module, you do not need a new `FAMILY_MODULES` entry.)

**4. Add a representative context to `server/tests/test_cases_contract.py`.** The `CONTEXTS` dict must have an entry for every class, or `test_every_class_has_a_context_and_a_generator` fails:

```python
"csp_bypass": [dict(method="GET", path_template="/app", csp="default-src *")],
```

Each entry is a list of override dicts; the generator must satisfy the contract in every one.

**5. Run the contract tests:**

```
cd C:/Tools/burp-mcp/bbh/server
python -m pytest tests/test_cases_contract.py -q
```

This parametrizes over every class and context and asserts the contract holds, determinism holds, the token has no fixed prefix, and the safety screen accepts your safe payloads / rejects dangerous ones.

---

## Recipe 2: add a planner rule

The planner decides which cells exist. Rules are deterministic and idempotent (they only insert missing cells).

**1. Edit `server/bbh/planner.py::plan()`.** Endpoint-level rules live before the `for spec_row in inputs` loop; input-level rules inside it. Open a cell with the helper:

```python
if flags.get("websocket"):
    _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="ws_hijack")
```

Signals available: endpoint `flags` (`state_changing`, `list_endpoint`, `graphql`, `json_body`, `limit`, `mutating_get`, `xml_body`, `login`, `logout`, ...) come from `normalise.py`; input `roles` come from `normalise.input_roles(spec)` (`url_like`, `datastore`, `object_id`, `file_like`, `orderby`). Family-once classes guard on a `kv_get`/`kv_set` key so they open once per `(origin, family)`. If your rule needs a genuinely new signal, derive it in `normalise.py` first (that is where flags and roles are computed) — the planner only reads what normalisation produced.

**2. Add a test to `server/tests/test_scope_planner.py`** using the `_ep` + `plan` + `classes_opened` helpers already in the file:

```python
def test_websocket_opens_ws_hijack(L):
    eid = _ep(L, "GET", "/socket")
    plan(L, eid)
    assert "ws_hijack" in classes_opened(L, eid)
```

Run `python -m pytest tests/test_scope_planner.py -q`. Keep `test_plan_is_idempotent` green: a second `plan()` must not add or change cells.

---

## Recipe 3: add an MCP tool

**Edit `server/bbh/server.py`.** Add a decorated function; keep it a thin wrapper and return `_err(exc)` on failure:

```python
@mcp.tool()
def my_tool(cell_id: int, flag: bool = False) -> dict:
    """One-line description the agent reads. Say what it does and what it returns."""
    try:
        return {"ok": True, "result": L().my_ledger_method(cell_id, flag)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
```

Rules:

- **No SQL in `server.py`.** The real work belongs in `ledger.py` (state) or the relevant module (`tasks.py`, `render.py`, `oob.py`, the sender, ...). The tool just calls it and shapes the dict.
- Use `L()` for the ledger (a lazy singleton) and `_sender()` when you need the network sender.
- Always wrap in `try/except` returning `_err(exc)`; `_err` surfaces a `LedgerError`'s `missing` list so the agent learns exactly what to fix.
- Return only JSON-serializable values.
- The PreToolUse matcher already covers `mcp__plugin_bbh_bbh__.*`, so no hook change is needed. If a sub-agent should be allowed to call it, add the tool name to that agent's `tools:` list in `agents/*.md` (wildcards are not relied on; tools are listed explicitly).
- There is no separate registry: the `@mcp.tool()` decorator is the registration. Keep `docs/design.md` Section 11 and this repo's counts in sync when you change the tool set.

There is no dedicated unit test per tool; cover the behaviour through the module it wraps (e.g. a `ledger.py` method tested in `tests/test_ledger.py`).

---

## Recipe 4: add a hook

Hooks are stdlib-only scripts that run on Claude Code lifecycle events. They must be fast and fail open.

**1. Write `hooks/<name>.py`** on top of `_hooklib.run`:

```python
from _hooklib import run, post_context  # emit/deny/stop_block/session_context as needed

def _body(data, root):
    # `data` is the hook JSON from stdin; `root` is the resolved engagement dir.
    # Open the ledger only if you need it:
    #   from _hooklib import open_ledger; led = open_ledger(root)
    post_context("a short line injected into the model's context")

if __name__ == "__main__":
    run("my_hook", _body)
```

`run()` reads stdin, resolves the engagement from the payload's `cwd`, **no-ops in any folder without `prompt.md` or `.bbh/`**, enforces a ~1.8 s internal deadline, and on any exception logs to `.bbh/hook.log` and exits 0 (fail open). Import only stdlib and the stdlib-only bbh modules (`paths`, `config`, `scope`, `hedge`, `ledger`, `tasks`, `lint`, `render`); never `httpx` or `mcp` (they would blow the time budget).

Output helpers and what each event honours: `session_context(text)` (SessionStart `additionalContext`), `post_context(text)` (PostToolUse `additionalContext`), `deny(reason)` (PreToolUse `permissionDecision: deny`, works even in bypassPermissions mode), `stop_block(reason)` (Stop/SubagentStop `decision: block`).

**2. Register it in `hooks/hooks.json`** under the event, with the command spelled exactly like the others:

```json
{ "type": "command", "command": "python \"${CLAUDE_PLUGIN_ROOT}/hooks/my_hook.py\"", "timeout": 10 }
```

**3. Verify the matcher.** PreToolUse and PostToolUse entries carry a `matcher` regex against the tool name; confirm it matches the tools you intend (e.g. `mcp__plugin_bbh_bbh__.*|Bash`) and nothing you don't. SessionStart matches on source (`startup|resume|compact|clear`). There is a test harness in `server/tests/test_hooks.py` that drives hook scripts with synthetic payloads; add a case there.

---

## Recipe 5: add a condition or a mutation op

These are the vocabulary cases are written in. A new one is: declare it in the schema, implement it, and document it.

**Mutation op** (transforms the request before sending):

1. Add it to `MUTATION_OPS` in `cases/base.py` (`name -> tuple of required keys`); `validate_mutation` checks those keys, plus the `LOCATIONS` enum for location-bearing ops.
2. Implement it in `mutate.py::apply()` (the `if name == ...` chain). Respect the value-encoding rules at the top of `mutate.py` (decoded values are percent-encoded on the way out; `"raw": true` inserts verbatim).
3. Document it in the `MUTATION OPS` block of the `cases/base.py` module docstring.

**Condition** (scores a case's `positive`):

1. Add it to `CONDITIONS` in `cases/base.py` (`name -> required keys`); `validate_condition` checks them and recurses through `all`/`any`/`not`.
2. Implement it in `evaluate.py::evaluate()`, returning `(result, detail)` where `result` is `True`/`False`, or `None` when it cannot be machine-checked; `detail` is a short factual string **with no hedge words**.
3. If it needs data the evaluator does not yet have (a browser signal, an OOB hit, a counter-read), extend `EvalContext` in `evaluate.py` and populate it in `runner.py` where the exchange is scored.
4. Document it in the `CONDITIONS` block of the `cases/base.py` docstring.

Both are covered by `tests/test_mutate_evaluate.py`; add a case there, then run `python -m pytest tests/test_mutate_evaluate.py tests/test_cases_contract.py -q`.

---

## Invariants you must not break

These are the whole point of the harness. Several are enforced by code and tests; keep them that way.

1. **One cell per transition.** Every ledger transition touches exactly one `cells` row (`WHERE id = ?`). There is no "close all classes on this input" path, and you must never add one. Sibling independence is asserted by snapshotting every other cell before and after each transition type.
2. **The evidence floor.** A cell closes `negative` only with at least 10 negative cases over at least 5 technique ids, at least one `control_pass`, no outstanding `control_fail`, every cited capture present and non-empty, the class's required families, and a counter-read for write classes. Class minimums in `classes.py` may *raise* this; nothing may lower it. A failing control reopens the cell with a tooling note.
3. **No destructive payloads, no evasion.** Every case passes `screen_payload` (`cases/base.py`): no destructive SQL, command execution, file-scheme URLs, system paths, cloud-metadata addresses, recursive entity expansion, or the stable marker `bbh`. Race bursts are capped at 30; cache probes carry a unique buster. The sender records a block, it never works around one.
4. **Scope and Rule 0 live in code.** `add_endpoint`, ingest, and the sender all call `scope.check(url)`; the sender's Rule 0 guard redacts and locks any endpoint that returns data outside the registered test principals. Do not add a path to the network that skips the sender, and do not weaken either guard.
5. **Ladders never downgrade.** `findings.rung_index` only rises (a code check and a SQL trigger both enforce it). A failed climb is appended to `escalation_blocked_by`, and the confirmed rung is kept.
6. **Candidates never die silently.** `candidate -> negative|blocked` requires the `bbh:verifier` agent's sign-off recorded via `verifier_signoff`; the PreToolUse hook refuses that call from any other caller.
7. **Hooks fail open, except scope and the kill switch.** A hook that errors must log and exit 0, never block the session. The scope guard and kill switch are the only hooks allowed to deny when they cannot load the engagement, because failing open there would defeat the control.
8. **No hedge text in ledger fields; reports in the house format.** Observations, reasons, notes and finding text reject hedge words (`hedge.py`); `report-*.md` is linted on every write (`lint.py`).
9. **Determinism.** Generators and canaries are deterministic for a fixed salt, so a regenerated plan is byte-identical.

---

## How to run everything

```
# Unit + integration suite (314 tests): ledger invariants, planner rules, the per-class
# contract, scope, rate limiter, kill switch, report lint, stop gate, finding lifecycle.
cd C:/Tools/burp-mcp/bbh/server
python -m pytest tests/ -q

# Narrow runs while iterating:
python -m pytest tests/test_cases_contract.py -q     # every class generator's contract
python -m pytest tests/test_scope_planner.py -q      # scope grammar + planner rules
python -m pytest tests/test_mutate_evaluate.py -q    # mutation ops + conditions

# The planted-bug lab (binds 127.0.0.1 only):
cd C:/Tools/burp-mcp/bbh/lab
python -m pytest test_lab.py -q          # proves each planted bug fires and each decoy resists
python ../lab/acceptance.py              # drives the WHOLE harness end-to-end; rewrites docs/lab-results.md
python ../lab/run_lab.py --port 5057     # serve the lab to poke by hand (alice/alice-pass, bob/bob-pass)

# Validate the plugin layout:
claude plugin validate C:/Tools/burp-mcp/bbh
```

`acceptance.py` is the regression bar for any change that touches the planner, generators, sender, evaluator, or ledger: it must stay at **10/10 recall, 0 false confirmations, 0 negatives missing evidence**, with sibling independence and the full lifecycle intact (see `docs/lab-results.md`). It starts its own lab on port 5099; `run_lab.py` uses 5057. Use `python`, never `py`.

---

## One inaccuracy to be aware of while extending

`cases/__init__.py` lists `"template"` in `FAMILY_MODULES` and comments it as the home of `ssti`/`csti`, but there is **no `cases/template.py`**: those two generators actually live in `cases/markup.py`, and `registry()` silently skips the missing `template` module. It is harmless today (the generators are registered, every test passes), but if you move `ssti`/`csti` into a real `template.py`, remember that the `"template"` slot is already declared. When in doubt, grep for `@_gen("<class>")` to find a generator's true home.

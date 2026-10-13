"""Cross-class chaining engine: capabilities + traffic signals compose into chains."""

from bbh.chains import available_capabilities, detect_chains


def _candidate(ledger, eid, iid, cls):
    cid, _ = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class=cls)
    ledger.conn.execute("UPDATE cells SET state='candidate' WHERE id=?", (cid,))
    ledger.conn.commit()
    return cid


def test_open_redirect_token_exfil_chain_is_the_named_one(ledger, eng):
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/redirect")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="url", location="query", sample_value="/home")
    cid = _candidate(ledger, eid, iid, "open_redirect")
    # with only the redirect, the chain is listed as a hypothesis (the token signal is its missing precondition)
    by_name = {c["name"]: c for c in detect_chains(ledger)}
    name = "Credential/token exfiltration via open redirect"
    assert name in by_name and by_name[name]["confidence"] == "hypothesis"
    assert "token_in_url" in by_name[name]["missing_preconditions"]
    # once a token is observed in a URL in traffic, the same chain is high-confidence
    ledger.add_request(source="burp", method="GET", url="http://127.0.0.1:5057/cb?code=abc123def456xyz",
                       host="127.0.0.1:5057", raw_path=None, content_hash="h1", principal_id=None)
    c = {x["name"]: x for x in detect_chains(ledger)}[name]
    assert c["confidence"] == "high" and cid in c["from_cells"] and "token_in_url" in c["boosts_present"]


def test_chain_requires_all_hard_preconditions(ledger, eng):
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="POST", path_template="/x")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="q", location="query", sample_value="1")
    _candidate(ledger, eid, iid, "xss_reflected")  # grants js_execution only
    name = "CSRF-driven state change executed from XSS (same-site)"
    assert name not in {c["name"] for c in detect_chains(ledger)}  # still needs cross_site_write
    _candidate(ledger, eid, None, "csrf")  # endpoint-level, grants cross_site_write
    assert name in {c["name"] for c in detect_chains(ledger)}


def test_available_capabilities_maps_classes(ledger, eng):
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/f")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="id", location="query", sample_value="1")
    _candidate(ledger, eid, iid, "idor_read")
    caps = available_capabilities(ledger)
    assert "reads_foreign_object" in caps and len(caps["reads_foreign_object"]) == 1
    # a cell that is still open (not candidate/confirmed) grants nothing
    ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="sqli")
    assert "db_read" not in available_capabilities(ledger)

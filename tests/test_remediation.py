"""Offline behavior tests for the remediation layer (remediation.py).

Covers the acceptance contract without any network/LLM: the PoC runner
(agent.tools.t_run_poc_check) is stubbed, ownership is enforced, compare()
produces verdict-normalized added/removed/changed buckets, plan() orders
deterministically and enriches from the private library, and retest() reports
successful/timeout semantics additively — with INCONCLUSIVE preserved and no
false "fixed" claim anywhere.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile

import pytest

import db as dbmod
import remediation as rem


@pytest.fixture()
def tmp_db(monkeypatch):
    """Temp DB with base + library + remediation schema."""
    d = os.path.join(tempfile.mkdtemp(), "test.db")
    monkeypatch.setattr(dbmod, "DB_PATH", d)
    dbmod.init_db()
    rem.init_remediation_sync()
    return d


def _run(coro):
    return asyncio.run(coro)


def _save_scan(scan_id, user_id, target, vulns, report="report"):
    dbmod._save_scan(scan_id, user_id, target, ["php"],
                     {"vulnerabilities": vulns}, {"status": report})


def _save_poc(scan_id, cve, verdict=None):
    path = f"/tmp/poc_{scan_id}_{cve}.py"
    dbmod._save_poc(scan_id, cve, path, "code")
    if verdict:
        dbmod._set_poc_verdict(scan_id, cve, verdict, "stored", 1)


def _stub_runner(monkeypatch, result):
    """Point the runner tool at a fake returning `result` (str or dict)."""
    async def fake(scan_id, cve, target):
        return result
    monkeypatch.setattr("agent.tools.t_run_poc_check", fake)


# ---- ownership --------------------------------------------------------------

def test_ownership_enforced_across_apis(tmp_db):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"}])
    with pytest.raises(PermissionError):
        _run(rem.compare(8, "s1", "s1"))
    with pytest.raises(PermissionError):
        _run(rem.plan(8, "s1"))
    with pytest.raises(PermissionError):
        _run(rem.retest(8, "s1"))
    # owner passes
    assert _run(rem.compare(7, "s1", "s1"))["summary"] == "no change"
    assert _run(rem.plan(7, "s1"))["scan_id"] == "s1"
    assert _run(rem.retest(7, "s1"))["runs"] == []


def test_missing_scan_raises_value_error(tmp_db):
    with pytest.raises(ValueError):
        _run(rem.plan(7, "nope"))
    with pytest.raises(ValueError):
        _run(rem.compare(7, "nope", "nope2"))


# ---- compare ----------------------------------------------------------------

def test_compare_added_removed_changed(tmp_db):
    old = [
        {"cve": "CVE-2026-1001", "verified": "EXPLOITABLE", "severity": "CRITICAL",
         "cvss": 9.8},
        {"cve": "CVE-2026-1002", "verified": "NOT EXPLOITABLE", "severity": "HIGH"},
        {"cve": "CVE-2026-1004", "verified": "EXPLOITABLE", "severity": "MEDIUM"},
    ]
    new = [
        {"cve": "CVE-2026-1001", "verified": "NOT EXPLOITABLE", "severity": "CRITICAL"},
        {"cve": "CVE-2026-1002", "verified": "EXPLOITABLE", "severity": "HIGH"},
        {"cve": "CVE-2026-1003", "verified": "EXPLOITABLE", "severity": "LOW"},
    ]
    _save_scan("s-old", 7, "http://acme.test", old)
    _save_scan("s-new", 7, "http://acme.test", new)
    res = _run(rem.compare(7, "s-old", "s-new"))
    assert [c["cve"] for c in res["added"]] == ["CVE-2026-1003"]
    assert [c["cve"] for c in res["removed"]] == ["CVE-2026-1004"]
    ch = {c["cve"]: c for c in res["changed"]}
    assert set(ch) == {"CVE-2026-1001", "CVE-2026-1002"}
    assert ch["CVE-2026-1001"]["old_verdict"] == "EXPLOITABLE"
    assert ch["CVE-2026-1001"]["new_verdict"] == "NOT_REPRODUCED"
    assert ch["CVE-2026-1002"]["old_verdict"] == "NOT_REPRODUCED"
    assert ch["CVE-2026-1002"]["new_verdict"] == "EXPLOITABLE"
    assert res["unchanged"] == []
    assert res["summary"] == "1 added, 1 removed, 2 changed"


def test_compare_unchanged_and_verdict_normalization(tmp_db):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"},
                {"cve": "CVE-2026-1002", "label": "NOT_AFFECTED"}])
    _save_scan("s2", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"},
                {"cve": "CVE-2026-1002", "label": "NOT_AFFECTED"}])
    res = _run(rem.compare(7, "s1", "s2"))
    assert res["summary"] == "no change"
    assert {c["cve"] for c in res["unchanged"]} == {"CVE-2026-1001", "CVE-2026-1002"}
    by_cve = {c["cve"]: c for c in res["unchanged"]}
    # labels are normalized onto the shared enum (NOT_AFFECTED → NOT_APPLICABLE)
    assert by_cve["CVE-2026-1002"]["verdict"] == "NOT_APPLICABLE"


# ---- plan -------------------------------------------------------------------

def test_plan_orders_exploitable_first_and_is_deterministic(tmp_db):
    vulns = [
        {"cve": "CVE-2026-2001", "verified": "INCONCLUSIVE", "severity": "HIGH"},
        {"cve": "CVE-2026-2002", "verified": "EXPLOITABLE", "severity": "LOW"},
        {"cve": "CVE-2026-2003", "verified": "EXPLOITABLE", "severity": "CRITICAL",
         "cvss": 9.8},
    ]
    _save_scan("s1", 7, "http://acme.test", vulns)
    p1 = _run(rem.plan(7, "s1"))
    p2 = _run(rem.plan(7, "s1"))
    assert p1["plan"] == p2["plan"], "plan must be deterministic"
    cves = [i["cve"] for i in p1["plan"]]
    # exploitable first, then severity desc (cvss tiebreak), then cve asc
    assert cves == ["CVE-2026-2003", "CVE-2026-2002", "CVE-2026-2001"]
    assert [i["verdict"] for i in p1["plan"]] == \
        ["EXPLOITABLE", "EXPLOITABLE", "INCONCLUSIVE"]
    assert all("action" in i for i in p1["plan"])
    # persisted for the bot layer to read back
    conn = sqlite3.connect(dbmod.DB_PATH)
    n = conn.execute("SELECT COUNT(*) FROM rem_plans WHERE user_id=7 AND scan_id='s1'"
                     ).fetchone()[0]
    conn.close()
    assert n == 1


def test_plan_enriches_fixed_versions_diff_and_refs(tmp_db):
    from library import ingest_vulnerability
    _run(ingest_vulnerability({
        "cve": "CVE-2026-2003",
        "title": "Acme Core RCE",
        "summary": "RCE in Acme Core",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "url": "https://example.com/advisory",
        "poc_refs": ["https://example.com/poc"],
        "diff_patch": "https://example.com/patch.diff",
        "affected": [{"product": "acme-core", "fixed": "2.1.0"},
                     {"product": "acme-core", "fixed": "2.0.3"}],
    }, source_name="test"))
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-2003", "verified": "EXPLOITABLE"}])
    p = _run(rem.plan(7, "s1"))
    item = p["plan"][0]
    assert item["fixed_versions"] == ["2.0.3", "2.1.0"]  # sorted, deduped
    assert item["diff_patch"] == "https://example.com/patch.diff"
    assert item["references"] == ["https://example.com/advisory",
                                  "https://example.com/poc"]
    assert item["component"] == "acme-core"
    assert item["severity"] == "CRITICAL"
    assert item["title"] == "Acme Core RCE"
    assert "2.1.0" in item["action"] and "Upgrade" in item["action"]


# ---- retest -----------------------------------------------------------------

def test_retest_successful_reuses_stored_poc(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"}])
    _save_poc("s1", "CVE-2026-1001", verdict="EXPLOITABLE")
    seen = {}

    async def fake(scan_id, cve, target):
        seen.update(scan_id=scan_id, cve=cve, target=target)
        return json.dumps({"returncode": 0,
                           "output": "[EXPLOITABLE] marker reflected in response\n"})

    monkeypatch.setattr("agent.tools.t_run_poc_check", fake)
    res = _run(rem.retest(7, "s1"))
    assert seen == {"scan_id": "s1", "cve": "CVE-2026-1001",
                    "target": "http://acme.test"}
    runs = res["runs"]
    assert len(runs) == 1
    r = runs[0]
    assert r["outcome"] == "EXPLOITABLE"
    assert r["status"] == "completed"
    assert r["previous_verdict"] == "EXPLOITABLE"
    assert r["changed"] is False
    assert r["fixed"] is False


def test_retest_not_exploitable_is_not_reproduced_not_fixed(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"}])
    _save_poc("s1", "CVE-2026-1001", verdict="EXPLOITABLE")
    _stub_runner(monkeypatch, json.dumps(
        {"returncode": 0, "output": "[NOT EXPLOITABLE] no marker; version patched\n"}))
    r = _run(rem.retest(7, "s1"))["runs"][0]
    assert r["outcome"] == "NOT_REPRODUCED"
    assert r["changed"] is True          # differs from previous EXPLOITABLE
    assert r["fixed"] is False           # never a "fixed" claim
    assert "not reproduced" in r["detail"].lower()


def test_retest_timeout_is_inconclusive(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"}])
    _save_poc("s1", "CVE-2026-1001")

    async def slow(scan_id, cve, target):
        await asyncio.sleep(30)

    monkeypatch.setattr("agent.tools.t_run_poc_check", slow)
    monkeypatch.setattr(rem, "RETEST_TIMEOUT", 0.05)
    r = _run(rem.retest(7, "s1"))["runs"][0]
    assert r["status"] == "timeout"
    assert r["outcome"] == "INCONCLUSIVE"   # timeout never becomes NOT_REPRODUCED
    assert "wall-clock cap" in r["detail"]


def test_retest_unreachable_only_on_connection_evidence(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"}])
    _save_poc("s1", "CVE-2026-1001")
    _stub_runner(monkeypatch, json.dumps(
        {"returncode": 1,
         "output": "urllib.error.URLError: <urlopen error [Errno 111] Connection refused>"}))
    r = _run(rem.retest(7, "s1"))["runs"][0]
    assert r["outcome"] == "UNREACHABLE"


def test_retest_inconclusive_preserved(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "INCONCLUSIVE"}])
    _save_poc("s1", "CVE-2026-1001", verdict="INCONCLUSIVE")
    # ambiguous output: no marker, no timeout, no connection error
    _stub_runner(monkeypatch, json.dumps(
        {"returncode": 0, "output": "banner: Acme 1.2\n[stderr]\n"}))
    r = _run(rem.retest(7, "s1"))["runs"][0]
    assert r["outcome"] == "INCONCLUSIVE"        # preserved, not flipped to safe
    assert r["previous_verdict"] == "INCONCLUSIVE"
    assert r["changed"] is False
    assert r["fixed"] is False


def test_retest_explicit_cve_and_additive_persistence(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"},
                {"cve": "CVE-2026-1002", "verified": "EXPLOITABLE"}])
    # only CVE-2026-1002 has a stored PoC → cve=None retests just that one
    _save_poc("s1", "CVE-2026-1002", verdict="EXPLOITABLE")
    _stub_runner(monkeypatch, json.dumps(
        {"returncode": 0, "output": "[EXPLOITABLE] marker\n"}))
    res = _run(rem.retest(7, "s1"))
    assert [r["cve"] for r in res["runs"]] == ["CVE-2026-1002"]
    # explicit cve with no stored PoC → reported, not raised, nothing fabricated
    res2 = _run(rem.retest(7, "s1", cve="CVE-2026-1001"))
    assert res2["runs"][0]["status"] == "failed"
    assert res2["runs"][0]["outcome"] == "INCONCLUSIVE"
    assert "no stored PoC" in res2["runs"][0]["detail"]
    # every run persisted additively (one row per retest, nothing overwritten)
    conn = sqlite3.connect(dbmod.DB_PATH)
    rows = conn.execute("SELECT scan_id, cve, outcome, status FROM rem_runs"
                        " WHERE user_id=7 AND scan_id='s1' ORDER BY id").fetchall()
    conn.close()
    assert [tuple(r) for r in rows] == [
        ("s1", "CVE-2026-1002", "EXPLOITABLE", "completed"),
        ("s1", "CVE-2026-1001", "INCONCLUSIVE", "failed"),
    ]


def test_retest_progress_callback(tmp_db, monkeypatch):
    _save_scan("s1", 7, "http://acme.test",
               [{"cve": "CVE-2026-1001", "verified": "EXPLOITABLE"},
                {"cve": "CVE-2026-1002", "verified": "EXPLOITABLE"}])
    _save_poc("s1", "CVE-2026-1001")
    _save_poc("s1", "CVE-2026-1002")

    async def fake(scan_id, cve, target):
        return json.dumps({"returncode": 0, "output": "[EXPLOITABLE] marker\n"})

    monkeypatch.setattr("agent.tools.t_run_poc_check", fake)
    calls = []

    async def progress(done, total, msg):
        calls.append((done, total, msg))

    res = _run(rem.retest(7, "s1", progress=progress))
    assert len(res["runs"]) == 2
    assert [c[0] for c in calls] == [1, 2]
    assert calls[0][1] == 2

"""Offline behavior tests for the private security-intelligence library (library.py).

Deterministic and network-free: every test runs against a throwaway SQLite DB
using the repo's DB_PATH monkeypatch convention (see test_db_writers.py), and the
async API is driven with asyncio.run (no pytest-asyncio dependency). Refresh tests
stub the scraper network path so nothing ever touches the wire.

These tests assert observable contracts (idempotency, conflict semantics, search
results, ownership scoping, round-trips) — never SQL/schema implementation details.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3

import pytest

import db as dbmod
import library as libmod
from scrapers.base import VulnRecord

_SQLI = {
    "cve": "CVE-2026-1001",
    "title": "Acme Login SQL Injection",
    "summary": "SQL injection in the Acme login form allows authentication bypass.",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "published": "2026-01-10",
    "poc_refs": ["https://example.com/poc-1", "https://example.com/poc-2"],
    "diff_patch": "https://example.com/patch.diff",
    "url": "https://example.com/CVE-2026-1001",
}
_SQLI2 = {
    "cve": "CVE-2026-1002",
    "title": "Acme Admin Panel SQL Injection",
    # description-only on purpose: summary must fall back to description
    "description": "SQL injection in the admin panel search box; the admin search "
                   "form lacks parameterization.",
    "severity": "HIGH",
    "cvss": 7.5,
    "published": "2026-02-01",
}
_XSS = {
    "cve": "CVE-2026-1003",
    "title": "Acme Theme Cross-Site Scripting",
    "summary": "Stored cross-site scripting in the theme customizer.",
    "severity": "MEDIUM",
    "cvss": 5.4,
    "published": "2026-03-01",
}


@pytest.fixture()
def lib(tmp_path, monkeypatch):
    """Temp DB with migrations + library schema. Patching db.DB_PATH covers
    library too: library.py opens connections via db._conn() at call time."""
    path = str(tmp_path / "lib.db")
    monkeypatch.setattr(dbmod, "DB_PATH", path)
    dbmod.init_db()
    _run(libmod.init_library())  # idempotent; explicit so tests don't rely on the db.py hook
    return path


def _run(coro):
    return asyncio.run(coro)


def _strip_temporal(obj):
    """Drop implementation artifacts (ids/timestamps) before comparing data across
    an export/import round trip — the data, not the row identity, is the contract."""
    if isinstance(obj, dict):
        return {k: _strip_temporal(v) for k, v in obj.items()
                if k not in {"id", "ts", "created", "updated",
                             "last_refreshed", "next_refresh"}}
    if isinstance(obj, list):
        return [_strip_temporal(x) for x in obj]
    return obj


# ---- ingest: idempotency + canonicalization ----

def test_ingest_same_source_is_idempotent(lib):
    r1 = _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd",
                                          source_url="https://nvd.example/1"))
    assert r1["canonical_id"] == "CVE-2026-1001"
    assert r1["conflicts"] == []

    # same record, same source, second time: must be an in-place update, not a dup
    r2 = _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd",
                                          source_url="https://nvd.example/1"))
    assert r2["canonical_id"] == "CVE-2026-1001"
    assert r2["sources"] == ["nvd"]
    assert r2["conflicts"] == []

    hits = _run(libmod.search("acme"))
    assert len(hits) == 1, "re-ingesting the same (canonical, source) pair must not duplicate rows"
    assert hits[0]["canonical_id"] == "CVE-2026-1001"

    v = _run(libmod.get_vulnerability("CVE-2026-1001"))
    assert v["sources"] == ["nvd"]
    assert {"canonical_id", "title", "summary", "description", "severity", "cvss",
            "sources", "created", "updated", "evidence_count"} <= set(v)

    st = _run(libmod.stats())
    assert st["vulnerabilities"] == 1
    assert st["sources"] == 1


def test_canonical_id_is_normalized_uppercase(lib):
    rec = dict(_SQLI)
    rec["cve"] = "cve-2026-1001"  # lowercase input
    r = _run(libmod.ingest_vulnerability(rec, source_name="nvd"))
    assert r["canonical_id"] == "CVE-2026-1001"
    v = _run(libmod.get_vulnerability("CVE-2026-1001"))
    assert v["canonical_id"] == "CVE-2026-1001"
    assert _run(libmod.stats())["vulnerabilities"] == 1


def test_summary_falls_back_to_description(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI2), source_name="nvd"))
    v = _run(libmod.get_vulnerability("CVE-2026-1002"))
    assert v["description"], "description must be stored"
    assert v["summary"], "summary must fall back to description when not provided"


# ---- provenance ----

def test_provenance_conflict_first_seen_wins(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd",
                                     source_url="https://nvd.example/1"))
    conf = dict(_SQLI)
    conf["cvss"] = 6.1
    conf["severity"] = "MEDIUM"
    r = _run(libmod.ingest_vulnerability(conf, source_name="wordfence",
                                         source_url="https://wf.example/1"))
    assert any(c["field"] == "cvss" and str(c["observed"]) == "6.1" for c in r["conflicts"])
    assert any(c["field"] == "severity" and c["observed"] == "MEDIUM" for c in r["conflicts"])

    # canonical keeps first-seen values; both sources are recorded
    v = _run(libmod.get_vulnerability("CVE-2026-1001"))
    assert v["cvss"] == 9.8, "conflicting claim must not overwrite the canonical value"
    assert v["severity"] == "CRITICAL"
    assert set(v["sources"]) == {"nvd", "wordfence"}
    st = _run(libmod.stats())
    assert st["conflicts"] == 2  # cvss + severity
    assert st["vulnerabilities"] == 1

    # re-ingesting the same claim from the same source: no new conflicts, no dup
    r3 = _run(libmod.ingest_vulnerability(conf, source_name="wordfence"))
    assert r3["conflicts"] == []
    assert _run(libmod.stats())["conflicts"] == 2

    # an AGREEING claim from a third source is not a conflict
    r4 = _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="cisa_kev"))
    assert r4["conflicts"] == []
    st = _run(libmod.stats())
    assert st["conflicts"] == 2
    assert st["sources"] == 3
    assert st["vulnerabilities"] == 1


# ---- search: FTS + fallback ----

def test_search_matches_title_summary_and_description(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    _run(libmod.ingest_vulnerability(dict(_SQLI2), source_name="nvd"))

    hits = _run(libmod.search("sql injection"))
    ids = {h["canonical_id"] for h in hits}
    assert {"CVE-2026-1001", "CVE-2026-1002"} <= ids
    for h in hits:
        assert {"canonical_id", "title", "severity", "cvss", "sources", "snippet"} <= set(h)

    # terms found only in summary/description still match
    assert {h["canonical_id"] for h in _run(libmod.search("authentication bypass"))} \
        == {"CVE-2026-1001"}
    assert {h["canonical_id"] for h in _run(libmod.search("search box"))} \
        == {"CVE-2026-1002"}


def test_search_fallback_and_limit(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    # a bare token present in the title still finds the record (fallback path)
    assert {h["canonical_id"] for h in _run(libmod.search("acme"))} == {"CVE-2026-1001"}
    # an unrelated query is an empty list, not an error
    assert _run(libmod.search("quantum flux capacitor")) == []
    # limit is honored
    _run(libmod.ingest_vulnerability(dict(_SQLI2), source_name="nvd"))
    assert len(_run(libmod.search("sql", limit=1))) == 1


# ---- concept-related retrieval ----

def test_related_concept_retrieval_is_deterministic(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    _run(libmod.ingest_vulnerability(dict(_SQLI2), source_name="nvd"))
    _run(libmod.ingest_vulnerability(dict(_XSS), source_name="nvd"))

    rel1 = _run(libmod.related("CVE-2026-1001"))
    rel2 = _run(libmod.related("CVE-2026-1001"))
    assert rel1 == rel2, "related() must be deterministic (no random vectors)"

    ids = {r["canonical_id"] for r in rel1}
    assert "CVE-2026-1002" in ids, "same-technique sibling must be related"
    assert "CVE-2026-1003" not in ids, "XSS vuln is not SQLi-related"
    assert "CVE-2026-1001" not in ids, "related() must not return the query entity itself"
    for r in rel1:
        assert {"canonical_id", "title", "severity", "score"} <= set(r)
        assert r["score"] > 0

    # query-string form routes through the same matcher
    qrel = {r["canonical_id"] for r in _run(libmod.related("sql injection"))}
    assert {"CVE-2026-1001", "CVE-2026-1002"} <= qrel


# ---- scan evidence + target history ----

def test_scan_ingest_creates_snapshot_and_evidence(lib):
    findings = [
        {"cve": "CVE-2026-1001", "label": "VULNERABLE", "cvss": 9.8, "verified": "EXPLOITABLE"},
        {"cve": "CVE-2026-1002", "label": "VULNERABLE", "cvss": 7.5, "verified": "NOT_EXPLOITABLE"},
    ]
    _run(libmod.ingest_scan(7, "scan-1", "http://acme.test", findings, "report text"))

    th = _run(libmod.target_history(7, "http://acme.test"))
    assert len(th) == 1
    s = th[0]
    assert s["scan_id"] == "scan-1"
    assert s["target"] == "http://acme.test"
    assert s["findings_count"] == 2
    assert s["exploitable"] == 1
    assert s["report"] == "report text"
    assert s["drift"] is None, "first scan of a target has nothing to drift against"

    ev = _run(libmod.get_evidence("CVE-2026-1001", user_id=7))
    scan_ev = [e for e in ev if e.get("kind") == "scan" and e.get("entity_id") == "CVE-2026-1001"]
    assert len(scan_ev) == 1, "each scan finding must produce one evidence row"
    assert scan_ev[0]["summary"] and scan_ev[0]["detail"]
    assert str(scan_ev[0]["user_id"]) == "7"

    st = _run(libmod.stats())
    assert st["targets"] == 1 and st["snapshots"] == 1
    assert st["evidence"] >= 2


def test_target_drift_between_scans(lib):
    f1 = [{"cve": "CVE-2026-1001", "label": "VULNERABLE", "verified": "EXPLOITABLE"}]
    f2 = [
        {"cve": "CVE-2026-1001", "label": "VULNERABLE", "verified": "EXPLOITABLE"},
        {"cve": "CVE-2026-1002", "label": "VULNERABLE", "verified": "NOT_EXPLOITABLE"},
    ]
    _run(libmod.ingest_scan(7, "scan-1", "http://acme.test", f1, "r1"))
    _run(libmod.ingest_scan(7, "scan-2", "http://acme.test", f2, "r2"))

    by_scan = {s["scan_id"]: s for s in _run(libmod.target_history(7, "http://acme.test"))}
    assert set(by_scan) == {"scan-1", "scan-2"}
    assert by_scan["scan-1"]["drift"] is None
    drift = by_scan["scan-2"]["drift"]
    assert isinstance(drift, list) and len(drift) > 0, \
        "a new finding on the same target must be reported as drift"

    # a different user scanning the same target has its own history, no drift
    _run(libmod.ingest_scan(9, "scan-x", "http://acme.test", f1, "rx"))
    hist9 = _run(libmod.target_history(9, "http://acme.test"))
    assert len(hist9) == 1 and hist9[0]["drift"] is None


def test_ownership_isolation(lib):
    _run(libmod.ingest_scan(7, "scan-a", "http://acme.test",
                            [{"cve": "CVE-2026-1001", "label": "VULNERABLE",
                              "verified": "EXPLOITABLE"}], "ra"))
    _run(libmod.ingest_scan(8, "scan-b", "http://other.test",
                            [{"cve": "CVE-2026-1002", "label": "VULNERABLE",
                              "verified": "NOT_EXPLOITABLE"}], "rb"))

    # targets are user-scoped
    assert len(_run(libmod.target_history(7, "http://acme.test"))) == 1
    assert _run(libmod.target_history(8, "http://acme.test")) == []

    # evidence is user-scoped when a user is given, global otherwise
    assert len(_run(libmod.get_evidence("CVE-2026-1001", user_id=7))) >= 1
    assert _run(libmod.get_evidence("CVE-2026-1001", user_id=8)) == []
    assert _run(libmod.get_evidence("CVE-2026-1002", user_id=7)) == []
    assert len(_run(libmod.get_evidence("CVE-2026-1001"))) >= 1  # global view


# ---- notes ----

def test_notes_stored_and_exported(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    _run(libmod.add_note(7, "CVE-2026-1001", "confirmed in the wild", tags=["poc", "exploited"]))
    _run(libmod.add_note(7, "CVE-2026-1001", "second thought"))
    assert _run(libmod.stats())["notes"] == 2

    lines = [json.loads(l) for l in _run(libmod.export_jsonl()).strip().splitlines() if l.strip()]
    notes = [ln for ln in lines if ln.get("type") == "note"]
    assert len(notes) == 2, "both notes must survive export"
    tagged = [n for n in notes
              if "confirmed in the wild" in json.dumps(n)
              and "poc" in json.dumps(n) and "exploited" in json.dumps(n)]
    assert len(tagged) == 1, "tags must round-trip with the note"
    assert any("second thought" in json.dumps(n) for n in notes)


# ---- JSONL export / import ----

def test_export_import_jsonl_roundtrip_and_idempotent(lib, tmp_path, monkeypatch):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd",
                                     source_url="https://nvd.example/1"))
    conf = dict(_SQLI2)
    conf["cvss"] = 9.0  # conflicting claim from wordfence
    _run(libmod.ingest_vulnerability(conf, source_name="wordfence"))
    _run(libmod.ingest_scan(7, "scan-1", "http://acme.test",
                            [{"cve": "CVE-2026-1001", "label": "VULNERABLE",
                              "verified": "EXPLOITABLE"}], "report"))
    _run(libmod.add_note(7, "CVE-2026-1001", "note text", tags=["x"]))

    blob = _run(libmod.export_jsonl())
    lines = [json.loads(l) for l in blob.strip().splitlines() if l.strip()]
    assert len(lines) >= 5
    for ln in lines:
        assert "type" in ln and "ts" in ln
    assert {"vulnerability", "evidence", "snapshot", "note"} <= {ln["type"] for ln in lines}

    # capture the source DB state before switching paths
    stats1 = _run(libmod.stats())
    v1 = _run(libmod.get_vulnerability("CVE-2026-1001"))
    ev1 = _run(libmod.get_evidence("CVE-2026-1001", user_id=7))
    hits1 = {h["canonical_id"] for h in _run(libmod.search("acme"))}

    # import into a fresh DB
    path2 = str(tmp_path / "lib2.db")
    monkeypatch.setattr(dbmod, "DB_PATH", path2)
    dbmod.init_db()
    _run(libmod.init_library())
    r = _run(libmod.import_jsonl(blob))
    assert r["imported"] > 0 and r["skipped"] == 0

    # round trip preserved the data (identities/timestamps may differ)
    st2 = _run(libmod.stats())
    for key in ("vulnerabilities", "sources", "evidence", "targets",
                "snapshots", "notes", "conflicts"):
        assert st2[key] == stats1[key], f"{key} diverged after import"
    assert {h["canonical_id"] for h in _run(libmod.search("acme"))} == hits1
    assert _strip_temporal(_run(libmod.get_vulnerability("CVE-2026-1001"))) \
        == _strip_temporal(v1)
    assert [_strip_temporal(e) for e in _run(libmod.get_evidence("CVE-2026-1001", user_id=7))] \
        == [_strip_temporal(e) for e in ev1]

    # importing the same blob again is a no-op
    r2 = _run(libmod.import_jsonl(blob))
    assert r2["imported"] == 0 and r2["skipped"] == r["imported"]


# ---- refresh queue (offline) ----

async def _no_records(scrappers, cve):
    return []


async def _fresh_records(scrappers, cve):
    if cve not in {"CVE-2026-1001", "CVE-2026-1002"}:
        return []
    return [VulnRecord(cve=cve, title="Updated Acme SQLi", source="nvd",
                       severity="CRITICAL", cvss=9.9,
                       description="refreshed description", published="2026-01-10")]


def test_refresh_queue_offline(lib, monkeypatch):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    _run(libmod.ingest_vulnerability(dict(_SQLI2), source_name="nvd"))
    assert _run(libmod.stats())["due_for_refresh"] == 2

    due = _run(libmod.refresh_due(limit=1))
    assert len(due) == 1
    item = due[0]
    assert item["canonical_id"] in {"CVE-2026-1001", "CVE-2026-1002"}
    assert "last_refreshed" in item and "next_refresh" in item

    # network down: 0 records fetched -> graceful failure, data kept, still due
    monkeypatch.setattr(libmod, "get_all", _no_records)
    monkeypatch.setattr(libmod, "build_scrapers", lambda *a, **k: [])
    out = _run(libmod.refresh_vulnerability(item["canonical_id"]))
    assert out["refreshed"] is False
    assert out["stale"] is True
    assert _run(libmod.get_vulnerability(item["canonical_id"]))["cvss"] in (9.8, 7.5), \
        "failed refresh must not clobber stored data"

    # network up: fresh record re-ingested under its own source -> in-place update
    monkeypatch.setattr(libmod, "get_all", _fresh_records)
    out2 = _run(libmod.refresh_vulnerability(item["canonical_id"]))
    assert out2["refreshed"] is True
    assert out2["fetched"] == 1
    assert _run(libmod.get_vulnerability(item["canonical_id"]))["cvss"] == 9.9

    # refreshed item drops out of the due queue; the other stays due
    due_after = {d["canonical_id"] for d in _run(libmod.refresh_due(limit=10))}
    assert item["canonical_id"] not in due_after
    assert due_after == {"CVE-2026-1001", "CVE-2026-1002"} - {item["canonical_id"]}
    assert _run(libmod.stats())["due_for_refresh"] == 1

    # unknown id: graceful failure, never an exception
    out3 = _run(libmod.refresh_vulnerability("CVE-2099-9999"))
    assert out3["refreshed"] is False


# ---- backup + integrity ----

def test_backup_is_restorable(lib, tmp_path, monkeypatch):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    bak = str(tmp_path / "backup.db")
    out = _run(libmod.backup(path=bak))
    assert out["path"] == bak
    assert os.path.exists(bak) and out["bytes"] > 0

    # the backup must be a valid SQLite database
    con = sqlite3.connect(bak)
    try:
        assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables, "backup must contain real tables, not an empty stub"
    finally:
        con.close()

    # restore: point the app at the backup and re-init (idempotent) -> data is there
    monkeypatch.setattr(dbmod, "DB_PATH", bak)
    dbmod.init_db()
    _run(libmod.init_library())
    assert _run(libmod.stats())["vulnerabilities"] == 1
    v = _run(libmod.get_vulnerability("CVE-2026-1001"))
    assert v["canonical_id"] == "CVE-2026-1001" and v["cvss"] == 9.8


def test_verify_integrity_healthy_and_corrupted(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    ok = _run(libmod.verify_integrity())
    assert ok["ok"] is True
    assert ok["integrity_check"] == "ok"
    assert ok["problems"] == []

    # corrupt the underlying file -> verify must REPORT it, never raise
    with open(lib, "r+b") as f:
        f.seek(0)
        f.write(b"\x00" * 4096)
    bad = _run(libmod.verify_integrity())
    assert bad["ok"] is False
    assert bad["integrity_check"] != "ok"


# ---- lifecycle ----

def test_reinit_keeps_data(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    dbmod.init_db()
    _run(libmod.init_library())
    st = _run(libmod.stats())
    assert st["vulnerabilities"] == 1
    assert len(_run(libmod.search("acme"))) == 1


def test_stats_breakdown(lib):
    _run(libmod.ingest_vulnerability(dict(_SQLI), source_name="nvd"))
    _run(libmod.ingest_vulnerability(dict(_SQLI2), source_name="nvd"))
    _run(libmod.ingest_vulnerability(dict(_XSS), source_name="nvd"))
    st = _run(libmod.stats())
    assert st["vulnerabilities"] == 3
    assert st["sources"] == 1
    assert st["due_for_refresh"] == 3
    assert st["by_severity"].get("CRITICAL") == 1
    assert st["by_severity"].get("HIGH") == 1
    assert st["by_severity"].get("MEDIUM") == 1

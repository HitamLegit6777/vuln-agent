"""Tests for exploit strategy memory (library lib_strategy + runner ingest glue).

Deterministic and network-free: every test runs against a throwaway SQLite DB
using the repo's DB_PATH monkeypatch convention (see test_library.py). Exercises
the idempotent upsert contract, the ranked retrieval contract, the JSONL
export/import round-trip, integrity checks, and the runner-side ingest helper.
"""
from __future__ import annotations

import asyncio
import json

import pytest

import db as dbmod
import library as libmod
from agent import runner


@pytest.fixture()
def lib(tmp_path, monkeypatch):
    """Temp DB with migrations + library schema (strategy table included)."""
    path = str(tmp_path / "lib.db")
    monkeypatch.setattr(dbmod, "DB_PATH", path)
    dbmod.init_db()
    _run(libmod.init_library())
    return path


def _run(coro):
    return asyncio.run(coro)


def _ingest(cve, method, result, reason="", waf="", detail=None):
    return _run(libmod.ingest_strategy({
        "cve": cve, "method": method, "result": result,
        "reason": reason, "waf": waf, "detail": detail or {},
    }))


def test_strategy_ingest_idempotent_bumps_hits(lib):
    r1 = _ingest("CVE-2026-1001", "run #1", "EXPLOITABLE", reason="uid=33 reflected")
    assert r1["hits"] == 1 and r1["updated"] is False
    # same (cve, method, result) again -> same row, hits bumped, no duplicate
    r2 = _ingest("CVE-2026-1001", "run #1", "EXPLOITABLE", reason="uid=33 reflected")
    assert r2["hits"] == 2 and r2["updated"] is True
    ctx = _run(libmod.strategy_context("CVE-2026-1001"))
    assert len(ctx) == 1
    assert ctx[0]["hits"] == 2
    assert _run(libmod.list_strategies(cve="CVE-2026-1001"))[0]["hits"] == 2


def test_strategy_distinct_methods_and_results_are_distinct_rows(lib):
    _ingest("CVE-2026-1001", "method A", "EXPLOITABLE")
    _ingest("CVE-2026-1001", "method B", "NOT_REPRODUCED")
    _ingest("CVE-2026-1001", "method A", "NOT_REPRODUCED")  # same method, other result
    ctx = _run(libmod.strategy_context("CVE-2026-1001", limit=10))
    assert len(ctx) == 3
    # result rank: EXPLOITABLE rows first
    assert [s["result"] for s in ctx] == ["EXPLOITABLE", "NOT_REPRODUCED", "NOT_REPRODUCED"]


def test_strategy_context_ranks_exploitable_then_hits(lib):
    _ingest("CVE-2026-1002", "method slow", "NOT_REPRODUCED")
    _ingest("CVE-2026-1002", "method hit", "EXPLOITABLE")
    _ingest("CVE-2026-1002", "method hit", "EXPLOITABLE")  # hits=2 now
    ctx = _run(libmod.strategy_context("CVE-2026-1002", limit=6))
    assert [s["method"] for s in ctx] == ["method hit", "method slow"]
    assert ctx[0]["hits"] == 2
    # bounded + deterministic: asking twice returns identical rows
    assert ctx == _run(libmod.strategy_context("CVE-2026-1002", limit=6))
    assert len(_run(libmod.strategy_context("CVE-2026-1002", limit=1))) == 1


def test_strategy_captures_reason_waf_path_timing(lib):
    detail = {"attempts": 4, "timing_ms": 12345}
    _ingest("CVE-2026-1003", "nuclei template (x.yaml)", "EXPLOITABLE",
            reason="webshell uploaded", waf="cloudflare", detail=detail)
    s = _run(libmod.strategy_context("CVE-2026-1003"))[0]
    assert s["reason"] == "webshell uploaded"
    assert s["waf"] == "cloudflare"
    assert s["detail"]["timing_ms"] == 12345
    assert s["method"].startswith("nuclei")


def test_strategy_unknown_cve_returns_empty(lib):
    assert _run(libmod.strategy_context("CVE-NOPE")) == []
    assert _run(libmod.strategy_context("")) == []


def test_strategy_export_import_roundtrip_and_idempotent(lib, tmp_path, monkeypatch):
    _ingest("CVE-2026-1001", "run #1", "EXPLOITABLE", reason="uid=0 reflected", waf="modsecurity")
    _ingest("CVE-2026-1001", "run #2", "NOT_REPRODUCED", reason="403 on endpoint")
    exported = _run(libmod.export_jsonl())
    lines = [json.loads(l) for l in exported.splitlines() if l.strip()]
    strat_lines = [l for l in lines if l.get("type") == "strategy"]
    assert len(strat_lines) == 2
    assert {l["result"] for l in strat_lines} == {"EXPLOITABLE", "NOT_REPRODUCED"}

    # fresh DB -> import restores the strategy rows
    dbmod.DB_PATH = str(tmp_path / "lib2.db")
    dbmod.init_db()
    _run(libmod.init_library())
    r1 = _run(libmod.import_jsonl(exported))
    assert r1["imported"] == 2 and r1["skipped"] == 0
    ctx = _run(libmod.strategy_context("CVE-2026-1001"))
    assert len(ctx) == 2
    assert ctx[0]["result"] == "EXPLOITABLE" and ctx[0]["hits"] == 1
    # re-import is a no-op (idempotent round-trip)
    r2 = _run(libmod.import_jsonl(exported))
    assert r2["imported"] == 0 and r2["skipped"] == 2


def test_strategy_verify_integrity_ok_with_strategy_rows(lib):
    _ingest("CVE-2026-1001", "run #1", "EXPLOITABLE")
    res = _run(libmod.verify_integrity())
    assert res["ok"] is True
    assert res["row_checks"]["strategies"] == 1


def test_runner_ingest_verify_strategy(lib):
    """The runner glue persists methods_tried + verdict via the library API."""
    res = {"verdict": "EXPLOITABLE", "reason": "webshell uploaded uid=33",
           "path": "/tmp/poc_x.py", "attempts": 3,
           "methods_tried": ["run #1", "run #2", "run #3"]}
    _run(runner._ingest_verify_strategy("cve-2026-1001", res, "EXPLOITABLE",
                                        "webshell uploaded uid=33", waf="cloudflare",
                                        timing_ms=987))
    ctx = _run(libmod.strategy_context("CVE-2026-1001"))
    assert len(ctx) == 3  # one row per method tried
    assert all(s["result"] == "EXPLOITABLE" for s in ctx)
    assert all(s["waf"] == "cloudflare" for s in ctx)
    assert ctx[0]["detail"]["timing_ms"] == 987
    # re-ingesting the same verify outcome only bumps hits, no new rows
    _run(runner._ingest_verify_strategy("CVE-2026-1001", res, "EXPLOITABLE",
                                        "webshell uploaded uid=33", waf="cloudflare",
                                        timing_ms=987))
    ctx2 = _run(libmod.strategy_context("CVE-2026-1001"))
    assert len(ctx2) == 3
    assert sum(s["hits"] for s in ctx2) == 6

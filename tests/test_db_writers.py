"""Smoke tests for db.py writers — guards against SQL binding-count mismatches.

Every `_save_*`/`_mark_*`/`_update_*` sync writer is exercised against a temp SQLite
DB, twice each (to hit both the INSERT and the UPDATE/upsert branch). A past bug in
`_save_learned_sig` had 5 placeholders but 6 bound params (`VALUES(?,?,?,1,1,?,?)`)
so it raised sqlite3.ProgrammingError on every first-seen signature — silently
swallowed by the caller, so the learned-signatures feature never stored anything.
"""
import os
import tempfile

import pytest

import db as dbmod


@pytest.fixture()
def tmp_db(monkeypatch):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "test.db")
    monkeypatch.setattr(dbmod, "DB_PATH", path)
    dbmod.init_db()
    return path


# (writer name, args). Each is called twice to exercise upsert/update branches.
_WRITERS = [
    ("_save_scan", ("s1", 1, "t", "{}", "{}", "{}", "g")),
    ("_save_chat", ("s1", [{"role": "user", "content": "hi"}])),
    ("_save_poc", ("s1", "CVE-2024-1", "/tmp/p.py", "code")),
    ("_set_poc_verdict", ("s1", "CVE-2024-1", "EXPLOITABLE", "reason", 2)),
    ("_cache_set_sync", ("k1", {"a": 1})),
    ("_save_poc_pattern", ("CVE-2024-1", "sqli", "m1", "code", "wf")),
    ("_mark_poc_pattern_fail", ("CVE-2024-1", "m1")),
    ("_save_learned_sig", ("wordpress", "generator", "WP 6.0", "evidence-string")),
    ("_save_knowledge", ("wordpress", "6.0", ["finding"], "lessons", "s1")),
    ("_save_waf_bypass", ("cloudflare", "CVE-2024-1", "payload", True)),
    ("_save_feedback", ("s1", "up", "note")),
    ("_save_job", ("s1", 1, "t", "2026-01-01", "running")),
    ("_update_job", ("s1", "done")),
    ("_mark_cve_sent", ("CVE-2024-1", "sum", "HIGH", 9.8, "rce", "unauth", "x", "poc", {"d": 1})),
]


@pytest.mark.parametrize("name,args", _WRITERS, ids=[w[0] for w in _WRITERS])
def test_writer_executes_twice(tmp_db, name, args):
    fn = getattr(dbmod, name)
    fn(*args)   # INSERT branch
    fn(*args)   # UPDATE / upsert / INSERT-OR-REPLACE branch


def test_learned_sig_roundtrip(tmp_db):
    # The regression target: insert a signature, then read it back intact.
    dbmod._save_learned_sig("joomla", "path", "/administrator/", "found in body")
    sigs = dbmod._get_learned_sigs()
    assert len(sigs) == 1
    s = sigs[0]
    assert s["cms_name"] == "joomla"
    assert s["signal_type"] == "path"
    assert s["signal_value"] == "/administrator/"
    assert s["evidence"] == "found in body", "evidence must not be clobbered by a literal"
    assert s["hit_count"] == 1
    # second save of same signal bumps hit_count, keeps evidence
    dbmod._save_learned_sig("joomla", "path", "/administrator/", "found in body")
    s2 = dbmod._get_learned_sigs()[0]
    assert s2["hit_count"] == 2


def test_mark_all_interrupted_runs(tmp_db):
    dbmod._save_job("s9", 1, "t", "2026-01-01", "running")
    dbmod._mark_all_interrupted()
    jobs = dbmod._get_interrupted_jobs(1)
    assert any(j["scan_id"] == "s9" for j in jobs)

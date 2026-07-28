"""Tests for report rendering logic in agent/runner.py.

run_report is deterministic (no LLM in this code path): it buckets CVEs by the
`verified` field, computes status, and writes a grounded recommendation. These tests
lock in the schema the Telegram UI depends on (`exploitable` / `checked` / `status`).
"""
from __future__ import annotations

import asyncio
import json

from agent import runner


def _run(coro):
    return asyncio.run(coro)


def test_report_buckets_exploitable_and_checked():
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "joomla", "version": "4.2.0"}],
        "vulnerabilities": [
            {"cve": "CVE-2023-23752", "verified": "EXPLOITABLE", "severity": "HIGH",
             "cvss": 7.5, "component": "joomla core", "title": "info disclosure",
             "verify_reason": "config leaked: db password reflected in response"},
            {"cve": "CVE-2020-0000", "verified": "NOT EXPLOITABLE",
             "verify_reason": "version not in range"},
        ],
    })
    rep = _run(runner.run_report("https://x.test", findings))
    assert rep["status"] == "EXPLOITABLE"
    assert [v["cve"] for v in rep["exploitable"]] == ["CVE-2023-23752"]
    assert [v["cve"] for v in rep["checked"]] == ["CVE-2020-0000"]
    assert "CVE-2023-23752" in rep["recommendation"]


def test_report_clean_when_nothing_exploitable():
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "wordpress", "version": "6.5"}],
        "vulnerabilities": [
            {"cve": "CVE-2024-1111", "verified": "NOT EXPLOITABLE",
             "verify_reason": "patched"},
        ],
    })
    rep = _run(runner.run_report("https://y.test", findings))
    assert rep["status"] == "CLEAN"
    assert rep["exploitable"] == []
    assert [v["cve"] for v in rep["checked"]] == ["CVE-2024-1111"]


def test_report_unreachable_keeps_its_recommendation():
    # No stack, nothing exploitable/checked -> UNREACHABLE, and the recommendation
    # must NOT be blanked out (regression: it was overwritten by dead code).
    findings = json.dumps({"stack": [], "vulnerabilities": []})
    rep = _run(runner.run_report("https://down.test", findings))
    assert rep["status"] == "UNREACHABLE"
    assert rep["recommendation"].strip() != ""
    assert "dijangkau" in rep["recommendation"].lower()


def test_report_survives_bad_json():
    rep = _run(runner.run_report("https://z.test", "not json at all"))
    # empty findings -> unreachable, but must not raise
    assert rep["status"] == "UNREACHABLE"


def test_filter_vulns_drops_not_affected():
    vulns = [
        {"cve": "CVE-1", "label": "VULNERABLE"},
        {"cve": "CVE-2", "label": "NOT_AFFECTED"},
        {"cve": "CVE-3", "label": "not-affected"},  # hyphen variant
        {"cve": "CVE-4", "label": "UNCONFIRMED"},
    ]
    kept = [v["cve"] for v in runner._filter_vulns(vulns)]
    assert kept == ["CVE-1", "CVE-4"]

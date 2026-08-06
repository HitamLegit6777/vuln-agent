"""Tests for report rendering logic in agent/runner.py.

run_report is deterministic (no LLM in this code path): it normalizes every candidate
verdict through the verdict state machine, buckets CVEs into exploitable / checked
(NOT_REPRODUCED) / not_applicable / inconclusive, computes status + coverage, and
writes a grounded recommendation. These tests lock in the schema the Telegram UI
depends on (`exploitable` / `checked` / `status`) plus the new additive buckets.
"""
import asyncio
import json

from agent import runner


def _run(coro):
    return asyncio.run(coro)


def test_report_buckets_exploitable_and_not_applicable():
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
    # "version not in range" is a deterministic NOT_APPLICABLE, not a checked item
    assert [v["cve"] for v in rep["checked"]] == []
    assert [v["cve"] for v in rep["not_applicable"]] == ["CVE-2020-0000"]
    assert rep["inconclusive"] == []
    assert "CVE-2023-23752" in rep["recommendation"]
    # coverage: both candidates reached a definite verdict
    assert rep["coverage"]["coverage"] == 1.0


def test_report_no_exploit_reproduced_when_nothing_exploitable():
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "wordpress", "version": "6.5"}],
        "vulnerabilities": [
            {"cve": "CVE-2024-1111", "verified": "NOT EXPLOITABLE",
             "verify_reason": "patched"},
        ],
    })
    rep = _run(runner.run_report("https://y.test", findings))
    # "patched" -> NOT_APPLICABLE; no exploit reproduced -> NO_EXPLOIT_REPRODUCED
    assert rep["status"] == "NO_EXPLOIT_REPRODUCED"
    assert rep["exploitable"] == []
    assert rep["checked"] == []
    assert [v["cve"] for v in rep["not_applicable"]] == ["CVE-2024-1111"]


def test_report_legacy_verdicts_render_safely():
    # Old stored verdicts: underscore variant, UNKNOWN, and NOT EXPLOITABLE without
    # version-evidence must all render without raising and land in honest buckets.
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "joomla", "version": "4.2.0"}],
        "vulnerabilities": [
            {"cve": "CVE-1", "verified": "NOT_EXPLOITABLE",
             "verify_reason": "endpoint returned 403"},
            {"cve": "CVE-2", "verified": "UNKNOWN",
             "verify_reason": "no run output"},
            {"cve": "CVE-3", "verified": "NOT EXPLOITABLE",
             "verify_reason": "version patched"},
            {"cve": "CVE-4", "verified": "", "verify_reason": "never verified"},
        ],
    })
    rep = _run(runner.run_report("https://legacy.test", findings))
    assert [v["cve"] for v in rep["checked"]] == ["CVE-1"]            # NOT_REPRODUCED
    assert [v["cve"] for v in rep["not_applicable"]] == ["CVE-3"]     # patched
    assert [v["cve"] for v in rep["inconclusive"]] == ["CVE-2"]       # UNKNOWN -> INCONCLUSIVE
    # never-verified candidates are not bucketed (matches legacy behavior)
    assert all(v["cve"] != "CVE-4" for v in
               rep["exploitable"] + rep["checked"] + rep["not_applicable"] + rep["inconclusive"])
    assert rep["status"] == "NO_EXPLOIT_REPRODUCED"


def test_report_inconclusive_when_all_verification_timed_out():
    # Timeout/error verdicts must NEVER render as clean.
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "wordpress", "version": "6.4"}],
        "vulnerabilities": [
            {"cve": "CVE-9", "verified": "INCONCLUSIVE",
             "verify_reason": "verify timeout (600s per candidate)"},
            {"cve": "CVE-8", "verified": "INCONCLUSIVE",
             "verify_reason": "verify err: connection error"},
        ],
    })
    rep = _run(runner.run_report("https://t.test", findings))
    assert rep["status"] == "INCONCLUSIVE"
    assert [v["cve"] for v in rep["inconclusive"]] == ["CVE-9", "CVE-8"]
    assert rep["coverage"]["coverage"] == 0.0
    assert "INCONCLUSIVE" in rep["recommendation"]


def test_report_mixed_verdicts_status_precedence():
    # One definite negative + one inconclusive -> NO_EXPLOIT_REPRODUCED (definite
    # negatives win over inconclusives; nothing is called clean).
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "joomla", "version": "4.2"}],
        "vulnerabilities": [
            {"cve": "CVE-7", "verified": "NOT_REPRODUCED",
             "verify_reason": "endpoint returned 403"},
            {"cve": "CVE-6", "verified": "INCONCLUSIVE",
             "verify_reason": "verify timeout (600s per candidate)"},
        ],
    })
    rep = _run(runner.run_report("https://mix.test", findings))
    assert rep["status"] == "NO_EXPLOIT_REPRODUCED"
    assert rep["coverage"]["coverage"] == 0.5
    # every bucketed item carries deterministic confidence
    for bucket in ("checked", "not_applicable", "inconclusive"):
        assert all(0.0 <= v["confidence"] <= 1.0 for v in rep[bucket])


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

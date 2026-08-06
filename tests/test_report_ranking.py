"""Integration test: findings -> run_report -> render_report.

Verifies the risk layer actually reorders the report (in-the-wild + high EPSS should lead)
and that the rendered Telegram HTML surfaces the RISK band. No LLM / network involved.
"""
from __future__ import annotations

import asyncio
import json

from agent import runner
from format import rich


def _run(coro):
    return asyncio.run(coro)


def _findings():
    return json.dumps({
        "stack": [{"type": "cms", "name": "wordpress", "version": "6.4"}],
        "exploited_in_wild": ["CVE-2099-HOT"],
        "vulnerabilities": [
            # lower CVSS, but actively exploited + high EPSS -> should rank first
            {"cve": "CVE-2099-HOT", "verified": "EXPLOITABLE", "cvss": 6.0,
             "severity": "medium", "epss": 0.95, "poc_refs": ["http://poc"],
             "title": "hot bug", "verify_reason": "webshell uploaded, uid=33(www-data)"},
            # higher CVSS but no extra signals
            {"cve": "CVE-2099-BIG", "verified": "EXPLOITABLE", "cvss": 9.1,
             "severity": "critical", "title": "big bug",
             "verify_reason": "config leaked: db credential in response"},
            {"cve": "CVE-2099-SAFE", "verified": "NOT EXPLOITABLE",
             "verify_reason": "version patched"},
        ],
    })


def test_report_ranks_and_bands():
    rep = _run(runner.run_report("https://wp.test", _findings()))
    assert rep["status"] == "EXPLOITABLE"
    cves = [v["cve"] for v in rep["exploitable"]]
    # in-the-wild + EPSS 0.95 beats the raw higher-CVSS finding
    assert cves[0] == "CVE-2099-HOT"
    # every exploitable item carries a risk band, and a verified-exploitable finding
    # must land in the actionable HIGH/CRITICAL range (verified +60 dominates)
    assert all(v.get("risk_band") for v in rep["exploitable"])
    assert all(v["risk_band"] in ("HIGH", "CRITICAL") for v in rep["exploitable"])
    # "version patched" is a deterministic NOT_APPLICABLE — sits in not_applicable,
    # not in checked (NOT_REPRODUCED)
    assert rep["checked"] == []
    assert [c["cve"] for c in rep["not_applicable"]] == ["CVE-2099-SAFE"]


def test_render_report_shows_risk_band():
    rep = _run(runner.run_report("https://wp.test", _findings()))
    html = "".join(rich.render_report(rep, "scan123"))
    assert "RISK" in html
    assert "CVE-2099-HOT" in html
    # EPSS percentage surfaced
    assert "EPSS" in html


def test_kev_flag_boosts_and_renders_badge():
    # A finding carrying kev=True (set by _enrich_kev) must get the in-the-wild boost even
    # when it is NOT in the top-level exploited_in_wild list, and the report shows a KEV badge.
    findings = json.dumps({
        "stack": [{"type": "cms", "name": "joomla", "version": "4.2"}],
        "vulnerabilities": [
            {"cve": "CVE-2023-23752", "verified": "EXPLOITABLE", "cvss": 5.3,
             "severity": "medium", "kev": True, "title": "info disclosure",
             "verify_reason": "config leaked: db credential reflected"},
        ],
    })
    rep = _run(runner.run_report("https://j.test", findings))
    item = rep["exploitable"][0]
    assert item["kev"] is True
    assert any("wild" in fct.lower() or "kev" in fct.lower() for fct in item["risk_factors"])
    html = "".join(rich.render_report(rep, "scanKEV"))
    assert "KEV" in html

"""Tests for the deterministic risk-scoring layer (agent/scoring.py).

These lock in the *ordering invariants* that make the report useful: a bug proven
exploitable on the actual target must outrank a scarier-on-paper but unverified bug, and
in-the-wild / EPSS signals must move the needle.
"""
from __future__ import annotations

from agent import scoring


def test_verified_exploitable_scores_high():
    r = scoring.score_finding({"cve": "CVE-1", "verified": "EXPLOITABLE", "cvss": 7.5})
    assert r["risk"] >= 70
    assert r["risk_band"] in ("HIGH", "CRITICAL")


def test_verified_not_exploitable_is_demoted_below_unverified():
    # Same CVSS, but one is proven safe on the target -> must rank lower.
    safe = scoring.score_finding({"cve": "A", "verified": "NOT EXPLOITABLE", "cvss": 9.8})
    unknown = scoring.score_finding({"cve": "B", "cvss": 9.8})
    assert safe["risk"] < unknown["risk"]


def test_verified_exploitable_outranks_higher_cvss_unverified():
    # The whole point: proof-on-target > raw severity.
    verified_mid = scoring.score_finding({"cve": "A", "verified": "EXPLOITABLE", "cvss": 6.0})
    unverified_crit = scoring.score_finding({"cve": "B", "cvss": 10.0})
    assert verified_mid["risk"] > unverified_crit["risk"]


def test_kev_and_epss_boost():
    base = scoring.score_finding({"cve": "A", "cvss": 5.0})
    boosted = scoring.score_finding({"cve": "A", "cvss": 5.0}, epss=0.9, kev=True)
    assert boosted["risk"] > base["risk"]
    # both factors should be recorded
    joined = " ".join(boosted["risk_factors"]).lower()
    assert "kev" in joined and "epss" in joined


def test_epss_read_from_finding_field_when_arg_absent():
    r = scoring.score_finding({"cve": "A", "cvss": 5.0, "epss": 0.5})
    assert any("epss" in f.lower() for f in r["risk_factors"])


def test_poc_availability_adds_weight():
    with_poc = scoring.score_finding({"cve": "A", "cvss": 5.0, "poc_refs": ["http://x"]})
    without = scoring.score_finding({"cve": "A", "cvss": 5.0})
    assert with_poc["risk"] > without["risk"]


def test_score_is_clamped_0_100():
    r = scoring.score_finding(
        {"cve": "A", "verified": "EXPLOITABLE", "cvss": 10.0, "poc_refs": ["x"]},
        epss=1.0, kev=True)
    assert 0.0 <= r["risk"] <= 100.0


def test_band_thresholds():
    assert scoring.band_for(90) == "CRITICAL"
    assert scoring.band_for(70) == "HIGH"
    assert scoring.band_for(50) == "MEDIUM"
    assert scoring.band_for(20) == "LOW"
    assert scoring.band_for(5) == "INFO"


def test_rank_findings_sorts_and_annotates():
    findings = [
        {"cve": "CVE-LOW", "cvss": 3.0},
        {"cve": "CVE-HOT", "verified": "EXPLOITABLE", "cvss": 6.0},
        {"cve": "CVE-KNOWN", "cvss": 8.0},
    ]
    ranked = scoring.rank_findings(findings, exploited_in_wild=["CVE-KNOWN"])
    # every finding annotated
    assert all("risk" in v and "risk_band" in v for v in ranked)
    # verified-exploitable should be first
    assert ranked[0]["cve"] == "CVE-HOT"
    # sorted descending
    risks = [v["risk"] for v in ranked]
    assert risks == sorted(risks, reverse=True)


def test_rank_findings_handles_empty():
    assert scoring.rank_findings([]) == []
    assert scoring.rank_findings(None) == []

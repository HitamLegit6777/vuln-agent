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


# ---- verdict state machine (normalize_verdict) ----


def test_normalize_legacy_not_exploitable_to_not_reproduced():
    assert scoring.normalize_verdict("NOT EXPLOITABLE", "endpoint returned 403")[0] == "NOT_REPRODUCED"
    assert scoring.normalize_verdict("NOT_EXPLOITABLE", "no direct proof")[0] == "NOT_REPRODUCED"


def test_normalize_version_evidence_maps_to_not_applicable():
    for reason in ("version not in range", "version patched", "not affected",
                   "outside the affected range", "already fixed"):
        v, _ = scoring.normalize_verdict("NOT EXPLOITABLE", reason)
        assert v == "NOT_APPLICABLE", reason
    # NOT_AFFECTED label itself maps to NOT_APPLICABLE
    assert scoring.normalize_verdict("NOT_AFFECTED", "")[0] == "NOT_APPLICABLE"


def test_normalize_timeout_and_error():
    v, r = scoring.normalize_verdict("NOT EXPLOITABLE", "verify timeout (600s per candidate)",
                                     timeout=True)
    assert v == "INCONCLUSIVE" and r == "verify timeout (600s per candidate)"
    v, _ = scoring.normalize_verdict("EXPLOITABLE", "verify err: boom", error=True)
    assert v == "INCONCLUSIVE"


def test_normalize_connectivity_error_maps_to_unreachable():
    v, _ = scoring.normalize_verdict("", "verify err: Connection refused to target", error=True)
    assert v == "UNREACHABLE"
    v, _ = scoring.normalize_verdict("", "verify err: Name or service not known", error=True)
    assert v == "UNREACHABLE"


def test_normalize_exploitable_requires_direct_proof():
    strong = "webshell uploaded, uid=33(www-data) reflected in response"
    assert scoring.normalize_verdict("EXPLOITABLE", strong)[0] == "EXPLOITABLE"
    # circumstantial / no proof -> downgrade to NOT_REPRODUCED with rewritten reason
    v, r = scoring.normalize_verdict("EXPLOITABLE", "detected version in affected range, http 200")
    assert v == "NOT_REPRODUCED"
    assert "no direct exploitation proof" in r
    v, r = scoring.normalize_verdict("EXPLOITABLE", "advisory says exploitable")
    assert v == "NOT_REPRODUCED"


def test_normalize_unknown_to_inconclusive():
    assert scoring.normalize_verdict("", "")[0] == "INCONCLUSIVE"
    assert scoring.normalize_verdict("UNKNOWN", "")[0] == "INCONCLUSIVE"
    assert scoring.normalize_verdict("garbage", "")[0] == "INCONCLUSIVE"


def test_normalize_is_deterministic():
    inputs = [("NOT EXPLOITABLE", "version patched"), ("EXPLOITABLE", "uid=0 root"),
              ("UNKNOWN", ""), ("INCONCLUSIVE", "verify timeout")]
    assert len({scoring.normalize_verdict(v, r) for v, r in inputs}) == len(inputs)
    # same input twice -> same output (no clock, no randomness)
    assert (scoring.normalize_verdict("NOT EXPLOITABLE", "version patched")
            == scoring.normalize_verdict("NOT EXPLOITABLE", "version patched"))


# ---- confidence + coverage ----


def test_confidence_deterministic_and_ordered():
    c_expl = scoring.verdict_confidence("EXPLOITABLE")
    c_na = scoring.verdict_confidence("NOT_APPLICABLE")
    c_nr = scoring.verdict_confidence("NOT_REPRODUCED", attempts=3)
    c_inc = scoring.verdict_confidence("INCONCLUSIVE")
    c_unr = scoring.verdict_confidence("UNREACHABLE")
    assert c_expl > c_na > c_nr > c_inc > c_unr
    # attempts raise NOT_REPRODUCED confidence (tested run > nothing run)
    assert scoring.verdict_confidence("NOT_REPRODUCED", attempts=2) > \
        scoring.verdict_confidence("NOT_REPRODUCED", attempts=0)
    assert scoring.verdict_confidence("EXPLOITABLE") == scoring.verdict_confidence("EXPLOITABLE")


def test_report_coverage_fraction():
    full = scoring.report_coverage(["EXPLOITABLE", "NOT_REPRODUCED", "NOT_APPLICABLE"])
    assert full == {"total": 3, "definite": 3, "coverage": 1.0}
    partial = scoring.report_coverage(["EXPLOITABLE", "INCONCLUSIVE", "NOT_REPRODUCED"])
    assert partial["total"] == 3 and partial["definite"] == 2 and partial["coverage"] == round(2 / 3, 3)
    none = scoring.report_coverage([])
    assert none == {"total": 0, "definite": 0, "coverage": 0.0}


def test_not_reproduced_demoted_in_score():
    safe = scoring.score_finding({"cve": "A", "verified": "NOT_REPRODUCED", "cvss": 9.8})
    unknown = scoring.score_finding({"cve": "B", "cvss": 9.8})
    assert safe["risk"] < unknown["risk"]
    na = scoring.score_finding({"cve": "C", "verified": "NOT_APPLICABLE", "cvss": 9.8})
    assert na["risk"] < unknown["risk"]

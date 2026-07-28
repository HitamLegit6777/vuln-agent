"""Deterministic risk scoring for findings.

Given everything the agent knows about a CVE on a specific target, collapse it into one
0-100 priority number plus a coarse band. This is what lets the report list the things
that actually matter first, instead of ordering by raw CVSS (which ignores whether the bug
is being exploited in the wild, whether a PoC exists, and whether *this* target was proven
exploitable).

Signals, in rough order of weight:
  * verified verdict      — a PoC that actually fired on THIS target dominates everything.
  * exploited-in-wild/KEV — CISA KEV / in-the-wild = attackers are using it now.
  * EPSS                  — forward-looking probability of exploitation (0..1).
  * CVSS base score       — intrinsic technical severity (0..10).
  * PoC availability      — public exploit code lowers the bar to attack.

The function is pure and side-effect free, so it is fully unit-testable and stable across
runs (no randomness, no clock, no network).
"""
from __future__ import annotations

from typing import Optional

_BANDS = (
    (85, "CRITICAL"),
    (65, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0, "INFO"),
)


def _as_float(x) -> Optional[float]:
    if x is None:
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def band_for(score: float) -> str:
    """Map a 0-100 risk score to a coarse priority band."""
    for threshold, label in _BANDS:
        if score >= threshold:
            return label
    return "INFO"


def score_finding(finding: dict,
                   *,
                   epss: Optional[float] = None,
                   kev: Optional[bool] = None,
                   exploited_in_wild: bool = False) -> dict:
    """Compute a risk score for one finding dict.

    `finding` is the per-CVE dict used throughout runner.py (keys: verified, cvss, severity,
    poc_refs, sources, ...). `epss`/`kev` may be passed explicitly by the caller (e.g. from
    the EPSS scraper `raw.epss` or a KEV lookup); if omitted, they are read from the finding
    (`finding['epss']`, `finding['kev']`). `exploited_in_wild` is an OR'd hint from the
    top-level findings list.

    Returns {risk, risk_band, risk_factors} where risk is 0-100.
    """
    factors: list[str] = []
    score = 0.0

    # --- pull signals (explicit args win over embedded fields) ---
    verified = str(finding.get("verified", "")).upper()
    cvss = _as_float(finding.get("cvss"))
    epss_v = epss if epss is not None else _as_float(finding.get("epss"))
    if kev is None:
        kev = bool(finding.get("kev"))
    itw = exploited_in_wild or kev or bool(finding.get("exploited_in_wild"))
    poc = bool(finding.get("poc_refs")) or bool(finding.get("poc_path"))

    # --- verified verdict dominates: proof on THIS target ---
    if verified == "EXPLOITABLE":
        score += 60.0
        factors.append("verified exploitable on target (+60)")
    elif verified in ("NOT EXPLOITABLE", "NOT_EXPLOITABLE"):
        # proven safe on this target: keep it low regardless of intrinsic severity
        score -= 25.0
        factors.append("verified NOT exploitable on target (-25)")

    # --- in-the-wild / KEV ---
    if itw:
        score += 20.0
        factors.append("exploited in the wild / KEV (+20)")

    # --- EPSS (0..1 probability -> up to +15) ---
    if epss_v is not None:
        contrib = round(15.0 * max(0.0, min(epss_v, 1.0)), 2)
        score += contrib
        factors.append(f"EPSS {epss_v:.3f} (+{contrib})")

    # --- CVSS base (0..10 -> up to +20) ---
    if cvss is not None:
        contrib = round(2.0 * max(0.0, min(cvss, 10.0)), 2)
        score += contrib
        factors.append(f"CVSS {cvss:.1f} (+{contrib})")

    # --- public PoC availability ---
    if poc:
        score += 5.0
        factors.append("public PoC available (+5)")

    score = max(0.0, min(round(score, 2), 100.0))
    return {"risk": score, "risk_band": band_for(score), "risk_factors": factors}


def rank_findings(findings: list[dict],
                  *,
                  exploited_in_wild: Optional[list] = None) -> list[dict]:
    """Annotate each finding with risk fields and return them sorted high-risk first.

    Mutates each dict in place (adds risk/risk_band/risk_factors) AND returns the sorted
    list, so callers can use either style. `exploited_in_wild` is the top-level CVE list
    from the findings JSON; any finding whose CVE is in it gets the in-the-wild boost.
    """
    itw_set = {str(c).upper() for c in (exploited_in_wild or [])}
    for v in findings or []:
        cve_up = str(v.get("cve", "")).upper()
        res = score_finding(v, exploited_in_wild=cve_up in itw_set)
        v.update(res)
    return sorted(findings or [], key=lambda v: v.get("risk", 0.0), reverse=True)

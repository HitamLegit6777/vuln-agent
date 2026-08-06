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
    elif verified in ("NOT EXPLOITABLE", "NOT_EXPLOITABLE", "NOT_REPRODUCED", "NOT_APPLICABLE"):
        # proven safe / not applicable on this target: keep it low regardless of
        # intrinsic severity (NOT_REPRODUCED/NOT_APPLICABLE are the canonical
        # successors of the legacy NOT EXPLOITABLE verdict)
        score -= 25.0
        factors.append("verified not exploitable on target (-25)")

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


# ---------------------------------------------------------------------------
# Verdict state machine — the single canonical mapping for exploitability
# verdicts, confidence, and coverage. Pure and deterministic (no clock, no
# randomness, no network), so reports, verify phase, and stored-data re-renders
# all agree on what a verdict means.
# ---------------------------------------------------------------------------

# Canonical per-finding verdicts.
VERDICTS = ("EXPLOITABLE", "NOT_REPRODUCED", "NOT_APPLICABLE", "INCONCLUSIVE", "UNREACHABLE")
# Canonical report-level statuses (successors of the old binary EXPLOITABLE/CLEAN).
REPORT_STATUSES = ("EXPLOITABLE", "NO_EXPLOIT_REPRODUCED", "INCONCLUSIVE", "UNREACHABLE")

# Reasons that deterministically say the target version is outside the affected
# range or already patched — a legacy NOT EXPLOITABLE with one of these maps to
# NOT_APPLICABLE (the vuln does not apply to this target), not NOT_REPRODUCED.
_NOT_APPLICABLE_PATTERNS = (
    "not in the affected range", "not in affected range", "not in range",
    "outside the affected range", "out of the affected range", "outside affected range",
    "out of range", "version not affected", "version is not affected", "not affected",
    "version patched", "already patched", "patched", "already fixed", "fixed in",
    "fixed version", "not vulnerable", "not exploitable in this version",
    "version out of range", "version not in",
)

# Connectivity-level failures that make the TARGET itself unreachable (as opposed
# to the PoC merely not reproducing) — a verify error with one of these maps to
# UNREACHABLE, anything else to INCONCLUSIVE.
_UNREACHABLE_PATTERNS = (
    "unreachable", "connection refused", "connection reset", "connection error",
    "connection timed out", "getaddrinfo", "name or service not known",
    "name resolution", "failed to resolve", "timed out resolving", "cannot connect",
    "no route to host", "network is unreachable", "econnrefused", "econnreset",
    "dns resolution", "max retries exceeded", "tunnel connection failed",
)

# Weak evidence patterns — if an EXPLOITABLE reason contains only these, the claim
# is circumstantial (version in range / HTTP status / advisory text), so the verdict
# downgrades to NOT_REPRODUCED: the exploit was NOT reproduced on this target.
_WEAK_PATTERNS = [
    "version in range", "version is within", "detected version", "affected range",
    "http 200", "status 200", "returned 200", "http 302", "redirect",
    "endpoint accessible", "endpoint returned", "returned http",
    "advisory says", "cve advisory", "vulnerable version",
    "empty data", "data:[]", "success\":true", "no authentication required",
]

# Direct proof patterns — an EXPLOITABLE reason containing any of these is genuine
# exploitation evidence (output reflected, code executed, data exfiltrated, ...).
_STRONG_PATTERNS = [
    "reflected", "marker", "uid=", "gid=", "www-data", "root:x:0",
    "command output", "echo ", "sleep confirmed", "delay measured",
    "uploaded file", "file accessible", "webshell", "php executed",
    "sql", "database", "query returned", "data exfil",
    "admin dashboard", "authenticated content", "user list",
    "privilege escalated", "group changed", "user created",
    "api key", "credential", "secret", "config leaked",
    "rce confirmed", "code execution", "payload executed",
    "math result", "arithmetic", "3105",
]


def is_not_applicable_reason(reason: str) -> bool:
    """Deterministic: does the reason say the target version is out of range / patched?"""
    low = str(reason or "").lower()
    return any(p in low for p in _NOT_APPLICABLE_PATTERNS)


def is_unreachable_error(reason: str) -> bool:
    """Deterministic: does the error say the TARGET itself could not be reached?"""
    low = str(reason or "").lower()
    return any(p in low for p in _UNREACHABLE_PATTERNS)


def normalize_verdict(verdict, reason: str = "",
                      *, timeout: bool = False, error: bool = False) -> tuple[str, str]:
    """Map any raw/legacy verdict onto the canonical verdict set (deterministic).

    * timeout/error flags (from the verify phase's wall-clock cap) -> INCONCLUSIVE;
      an error whose text shows connectivity failure -> UNREACHABLE.
    * EXPLOITABLE is kept only with DIRECT proof in the reason; weak/circumstantial
      proof downgrades to NOT_REPRODUCED (exploit not reproduced on this target).
    * legacy NOT EXPLOITABLE / NOT_EXPLOITABLE -> NOT_APPLICABLE when the reason
      deterministically says version out of range / patched, else NOT_REPRODUCED.
    * any unrecognized value (UNKNOWN, empty, ...) -> INCONCLUSIVE, so a missing
      verdict can never be misread as "safe".

    Returns (canonical_verdict, reason) — the reason is rewritten only on the
    weak-proof downgrade, so the original evidence text survives everywhere else.
    """
    v = str(verdict or "").strip().upper().replace("-", "_").replace(" ", "_")
    r = str(reason or "")
    if timeout:
        return "INCONCLUSIVE", r
    if error:
        return ("UNREACHABLE", r) if is_unreachable_error(r) else ("INCONCLUSIVE", r)
    if v in ("EXPLOITABLE", "VERIFIED", "CONFIRMED"):
        low = r.lower()
        if any(p in low for p in _STRONG_PATTERNS):
            return "EXPLOITABLE", r  # direct proof present — keep
        if any(p in low for p in _WEAK_PATTERNS):
            return "NOT_REPRODUCED", (
                "Version in range but no direct exploitation proof. PoC claimed "
                "EXPLOITABLE but reason only shows circumstantial evidence: " + r[:150])
        return "NOT_REPRODUCED", f"No direct proof found in verify reason. {r[:150]}"
    if v in ("NOT_EXPLOITABLE", "NOT_REPRODUCED", "NOT_EXPLOITED", "SAFE",
             "PATCHED", "NOT_VERIFIED"):
        if is_not_applicable_reason(r):
            return "NOT_APPLICABLE", r
        return "NOT_REPRODUCED", r
    if v in ("NOT_AFFECTED", "NOT_APPLICABLE", "OUT_OF_RANGE", "NO_MATCH"):
        return "NOT_APPLICABLE", r
    if v in ("UNREACHABLE", "DOWN", "OFFLINE", "UNRESOLVED"):
        return "UNREACHABLE", r
    return "INCONCLUSIVE", r


def verdict_confidence(verdict, attempts: int = 0, reason: str = "") -> float:
    """Deterministic confidence (0..1) in a single finding's verdict.

    EXPLOITABLE requires direct proof (0.95); NOT_REPRODUCED from an actual test run
    is 0.8 (0.7 when nothing was run); NOT_APPLICABLE rests on version evidence (0.9);
    INCONCLUSIVE/UNREACHABLE are knowingly low (0.35 / 0.1). Pure function of inputs.
    """
    v = str(verdict or "").upper()
    if v == "EXPLOITABLE":
        return 0.95
    if v == "NOT_REPRODUCED":
        return 0.8 if int(attempts or 0) > 0 else 0.7
    if v == "NOT_APPLICABLE":
        return 0.9
    if v == "INCONCLUSIVE":
        return 0.35
    if v == "UNREACHABLE":
        return 0.1
    return 0.0


_DEFINITE = frozenset(("EXPLOITABLE", "NOT_REPRODUCED", "NOT_APPLICABLE"))


def report_coverage(verdicts) -> dict:
    """Deterministic coverage of a scan's verified candidates: the fraction that
    reached a DEFINITE outcome (exploitable / not reproduced / not applicable).
    Timeouts/errors keep coverage below 1.0, so a partially-verified scan visibly
    reports lower coverage instead of pretending full confidence."""
    total = len(verdicts or [])
    definite = sum(1 for v in (verdicts or [])
                   if str(v or "").upper() in _DEFINITE)
    return {"total": total, "definite": definite,
            "coverage": round(definite / total, 3) if total else 0.0}

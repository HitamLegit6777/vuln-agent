"""CVSS v3.1 base-score computation + severity normalization.

Vuln sources are inconsistent: some records carry a numeric `cvss` but no severity band,
some carry a `CVSS:3.1/...` vector string but no score, and severity labels arrive in a
dozen spellings ("High", "high", "IMPORTANT", "sev:high"). This module turns any of those
into a single grounded (score, severity) pair so downstream ranking is deterministic.

The base-score math follows the official CVSS v3.1 specification (FIRST.org), including the
spec's `roundup` (ceil to 1 decimal on a 100000-scaled integer) rather than naive rounding.
Only the BASE metric group is computed (temporal/environmental are out of scope for grounding).

Reference: https://www.first.org/cvss/v3.1/specification-document (section 7.1).
"""
from __future__ import annotations

import math
import re
from typing import Optional

# ---- metric weight tables (CVSS v3.1 spec, section 7.4) ----

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}          # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                                 # Attack Complexity
_UI = {"N": 0.85, "R": 0.62}                                 # User Interaction
# Privileges Required is scope-dependent: (unchanged, changed)
_PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}                      # C / I / A impact

_SEVERITY_BANDS = (
    (0.0, 0.0, "NONE"),
    (0.1, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
)

# free-text severity spellings -> canonical band
_SEVERITY_ALIASES = {
    "none": "NONE", "informational": "NONE", "info": "NONE",
    "low": "LOW", "minor": "LOW",
    "medium": "MEDIUM", "moderate": "MEDIUM", "warning": "MEDIUM",
    "high": "HIGH", "important": "HIGH", "severe": "HIGH",
    "critical": "CRITICAL", "crit": "CRITICAL",
}

_VECTOR_TOKEN_RE = re.compile(r"([A-Za-z]+):([A-Za-z]+)")


def _roundup(x: float) -> float:
    """CVSS v3.1 roundup: round *up* to one decimal place, integer-scaled to avoid
    binary float error (spec Appendix A). roundup(4.02) == 4.1, roundup(4.00) == 4.0."""
    scaled = int(round(x * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse_vector(vector: str) -> Optional[dict]:
    """Parse a CVSS v3.x vector string into a metric dict (e.g. {'AV':'N', ...}).

    Accepts an optional 'CVSS:3.1/' prefix. Returns None if the mandatory base metrics
    (AV, AC, PR, UI, S, C, I, A) are not all present.
    """
    if not vector or not isinstance(vector, str):
        return None
    metrics: dict[str, str] = {}
    for k, v in _VECTOR_TOKEN_RE.findall(vector.upper()):
        if k == "CVSS":
            continue
        metrics[k] = v
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(m in metrics for m in required):
        return None
    return metrics


def base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.1 base score (0.0-10.0) from a vector string.

    Returns None if the vector is missing base metrics or uses an unknown metric value.
    """
    m = parse_vector(vector)
    if not m:
        return None
    try:
        scope_changed = m["S"] == "C"
        iss = 1.0 - (1.0 - _CIA[m["C"]]) * (1.0 - _CIA[m["I"]]) * (1.0 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = _PR[m["PR"]][1 if scope_changed else 0]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return None  # unknown metric value (e.g. AV:X)
    if impact <= 0:
        return 0.0
    if scope_changed:
        return min(_roundup(1.08 * (impact + exploitability)), 10.0)
    return min(_roundup(impact + exploitability), 10.0)


def severity_for_score(score: Optional[float]) -> Optional[str]:
    """Map a numeric CVSS score to its qualitative band (CVSS v3.1 section 5)."""
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    for lo, hi, label in _SEVERITY_BANDS:
        if lo <= s <= hi:
            return label
    return "CRITICAL" if s > 10 else "NONE"


def normalize_severity(severity: Optional[str]) -> Optional[str]:
    """Canonicalize a free-text severity label to NONE/LOW/MEDIUM/HIGH/CRITICAL.

    Handles messy source labels: an exact alias wins first ("moderate" -> MEDIUM), then a
    substring scan catches embedded tokens ("sev:high" -> HIGH). Returns None if nothing
    recognizable is found, so callers can fall back to a score-derived band.
    """
    if not severity:
        return None
    key = re.sub(r"[^a-z]", "", str(severity).lower())
    if not key:
        return None
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key]
    # embedded-token scan, longest alias first so "critical" beats "crit"
    for alias in sorted(_SEVERITY_ALIASES, key=len, reverse=True):
        if alias in key:
            return _SEVERITY_ALIASES[alias]
    return None


def enrich(cvss: Optional[float], severity: Optional[str],
           vector: Optional[str] = None) -> tuple[Optional[float], Optional[str]]:
    """Best-effort (score, severity) reconciliation from possibly-partial inputs.

    Priority:
      1. keep an explicit numeric score if present;
      2. else derive the score from the vector string;
      3. severity = normalized label if valid, else derived from whichever score we have.
    """
    score = None
    if cvss is not None:
        try:
            score = float(cvss)
        except (TypeError, ValueError):
            score = None
    if score is None and vector:
        score = base_score(vector)
    sev = normalize_severity(severity) or severity_for_score(score)
    return score, sev

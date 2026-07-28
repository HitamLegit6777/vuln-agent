"""Tests for the CVSS v3.1 base-score engine (scrapers/cvss.py).

The expected scores are the canonical values published by FIRST.org for these exact
vectors, so any drift in the formula or rounding is caught immediately.
"""
from __future__ import annotations

import pytest

from scrapers import cvss


# (vector, expected base score) — canonical FIRST.org examples.
CANONICAL = [
    # CVE-2020-1472 "Zerologon" — critical, scope changed
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    # Classic unauth RCE, scope unchanged
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    # Heartbleed-style info leak (conf only, scope unchanged)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    # Reflected XSS: scope changed, low conf/integrity, needs user interaction
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    # Local low-priv DoS
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),
    # Fully benign vector -> 0.0
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize("vector,expected", CANONICAL)
def test_base_score_matches_canonical(vector, expected):
    assert cvss.base_score(vector) == expected


def test_base_score_accepts_bare_vector_without_prefix():
    assert cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_base_score_none_on_missing_metrics():
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L") is None


def test_base_score_none_on_unknown_metric_value():
    assert cvss.base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_base_score_none_on_junk():
    assert cvss.base_score("") is None
    assert cvss.base_score(None) is None
    assert cvss.base_score("not a vector") is None


def test_roundup_semantics():
    # spec examples: exact tenths stay, anything above rounds *up*
    assert cvss._roundup(4.0) == 4.0
    assert cvss._roundup(4.01) == 4.1
    assert cvss._roundup(4.00001) == 4.1


@pytest.mark.parametrize("score,band", [
    (0.0, "NONE"),
    (0.1, "LOW"),
    (3.9, "LOW"),
    (4.0, "MEDIUM"),
    (6.9, "MEDIUM"),
    (7.0, "HIGH"),
    (8.9, "HIGH"),
    (9.0, "CRITICAL"),
    (10.0, "CRITICAL"),
])
def test_severity_bands(score, band):
    assert cvss.severity_for_score(score) == band


def test_severity_for_score_none():
    assert cvss.severity_for_score(None) is None


@pytest.mark.parametrize("raw,canon", [
    ("High", "HIGH"),
    ("high", "HIGH"),
    ("IMPORTANT", "HIGH"),
    ("Moderate", "MEDIUM"),
    ("critical", "CRITICAL"),
    ("informational", "NONE"),
    ("sev: high", "HIGH"),   # non-alpha stripped
])
def test_normalize_severity(raw, canon):
    assert cvss.normalize_severity(raw) == canon


def test_normalize_severity_unknown_is_none():
    assert cvss.normalize_severity("bananas") is None
    assert cvss.normalize_severity("") is None
    assert cvss.normalize_severity(None) is None


def test_enrich_keeps_explicit_score_and_derives_band():
    score, sev = cvss.enrich(7.5, None)
    assert score == 7.5 and sev == "HIGH"


def test_enrich_derives_score_from_vector():
    score, sev = cvss.enrich(None, None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8 and sev == "CRITICAL"


def test_enrich_prefers_valid_label_over_derived_band():
    # explicit "critical" label kept even though score would say HIGH
    score, sev = cvss.enrich(7.5, "critical")
    assert score == 7.5 and sev == "CRITICAL"


def test_enrich_all_none():
    assert cvss.enrich(None, None, None) == (None, None)

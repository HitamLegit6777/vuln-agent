"""Tests for the version-range matching engine in scrapers/base.py.

This is the accuracy-critical core of the whole agent: a wrong verdict here means a
CVE is either wrongly flagged VULNERABLE (false positive) or wrongly dropped
NOT_AFFECTED (false negative). The engine documents strict semantics:

  * a range must be CLOSED ON TOP (has a max bound) before `True` is ever returned;
    "affected from X onwards" with no known fix -> UNKNOWN (None).
  * non-semver bounds (git commit hashes) -> UNKNOWN (None).
  * an unparsable target version against a bounded range -> UNKNOWN (None).
"""
from __future__ import annotations

from scrapers.base import (
    AffectedRange,
    VulnRecord,
    _cmp_ver,
    _is_semver_bound,
    _norm_ver,
    version_in_range,
)


# --------------------------- _norm_ver ---------------------------

def test_norm_ver_basic_numeric():
    assert _norm_ver("1.2.3") == [(0, 1), (0, 2), (0, 3)]


def test_norm_ver_strips_v_prefix():
    assert _norm_ver("v2.4.60") == [(0, 2), (0, 4), (0, 60)]


def test_norm_ver_none_and_empty():
    assert _norm_ver(None) is None
    assert _norm_ver("") is None


def test_norm_ver_rejects_pure_hash():
    # a 40-char git sha has no leading digit -> not a version
    assert _norm_ver("deadbeef") is None


def test_norm_ver_prerelease_tokens_sort_after_numbers():
    # numeric parts are tagged 0, alpha parts tagged 1, so (0, n) < (1, "alpha")
    v = _norm_ver("1.0.0-alpha")
    assert v[0] == (0, 1)
    assert v[-1] == (1, "alpha")


# --------------------------- _cmp_ver ---------------------------

def test_cmp_ver_orders_correctly():
    assert _cmp_ver(_norm_ver("1.2.0"), _norm_ver("1.10.0")) < 0
    assert _cmp_ver(_norm_ver("2.0.0"), _norm_ver("1.9.9")) > 0
    assert _cmp_ver(_norm_ver("1.2.3"), _norm_ver("1.2.3")) == 0


def test_cmp_ver_shorter_is_less_when_prefix_equal():
    # 1.2 < 1.2.1
    assert _cmp_ver(_norm_ver("1.2"), _norm_ver("1.2.1")) < 0


def test_cmp_ver_none_handling():
    assert _cmp_ver(None, None) == 0
    assert _cmp_ver(None, _norm_ver("1.0")) < 0
    assert _cmp_ver(_norm_ver("1.0"), None) > 0


# --------------------------- _is_semver_bound ---------------------------

def test_is_semver_bound_true_for_clean_numeric():
    assert _is_semver_bound("2.4.60") is True


def test_is_semver_bound_false_for_commit_hash():
    assert _is_semver_bound("15e7241fa52e") is False


def test_is_semver_bound_false_for_none():
    assert _is_semver_bound(None) is False


# --------------------------- version_in_range ---------------------------

def _rng(**kw) -> AffectedRange:
    return AffectedRange(**kw)


def test_in_range_closed_top_exclusive_true():
    # affected < 2.4.60, target 2.4.59 -> vulnerable
    assert version_in_range("2.4.59", _rng(max_exclusive="2.4.60")) is True


def test_in_range_closed_top_exclusive_false_at_boundary():
    # target == fixed version -> NOT affected
    assert version_in_range("2.4.60", _rng(max_exclusive="2.4.60")) is False


def test_in_range_inclusive_upper_boundary_true():
    assert version_in_range("5.7.0", _rng(max_inclusive="5.7.0")) is True


def test_in_range_inclusive_upper_boundary_false_above():
    assert version_in_range("5.7.1", _rng(max_inclusive="5.7.0")) is False


def test_in_range_with_min_and_max_inside():
    r = _rng(min_inclusive="4.0.0", max_exclusive="4.5.0")
    assert version_in_range("4.2.0", r) is True


def test_in_range_with_min_and_max_below_min():
    r = _rng(min_inclusive="4.0.0", max_exclusive="4.5.0")
    assert version_in_range("3.9.9", r) is False


def test_only_lower_bound_is_unknown_when_at_or_above():
    # "affected from 3.0 onwards" with no fix -> cannot confirm target is affected
    assert version_in_range("3.5.0", _rng(min_inclusive="3.0.0")) is None


def test_only_lower_bound_is_false_when_below():
    assert version_in_range("2.9.0", _rng(min_inclusive="3.0.0")) is False


def test_no_bounds_is_unknown():
    assert version_in_range("1.0.0", _rng()) is None


def test_non_semver_bound_is_unknown():
    # git-commit-hash bound cannot be compared numerically
    assert version_in_range("2.4.59", _rng(max_exclusive="15e7241fa52e")) is None


def test_unparsable_target_against_bounded_range_is_unknown():
    assert version_in_range("not-a-version", _rng(max_exclusive="2.0.0")) is None


def test_none_target_against_bounded_range_is_unknown():
    assert version_in_range(None, _rng(max_exclusive="2.0.0")) is None


# --------------------------- VulnRecord.is_vulnerable ---------------------------

def test_record_no_ranges_returns_none():
    rec = VulnRecord(cve="CVE-2024-0001")
    assert rec.is_vulnerable("1.0.0") is None


def test_record_any_true_wins():
    rec = VulnRecord(
        cve="CVE-2024-0002",
        affected=[
            _rng(max_exclusive="1.0.0"),   # target 2.0 -> False
            _rng(min_inclusive="1.5.0", max_exclusive="3.0.0"),  # target 2.0 -> True
        ],
    )
    assert rec.is_vulnerable("2.0.0") is True


def test_record_false_when_all_false():
    rec = VulnRecord(
        cve="CVE-2024-0003",
        affected=[
            _rng(max_exclusive="1.0.0"),
            _rng(max_exclusive="1.5.0"),
        ],
    )
    assert rec.is_vulnerable("2.0.0") is False


def test_record_unknown_when_mix_of_false_and_none():
    rec = VulnRecord(
        cve="CVE-2024-0004",
        affected=[
            _rng(max_exclusive="1.0.0"),   # target 2.0 -> False
            _rng(min_inclusive="1.0.0"),   # target 2.0 -> None (open top)
        ],
    )
    # any False and no True -> False (documented aggregate: False wins over None)
    assert rec.is_vulnerable("2.0.0") is False

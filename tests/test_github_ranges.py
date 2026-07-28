"""Regression tests for scrapers.github._parse_ranges (GHSA affected-range parsing).

GHSA SEMVER ranges express the affected window with events: `introduced`,
`fixed` (exclusive upper), and `last_affected` (INCLUSIVE upper, used when there is
no fix release). A past bug set `hi_exc = None` on a `last_affected` event with a
"handled below" comment that never handled it, so the inclusive upper bound was
dropped -> a version clearly inside the window returned UNKNOWN instead of True.
"""
from scrapers.github import _parse_ranges


def _adv(events, eco="npm", name="foo"):
    return [{"package": {"ecosystem": eco, "name": name},
             "ranges": [{"type": "SEMVER", "events": events}]}]


def test_fixed_event_is_exclusive_upper():
    r = _parse_ranges(_adv([{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]))[0]
    assert r.min_inclusive == "1.0.0"
    assert r.max_exclusive == "1.5.0"
    assert r.matches("1.4.9") is True
    assert r.matches("1.5.0") is False   # fixed is exclusive
    assert r.matches("0.9.0") is False


def test_last_affected_is_inclusive_upper():
    # No fix release; upper bound expressed via last_affected (inclusive).
    r = _parse_ranges(_adv([{"introduced": "1.0.0"}, {"last_affected": "1.4.9"}]))[0]
    assert r.max_inclusive == "1.4.9", "last_affected must map to max_inclusive"
    assert r.max_exclusive is None
    assert r.matches("1.2.0") is True    # regression: was None (UNKNOWN) before fix
    assert r.matches("1.4.9") is True    # inclusive boundary is still affected
    assert r.matches("1.5.0") is False
    assert r.matches("0.5.0") is False


def test_introduced_zero_is_normalized_to_unbounded_min():
    r = _parse_ranges(_adv([{"introduced": "0"}, {"fixed": "2.0.0"}]))[0]
    assert r.min_inclusive is None      # "0" means unbounded lower
    assert r.max_exclusive == "2.0.0"
    assert r.matches("1.0.0") is True


def test_non_semver_range_type_skipped():
    ranges = _parse_ranges([{"package": {"ecosystem": "npm", "name": "foo"},
                             "ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}])
    assert ranges == []

"""Tests for the EPSS enrichment scraper (scrapers/epss.py).

Network is fully stubbed: `_get_json` is monkeypatched to return a canned FIRST.org
envelope, so these run offline and deterministically. The parser is also tested directly.
"""
from __future__ import annotations

import asyncio

from scrapers.epss import EPSSScraper, parse_epss_response


def _run(coro):
    return asyncio.run(coro)


_ENVELOPE = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.944710", "percentile": "0.999880", "date": "2024-01-01"},
        {"cve": "CVE-2020-0001", "epss": "0.001230", "percentile": "0.101000", "date": "2024-01-01"},
    ],
}


# --------------------------- parse_epss_response ---------------------------

def test_parse_basic():
    parsed = parse_epss_response(_ENVELOPE)
    assert parsed["CVE-2021-44228"]["epss"] == 0.94471
    assert parsed["CVE-2021-44228"]["percentile"] == 0.99988
    assert parsed["CVE-2020-0001"]["epss"] == 0.00123


def test_parse_skips_malformed_rows():
    data = {"data": [
        {"cve": "not-a-cve", "epss": "0.5"},
        {"cve": "CVE-2024-1001", "epss": "notnum"},          # unparsable score
        {"cve": "CVE-2024-1002", "epss": "", "percentile": ""},  # blank
        {"cve": "CVE-2024-1003", "epss": "0.42", "percentile": "0.9"},
        "junk-string",
    ]}
    parsed = parse_epss_response(data)
    assert "not-a-cve" not in parsed and "NOT-A-CVE" not in parsed
    assert parsed["CVE-2024-1001"]["epss"] is None
    assert parsed["CVE-2024-1002"]["epss"] is None
    assert parsed["CVE-2024-1003"]["epss"] == 0.42


def test_parse_empty_and_garbage():
    assert parse_epss_response({}) == {}
    assert parse_epss_response({"data": None}) == {}
    assert parse_epss_response(None) == {}


# --------------------------- scraper (stubbed HTTP) ---------------------------

def _stubbed_scraper(envelope=_ENVELOPE):
    s = EPSSScraper()

    async def fake_get_json(url, **kw):
        return envelope

    s._get_json = fake_get_json  # type: ignore[assignment]
    return s


def test_get_returns_record_with_epss_in_raw():
    s = _stubbed_scraper()
    rec = _run(s.get("CVE-2021-44228"))
    assert rec is not None
    assert rec.cve == "CVE-2021-44228"
    assert rec.source == "epss"
    assert rec.raw["epss"] == 0.94471
    assert rec.raw["epss_percentile"] == 0.99988
    # human-readable annotation carries the probability
    assert "94" in rec.title


def test_get_none_for_unscored_cve():
    s = _stubbed_scraper({"data": [{"cve": "CVE-2099-9999", "epss": "", "percentile": ""}]})
    assert _run(s.get("CVE-2099-9999")) is None


def test_get_none_for_non_cve_query():
    s = _stubbed_scraper()
    assert _run(s.get("wordpress")) is None


def test_score_shortcut():
    s = _stubbed_scraper()
    assert _run(s.score("CVE-2020-0001")) == 0.00123
    assert _run(s.score("nonsense")) is None


def test_search_only_matches_cve_ids():
    s = _stubbed_scraper()
    assert _run(s.search("apache struts")) == []
    recs = _run(s.search("look at CVE-2021-44228 please"))
    assert len(recs) == 1 and recs[0].cve == "CVE-2021-44228"

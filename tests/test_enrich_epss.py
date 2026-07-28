"""Test EPSS enrichment wiring in agent.runner._enrich_epss.

Stubs EPSSScraper._fetch so no network is touched: verifies candidates get an `epss`
field, and that a scraper failure leaves candidates untouched (best-effort contract).
"""
from __future__ import annotations

import asyncio

import scrapers.epss as epss_mod
from agent import runner


def _run(coro):
    return asyncio.run(coro)


def test_enrich_epss_annotates(monkeypatch):
    async def fake_fetch(self, cves):
        return {"CVE-2021-44228": {"epss": 0.94, "percentile": 0.99, "date": "2024-01-01"}}

    monkeypatch.setattr(epss_mod.EPSSScraper, "_fetch", fake_fetch, raising=True)
    cands = [{"cve": "CVE-2021-44228"}, {"cve": "CVE-2099-0000"}]
    _run(runner._enrich_epss(cands))
    assert cands[0]["epss"] == 0.94
    assert cands[0]["epss_percentile"] == 0.99
    # unscored CVE stays without an epss key
    assert "epss" not in cands[1]


def test_enrich_epss_silent_on_failure(monkeypatch):
    async def boom(self, cves):
        raise RuntimeError("network down")

    monkeypatch.setattr(epss_mod.EPSSScraper, "_fetch", boom, raising=True)
    cands = [{"cve": "CVE-2021-44228"}]
    # must not raise
    _run(runner._enrich_epss(cands))
    assert "epss" not in cands[0]


def test_enrich_epss_empty_list():
    _run(runner._enrich_epss([]))  # no CVEs -> no-op, no error

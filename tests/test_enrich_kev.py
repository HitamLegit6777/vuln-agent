"""Tests for CISA KEV enrichment wiring in agent.runner._enrich_kev.

Stubs CisaKevScraper._load so no network is touched: verifies KEV-listed candidates get
`kev=True`, the matched set is returned, and failures are silent (best-effort contract).
"""
from __future__ import annotations

import asyncio

import scrapers.cisa_kev as kev_mod
from agent import runner


def _run(coro):
    return asyncio.run(coro)


_CATALOG = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228"},
        {"cveID": "CVE-2023-23752"},
    ]
}


def test_enrich_kev_marks_and_returns_matched(monkeypatch):
    async def fake_load(self):
        return _CATALOG

    monkeypatch.setattr(kev_mod.CisaKevScraper, "_load", fake_load, raising=True)
    cands = [
        {"cve": "CVE-2021-44228"},   # in KEV
        {"cve": "CVE-2099-0000"},    # not in KEV
    ]
    matched = _run(runner._enrich_kev(cands))
    assert matched == {"CVE-2021-44228"}
    assert cands[0]["kev"] is True
    assert "kev" not in cands[1]


def test_enrich_kev_case_insensitive(monkeypatch):
    async def fake_load(self):
        return _CATALOG

    monkeypatch.setattr(kev_mod.CisaKevScraper, "_load", fake_load, raising=True)
    cands = [{"cve": "cve-2023-23752"}]  # lowercase
    matched = _run(runner._enrich_kev(cands))
    assert matched == {"CVE-2023-23752"}
    assert cands[0]["kev"] is True


def test_enrich_kev_silent_on_failure(monkeypatch):
    async def boom(self):
        raise RuntimeError("CISA down")

    monkeypatch.setattr(kev_mod.CisaKevScraper, "_load", boom, raising=True)
    cands = [{"cve": "CVE-2021-44228"}]
    assert _run(runner._enrich_kev(cands)) == set()
    assert "kev" not in cands[0]


def test_enrich_kev_empty_list():
    assert _run(runner._enrich_kev([])) == set()

"""Scraper registry + unified aggregator.

search_all(query, version=None): parallel gather across all sources, dedupe by CVE.
get_all(cve): per-CVE enrichment across sources.
Anti-mismatch: each VulnRecord keeps its source/url; agent never merges ranges blindly.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from .base import BaseScraper, VulnRecord, AffectedRange
from .nvd import NVDScraper
from .github import GitHubAdvisoryScraper
from .osv import OSVScraper
from .exploitdb import ExploitDBScraper
from .wordfence import WordfenceScraper
from .patchstack import PatchstackScraper
from .wpscan_free import WPScanFreeScraper
from .cisa_kev import CisaKevScraper
from .poc_github import PoCGitHubScraper
from .watchtowr import WatchTowrScraper
from .cve5 import Cve5Scraper
from .epss import EPSSScraper
from .news import BleepingComputerScraper
from .joomla_security import JoomlaSecurityScraper


def build_scrapers(client: Optional[httpx.AsyncClient] = None,
                   cache_get=None, cache_set=None) -> list[BaseScraper]:
    """Ordered: structured/exact-range sources first, enrichment last."""
    kw = {"client": client, "cache_get": cache_get, "cache_set": cache_set}
    return [
        Cve5Scraper(**kw),             # CVE 5.0 exact affected ranges (reachable where NVD blocked)
        JoomlaSecurityScraper(**kw),   # Joomla core CVE discovery (security-centre)
        GitHubAdvisoryScraper(**kw),   # reliable, exact ranges
        OSVScraper(**kw),              # reliable, exact ranges
        NVDScraper(**kw),              # authoritative CPE (needs services.nvd.nist.gov reachable)
        ExploitDBScraper(**kw),        # PoC/exploit refs
        WordfenceScraper(**kw),        # WP writeups
        PatchstackScraper(**kw),       # WP DB (best-effort)
        WPScanFreeScraper(**kw),       # WP DB (best-effort, no token)
        CisaKevScraper(**kw),          # in-the-wild exploitation flag
        PoCGitHubScraper(**kw),        # PoC repo discovery
        WatchTowrScraper(**kw),        # 1day analysis + PoC
        EPSSScraper(**kw),             # exploit-probability enrichment (annotates raw.epss)
        BleepingComputerScraper(**kw),  # real-world incident news (per-CVE enrichment)
    ]


def _merge_raw(ex: dict, r: dict) -> None:
    """Merge raw dicts: extend list-valued keys, copy missing scalars, preserve exploit_source.
    Does NOT touch merged_sources (managed by _dedupe)."""
    if not isinstance(ex, dict):
        ex = {}
    for k, v in (r or {}).items():
        if v is None:
            continue
        if k == "exploit_source" and v:
            ex["exploit_source"] = v  # exploit-db PoC code — keep verbatim
        elif k == "merged_sources":
            continue  # handled by _dedupe
        elif isinstance(v, list):
            ex.setdefault(k, [])
            for item in v:
                if item not in ex[k]:
                    ex[k].append(item)
        elif k not in ex or ex[k] in (None, "", []):
            ex[k] = v


def _dedupe(records: list[VulnRecord]) -> list[VulnRecord]:
    """Dedupe by CVE; keep first (structured sources win by registry order).
    Merge poc_refs, ranges, diff_patch, severity, raw (incl. exploit_source) + track sources.
    Non-CVE records kept by source:id."""
    seen_cve: dict[str, VulnRecord] = {}
    others: list[VulnRecord] = []
    for r in records:
        if r.cve:
            if r.cve not in seen_cve:
                if not isinstance(r.raw, dict):
                    r.raw = {}
                r.raw.setdefault("merged_sources", [])
                if r.source not in r.raw["merged_sources"]:
                    r.raw["merged_sources"].append(r.source)
                seen_cve[r.cve] = r
            else:
                ex = seen_cve[r.cve]
                ex.poc_refs = list(dict.fromkeys(ex.poc_refs + r.poc_refs))
                if not ex.affected and r.affected:
                    ex.affected = r.affected
                if not ex.cvss and r.cvss:
                    ex.cvss = r.cvss; ex.severity = r.severity or ex.severity
                if not ex.diff_patch and r.diff_patch:
                    ex.diff_patch = r.diff_patch
                if len(r.description) > len(ex.description):
                    ex.description = r.description
                _merge_raw(ex.raw, r.raw)
                if r.source not in ex.raw.get("merged_sources", []):
                    ex.raw.setdefault("merged_sources", []).append(r.source)
        else:
            others.append(r)
    return list(seen_cve.values()) + others


async def search_all(scrappers: list[BaseScraper], query: str,
                     version: Optional[str] = None) -> list[VulnRecord]:
    async def _one(s: BaseScraper):
        try:
            return await s.search(query, version)
        except Exception:
            return []
    results = await asyncio.gather(*[_one(s) for s in scrappers], return_exceptions=False)
    flat = [r for sub in results for r in (sub or [])]
    return _dedupe(flat)


async def get_all(scrappers: list[BaseScraper], cve: str) -> list[VulnRecord]:
    async def _one(s: BaseScraper):
        try:
            r = await s.get(cve)
            return [r] if r else []
        except Exception:
            return []
    results = await asyncio.gather(*[_one(s) for s in scrappers])
    return _dedupe([r for sub in results for r in (sub or [])])


__all__ = ["VulnRecord", "AffectedRange", "build_scrapers",
           "search_all", "get_all"]

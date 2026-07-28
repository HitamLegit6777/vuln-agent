"""Joomla core CVE discovery via the official Joomla Security Centre.

developer.joomla.org/security-centre.html lists Joomla CORE advisories (with CVE IDs).
This scraper discovers those CVE IDs; exact affected ranges come from the cve5 scraper
(get_all enrichment) -> version_match. Fills the Joomla-core discovery gap where NVD CPE
is unreachable and GHSA keyword is noisy (returns old 3rd-party component CVEs).
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange
from bs4 import BeautifulSoup

SEC_URL = "https://developer.joomla.org/security-centre.html"
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.I)
_LINK_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class JoomlaSecurityScraper(BaseScraper):
    name = "joomla_sec"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        if "joomla" not in (query or "").lower():
            return []  # only relevant for Joomla core
        html = await self._cached("joomlasec:listing", lambda: self._get_text(SEC_URL))
        if not html:
            return []
        soup = BeautifulSoup(html, "lxml")
        out: list[VulnRecord] = []
        seen: set[str] = set()
        # advisories are links whose href/text contain a CVE id
        for a in soup.find_all("a", href=True):
            href = a.get("href", "")
            text = a.get_text(" ", strip=True)
            m = _CVE_RE.search(text) or _CVE_RE.search(href)
            if not m:
                continue
            cve = m.group(1).upper()
            if cve in seen:
                continue
            seen.add(cve)
            url = href if href.startswith("http") else f"https://developer.joomla.org/{href.lstrip('/')}"
            out.append(VulnRecord(
                cve=cve, id=cve, title=text[:200] or f"Joomla core advisory {cve}",
                source=self.name, url=url,
                severity=None, cvss=None, description=text,
                affected=[], poc_refs=[], diff_patch=None,
                published=None, raw={"core": True},
            ))
        return out

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id)
        if not m:
            return None
        cve = m.group(0).upper()
        for r in await self.search("joomla"):
            if r.cve == cve:
                return r
        return None

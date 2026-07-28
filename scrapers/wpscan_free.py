"""WPScan / WPVulnDB — free (no-token) scrape. Full API needs a token; this uses the
public vulnerabilities listing pages (React/SSR). Best-effort; graceful [].

ponytail: ceiling = WPSCAN_API_TOKEN env → structured JSON w/ exact ranges.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange
from bs4 import BeautifulSoup

SEARCH_URL = "https://wpscan.com/vulnerabilities?search={q}"
VULN_LINK_RE = re.compile(r'href="(/vulnerabilities/[a-z0-9\-]+)"', re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_VER_RE = re.compile(r"(?:<=?\s*|<\s*)(\d+\.\d+(?:\.\d+)?)", re.I)


class WPScanFreeScraper(BaseScraper):
    name = "wpscan"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        q = (query or "").strip().lower()
        html = await self._get_text(SEARCH_URL.format(q=q))
        if not html:
            return []
        ids: list[str] = []
        for m in VULN_LINK_RE.finditer(html):
            v = m.group(1).rsplit("/", 1)[-1]
            if v not in ids:
                ids.append(v)
        out = []
        for vid in ids[:15]:
            rec = await self._detail(vid, q)
            if rec:
                out.append(rec)
        return out

    async def _detail(self, vid: str, q: str) -> Optional[VulnRecord]:
        url = f"https://wpscan.com/vulnerabilities/{vid}"
        html = await self._get_text(url)
        if not html:
            return None
        soup = BeautifulSoup(html, "lxml")
        title = (soup.title.text.strip() if soup.title else vid)
        text = soup.get_text(" ", strip=True)
        cve = None
        m = _CVE_RE.search(text)
        if m:
            cve = m.group(0).upper()
        # "Version: <= 1.2.3" style
        ranges = []
        for vm in _VER_RE.finditer(text):
            ranges.append(AffectedRange(product=q, ecosystem="WordPress",
                                        max_exclusive=vm.group(1)))
        return VulnRecord(
            cve=cve, id=f"WPS:{vid}", title=title[:200],
            source=self.name, url=url, severity=None, cvss=None,
            description=text[:1500], affected=ranges, poc_refs=[],
            raw={"query": q},
        )

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        cve = _CVE_RE.search(cve_or_id)
        if not cve:
            return None
        for rec in await self.search(cve.group(0).upper()):
            if rec.cve == cve.group(0).upper():
                return rec
        return None

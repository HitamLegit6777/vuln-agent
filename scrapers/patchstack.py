"""Patchstack — WP-focused vuln DB. Public listing is Nuxt/JS-rendered; best-effort.

Tries listing SSR HTML for vuln/product slugs, then fetches detail pages.
Graceful [] when JS-blocked (data still covered by GitHub Advisory + NVD + WPScan).
ponytail: ceiling = Patchstack free API token (register) for structured JSON.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange
from bs4 import BeautifulSoup

LIST_URL = "https://patchstack.com/database/?search={q}"
DETAIL_RE = re.compile(r'href="(/database/(?:vulnerability|plugin|theme)/[a-z0-9\-]+)"', re.I)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_VER_RANGE_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)\s*[-–]\s*(\d+\.\d+(?:\.\d+)?|<\s*\d+\.\d+)", re.I)


class PatchstackScraper(BaseScraper):
    name = "patchstack"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        q = (query or "").lower().strip()
        html = await self._get_text(LIST_URL.format(q=q))
        if not html:
            return []
        slugs: list[str] = []
        for m in DETAIL_RE.finditer(html):
            slug = m.group(1)
            if slug not in slugs:
                slugs.append(slug)
        out = []
        for slug in slugs[:15]:
            rec = await self._detail(f"https://patchstack.com{slug}", q)
            if rec:
                out.append(rec)
        return out

    async def _detail(self, url: str, q: str) -> Optional[VulnRecord]:
        html = await self._get_text(url)
        if not html:
            return None
        soup = BeautifulSoup(html, "lxml")
        title = (soup.title.text.strip() if soup.title else "") or url
        text = soup.get_text(" ", strip=True)
        cve = None
        m = _CVE_RE.search(text)
        if m:
            cve = m.group(0).upper()
        ranges = []
        for lo, hi in _VER_RANGE_RE.findall(text):
            ranges.append(AffectedRange(product=q, ecosystem="WordPress",
                                        min_inclusive=lo, max_inclusive=hi))
        sev = None
        for s in ("critical", "high", "medium", "low"):
            if s in text.lower():
                sev = s.capitalize(); break
        return VulnRecord(
            cve=cve, id=f"PS:{url.rsplit('/', 1)[-1]}", title=title[:200],
            source=self.name, url=url, severity=sev, cvss=None,
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

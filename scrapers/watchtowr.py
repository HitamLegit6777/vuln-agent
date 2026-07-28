"""watchTowr — high-quality 1day analysis + PoC writeups.

Sitemap → filter posts by keyword/CVE → fetch post for PoC/github refs.
Best-effort; graceful [] when blocked.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange
from bs4 import BeautifulSoup

SITEMAP = "https://labs.watchtowr.com/sitemap-posts.xml"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class WatchTowrScraper(BaseScraper):
    name = "watchtowr"

    async def _posts(self) -> list[tuple[str, str]]:
        xml = await self._get_text(SITEMAP)
        if not xml:
            return []
        soup = BeautifulSoup(xml, "xml")
        out = []
        for u in soup.find_all("url"):
            loc = u.find("loc")
            if not loc or not loc.text:
                continue
            out.append((loc.text.strip(), (u.find("lastmod").text if u.find("lastmod") else "")))
        return out

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        q = (query or "").lower().strip()
        m = _CVE_RE.search(query or "")
        posts = await self._posts()
        # filter by slug BEFORE fetching — never fetch all posts (O(N) HTTP is too slow)
        cve_slug = m.group(0).lower().replace("-", "") if m else None  # e.g. cve20263055
        cve_dash = m.group(0).lower() if m else None
        cand: list[tuple[str, str]] = []
        for url, lastmod in posts:
            slug = url.rstrip("/").rsplit("/", 1)[-1].lower()
            if cve_slug and (cve_slug in slug.replace("-", "") or cve_dash in slug):
                cand.append((url, lastmod))
            elif not m and q and q.replace("-", "") in slug.replace("-", ""):
                cand.append((url, lastmod))
        out = []
        for url, _ in cand[:12]:
            rec = await self._detail(url, m.group(0).upper() if m else None)
            if rec:
                out.append(rec)
        return out

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id)
        if not m:
            return None
        recs = await self.search(m.group(0).upper())
        return recs[0] if recs else None

    async def _detail(self, url: str, cve_filter: Optional[str]) -> Optional[VulnRecord]:
        html = await self._get_text(url)
        if not html:
            return None
        soup = BeautifulSoup(html, "lxml")
        title = (soup.title.text.strip() if soup.title else url)
        text = soup.get_text(" ", strip=True)
        cves = {m.group(0).upper() for m in _CVE_RE.finditer(text)}
        if cve_filter and cve_filter not in cves:
            return None
        poc_refs = []
        for a in soup.find_all("a", href=True):
            h = a["href"]
            if any(k in h for k in ("github.com", "exploit-db.com", "packetstorm")) and h not in poc_refs:
                poc_refs.append(h)
        cve = cve_filter or (sorted(cves)[0] if cves else None)
        return VulnRecord(
            cve=cve, id=f"WT:{url.rsplit('/',1)[-1]}", title=title[:200],
            source=self.name, url=url, severity=None, cvss=None,
            description=text[:1500], affected=[], poc_refs=poc_refs,
            published=None, raw={"cves": sorted(cves)},
        )

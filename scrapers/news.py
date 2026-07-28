"""BleepingComputer news scraper — real-world incident/breach context per CVE.

The Hacker News is Cloudflare-403 from this host -> BleepingComputer only.
Participates in get_all(cve) enrichment (news articles mentioning the CVE) ->
adds real-world context to the CVE's poc_refs/description. search(keyword) is
disabled (returns []) to avoid polluting keyword product search with generic news.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange
from bs4 import BeautifulSoup

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class BleepingComputerScraper(BaseScraper):
    name = "bleepingcomputer"

    async def _search(self, query: str, limit: int = 5) -> list[dict]:
        url = f"https://www.bleepingcomputer.com/search/?q={urllib.parse.quote(query)}"
        html = await self._get_text(url)
        if not html:
            return []
        soup = BeautifulSoup(html, "lxml")
        out: list[dict] = []
        for a in soup.select("a"):
            href = a.get("href") or ""
            t = a.get_text(strip=True)
            if (href.startswith("https://www.bleepingcomputer.com/news/")
                    and t and len(t) > 20):
                if not any(o["url"] == href for o in out):
                    out.append({"title": t, "url": href})
            if len(out) >= limit:
                break
        return out

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        # keyword product search would return generic breach news (noise) -> skip.
        # News enriches per-CVE via get().
        return []

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id)
        q = m.group(0) if m else cve_or_id
        arts = await self._search(q, limit=4)
        if not arts:
            return None
        cve = m.group(0).upper() if m else None
        return VulnRecord(
            cve=cve, id=f"BC:{q}", title=f"News coverage for {q}",
            source=self.name, url=arts[0]["url"],
            severity=None, cvss=None,
            description="",  # leave empty so dedupe won't overwrite the real CVE description
            affected=[],
            poc_refs=[a["url"] for a in arts],
            published=None,
            raw={"articles": arts, "type": "news"},
        )

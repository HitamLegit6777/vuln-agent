"""Wordfence — threat-intel DB listing (ALL recent CVEs) + blog RSS feed.

threat-intel page (https://www.wordfence.com/threat-intel/vulnerabilities) lists ALL
recent WP CVEs in a table. Cloudflare-challenged → fetched via cloak browser (Playwright).
This is the PRIMARY feed source for the monitor — RSS only has ~10 recent blog posts.

get(cve) returns the most *specific* post mentioning that CVE (writeup > weekly report).
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from .base import BaseScraper, VulnRecord
from bs4 import BeautifulSoup

FEED = "https://www.wordfence.com/threat-intel/vulnerabilities"
RSS = "https://www.wordfence.com/blog/feed/"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_REPORT_RE = re.compile(r"weekly|intelligence|report|roundup", re.I)


def _strip_html(s: str) -> str:
    if not s:
        return ""
    return BeautifulSoup(s, "lxml").get_text(" ", strip=True)


def _sev(cvss: Optional[float]) -> Optional[str]:
    if cvss is None:
        return None
    if cvss >= 9: return "CRITICAL"
    if cvss >= 7: return "HIGH"
    if cvss >= 4: return "MEDIUM"
    return "LOW"


class WordfenceScraper(BaseScraper):
    name = "wordfence"

    async def _playwright_html(self, url: str, timeout: float = 45.0) -> str:
        """Fetch rendered HTML via headless Chromium (bypasses Cloudflare JS challenge).
        Bounded by wait_for + browser.close() in finally (no Chromium leak on failure)."""
        import asyncio
        def _sync():
            from playwright.sync_api import sync_playwright
            browser = None
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page = browser.new_page()
                    page.goto(url, wait_until="networkidle", timeout=30000)
                    import time
                    time.sleep(3)  # wait for CF challenge to resolve
                    return page.content()
            finally:
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:
                        pass
        try:
            return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=timeout)
        except asyncio.TimeoutError:
            return ""

    async def fetch_recent(self, pages: int = 3) -> list[VulnRecord]:
        """Scrape Wordfence threat-intel vulnerabilities listing via cloak browser.
        Returns ALL recent CVEs (feed source — no query needed). Filters year >= 2026.
        ponytail: page count covers ~60 CVEs (24h cycle). ceiling: infinite-scroll API."""
        out: list[VulnRecord] = []
        seen: set[str] = set()
        for pno in range(1, pages + 1):
            url = FEED if pno == 1 else f"{FEED}?page={pno}"
            try:
                html = await self._playwright_html(url)
            except Exception:
                continue
            if not html:
                continue
            soup = BeautifulSoup(html, "lxml")
            tables = soup.find_all("table")
            if not tables:
                continue
            # table 0 = vulnerabilities (Title, CVE ID, CVSS, Researchers, Date)
            tbl = tables[0]
            rows = tbl.find_all("tr")
            got = 0
            for r in rows:
                cells = [c.get_text(" ", strip=True) for c in r.find_all(["td", "th"])]
                if len(cells) < 5 or cells[0].lower() == "title":
                    continue  # skip header
                title, cve, cvss_s, _researcher, date = cells[0], cells[1], cells[2], cells[3], cells[4]
                if not _CVE_RE.fullmatch(cve):
                    continue
                cve = cve.upper()
                # year filter >= 2026 (don't go below)
                try:
                    year = int(cve.split("-")[1])
                except (IndexError, ValueError):
                    continue
                if year < 2026:
                    continue
                if cve in seen:
                    continue
                seen.add(cve)
                try:
                    cvss = float(cvss_s)
                except ValueError:
                    cvss = None
                out.append(VulnRecord(
                    cve=cve, id=f"WF:{cve}", title=title[:300],
                    source=self.name, url=url,
                    severity=_sev(cvss), cvss=cvss,
                    description=title, affected=[], poc_refs=[],
                    published=date, raw={"type": "threat-intel", "researcher": _researcher},
                ))
                got += 1
            if got == 0:
                break  # no more pages
        return out

    # ---- RSS feed (blog writeups — enrichment for specific CVE search) ----

    async def _feed(self) -> list[dict]:
        xml = await self._get_text(RSS)
        if not xml:
            return []
        soup = BeautifulSoup(xml, "xml")
        out = []
        for item in soup.find_all("item"):
            title = (item.title.text or "").strip()
            link = (item.link.text or "").strip()
            content = item.find("content:encoded").text if item.find("content:encoded") else ""
            desc = (item.description.text or "") if item.description else ""
            text = _strip_html(f"{title}\n{desc}\n{content}")
            out.append({"title": title, "link": link, "text": text,
                        "is_report": bool(_REPORT_RE.search(title))})
        return out

    def _rank(self, it: dict, cve: Optional[str], q: str) -> tuple:
        title = it["title"].lower()
        score = 0
        if not it["is_report"]:
            score -= 10
        if cve and cve.lower() in title:
            score -= 5
        if q and q in title:
            score -= 3
        return (score,)

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        q = (query or "").lower()
        cve_m = _CVE_RE.search(query or "")
        cve = cve_m.group(0).upper() if cve_m else None
        out: list[VulnRecord] = []
        # RSS blog feed FIRST — fast (no Playwright). Covers writeups + weekly reports.
        items = await self._feed()
        matched = []
        for it in items:
            hay = it["text"].lower()
            if cve:
                if cve not in it["text"].upper():
                    continue
            elif q and q not in hay:
                continue
            matched.append(it)
        matched.sort(key=lambda it: self._rank(it, cve, q))
        for it in matched[:15]:
            cves = {m.group(0).upper() for m in _CVE_RE.finditer(it["text"])}
            out.append(VulnRecord(
                cve=cve or (next(iter(cves)) if cves else None),
                id=f"WF:{it['link']}", title=it["title"][:200],
                source=self.name, url=it["link"],
                severity=None, cvss=None, description=it["text"][:1500],
                affected=[], poc_refs=[],
                published=None,
                raw={"cves": sorted(cves), "type": "report" if it["is_report"] else "writeup"},
            ))
        # only if the feed had no match, try ONE threat-intel page (not 5 — it's Playwright-slow)
        if not out and cve:
            try:
                for r in await asyncio.wait_for(self.fetch_recent(pages=1), timeout=25):
                    if r.cve == cve:
                        out.append(r)
                        break
            except Exception:
                pass
        return out

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        cve = _CVE_RE.search(cve_or_id)
        if not cve:
            return None
        recs = await self.search(cve.group(0).upper())
        return recs[0] if recs else None

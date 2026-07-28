"""EPSS — Exploit Prediction Scoring System (FIRST.org).

EPSS gives, per CVE, the probability (0.0-1.0) that the CVE will be exploited in the
wild within the next 30 days, plus a percentile ranking against all scored CVEs. It is a
forward-looking complement to CISA KEV (which is retrospective "already exploited"):
a high-CVSS bug with EPSS 0.001 is far less urgent to patch than a medium-CVSS bug at
EPSS 0.7. This scraper enriches each CVE record with `raw["epss"]` / `raw["epss_percentile"]`
so the risk-scoring layer can prioritize accordingly.

API: https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2023-5678  (batchable).
This is a pure enrichment source: it never invents affected ranges, so it never changes a
VULNERABLE/NOT_AFFECTED verdict — it only annotates records that already exist.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord

EPSS_API = "https://api.first.org/data/v1/epss"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_epss_response(data: dict) -> dict[str, dict]:
    """Turn the FIRST.org EPSS JSON envelope into {CVE: {epss, percentile, date}}.

    Tolerant of missing/blank fields and non-numeric values (skips them). Pure function so
    it can be unit-tested without any network access.
    """
    out: dict[str, dict] = {}
    if not isinstance(data, dict):
        return out
    for row in data.get("data", []) or []:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve", "")).upper()
        if not _CVE_RE.fullmatch(cve):
            continue
        try:
            epss = float(row["epss"]) if row.get("epss") not in (None, "") else None
        except (TypeError, ValueError):
            epss = None
        try:
            pct = float(row["percentile"]) if row.get("percentile") not in (None, "") else None
        except (TypeError, ValueError):
            pct = None
        out[cve] = {"epss": epss, "percentile": pct, "date": row.get("date")}
    return out


class EPSSScraper(BaseScraper):
    name = "epss"

    async def _fetch(self, cves: list[str]) -> dict[str, dict]:
        if not cves:
            return {}
        joined = ",".join(sorted({c.upper() for c in cves if _CVE_RE.fullmatch(c.upper())}))
        if not joined:
            return {}

        async def _producer():
            data = await self._get_json(EPSS_API, params={"cve": joined})
            return parse_epss_response(data or {})

        return await self._cached(f"epss:{joined}", _producer)

    async def score(self, cve: str) -> Optional[float]:
        """Convenience: EPSS probability for a single CVE, or None if unscored."""
        m = _CVE_RE.search(cve or "")
        if not m:
            return None
        info = (await self._fetch([m.group(0).upper()])).get(m.group(0).upper())
        return info.get("epss") if info else None

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id or "")
        if not m:
            return None
        cve = m.group(0).upper()
        info = (await self._fetch([cve])).get(cve)
        if not info or info.get("epss") is None:
            return None
        epss = info["epss"]
        pct = info.get("percentile")
        pct_txt = f" (percentile {pct:.2%})" if isinstance(pct, float) else ""
        return VulnRecord(
            cve=cve, id=f"EPSS:{cve}", title=f"[EPSS] {cve} exploit probability {epss:.2%}",
            source=self.name, url=f"https://api.first.org/data/v1/epss?cve={cve}",
            description=(f"EPSS score {epss:.4f}{pct_txt}: estimated probability this CVE is "
                         f"exploited in the wild within 30 days (FIRST.org, {info.get('date','')})."),
            raw={"epss": epss, "epss_percentile": pct, "epss_date": info.get("date")},
        )

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        # CVE-id keyed only; no keyword search (returns nothing for product names).
        m = _CVE_RE.search(query or "")
        if not m:
            return []
        rec = await self.get(m.group(0).upper())
        return [rec] if rec else []

"""CISA KEV — Known Exploited Vulnerabilities catalog (gold-standard in-the-wild).

Not a per-product search DB; flags whether a CVE is actively exploited.
is_exploited(cve) + search(cve|keyword) → VulnRecord w/ KEV context.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_TTL = 24 * 3600


class CisaKevScraper(BaseScraper):
    name = "cisa_kev"
    _cache: dict | None = None
    _ts: float = 0

    async def _load(self) -> dict:
        if self._cache and (time.time() - self._ts) < _TTL:
            return self._cache
        # persist via the pluggable cache so every research run doesn't re-download
        # the full KEV JSON (1.5MB) — in-memory TTL only helped within one process
        data = await self._cached("cisa_kev:feed", lambda: self._get_json(KEV_URL))
        if data and data.get("vulnerabilities"):
            self._cache = data
            self._ts = time.time()
            return data
        return self._cache or {}

    async def is_exploited(self, cve: str) -> bool:
        data = await self._load()
        cve = cve.upper()
        return any(v.get("cveID", "").upper() == cve for v in data.get("vulnerabilities", []))

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        data = await self._load()
        vulns = data.get("vulnerabilities", [])
        m = _CVE_RE.search(query or "")
        q = (query or "").lower()
        out = []
        for v in vulns:
            if m:
                if v.get("cveID", "").upper() != m.group(0).upper():
                    continue
            elif q and q not in f"{v.get('vendorProject','')} {v.get('product','')} {v.get('vulnerabilityName','')}".lower():
                continue
            out.append(self._parse(v))
        return out

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id)
        if not m:
            return None
        recs = await self.search(m.group(0).upper())
        return recs[0] if recs else None

    def _parse(self, v: dict) -> VulnRecord:
        cve = v.get("cveID", "").upper()
        name = v.get("vulnerabilityName", "")
        short = v.get("shortDescription", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        title = f"[KEV] {cve} {vendor} {product}: {name}"
        desc = f"{short}\nDue: {v.get('dueDate','')} | Ransomware: {v.get('knownRansomwareCampaignUse','')} | Notes: {v.get('notes','')[:200]}"
        return VulnRecord(
            cve=cve, id=f"KEV:{cve}", title=title[:200],
            source=self.name, url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            severity="CRITICAL", cvss=None, description=desc,
            affected=[AffectedRange(product=f"{vendor}/{product}", ecosystem="none")],
            poc_refs=[], published=v.get("dateAdded"),
            raw={"vendor": vendor, "product": product, "required_action": v.get("requiredAction"),
                 "ransomware": v.get("knownRansomwareCampaignUse"), "due": v.get("dueDate")},
        )

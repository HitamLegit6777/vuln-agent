"""CVE 5.0 records via MITRE CVE Services (cveawg.mitre.org) — reachable where NVD API is blocked.

Gives exact `affected` version ranges (lessThan / lessThanOrEqual) per CVE, CVSS, references.
CVE-id based (no keyword search) -> complements keyword sources (OSV/GHSA/EDB/Wordfence) by
adding exact ranges + CPE-style product/vendor for version_match.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange

CVE_API = "https://cveawg.mitre.org/api/cve"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class Cve5Scraper(BaseScraper):
    name = "cve5"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        m = _CVE_RE.search(query or "")
        if not m:
            return []  # CVE-id only; no keyword search
        rec = await self.get(m.group(0).upper())
        return [rec] if rec else []

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id)
        if not m:
            return None
        cve = m.group(0).upper()
        data = await self._cached(f"cve5:{cve}", lambda: self._get_json(f"{CVE_API}/{cve}"))
        if not data or not isinstance(data, dict) or data.get("error"):
            return None
        cna = (data.get("containers", {}) or {}).get("cna", {}) or {}
        desc = ""
        for d in cna.get("descriptions", []) or []:
            if (d.get("lang") or "").startswith("en"):
                desc = d.get("value", "")
                break
        if not desc and cna.get("descriptions"):
            desc = cna["descriptions"][0].get("value", "")
        refs = [r.get("url") for r in cna.get("references", []) or [] if r.get("url")]
        # affected ranges (exact, CPE-style)
        ranges: list[AffectedRange] = []
        for a in cna.get("affected", []) or []:
            prod = a.get("product", "") or ""
            eco = a.get("vendor", "") or a.get("package", {}).get("ecosystem", "")
            for v in a.get("versions", []) or []:
                if (v.get("status") or "").lower() not in ("affected", "unknown"):
                    continue
                base = (v.get("version") or "").strip()
                lt = v.get("lessThan")
                lte = v.get("lessThanOrEqual")
                lo = None; mx_exc = lt; mx_inc = lte
                # handle non-standard "X-Y" range string in `version` (some CNAs do this)
                rng_m = re.match(r"^(\d[\d.]+)\s*[-–]\s*(\d[\d.]+)$", base)
                if rng_m and not (lt or lte):
                    lo = rng_m.group(1)
                    mx_inc = rng_m.group(2)
                elif base and base not in ("0", "*"):
                    lo = base
                ranges.append(AffectedRange(
                    product=prod, ecosystem=eco,
                    min_inclusive=lo, max_exclusive=mx_exc, max_inclusive=mx_inc,
                    fixed=(mx_exc or mx_inc)))
        # CVSS (metrics may be a list of {scheme:{...}} or a dict)
        sev, cvss, vec = None, None, None
        metrics = cna.get("metrics", []) or []
        metric_items = []
        if isinstance(metrics, list):
            for m in metrics:
                if isinstance(m, dict):
                    metric_items.extend(m.items())
        elif isinstance(metrics, dict):
            metric_items = metrics.items()
        prio = {"cvssV4_0": 0, "cvssV3_1": 1, "cvssV3_0": 2, "cvssV2_0": 3}
        metric_items.sort(key=lambda kv: prio.get(kv[0], 9))
        for key, mm in metric_items:
            if isinstance(mm, dict):
                sev = mm.get("baseSeverity")
                cvss = mm.get("baseScore")
                vec = mm.get("vectorString")
                break
        poc = [u for u in refs if any(k in u.lower() for k in ("exploit", "poc", "github.com", "packetstorm"))]
        diff_patch = next((u for u in refs if any(k in u.lower() for k in ("/commit/", "/pull/", "/patch/", "/compare/"))), None)
        return VulnRecord(
            cve=cve, id=cve, title=desc.split(".")[0][:200] if desc else cve,
            source=self.name, url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            severity=(sev or "").upper() if sev else None,
            cvss=float(cvss) if cvss else None,
            description=desc, affected=ranges,
            poc_refs=poc, diff_patch=diff_patch,
            published=(cna.get("datePublic") or data.get("cveMetadata", {}).get("datePublished")),
            raw={"refs": refs, "cvss_vector": vec,
                 "vendor": [a.get("vendor") for a in cna.get("affected", []) or []]},
        )

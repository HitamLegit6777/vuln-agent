"""NVD CVE 2.0 API — authoritative CPE exact version ranges.

ponytail: NVD rate-limits (5/30s no key). May time out in some networks → graceful [].
        ceiling: NVD_API_KEY env raises to 50/30s; wire in config later.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CPE_RE = re.compile(r"cpe:(?P<cve>2\.3):(?P<part>[a-z]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<ver>[^:]*):")


def _parse_cpe(criteria: str) -> dict:
    m = _CPE_RE.match(criteria or "")
    if not m:
        return {}
    return {"product": m.group("product"), "vendor": m.group("vendor"), "version": m.group("ver")}


def _extract_cve(text: str) -> Optional[str]:
    m = re.search(r"CVE-\d{4}-\d{4,7}", text or "", re.I)
    return m.group(0).upper() if m else None


class NVDScraper(BaseScraper):
    name = "nvd"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        cve = _extract_cve(query)
        params = {"resultsPerPage": 50}
        try:
            from config import NVD_API_KEY
            if NVD_API_KEY:
                params["apiKey"] = NVD_API_KEY
        except Exception:
            pass
        if cve:
            params["cveId"] = cve
        else:
            params["keywordSearch"] = query
        data = await self._cached(
            f"nvd:{query}",
            lambda: self._get_json(NVD_URL, params=params),
        )
        if not data or "vulnerabilities" not in data:
            return []
        out = []
        for item in data["vulnerabilities"]:
            c = item.get("cve", {})
            out.append(self._parse_cve(c, version))
        return [r for r in out if r]

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        cve = _extract_cve(cve_or_id) or cve_or_id
        if not cve.startswith("CVE-"):
            return None
        data = await self._cached(
            f"nvd:{cve}",
            lambda: self._get_json(NVD_URL, params={"cveId": cve}))
        if not data or not data.get("vulnerabilities"):
            return None
        return self._parse_cve(data["vulnerabilities"][0]["cve"], None)

    def _parse_cve(self, c: dict, version: Optional[str]) -> Optional[VulnRecord]:
        cid = c.get("id", "")
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        refs = [r.get("url") for r in c.get("references", []) if r.get("url")]
        ranges: list[AffectedRange] = []
        for cfg in c.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    cpe = _parse_cpe(m.get("criteria", ""))
                    if not cpe:
                        continue
                    ranges.append(AffectedRange(
                        product=cpe.get("product", ""),
                        ecosystem="none",
                        min_inclusive=m.get("versionStartIncluding"),
                        max_inclusive=m.get("versionEndIncluding"),
                        max_exclusive=m.get("versionEndExcluding"),
                    ))
        sev, cvss = None, None
        for mm in c.get("metrics", {}).get("cvssMetricV31", []) or c.get("metrics", {}).get("cvssMetricV2", []):
            data = mm.get("cvssData", {})
            sev = sev or data.get("baseSeverity") or mm.get("baseSeverity")
            cvss = cvss or data.get("baseScore")
        wf_ref = next((r for r in refs if "wordfence.com" in r), None)
        edb_ref = next((r for r in refs if "exploit-db.com" in r), None)
        poc = [r for r in refs if any(k in r for k in ("exploit", "poc", "github.com", "packetstorm"))]
        diff_patch = next((r for r in refs if any(k in r.lower() for k in ("/commit/", "/pull/", "/patch/", "/compare/", "diff"))), None)
        return VulnRecord(
            cve=cid, id=cid, title=desc.split(".")[0][:200] if desc else cid,
            source=self.name, url=f"https://nvd.nist.gov/vuln/detail/{cid}",
            severity=sev, cvss=cvss, description=desc, affected=ranges,
            poc_refs=poc, diff_patch=diff_patch, published=c.get("published"),
            raw={"refs": refs, "wordfence": wf_ref, "exploitdb": edb_ref},
        )

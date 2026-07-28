"""GitHub Advisory Database (GHSA) — free REST, reliable, exact SemVer ranges.

Covers Packagist/Composer (WP plugins via packagist), npm, PyPI, Maven, Go, etc.
ponytail: unauthenticated GH API = 60 req/h. ceiling: GH_TOKEN env → 5000/h.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange

ADV_URL = "https://api.github.com/advisories"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _ecosystem_map(eco: str) -> str:
    m = {
        "composer": "Packagist", "packagist": "Packagist",
        "npm": "npm", "pypi": "PyPI", "maven": "Maven",
        "go": "Go", "gem": "RubyGems", "nuget": "NuGet",
        "wordpress": "WordPress", "wordpress-plugin": "WordPress",
    }
    return m.get((eco or "").lower(), eco or "none")


def _parse_ranges(affected: list) -> list[AffectedRange]:
    out = []
    for a in affected or []:
        pkg = a.get("package", {}) or {}
        eco = _ecosystem_map(pkg.get("ecosystem", ""))
        prod = pkg.get("name", "")
        for rng in a.get("ranges", []) or []:
            if rng.get("type") != "SEMVER":
                continue
            lo = hi_exc = hi_inc = None
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    lo = ev["introduced"] or "0"
                if "fixed" in ev:
                    hi_exc = ev["fixed"]
                if "last_affected" in ev:
                    hi_inc = ev["last_affected"]  # inclusive upper bound (no fix release)
            out.append(AffectedRange(product=prod, ecosystem=eco,
                                     min_inclusive=lo if lo and lo != "0" else None,
                                     max_exclusive=hi_exc, max_inclusive=hi_inc))
    return out


class GitHubAdvisoryScraper(BaseScraper):
    name = "github"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        cve = _CVE_RE.search(query or "")
        params = {"per_page": 50}
        if cve:
            params["cve_id"] = cve.group(0).upper()
        else:
            params["keyword"] = query
        data = await self._cached(
            f"ghsa:{query}",
            lambda: self._get_json(ADV_URL, params=params, headers={"Accept": "application/vnd.github+json"}),
        )
        if not isinstance(data, list):
            return []
        recs = [self._parse(a) for a in data if a]
        if not cve:
            # GHSA keyword search is noisy → keep only advisories whose *affected package*
            # or title actually mentions the query (anti-mismatch).
            q = (query or "").lower()
            recs = [r for r in recs if q in r.title.lower()
                    or any(q in (a.product or "").lower() for a in r.affected)
                    or q in r.description.lower()]
        return recs

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        m = _CVE_RE.search(cve_or_id)
        if m:
            data = await self._get_json(ADV_URL, params={"cve_id": m.group(0).upper()},
                                        headers={"Accept": "application/vnd.github+json"})
            if isinstance(data, list) and data:
                return self._parse(data[0])
        if cve_or_id.startswith("GHSA-"):
            data = await self._get_json(f"{ADV_URL}/{cve_or_id}",
                                        headers={"Accept": "application/vnd.github+json"})
            if isinstance(data, dict):
                return self._parse(data)
        return None

    def _parse(self, a: dict) -> VulnRecord:
        raw_refs = a.get("references", []) or []
        refs = []
        for r in raw_refs:
            if isinstance(r, dict):
                if r.get("url"): refs.append(r["url"])
            elif isinstance(r, str):
                refs.append(r)
        cvss_obj = a.get("cvss", {}) or {}
        sev = a.get("severity") or cvss_obj.get("severity")
        cvss = cvss_obj.get("score")
        cve = a.get("cve_id")
        ghsa = a.get("ghsa_id", "")
        poc = [r for r in refs if any(k in r.lower() for k in ("exploit", "poc", "github.com", "packetstorm"))]
        diff_patch = next((r for r in refs if any(k in r.lower() for k in ("/commit/", "/pull/", "/patch/", "diff", "/compare/"))), None)
        return VulnRecord(
            cve=cve, id=ghsa or cve or "",
            title=a.get("summary", "")[:200],
            source=self.name, url=a.get("html_url", ""),
            severity=(sev or "").upper() if sev else None,
            cvss=float(cvss) if cvss else None,
            description=a.get("description", "") or a.get("summary", ""),
            affected=_parse_ranges(a.get("affected", [])),
            poc_refs=poc, diff_patch=diff_patch, published=a.get("published_at"),
            raw={"refs": refs, "ghsa": ghsa, "cwes": [w.get("cwe_id") for w in a.get("cwes", [])]},
        )

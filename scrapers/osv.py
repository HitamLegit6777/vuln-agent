"""OSV.dev — open vuln DB, exact affected ranges (SemVer/Git/ECOSYSTEM).

Best for known package+version. Tries multiple ecosystems for the product slug.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# ecosystems worth probing for a generic product slug (e.g. a WP plugin name)
_ECOS = ["WordPress", "Packagist", "npm", "PyPI", "Go", "Maven", "RubyGems", "NuGet"]


def _parse_ranges(affected: list) -> tuple[list[AffectedRange], Optional[str]]:
    """Return (ranges, diff_patch_url). GIT ranges yield a commit-diff URL for AI grounding."""
    out = []
    diff_patch = None
    for a in affected or []:
        pkg = a.get("package", {}) or {}
        eco = pkg.get("ecosystem", "none")
        prod = pkg.get("name", "")
        for rng in a.get("ranges", []) or []:
            rtype = rng.get("type", "")
            repo = rng.get("repo", "")
            lo = hi_exc = hi_inc = fixed = None
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    lo = ev["introduced"] or "0"
                if "fixed" in ev:
                    fixed = ev["fixed"]; hi_exc = ev["fixed"]
                if "last_affected" in ev:
                    hi_inc = ev["last_affected"]
            if rtype == "GIT" and fixed and repo:
                # commit-hash range → not semver-matchable, but the fix commit = the patch diff
                diff_patch = f"{repo.rstrip('/')}/commit/{fixed}"
                out.append(AffectedRange(product=repo, ecosystem="git",
                                         max_exclusive=fixed, fixed=fixed))
            else:
                out.append(AffectedRange(product=prod, ecosystem=eco,
                                         min_inclusive=(lo if lo and lo != "0" else None),
                                         max_exclusive=hi_exc, max_inclusive=hi_inc, fixed=fixed))
    return out, diff_patch


def _severity(v: dict) -> tuple[Optional[str], Optional[float], Optional[str]]:
    """Returns (severity_label, cvss_score, cvss_vector). Score left None if only vector known."""
    for s in v.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS"):
            vec = s.get("score", "") or ""
            return _sev_from_vec(vec), None, vec
    ds = v.get("database_specific", {}) or {}
    sev = ds.get("severity") or ds.get("severity_rank")
    return (sev.upper() if sev else None), None, None


def _sev_from_vec(vec: str) -> Optional[str]:
    """Coarse CVSS-v3 vector → label. AV:N/AC:L + C:H/I:H → HIGH/CRITICAL."""
    v = (vec or "").upper()
    if not v:
        return None
    has = lambda k: k in v
    scope_changed = has("/S:C")
    cih = has("C:H") or has("I:H") or has("A:H")
    if scope_changed and cih:
        return "CRITICAL"
    if cih and (has("AV:N") or has("AV:A")):
        return "HIGH"
    if has("C:H") or has("I:H"):
        return "MEDIUM"
    return "LOW" if has("C:L") or has("I:L") else None


class OSVScraper(BaseScraper):
    name = "osv"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        cve = _CVE_RE.search(query or "")
        if cve:
            rec = await self.get(cve.group(0).upper())
            return [rec] if rec else []
        body_pkg = {"name": query}
        out: list[VulnRecord] = []
        for eco in _ECOS:
            payload = {"package": {**body_pkg, "ecosystem": eco}}
            if version:
                payload["version"] = version
            data = await self._cached(
                f"osv:{eco}:{query}:{version or ''}",
                lambda payload=payload: self._post_json(OSV_QUERY, payload),
            )
            if not data or not data.get("vulns"):
                continue
            for v in data["vulns"]:
                rec = self._parse(v)
                if rec:
                    out.append(rec)
            if out:
                break  # found the right ecosystem
        return out

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        cve = _CVE_RE.search(cve_or_id)
        vid = cve.group(0).upper() if cve else cve_or_id
        data = await self._get_json(f"{OSV_VULN}{vid}")
        if not data or data.get("code"):
            return None
        return self._parse(data)

    def _parse(self, v: dict) -> Optional[VulnRecord]:
        vid = v.get("id", "")
        # OSV often uses the CVE as the id for NVD-sourced records
        cve = vid if vid.startswith("CVE-") else \
            next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None)
        ghsa = next((a for a in v.get("aliases", []) if a.startswith("GHSA-")), None)
        summary = v.get("summary", "")
        details = v.get("details", "") or summary
        refs = [r.get("url") for r in v.get("references", []) if r.get("url")]
        sev, cvss, vec = _severity(v)
        ranges, diff_patch = _parse_ranges(v.get("affected", []))
        # exploit/poc refs (EXPLOIT type or url hints)
        poc = [r.get("url") for r in v.get("references", [])
               if r.get("type") == "EXPLOIT"
               or any(k in (r.get("url", "").lower()) for k in ("exploit", "poc", "packetstorm"))]
        if ghsa:
            poc.append(f"https://github.com/advisories/{ghsa}")
        return VulnRecord(
            cve=cve, id=vid, title=summary[:200] or vid,
            source=self.name, url=f"https://osv.dev/vulnerability/{vid}",
            severity=sev, cvss=cvss, description=details,
            affected=ranges, poc_refs=list(dict.fromkeys(poc)),
            diff_patch=diff_patch, published=v.get("published"),
            raw={"refs": refs, "aliases": v.get("aliases", []),
                 "cvss_vector": vec, "ghsa": ghsa},
        )

"""PoC-in-GitHub (nomi-sec) + GitHub repo search → PoC repo discovery per CVE.

get(cve) returns VulnRecord with poc_refs = list of PoC repo URLs (stars-based trust).
search(query) treats query as CVE if it matches, else keyword repo search.
ponytail: unauth GH API = 60/h. ceiling: GH_TOKEN.
"""
from __future__ import annotations

import re
from typing import Optional

from .base import BaseScraper, VulnRecord, AffectedRange

COMMIT_URL = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits/master"
SEARCH_URL = "https://api.github.com/search/repositories"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_GH_HEADERS = {"Accept": "application/vnd.github+json"}


class PoCGitHubScraper(BaseScraper):
    name = "poc_github"

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        # poc_github is CVE-centric; keyword repo search is too noisy → defer to get(cve)
        # (PoC discovery happens via fetch_cve_detail → get_all → get(cve)).
        m = _CVE_RE.search(query or "")
        if not m:
            return []
        rec = await self.get(m.group(0).upper())
        return [rec] if rec else []

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        async def _produce() -> Optional[dict]:
            cve = _CVE_RE.search(cve_or_id)
            if not cve:
                return None
            cve = cve.group(0).upper()
            year = cve.split("-")[1]
            repos: list[dict] = []
            # 1) nomi-sec latest commit → {year}/{cve}.json → raw → repo list
            commit = await self._get_json(COMMIT_URL, headers=_GH_HEADERS)
            if commit and commit.get("files"):
                for f in commit["files"]:
                    fname = f.get("filename", "")
                    if not fname.startswith(f"{year}/"):
                        continue
                    if cve != fname.upper().split("/")[-1].split(".")[0]:
                        continue
                    raw = f.get("raw_url", "")
                    if not raw:
                        continue
                    jr = await self._get_json(raw, headers=_GH_HEADERS)
                    if isinstance(jr, list):
                        repos.extend(jr[:5])
                    break
            # 2) direct GH repo search by CVE in:name
            data = await self._get_json(SEARCH_URL, params={"q": f"{cve} in:name",
                                                            "sort": "stars", "per_page": 10},
                                        headers=_GH_HEADERS)
            if data and data.get("items"):
                for repo in data["items"]:
                    if repo.get("stargazers_count", 0) >= 3:
                        repos.append(repo)
            if not repos:
                return None
            # dedupe by full_name
            seen = set()
            poc_refs = []
            descriptions = []
            for r in repos:
                fn = r.get("full_name", "")
                if fn in seen:
                    continue
                seen.add(fn)
                if r.get("html_url"):
                    poc_refs.append(r["html_url"])
                descriptions.append(f"{fn} ({r.get('stargazers_count',0)}*): {r.get('description','')}")
            return VulnRecord(
                cve=cve, id=f"POCGH:{cve}", title=f"{cve} PoC repos ({len(poc_refs)})",
                source=self.name, url=poc_refs[0] if poc_refs else "",
                severity=None, cvss=None, description="\n".join(descriptions)[:1500],
                affected=[], poc_refs=poc_refs, published=None,
                raw={"repo_count": len(poc_refs), "repos": descriptions},
            ).to_dict()
        d = await self._cached(f"pocgh:{cve_or_id.upper()}", _produce)
        return VulnRecord.from_dict(d)

    # no helper record builders — VulnRecord constructed inline in get()

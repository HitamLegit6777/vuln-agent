"""Shared scraper primitives: dataclasses, http session, version-range matching.

ponytail: cache is pluggable via `cache_get/cache_set` callables wired later by db.py.
        scrapers stay decoupled but cache-ready. ceiling: distributed cache.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

import httpx

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/html;q=0.9, */*;q=0.5",
    "Accept-Language": "en-US,en;q=0.8",
}
TIMEOUT = httpx.Timeout(25.0, connect=10.0)
_LIMITS = httpx.Limits(max_connections=30, max_keepalive_connections=15, keepalive_expiry=30.0)


@dataclass
class AffectedRange:
    """Exact affected version range. Empty bounds = unbounded."""
    product: str = ""
    ecosystem: str = ""            # e.g. WordPress, Maven, pip, none
    min_inclusive: Optional[str] = None
    max_inclusive: Optional[str] = None
    max_exclusive: Optional[str] = None
    fixed: Optional[str] = None

    def matches(self, version: Optional[str]) -> Optional[bool]:
        """True = vulnerable, False = not affected, None = cannot decide."""
        return version_in_range(version, self)


@dataclass
class VulnRecord:
    cve: Optional[str] = None
    id: str = ""                  # source-native id
    title: str = ""
    source: str = ""
    url: str = ""
    severity: Optional[str] = None
    cvss: Optional[float] = None
    description: str = ""
    affected: list[AffectedRange] = field(default_factory=list)
    poc_refs: list[str] = field(default_factory=list)
    diff_patch: Optional[str] = None
    published: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["affected"] = [asdict(a) for a in self.affected]
        return d
    @staticmethod
    def from_dict(d: Optional[dict]) -> Optional["VulnRecord"]:
        """Rebuild from to_dict() output (for cache round-trips)."""
        if not d:
            return None
        d = dict(d)
        d["affected"] = [AffectedRange(**a) for a in (d.get("affected") or [])]
        return VulnRecord(**d)

    def to_ai_context(self) -> str:
        """Grounded, AI-ready text block: description + ranges + PoC + patch + refs.

        Designed so the LLM can reason & build PoC without re-fetching. Every claim
        cites source/url → anti-mismatch."""
        parts = [f"[{self.source.upper()}] {self.cve or self.id}"]
        if self.title:
            parts.append(f"Title: {self.title}")
        if self.severity or self.cvss:
            parts.append(f"Severity: {self.severity or '?'}  CVSS: {self.cvss or '?'}")
        if self.published:
            parts.append(f"Published: {self.published}")
        parts.append(f"Source: {self.url}")
        if self.description:
            parts.append(f"Description:\n{self.description}")
        if self.affected:
            rng_lines = []
            for a in self.affected:
                rng_lines.append(
                    f"  - product={a.product or '?'} eco={a.ecosystem or '?'} "
                    f"min>={a.min_inclusive or '-'} max<={a.max_inclusive or '-'} "
                    f"max<{a.max_exclusive or '-'} fixed={a.fixed or '-'}"
                )
            parts.append("Affected ranges:\n" + "\n".join(rng_lines))
        if self.diff_patch:
            parts.append(f"Patch/Diff: {self.diff_patch}")
        if self.poc_refs:
            parts.append("PoC/Exploit refs:\n" + "\n".join(f"  - {u}" for u in self.poc_refs))
        refs = self.raw.get("refs") if isinstance(self.raw, dict) else None
        if refs:
            extra = [u for u in refs if u not in (self.poc_refs or []) and u != self.diff_patch][:8]
            if extra:
                parts.append("References:\n" + "\n".join(f"  - {u}" for u in extra))
        if isinstance(self.raw, dict) and self.raw.get("exploit_source"):
            parts.append("Exploit source / PoC code (verbatim from ExploitDB):\n"
                         + self.raw["exploit_source"][:4000])
        if isinstance(self.raw, dict) and self.raw.get("merged_sources"):
            parts.append("Aggregated from: " + ", ".join(self.raw["merged_sources"]))
        return "\n".join(parts)

    def is_vulnerable(self, version: Optional[str]) -> Optional[bool]:
        """Aggregate decision across affected ranges. Grounded: None if no ranges."""
        if not self.affected:
            return None
        decided = [a.matches(version) for a in self.affected]
        if any(d is True for d in decided):
            return True
        if any(d is False for d in decided):
            return False
        return None


_VER_RE = re.compile(r"^\s*v?([0-9][0-9a-zA-Z.\-+~]*)\s*$")


def _norm_ver(v: Optional[str]) -> Optional[list]:
    if not v:
        return None
    m = _VER_RE.match(v)
    if not m:
        return None
    raw = m.group(1)
    parts = re.split(r"[.\-+~]", raw)
    out = []
    for p in parts:
        if p == "":
            continue
        if p.isdigit():
            out.append((0, int(p)))
        else:
            out.append((1, p))
    return out


def _is_semver_bound(b: Optional[str]) -> bool:
    """True if bound is a clean numeric version (e.g. '2.4.60'), False for git commit
    hashes / non-numeric tokens (e.g. '15e7241fa52e...')."""
    n = _norm_ver(b)
    if not n:
        return False
    return all(t == 0 for (t, _) in n)


def _cmp_ver(a: Optional[list], b: Optional[list]) -> int:
    if a is None and b is None:
        return 0
    if a is None:
        return -1
    if b is None:
        return 1
    for x, y in zip(a, b):
        if x == y:
            continue
        return -1 if x < y else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def version_in_range(version: Optional[str], rng: AffectedRange) -> Optional[bool]:
    """Strict range check. Returns None if version unparsable OR a bound is non-semver
    (e.g. git commit hash) OR the range has only a lower bound (affected "from X onwards"
    but no known fix -> can't confirm the target is in the affected window).
    Only returns True when the version falls within a range CLOSED on top (has a max bound)."""
    v = _norm_ver(version)
    if version and v is None:
        if any([rng.min_inclusive, rng.max_inclusive, rng.max_exclusive]):
            return None
    lo = rng.min_inclusive
    hi_inc = rng.max_inclusive
    hi_exc = rng.max_exclusive
    # any non-semver bound (git commit hash etc.) -> cannot decide
    for b in (lo, hi_inc, hi_exc):
        if b and not _is_semver_bound(b):
            return None
    has_max = bool(hi_inc or hi_exc)
    has_min = bool(lo)
    if not has_max and not has_min:
        return None  # no bounds -> unknown
    if not has_max:
        # only a lower bound -> "affected from X onwards" but no known upper fix.
        # Can't confirm target is affected (could be patched later) -> UNKNOWN.
        if v is None:
            return None
        if _cmp_ver(v, _norm_ver(lo)) < 0:
            return False  # below the lower bound -> definitely not affected
        return None  # >= min but no max -> UNKNOWN
    # has a max bound (range closed on top):
    if v is None:
        return None
    if hi_exc and _cmp_ver(v, _norm_ver(hi_exc)) >= 0:
        return False
    if hi_inc and _cmp_ver(v, _norm_ver(hi_inc)) > 0:
        return False
    if lo and _cmp_ver(v, _norm_ver(lo)) < 0:
        return False
    return True


class BaseScraper:
    name: str = "base"

    def __init__(self, client: Optional[httpx.AsyncClient] = None,
                 cache_get: Optional[Callable] = None,
                 cache_set: Optional[Callable] = None):
        self._client = client
        self._cache_get = cache_get
        self._cache_set = cache_set

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers=HEADERS, timeout=TIMEOUT, follow_redirects=True,
                limits=_LIMITS,
            )
        return self._client

    async def close(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_text(self, url: str, **kw) -> Optional[str]:
        try:
            r = await self.client.get(url, **kw)
            if r.status_code >= 400:
                return None
            return r.text
        except (httpx.HTTPError, httpx.InvalidURL) as e:
            return None

    async def _get_json(self, url: str, **kw) -> Optional[Any]:
        try:
            r = await self.client.get(url, **kw)
            if r.status_code >= 400:
                return None
            return r.json()
        except (httpx.HTTPError, ValueError):
            return None

    async def _post_json(self, url: str, json_body: Any, **kw) -> Optional[Any]:
        try:
            r = await self.client.post(url, json=json_body, **kw)
            if r.status_code >= 400:
                return None
            return r.json()
        except (httpx.HTTPError, ValueError):
            return None

    async def _cached(self, key: str, producer: Callable[[], "Any"]) -> Any:
        """Best-effort cache: producer is async callable returning serializable."""
        if self._cache_get:
            try:
                hit = await self._cache_get(key)
                if hit is not None:
                    return hit
            except Exception:
                pass
        val = await producer()
        if self._cache_set and val is not None:
            try:
                await self._cache_set(key, val)
            except Exception:
                pass
        return val

    async def search(self, query: str, version: Optional[str] = None) -> list[VulnRecord]:
        raise NotImplementedError

    async def get(self, cve_or_id: str) -> Optional[VulnRecord]:
        return None

"""Scraper registry + unified aggregator.

search_all(query, version=None): parallel gather across all sources, dedupe by CVE.
get_all(cve): per-CVE enrichment across sources.
Anti-mismatch: each VulnRecord keeps its source/url; agent never merges ranges blindly.
"""
from __future__ import annotations

import asyncio
import contextvars
import re
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from .base import BaseScraper, VulnRecord, AffectedRange, Outcome
from .nvd import NVDScraper
from .github import GitHubAdvisoryScraper
from .osv import OSVScraper
from .exploitdb import ExploitDBScraper
from .wordfence import WordfenceScraper
from .patchstack import PatchstackScraper
from .wpscan_free import WPScanFreeScraper
from .cisa_kev import CisaKevScraper
from .poc_github import PoCGitHubScraper
from .watchtowr import WatchTowrScraper
from .cve5 import Cve5Scraper
from .epss import EPSSScraper
from .news import BleepingComputerScraper
from .joomla_security import JoomlaSecurityScraper


def build_scrapers(client: Optional[httpx.AsyncClient] = None,
                   cache_get=None, cache_set=None) -> list[BaseScraper]:
    """Ordered: structured/exact-range sources first, enrichment last."""
    kw = {"client": client, "cache_get": cache_get, "cache_set": cache_set}
    return [
        Cve5Scraper(**kw),             # CVE 5.0 exact affected ranges (reachable where NVD blocked)
        JoomlaSecurityScraper(**kw),   # Joomla core CVE discovery (security-centre)
        GitHubAdvisoryScraper(**kw),   # reliable, exact ranges
        OSVScraper(**kw),              # reliable, exact ranges
        NVDScraper(**kw),              # authoritative CPE (needs services.nvd.nist.gov reachable)
        ExploitDBScraper(**kw),        # PoC/exploit refs
        WordfenceScraper(**kw),        # WP writeups
        PatchstackScraper(**kw),       # WP DB (best-effort)
        WPScanFreeScraper(**kw),       # WP DB (best-effort, no token)
        CisaKevScraper(**kw),          # in-the-wild exploitation flag
        PoCGitHubScraper(**kw),        # PoC repo discovery
        WatchTowrScraper(**kw),        # 1day analysis + PoC
        EPSSScraper(**kw),             # exploit-probability enrichment (annotates raw.epss)
        BleepingComputerScraper(**kw),  # real-world incident news (per-CVE enrichment)
    ]


def _merge_raw(ex: dict, r: dict) -> None:
    """Merge raw dicts: extend list-valued keys, copy missing scalars, preserve exploit_source.
    Does NOT touch merged_sources (managed by _dedupe)."""
    if not isinstance(ex, dict):
        ex = {}
    for k, v in (r or {}).items():
        if v is None:
            continue
        if k == "exploit_source" and v:
            ex["exploit_source"] = v  # exploit-db PoC code — keep verbatim
        elif k == "merged_sources":
            continue  # handled by _dedupe
        elif isinstance(v, list):
            ex.setdefault(k, [])
            for item in v:
                if item not in ex[k]:
                    ex[k].append(item)
        elif k not in ex or ex[k] in (None, "", []):
            ex[k] = v


def _dedupe(records: list[VulnRecord]) -> list[VulnRecord]:
    """Dedupe by CVE; keep first (structured sources win by registry order).
    Merge poc_refs, ranges, diff_patch, severity, raw (incl. exploit_source) + track sources.
    Non-CVE records kept by source:id."""
    seen_cve: dict[str, VulnRecord] = {}
    others: list[VulnRecord] = []
    for r in records:
        if r.cve:
            if r.cve not in seen_cve:
                if not isinstance(r.raw, dict):
                    r.raw = {}
                r.raw.setdefault("merged_sources", [])
                if r.source not in r.raw["merged_sources"]:
                    r.raw["merged_sources"].append(r.source)
                seen_cve[r.cve] = r
            else:
                ex = seen_cve[r.cve]
                ex.poc_refs = list(dict.fromkeys(ex.poc_refs + r.poc_refs))
                if not ex.affected and r.affected:
                    ex.affected = r.affected
                if not ex.cvss and r.cvss:
                    ex.cvss = r.cvss; ex.severity = r.severity or ex.severity
                if not ex.diff_patch and r.diff_patch:
                    ex.diff_patch = r.diff_patch
                if len(r.description) > len(ex.description):
                    ex.description = r.description
                _merge_raw(ex.raw, r.raw)
                if r.source not in ex.raw.get("merged_sources", []):
                    ex.raw.setdefault("merged_sources", []).append(r.source)
        else:
            others.append(r)
    return list(seen_cve.values()) + others


_PER_SOURCE_TIMEOUT = 30.0    # default per-source deadline before adaptive history exists
_MIN_TIMEOUT = 10.0           # adaptive timeout floor (seconds)
_MAX_TIMEOUT = 45.0           # adaptive timeout ceiling (seconds)
_CIRCUIT_FAIL_THRESHOLD = 3   # consecutive failures → circuit opens
_CIRCUIT_OPEN_COOLDOWN = 30.0  # seconds open before a half-open probe is allowed
_MAX_CONCURRENT_AGGREGATES = 4  # one global fanout semaphore: >1 scan, no source saturation

_in_flight: dict[str, asyncio.Future] = {}  # single-flight: one scrape per key at a time


@dataclass
class SourceHealth:
    """Per-source circuit-breaker state (mirrors the source_health table row)."""
    name: str
    state: str = "closed"                  # closed | open | half_open
    consecutive_failures: int = 0
    total_success: int = 0
    total_failures: int = 0
    total_timeouts: int = 0
    total_rate_limited: int = 0
    latency: float = 0.0                   # EMA of last-success latency (seconds)
    last_error: str = ""
    open_until: float = 0.0                # epoch until which the circuit stays open
    last_success_at: float = 0.0
    last_failure_at: float = 0.0

    _ROW_KEYS = ("state", "consecutive_failures", "total_success", "total_failures",
                 "total_timeouts", "total_rate_limited", "latency", "last_error",
                 "open_until", "last_success_at", "last_failure_at")

    def to_row(self) -> dict:
        return {k: getattr(self, k) for k in self._ROW_KEYS}

    @classmethod
    def from_row(cls, name: str, row: dict) -> "SourceHealth":
        h = cls(name=name)
        for k in cls._ROW_KEYS:
            if k in row and row[k] is not None:
                setattr(h, k, row[k])
        return h


_RESPONDED_OUTCOMES = frozenset({Outcome.SUCCESS, Outcome.CLIENT_ERROR})
_FAIL_OUTCOMES = frozenset({Outcome.TIMEOUT, Outcome.HTTP_ERROR,
                            Outcome.NETWORK_ERROR, Outcome.RATE_LIMITED})

_call_ctx: "contextvars.ContextVar[Optional[_CallMonitor]]" = contextvars.ContextVar(
    "source_health_call", default=None)


class _CallMonitor:
    """Per aggregate-call outcome collector for one source."""
    __slots__ = ("reg", "name", "responded")

    def __init__(self, reg: "SourceHealthRegistry", name: str):
        self.reg = reg
        self.name = name
        self.responded = False

    def report(self, info: dict) -> None:
        outcome = info.get("outcome") or Outcome.NETWORK_ERROR
        self.reg.record(self.name, outcome,
                        cooldown=info.get("cooldown", 0.0),
                        latency=info.get("latency", 0.0),
                        error=info.get("error", ""))
        if outcome in _RESPONDED_OUTCOMES:
            self.responded = True


def _default_cb(info: dict) -> None:
    """Health callback wired onto scrapers; routes into the active call monitor."""
    mon = _call_ctx.get()
    if mon is not None:
        mon.report(info)


class SourceHealthRegistry:
    """Central source-outcome classification + persisted circuit breaker.

    Persistence is pluggable: an async (load, save) pair, defaulting to db.py's
    source_health_get/source_health_set (resolved lazily to avoid import cycles).
    """

    def __init__(self):
        self._health: dict[str, SourceHealth] = {}
        self._known_missing: set[str] = set()
        self._store = None             # async (load, save) pair or None
        self._store_fetched = False
        self._persist_tasks: set = set()

    # ---- store ----
    def set_store(self, store) -> None:
        """Set persistence: an async (load, save) tuple pair, an object exposing
        .load/.save coroutines, or None (→ lazy db.py discovery)."""
        if store is None:
            self._store = None
        elif isinstance(store, tuple):
            self._store = store
        else:
            self._store = (store.load, store.save)
        self._store_fetched = True

    async def _store_pair(self):
        if self._store is None and not self._store_fetched:
            self._store_fetched = True
            try:
                from db import source_health_get, source_health_set
                self._store = (source_health_get, source_health_set)
            except Exception:
                self._store = ()
        return self._store or ()

    # ---- state ----
    def get(self, name: str) -> SourceHealth:
        h = self._health.get(name)
        if h is None:
            h = self._health.setdefault(name, SourceHealth(name=name))
        return h

    async def ensure_loaded(self, name: str) -> None:
        if name in self._health or name in self._known_missing:
            return
        self._known_missing.add(name)
        pair = await self._store_pair()
        if not pair:
            return
        try:
            row = await pair[0](name)
        except Exception:
            return
        if row:
            self._known_missing.discard(name)
            self._health[name] = SourceHealth.from_row(name, row)

    # ---- policy ----
    def timeout_for(self, h: SourceHealth) -> float:
        """Adaptive per-source deadline: 3× EMA latency, bounded _MIN.._MAX (default)."""
        if h.latency <= 0:
            return _PER_SOURCE_TIMEOUT
        return min(_MAX_TIMEOUT, max(_MIN_TIMEOUT, h.latency * 3.0))

    def record(self, name: str, outcome: str, *, cooldown: float = 0.0,
               latency: float = 0.0, error: str = "") -> SourceHealth:
        """Classify one source outcome into counters + circuit transitions."""
        if outcome == Outcome.SKIPPED:
            return self.get(name)
        h = self.get(name)
        now = time.time()
        if outcome in _RESPONDED_OUTCOMES:
            h.consecutive_failures = 0
            h.total_success += 1
            if latency > 0:
                h.latency = latency if h.latency <= 0 else 0.8 * h.latency + 0.2 * latency
            h.last_error = ""
            h.last_success_at = now
            if h.state != "closed":
                h.state = "closed"  # a success proves the source works again
        elif outcome in _FAIL_OUTCOMES:
            h.consecutive_failures += 1
            h.total_failures += 1
            h.last_failure_at = now
            if outcome == Outcome.TIMEOUT:
                h.total_timeouts += 1
            elif outcome == Outcome.RATE_LIMITED:
                h.total_rate_limited += 1
            h.last_error = error or outcome
            if outcome == Outcome.RATE_LIMITED:
                h.state = "open"                 # server-mandated backoff
                h.open_until = now + cooldown    # Retry-After (default 60s)
            elif h.state == "half_open":
                h.state = "open"                 # probe failed — back to open
                h.open_until = now + _CIRCUIT_OPEN_COOLDOWN
            elif h.state == "closed" and h.consecutive_failures >= _CIRCUIT_FAIL_THRESHOLD:
                h.state = "open"
                h.open_until = now + _CIRCUIT_OPEN_COOLDOWN
        self._schedule_persist(name)
        return h

    def _schedule_persist(self, name: str) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        t = loop.create_task(self._persist(name))
        self._persist_tasks.add(t)
        t.add_done_callback(self._persist_tasks.discard)

    async def _persist(self, name: str) -> None:
        pair = await self._store_pair()
        if not pair:
            return
        h = self._health.get(name)
        if h is None:
            return
        try:
            await pair[1](name, h.to_row())
        except Exception:
            pass

    async def flush(self) -> None:
        """Await pending persistence writes (determinism for tests)."""
        while self._persist_tasks:
            await asyncio.gather(*list(self._persist_tasks), return_exceptions=True)


_health_reg: Optional[SourceHealthRegistry] = None
_agg_sem: Optional[asyncio.Semaphore] = None


def _get_health_reg() -> SourceHealthRegistry:
    global _health_reg
    if _health_reg is None:
        _health_reg = SourceHealthRegistry()
    return _health_reg


def _get_agg_sem() -> asyncio.Semaphore:
    global _agg_sem
    if _agg_sem is None:
        _agg_sem = asyncio.Semaphore(_MAX_CONCURRENT_AGGREGATES)
    return _agg_sem


def _reset_source_health(store=None) -> None:
    """Test hook: drop module-global circuit/single-flight state (loop-safe reset)."""
    global _health_reg, _agg_sem
    _in_flight.clear()
    _agg_sem = None
    reg = SourceHealthRegistry()
    if store is not None:
        reg.set_store(store)
    _health_reg = reg


async def _stale_aggregate(key: str) -> Optional[list[VulnRecord]]:
    """Stale aggregate fallback: cached value older than the cache TTL, else None."""
    try:
        from db import cache_get_stale
    except Exception:
        return None
    try:
        raw = await cache_get_stale(key)
    except Exception:
        return None
    if not raw:
        return None
    try:
        return [VulnRecord.from_dict(d) for d in raw if isinstance(d, dict)]
    except Exception:
        return None


async def _one(s: BaseScraper, reg: SourceHealthRegistry, query: str,
               version, is_get: bool) -> tuple:
    """Scrape one source with health gating: skip open circuits, probe half-open,
    classify every outcome, never outlive the adaptive deadline."""
    name = s.name
    try:
        await reg.ensure_loaded(name)
    except Exception:
        pass
    h = reg.get(name)
    now = time.time()
    mon = _CallMonitor(reg, name)
    if h.state == "open" and now < h.open_until:
        mon.report({"name": name, "outcome": Outcome.SKIPPED})
        return [], mon
    if h.state == "open":
        h.state = "half_open"  # cooldown elapsed — admit exactly one probe request
        reg._schedule_persist(name)
    timeout = reg.timeout_for(h)
    token = _call_ctx.set(mon)
    try:
        try:
            if is_get:
                r = await asyncio.wait_for(s.get(query), timeout=timeout)
                recs = [r] if r else []
            else:
                recs = await asyncio.wait_for(s.search(query, version), timeout=timeout)
        except asyncio.TimeoutError:
            mon.report({"name": name, "outcome": Outcome.TIMEOUT, "latency": timeout})
            recs = []
        except Exception as e:  # CancelledError is BaseException → propagates
            mon.report({"name": name, "outcome": Outcome.NETWORK_ERROR, "error": repr(e)})
            recs = []
    finally:
        _call_ctx.reset(token)
    return recs, mon


async def _aggregate(scrappers: list[BaseScraper], query: str, version, is_get: bool) -> list[VulnRecord]:
    """Shared get_all/search_all body with aggregate-level caching.

    One global semaphore bounds concurrent aggregate fanout (multi-scan safety);
    single-flight collapses same-key calls; circuit breakers skip unhealthy sources;
    all-source transient failure falls back to the stale aggregate instead of writing
    a 24h negative cache entry.
    """
    cache_get = next((s._cache_get for s in scrappers if s._cache_get), None)
    cache_set = next((s._cache_set for s in scrappers if s._cache_set), None)
    # normalize the key — get(CVE) case/space variants, search(q, None/""/version) variants
    if is_get:
        q_norm = re.sub(r"\s+", "", str(query or "")).upper()
        key = f"agg:get:{q_norm}"
    else:
        q_norm = re.sub(r"\s+", " ", str(query or "")).strip().lower()
        key = f"agg:search:{q_norm}:{str(version or '').strip()}"
    if cache_get:
        try:
            hit = await cache_get(key)
            if hit is not None:
                return [VulnRecord.from_dict(d) for d in hit if isinstance(d, dict)]
        except Exception:
            pass

    # single-flight: if another coroutine is already scraping this key, await its result
    existing = _in_flight.get(key)
    if existing is not None:
        try:
            return await asyncio.shield(existing)
        except Exception:
            pass  # the other scrape failed — fall through and re-scrape

    reg = _get_health_reg()
    for s in scrappers:
        if s._health_cb is None:
            s.set_health_cb(_default_cb)

    async def _scrape():
        async with _get_agg_sem():
            results = await asyncio.gather(
                *[_one(s, reg, query, version, is_get) for s in scrappers],
                return_exceptions=True)
        flat: list[VulnRecord] = []
        responded = False
        for r in results:
            if isinstance(r, BaseException):
                continue
            recs, mon = r
            flat.extend(recs)
            if mon is not None and mon.responded:
                responded = True
        recs = _dedupe(flat)
        # Negative caching is only safe when ≥1 source actually answered. When every
        # source failed transiently (network down / all circuits open) a 24h empty
        # cache entry would hide the outage — skip it and prefer stale data instead.
        if cache_set and responded:
            try:
                await cache_set(key, [r.to_dict() for r in recs])
            except Exception:
                pass
        if not recs and not responded:
            stale = await _stale_aggregate(key)
            if stale is not None:
                return stale
        return recs

    fut = asyncio.ensure_future(_scrape())
    _in_flight[key] = fut
    # Entry is dropped only when the shared future finishes — a cancelled creator
    # leaves the work running for other waiters instead of re-scraping mid-flight.
    fut.add_done_callback(lambda f: _in_flight.pop(key, None) if _in_flight.get(key) is f else None)
    try:
        return await asyncio.shield(fut)
    except asyncio.CancelledError:
        raise


async def search_all(scrappers: list[BaseScraper], query: str,
                     version: Optional[str] = None) -> list[VulnRecord]:
    return await _aggregate(scrappers, query, version, is_get=False)


async def get_all(scrappers: list[BaseScraper], cve: str) -> list[VulnRecord]:
    return await _aggregate(scrappers, cve, None, is_get=True)


__all__ = ["VulnRecord", "AffectedRange", "build_scrapers",
           "search_all", "get_all"]

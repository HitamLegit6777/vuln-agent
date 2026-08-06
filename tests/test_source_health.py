"""Source health: outcome classification, circuit breakers, adaptive timeouts,
stale aggregate fallback, and hardened single-flight (registry-level, deterministic).

Fake scrapers report outcomes through base._report (no network), a fake persistence
store replaces db.py (real-db tests use the tmp_db convention), and module-global
circuit/single-flight state — plus db.py's event-loop-bound lock — is reset between
tests. Every test body runs in ONE asyncio.run loop: the persist task spawned by
record() contends db._lock with the aggregate's cache ops, and contended acquires
bind the lock to the current loop (a second loop would raise).
"""
from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest

import db as dbmod
from scrapers import registry as regmod
from scrapers.base import BaseScraper, Outcome, VulnRecord, classify_http
from scrapers.registry import get_all, search_all


def rec(cve, source="test"):
    return VulnRecord(cve=cve, source=source, title=f"t {cve}", url=f"https://ex/{cve}")


def arun(coro):
    """Run one async test body (plus pending health persistence) in a single loop."""
    async def _wrapped():
        out = await coro
        await regmod._get_health_reg().flush()
        return out
    return asyncio.run(_wrapped())


class FakeStore:
    """In-memory persistence pair (rows keyed by source name)."""

    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def load(self, name):
        return self.rows.get(name)

    async def save(self, name, row):
        self.rows[name] = dict(row)


class ScriptedScraper(BaseScraper):
    """Reports canned outcomes via base._report; script steps drive each call.

    Step keys: status / retry_after / exc / hang / sleep.
    """

    def __init__(self, name, script, records=None, cache_get=None, cache_set=None):
        super().__init__(cache_get=cache_get, cache_set=cache_set)
        self.name = name
        self.script = list(script)
        self.records = list(records or [])
        self.calls = 0
        self.entered = asyncio.Event()

    async def _emit(self):
        self.calls += 1
        self.entered.set()
        step = self.script.pop(0) if self.script else {}
        if step.get("sleep"):
            await asyncio.sleep(step["sleep"])
        if step.get("hang"):
            await asyncio.sleep(999)
        if step.get("status") is not None:
            self._report(status_code=step["status"], retry_after=step.get("retry_after"),
                         latency=0.01)
            return list(self.records) if step["status"] < 400 else []
        if step.get("exc"):
            self._report(exc=step["exc"], latency=0.01)
            return []
        return list(self.records)

    async def search(self, query, version=None):
        return await self._emit()

    async def get(self, cve_or_id):
        out = await self._emit()
        return out[0] if out else None


@pytest.fixture()
def store(monkeypatch, tmp_path):
    """Fresh registry + fake store; fast circuit/timeout knobs; no real-DB touching."""
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "unused.db"))
    monkeypatch.setattr(dbmod, "_src_health_ready", False)
    monkeypatch.setattr(dbmod, "_lock", asyncio.Lock())
    s = FakeStore()
    regmod._reset_source_health(store=s)
    monkeypatch.setattr(regmod, "_CIRCUIT_FAIL_THRESHOLD", 2)
    monkeypatch.setattr(regmod, "_CIRCUIT_OPEN_COOLDOWN", 0.05)
    monkeypatch.setattr(regmod, "_MIN_TIMEOUT", 0.05)
    monkeypatch.setattr(regmod, "_MAX_TIMEOUT", 0.2)
    monkeypatch.setattr(regmod, "_PER_SOURCE_TIMEOUT", 0.1)
    yield s
    regmod._reset_source_health()


@pytest.fixture()
def db_reg(tmp_path, monkeypatch):
    """Real SQLite (db.py hooks): temp DB + migrated schema + lazy db discovery."""
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "health.db"))
    monkeypatch.setattr(dbmod, "_src_health_ready", False)
    monkeypatch.setattr(dbmod, "_lock", asyncio.Lock())
    dbmod.init_db()
    regmod._reset_source_health()  # store=None → registry lazily uses db.py hooks
    yield
    regmod._reset_source_health()


# ---------- pure classification ----------

def test_classify_http_statuses():
    assert classify_http(200) == (Outcome.SUCCESS, 0.0)
    assert classify_http(301) == (Outcome.SUCCESS, 0.0)
    assert classify_http(404) == (Outcome.CLIENT_ERROR, 0.0)   # answered, legit negative
    assert classify_http(500) == (Outcome.HTTP_ERROR, 0.0)
    out, cd = classify_http(429, retry_after="5")
    assert out == Outcome.RATE_LIMITED and cd == 5.0
    out, cd = classify_http(429)
    assert out == Outcome.RATE_LIMITED and cd == 60.0
    out, cd = classify_http(429, retry_after="Thu, 01 Jan 2026 00:00:00 GMT")
    assert out == Outcome.RATE_LIMITED and cd == 60.0  # HTTP-date → default


def test_adaptive_timeout_bounded_10_45():
    reg = regmod.SourceHealthRegistry()
    assert reg.timeout_for(regmod.SourceHealth(name="x", latency=0.0)) == 30.0
    assert reg.timeout_for(regmod.SourceHealth(name="x", latency=2.0)) == 10.0   # floor
    assert reg.timeout_for(regmod.SourceHealth(name="x", latency=20.0)) == 45.0  # ceiling
    assert reg.timeout_for(regmod.SourceHealth(name="x", latency=5.0)) == 15.0
    t = reg.timeout_for(regmod.SourceHealth(name="x", latency=7.0))
    assert 10.0 <= t <= 45.0


def test_record_transitions(store):
    reg = regmod._get_health_reg()
    reg.record("x", Outcome.TIMEOUT)
    reg.record("x", Outcome.TIMEOUT)
    h = reg.get("x")
    assert h.state == "open"
    assert h.total_timeouts == 2 and h.consecutive_failures == 2
    reg.record("x", Outcome.SUCCESS, latency=1.0)
    h = reg.get("x")
    assert h.state == "closed" and h.consecutive_failures == 0 and h.latency == 1.0
    # 429 opens immediately regardless of threshold, honoring Retry-After
    reg.record("x", Outcome.RATE_LIMITED, cooldown=7.5)
    h = reg.get("x")
    assert h.state == "open" and h.total_rate_limited == 1
    assert abs(h.open_until - (time.time() + 7.5)) < 0.5
    # SKIPPED mutates nothing
    h2 = reg.get("y")
    reg.record("y", Outcome.SKIPPED)
    assert reg.get("y") is h2 and h2.total_failures == 0 and h2.state == "closed"


def test_outcomes_persist_to_store(store):
    async def _do():
        reg = regmod._get_health_reg()
        reg.record("persistme", Outcome.TIMEOUT)
        reg.record("persistme", Outcome.RATE_LIMITED, cooldown=3.0)

    arun(_do())
    row = store.rows["persistme"]
    assert row["state"] == "open"
    assert row["total_timeouts"] == 1
    assert row["total_rate_limited"] == 1
    assert row["consecutive_failures"] == 2


# ---------- aggregate behavior ----------

def test_success_records_health_and_caches(store):
    class FakeCache:
        def __init__(self):
            self.data = {}
            self.writes = []

        async def get(self, key):
            return self.data.get(key)

        async def set(self, key, value):
            self.data[key] = value
            self.writes.append(key)

    cache = FakeCache()
    s1 = ScriptedScraper("s1", [{"status": 200}], records=[rec("CVE-2026-9001")],
                         cache_get=cache.get, cache_set=cache.set)
    s2 = ScriptedScraper("s2", [{"status": 200}], records=[rec("CVE-2026-9002")],
                         cache_get=cache.get, cache_set=cache.set)

    async def _run():
        outs = await get_all([s1, s2], "CVE-2026-9001")
        reg = regmod._get_health_reg()
        assert {r.cve for r in outs} == {"CVE-2026-9001", "CVE-2026-9002"}
        assert reg.get("s1").total_success == 1 and reg.get("s1").consecutive_failures == 0
        assert reg.get("s2").total_success == 1
        # second call is served from the fresh aggregate cache — no re-scrape
        outs2 = await get_all([s1, s2], "CVE-2026-9001")
        assert {r.cve for r in outs2} == {"CVE-2026-9001", "CVE-2026-9002"}
        assert s1.calls == 1 and s2.calls == 1
        return cache

    cache = arun(_run())
    assert cache.writes == ["agg:get:CVE-2026-9001"]


def test_timeout_trips_circuit_then_skips(store):
    s = ScriptedScraper("hung", [{"hang": True}, {"hang": True}, {"hang": True}])
    reg = regmod._get_health_reg()

    async def _run():
        assert await get_all([s], "CVE-2026-9101") == []
        assert await get_all([s], "CVE-2026-9101") == []
        h = reg.get("hung")
        assert h.state == "open"
        assert h.total_timeouts == 2
        t0 = time.monotonic()
        assert await get_all([s], "CVE-2026-9101") == []
        assert time.monotonic() - t0 < 0.5          # skipped — no third hang
        assert h.total_timeouts == 2                # skipped ⇒ no new timeout
        assert s.calls == 2

    arun(_run())


def test_half_open_probe_recovers_and_refails(store):
    reg = regmod._get_health_reg()
    s = ScriptedScraper("wobble", [{"hang": True}, {"hang": True}, {"status": 200}],
                        records=[rec("CVE-2026-9102")])

    async def _run():
        assert await get_all([s], "CVE-2026-9102") == []
        assert await get_all([s], "CVE-2026-9102") == []
        assert reg.get("wobble").state == "open"
        await asyncio.sleep(0.06)                   # cooldown elapses → half-open probe
        outs = await get_all([s], "CVE-2026-9102")
        assert [r.cve for r in outs] == ["CVE-2026-9102"]
        h = reg.get("wobble")
        assert h.state == "closed" and h.consecutive_failures == 0

        # a failed probe re-opens the circuit
        s2 = ScriptedScraper("wob2", [{"hang": True}, {"hang": True}, {"hang": True}, {"hang": True}])
        assert await get_all([s2], "CVE-2026-9103") == []
        assert await get_all([s2], "CVE-2026-9103") == []
        assert reg.get("wob2").state == "open"
        await asyncio.sleep(0.06)
        assert await get_all([s2], "CVE-2026-9103") == []   # probe fails → re-open
        h2 = reg.get("wob2")
        assert h2.state == "open" and h2.total_timeouts == 3

    arun(_run())


def test_429_opens_immediately_honors_retry_after(store):
    s = ScriptedScraper("throttled", [{"status": 429, "retry_after": "0.3"}, {"status": 200}],
                        records=[rec("CVE-2026-9104")])
    reg = regmod._get_health_reg()

    async def _run():
        assert await get_all([s], "CVE-2026-9104") == []
        h = reg.get("throttled")
        assert h.state == "open" and h.total_rate_limited == 1
        assert h.open_until > time.time() + 0.2
        t0 = time.monotonic()
        assert await get_all([s], "CVE-2026-9104") == []   # skipped inside Retry-After
        assert s.calls == 1                                 # no second 429 fired
        assert time.monotonic() - t0 < 0.2
        await asyncio.sleep(0.35)                           # Retry-After elapses
        outs = await get_all([s], "CVE-2026-9104")          # half-open probe succeeds
        assert [r.cve for r in outs] == ["CVE-2026-9104"]
        assert reg.get("throttled").state == "closed"

    arun(_run())


def test_client_error_is_clean_negative_not_failure(store):
    s = ScriptedScraper("cfour", [{"status": 404}])

    async def _run():
        assert await get_all([s], "CVE-2026-9105") == []
        h = regmod._get_health_reg().get("cfour")
        assert h.state == "closed"
        assert h.consecutive_failures == 0 and h.total_success == 1

    arun(_run())


def test_cancelled_creator_does_not_cancel_shared_work(store, monkeypatch):
    monkeypatch.setattr(regmod, "_PER_SOURCE_TIMEOUT", 5.0)
    s = ScriptedScraper("slow", [{"status": 200, "sleep": 0.3}],
                        records=[rec("CVE-2026-9106")])

    async def _run():
        task_a = asyncio.create_task(get_all([s], "CVE-2026-9106"))
        await s.entered.wait()                       # scraper is inside the shared future
        task_b = asyncio.create_task(get_all([s], "CVE-2026-9106"))
        await asyncio.sleep(0.03)
        task_a.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task_a
        outs = await task_b                          # shared work kept running → result
        assert [r.cve for r in outs] == ["CVE-2026-9106"]
        assert s.calls == 1                          # not re-scraped after cancellation
        for _ in range(50):                          # entry dropped once the future finished
            if not regmod._in_flight:
                break
            await asyncio.sleep(0.01)
        assert regmod._in_flight == {}

    arun(_run())


def test_concurrent_different_keys(store):
    scrapers = [
        ScriptedScraper(f"par{i}", [{"status": 200, "sleep": 0.05}],
                        records=[rec(f"CVE-2026-800{i}")])
        for i in range(1, 5)
    ]

    async def _run():
        outs = await asyncio.gather(*[
            get_all([s], f"CVE-2026-800{i}") for i, s in enumerate(scrapers, 1)
        ])
        for i, (s, o) in enumerate(zip(scrapers, outs), 1):
            assert [r.cve for r in o] == [f"CVE-2026-800{i}"]
            assert s.calls == 1
        reg = regmod._get_health_reg()
        assert all(reg.get(s.name).total_success == 1 for s in scrapers)

    arun(_run())


def test_global_semaphore_serializes_fanout(store, monkeypatch):
    monkeypatch.setattr(regmod, "_MAX_CONCURRENT_AGGREGATES", 1)
    active = 0
    peak = 0

    class Tracked(ScriptedScraper):
        async def _emit(self):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                return await super()._emit()
            finally:
                active -= 1

    a = Tracked("ta", [{"status": 200, "sleep": 0.05}], records=[rec("CVE-2026-8101")])
    b = Tracked("tb", [{"status": 200, "sleep": 0.05}], records=[rec("CVE-2026-8102")])

    async def _run():
        oa, ob = await asyncio.gather(get_all([a], "CVE-2026-8101"),
                                      get_all([b], "CVE-2026-8102"))
        assert [r.cve for r in oa] == ["CVE-2026-8101"]
        assert [r.cve for r in ob] == ["CVE-2026-8102"]
        assert peak == 1                             # sem=1 ⇒ aggregates never overlapped

    arun(_run())


def test_multiple_aggregates_run_in_parallel(store, monkeypatch):
    monkeypatch.setattr(regmod, "_MAX_CONCURRENT_AGGREGATES", 4)
    active = 0
    peak = 0

    class Tracked(ScriptedScraper):
        async def _emit(self):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            try:
                return await super()._emit()
            finally:
                active -= 1

    a = Tracked("pa", [{"status": 200, "sleep": 0.1}], records=[rec("CVE-2026-8201")])
    b = Tracked("pb", [{"status": 200, "sleep": 0.1}], records=[rec("CVE-2026-8202")])

    async def _run():
        await asyncio.gather(get_all([a], "CVE-2026-8201"), get_all([b], "CVE-2026-8202"))
        assert peak == 2                             # >1 scan allowed concurrently

    arun(_run())


def test_search_all_path(store):
    s = ScriptedScraper("s1", [{"status": 200}], records=[rec("CVE-2026-9501")])

    async def _run():
        outs = await search_all([s], "wordpress plugin xyz")
        assert [r.cve for r in outs] == ["CVE-2026-9501"]
        assert regmod._get_health_reg().get("s1").total_success == 1

    arun(_run())


# ---------- real db: persistence + stale fallback ----------

def test_source_health_db_roundtrip(db_reg):
    fields = {"state": "open", "consecutive_failures": 3, "total_success": 5,
              "total_failures": 4, "total_timeouts": 2, "total_rate_limited": 1,
              "latency": 1.5, "last_error": "429", "open_until": time.time() + 100}

    async def _run():
        await dbmod.source_health_set("gh", fields)
        row = await dbmod.source_health_get("gh")
        assert row["state"] == "open"
        assert row["consecutive_failures"] == 3 and row["latency"] == 1.5
        # upsert: untouched fields survive
        await dbmod.source_health_set("gh", {"state": "closed", "consecutive_failures": 0})
        row2 = await dbmod.source_health_get("gh")
        assert row2["state"] == "closed" and row2["consecutive_failures"] == 0
        assert row2["total_success"] == 5 and row2["total_rate_limited"] == 1

    arun(_run())


def test_persisted_open_circuit_skips_source(db_reg):
    async def _run():
        await dbmod.source_health_set("nvd", {"state": "open",
                                              "open_until": time.time() + 3600,
                                              "consecutive_failures": 3,
                                              "total_failures": 3})
        s = ScriptedScraper("nvd", [{"hang": True}], records=[rec("CVE-2026-9401")])
        t0 = time.monotonic()
        assert await get_all([s], "CVE-2026-9401") == []
        assert time.monotonic() - t0 < 0.5           # skipped — did not hang
        assert s.calls == 0

    arun(_run())


def test_stale_fallback_and_no_negative_cache_on_transient(db_reg):
    async def _run():
        key = "agg:get:CVE-2026-9301"
        dbmod._cache_set_sync(key, [rec("CVE-2026-9301").to_dict()])
        with sqlite3.connect(dbmod.DB_PATH) as c:
            c.execute("UPDATE cache SET ts=? WHERE key=?", (time.time() - 3 * 86400, key))

        flaky = ScriptedScraper("flaky", [{"status": 429}, {"status": 200}],
                                cache_get=dbmod.cache_get, cache_set=dbmod.cache_set)
        # all sources failed transiently → stale aggregate returned, NOT a 24h negative
        outs = await get_all([flaky], "CVE-2026-9301")
        assert [r.cve for r in outs] == ["CVE-2026-9301"]
        with sqlite3.connect(dbmod.DB_PATH) as c:
            ts = c.execute("SELECT ts FROM cache WHERE key=?", (key,)).fetchone()[0]
        assert time.time() - ts > 2 * 86400          # stale row untouched → no rewrite

        # clean negative: a source answered 200-empty → empty IS cached (fresh)
        key2 = "agg:get:CVE-2026-9302"
        ok = ScriptedScraper("ok", [{"status": 200}],
                             cache_get=dbmod.cache_get, cache_set=dbmod.cache_set)
        assert await get_all([ok], "CVE-2026-9302") == []
        before = ok.calls
        assert await get_all([ok], "CVE-2026-9302") == []   # served from negative cache
        assert ok.calls == before
        with sqlite3.connect(dbmod.DB_PATH) as c:
            ts2 = c.execute("SELECT ts FROM cache WHERE key=?", (key2,)).fetchone()[0]
        assert time.time() - ts2 < 60

    arun(_run())

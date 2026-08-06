"""Focused tests for the bg_jobs lifecycle machine (db.py) and the in-process
job orchestrator (jobs.py).

Offline + deterministic: no network, no Telegram, no LLM. Async APIs are driven
with asyncio.run (no pytest-asyncio dependency), following the repo convention.
"""
import asyncio
import json
import os
import sqlite3
import tempfile

import pytest

import db as dbmod
import jobs


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def tmp_db(monkeypatch):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "test.db")
    monkeypatch.setattr(dbmod, "DB_PATH", path)
    monkeypatch.setattr(dbmod, "_lock", asyncio.Lock())
    dbmod.init_db()
    return path


@pytest.fixture(autouse=True)
def _clean_jobs_state():
    """Isolate the module-level task registry / semaphore between tests."""
    jobs._tasks.clear()
    jobs._sem = None
    jobs._sem_limit = jobs.SEMAPHORE_LIMIT
    yield
    jobs._tasks.clear()
    jobs._sem = None
    jobs._sem_limit = jobs.SEMAPHORE_LIMIT


# ---------- DB: create / read / ownership ----------

def test_create_job_roundtrip(tmp_db):
    async def run():
        row = await dbmod.create_job("s1", 1, "https://t/",
                                     model_detect="det", model_report="rep")
        assert row["stage"] == "QUEUED"
        assert row["status"] == "running"
        assert row["progress"] == 0
        assert row["cancel_requested"] == 0
        assert row["model_detect"] == "det" and row["model_report"] == "rep"
        got = await dbmod.get_job("s1")
        assert got["target"] == "https://t/"
        assert got["user_id"] == 1
        with pytest.raises(ValueError):  # duplicate id is rejected, not overwritten
            await dbmod.create_job("s1", 1, "https://t/")
        assert (await dbmod.get_job("nope")) is None
    _run(run())


def test_ownership(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        assert (await dbmod.get_job_for_user("s1", 2)) is None
        assert (await dbmod.get_job_for_user("s1", 1)) is not None
        assert (await dbmod.claim_job("s1", 2)) is None        # not owned
        assert (await dbmod.request_cancel("s1", 2)) is None   # not owned
        assert (await dbmod.get_job("s1"))["cancel_requested"] == 0
        assert await dbmod.list_jobs(2) == []
        assert [r["scan_id"] for r in await dbmod.list_jobs(1)] == ["s1"]
    _run(run())


def test_list_jobs_filters(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        await dbmod.transition_job("s1", "RESEARCHING")
        await dbmod.transition_job("s1", "VERIFYING")
        await dbmod.transition_job("s1", "REPORTING")
        await dbmod.transition_job("s1", "COMPLETED")
        await dbmod.create_job("s2", 1, "t")
        await dbmod.create_job("s3", 2, "t")
        assert [r["scan_id"] for r in await dbmod.list_jobs(1, stage="QUEUED")] == ["s2"]
        assert [r["scan_id"] for r in await dbmod.list_jobs(1, status="done")] == ["s1"]
        assert [r["scan_id"] for r in await dbmod.list_jobs(limit=2)] == ["s3", "s2"]
        assert await dbmod.list_jobs(1, stage="CANCELLED") == []
    _run(run())


# ---------- DB: stage machine ----------

def test_valid_transitions_and_status_sync(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        await dbmod.transition_job("s1", "RESEARCHING")
        row = await dbmod.transition_job("s1", "VERIFYING", progress=3, total=10,
                                         current="CVE-2026-1",
                                         checkpoint=json.dumps({"findings": []}))
        assert row["stage"] == "VERIFYING" and row["status"] == "running"
        assert row["progress"] == 3 and row["total"] == 10
        assert row["current"] == "CVE-2026-1"
        await dbmod.transition_job("s1", "REPORTING")
        row = await dbmod.transition_job("s1", "COMPLETED",
                                         report=json.dumps({"ok": True}),
                                         report_status="EXPLOITABLE")
        assert row["stage"] == "COMPLETED" and row["status"] == "done"
        assert row["report_status"] == "EXPLOITABLE"
        # idempotent self-transition on a terminal stage
        await dbmod.transition_job("s1", "COMPLETED")
    _run(run())


def test_invalid_transitions(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        with pytest.raises(ValueError):
            await dbmod.transition_job("s1", "COMPLETED")    # QUEUED -> COMPLETED
        with pytest.raises(ValueError):
            await dbmod.transition_job("s1", "REPORTING")    # skip stages
        await dbmod.transition_job("s1", "CANCELLED")
        with pytest.raises(ValueError):
            await dbmod.transition_job("s1", "RESEARCHING")  # terminal frozen
        await dbmod.create_job("s2", 1, "t")
        with pytest.raises(ValueError):
            await dbmod.transition_job("s2", "NOPE")         # unknown stage
        with pytest.raises(ValueError):
            await dbmod.transition_job("missing", "RESEARCHING")  # no such job
    _run(run())


def test_resume_and_retry_transitions(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        await dbmod.transition_job("s1", "RESEARCHING")
        await dbmod.transition_job("s1", "INTERRUPTED")      # process death
        row = await dbmod.transition_job("s1", "VERIFYING")  # /resume at verify
        assert row["stage"] == "VERIFYING" and row["status"] == "running"
        await dbmod.transition_job("s1", "FAILED", last_error="boom")
        row = await dbmod.transition_job("s1", "RESEARCHING", progress=0)  # /retry
        assert row["stage"] == "RESEARCHING" and row["progress"] == 0
        await dbmod.transition_job("s1", "VERIFYING")
        await dbmod.transition_job("s1", "REPORTING")
        await dbmod.transition_job("s1", "COMPLETED")
        with pytest.raises(ValueError):
            await dbmod.transition_job("s1", "RESEARCHING")  # COMPLETED frozen
    _run(run())


def test_claim_semantics(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        row = await dbmod.claim_job("s1", 1)
        assert row["stage"] == "RESEARCHING"
        assert (await dbmod.claim_job("s1", 1)) is None      # already claimed
        await dbmod.create_job("s2", 1, "t")
        await dbmod.request_cancel("s2", 1)
        assert (await dbmod.claim_job("s2", 1)) is None      # cancel-requested
        assert (await dbmod.get_job("s2"))["stage"] == "QUEUED"
        with pytest.raises(ValueError):
            await dbmod.claim_job("s3x", 1, to_stage="REPORTING")  # invalid claim stage
    _run(run())


# ---------- DB: checkpoints / heartbeat ----------

def test_checkpoint_roundtrip(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        row = await dbmod.checkpoint_job(
            "s1", progress=5, current="CVE-2026-1", total=9,
            checkpoint=json.dumps({"findings": ["x"]}),
            report=json.dumps({"r": 1}), report_status="INCONCLUSIVE")
        assert row["progress"] == 5 and row["current"] == "CVE-2026-1" and row["total"] == 9
        assert json.loads(row["checkpoint"]) == {"findings": ["x"]}
        assert json.loads(row["report"]) == {"r": 1}
        assert row["report_status"] == "INCONCLUSIVE"
        assert row["stage"] == "QUEUED"        # checkpoint never changes stage
        # partial updates leave other fields intact
        row2 = await dbmod.checkpoint_job("s1", progress=6)
        assert row2["progress"] == 6 and row2["total"] == 9 and row2["current"] == "CVE-2026-1"
        assert (await dbmod.checkpoint_job("missing", progress=1)) is None
    _run(run())


def test_heartbeat_returns_cancel_flag(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        hb = await dbmod.heartbeat_job("s1", progress=2)
        assert hb["progress"] == 2 and hb["cancel_requested"] == 0
        await dbmod.request_cancel("s1")
        hb2 = await dbmod.heartbeat_job("s1")   # runner polls the flag each beat
        assert hb2["cancel_requested"] == 1
        assert hb2["progress"] == 2             # beat did not clobber progress
        assert (await dbmod.heartbeat_job("missing")) is None
    _run(run())


# ---------- cancellation (idempotent, before/during task) ----------

def test_cancel_before_task(tmp_db):
    async def run():
        await dbmod.create_job("s1", 1, "t")
        row = await jobs.cancel("s1")
        assert row is not None
        assert (await dbmod.get_job("s1"))["stage"] == "CANCELLED"
        assert (await dbmod.get_job("s1"))["cancel_requested"] == 1
        row2 = await jobs.cancel("s1")          # idempotent
        assert row2 is not None
        assert (await dbmod.get_job("s1"))["stage"] == "CANCELLED"
        assert (await jobs.cancel("missing")) is None
    _run(run())


def test_cancel_during_task(tmp_db):
    async def run():
        jobs.configure(3)
        started = asyncio.Event()
        release = asyncio.Event()

        async def scan():
            started.set()
            await release.wait()                # blocked until cancelled
            return "done"

        task = await jobs.submit("s1", 1, "t", lambda: scan())
        await started.wait()
        assert await jobs.active("s1")
        await jobs.cancel("s1")
        with pytest.raises(asyncio.CancelledError):
            await task
        job = await dbmod.get_job("s1")
        assert job["stage"] == "CANCELLED"
        assert job["cancel_requested"] == 1
        assert not await jobs.active("s1")      # registry entry dropped
        assert await jobs.running_count() == 0
    _run(run())


def test_cancel_queued_task_behind_semaphore(tmp_db):
    async def run():
        jobs.configure(1)                       # serial: s2 waits for s1
        started = asyncio.Event()
        release = asyncio.Event()

        async def first():
            started.set()
            await release.wait()

        async def second():
            await asyncio.sleep(0)
            return "done"

        t1 = await jobs.submit("s1", 1, "t", lambda: first())
        await started.wait()                    # s1 now holds the semaphore
        t2 = await jobs.submit("s2", 1, "t", lambda: second())
        assert await jobs.active("s2")
        row = await jobs.cancel("s2")
        assert row["stage"] == "CANCELLED"      # queued -> cancelled directly
        with pytest.raises(asyncio.CancelledError):
            await t2
        release.set()
        assert await t1 is None
        assert await jobs.running_count() == 0
        assert (await dbmod.get_job("s2"))["stage"] == "CANCELLED"
    _run(run())


# ---------- submit wrapper: concurrency, fallback, cleanup ----------

def test_concurrent_independent_tasks(tmp_db):
    async def run():
        jobs.configure(3)
        active = 0
        peak = 0
        done = asyncio.Event()

        async def scan(i):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1
            if active == 0:
                done.set()
            await dbmod.transition_job(f"s{i}", "VERIFYING")
            await dbmod.transition_job(f"s{i}", "REPORTING")
            await dbmod.transition_job(f"s{i}", "COMPLETED")
            return i

        tasks = [await jobs.submit(f"s{i}", 1, f"t{i}", lambda i=i: scan(i))
                 for i in range(3)]
        results = await asyncio.gather(*tasks)
        assert results == [0, 1, 2]
        await done.wait()
        assert peak >= 2, f"expected overlap under limit 3, peak={peak}"
        for i in range(3):
            assert (await dbmod.get_job(f"s{i}"))["stage"] == "COMPLETED"
            assert not await jobs.active(f"s{i}")
        assert await jobs.running_count() == 0
    _run(run())


def test_semaphore_serializes(tmp_db):
    async def run():
        jobs.configure(1)
        in_use = 0
        overlap = 0
        counter = 0

        async def scan(i):
            nonlocal in_use, overlap, counter
            in_use += 1
            overlap = max(overlap, in_use)
            await asyncio.sleep(0.02)
            in_use -= 1
            counter += 1
            await dbmod.transition_job(f"s{i}", "VERIFYING")
            await dbmod.transition_job(f"s{i}", "REPORTING")
            await dbmod.transition_job(f"s{i}", "COMPLETED")

        tasks = [await jobs.submit(f"s{i}", 1, f"t{i}", lambda i=i: scan(i))
                 for i in range(4)]
        await asyncio.gather(*tasks)
        assert counter == 4
        assert overlap == 1, f"limit 1 must serialize, overlap={overlap}"
        assert await jobs.running_count() == 0
    _run(run())


def test_submit_terminal_fallback(tmp_db):
    async def run():
        jobs.configure(3)

        async def boom():
            raise RuntimeError("kaput")

        async def stop():
            raise asyncio.CancelledError()

        t1 = await jobs.submit("s1", 1, "t", lambda: boom())
        with pytest.raises(RuntimeError):
            await t1
        job1 = await dbmod.get_job("s1")
        assert job1["stage"] == "FAILED"
        assert "kaput" in job1["last_error"]

        t2 = await jobs.submit("s2", 1, "t", lambda: stop())
        with pytest.raises(asyncio.CancelledError):
            await t2
        assert (await dbmod.get_job("s2"))["stage"] == "CANCELLED"
        assert await jobs.running_count() == 0
    _run(run())


def test_registry_cleanup_no_leak(tmp_db):
    async def run():
        jobs.configure(3)

        async def quick():
            await asyncio.sleep(0)
            return "ok"

        tasks = [await jobs.submit(f"s{i}", 1, f"t{i}", lambda: quick())
                 for i in range(5)]
        assert 1 <= await jobs.running_count() <= 5
        await asyncio.gather(*tasks)
        await asyncio.sleep(0)                    # run done callbacks
        assert await jobs.running_count() == 0   # done-callback dropped them all
        assert not await jobs.active("s0")
        for i in range(5):
            assert (await jobs.status(f"s{i}", 1))["stage"] == "RESEARCHING"
    _run(run())


def test_submit_duplicate_scan_id(tmp_db):
    async def run():
        jobs.configure(3)

        async def quick():
            await asyncio.sleep(0)

        t = await jobs.submit("s1", 1, "t", lambda: quick())
        with pytest.raises(ValueError):
            await jobs.submit("s1", 1, "t", lambda: quick())
        await t
        assert await jobs.running_count() == 0
    _run(run())


def test_drain(tmp_db):
    async def run():
        jobs.configure(3)
        assert await jobs.drain() == 0          # nothing registered
        release = asyncio.Event()

        async def slow():
            await release.wait()

        t = await jobs.submit("s1", 1, "t", lambda: slow())
        await asyncio.sleep(0)                  # let it claim and start
        assert await jobs.drain(0.1) == 1       # still running after timeout
        await jobs.cancel("s1")
        with pytest.raises(asyncio.CancelledError):
            await t
        assert await jobs.drain(1) == 0
    _run(run())


# ---------- legacy compatibility ----------

def test_legacy_compat(tmp_db):
    async def run():
        await dbmod.save_job("s1", 1, "t", "10:00:00", "running")
        assert [j["scan_id"] for j in await dbmod.get_active_jobs(1)] == ["s1"]
        assert (await dbmod.get_job("s1"))["stage"] == "QUEUED"
        await dbmod.update_job("s1", "done")
        assert (await dbmod.get_job("s1"))["stage"] == "COMPLETED"
        assert (await dbmod.get_job("s1"))["status"] == "done"
        assert (await dbmod.get_active_jobs(1)) == []
        # interrupted flow
        await dbmod.save_job("s2", 1, "t", "10:00:01", "running")
        await dbmod.mark_all_interrupted()
        assert "s2" in [j["scan_id"] for j in await dbmod.get_interrupted_jobs(1)]
        assert (await dbmod.get_job("s2"))["stage"] == "INTERRUPTED"
        # legacy writer cannot un-freeze a CANCELLED job
        await dbmod.save_job("s3", 1, "t", "10:00:02", "running")
        await dbmod.update_job("s3", "cancelled")
        await dbmod.update_job("s3", "done")
        assert (await dbmod.get_job("s3"))["stage"] == "CANCELLED"
    _run(run())


# ---------- schema migration ----------

def test_bg_jobs_schema_migration(tmp_db):
    """A pre-upgrade DB (legacy columns only) gains the lifecycle columns and
    backfills stage from the legacy status label on init_db."""
    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row
    for col in ("stage", "progress", "current", "total", "checkpoint", "report",
                "report_status", "last_error", "cancel_requested", "updated",
                "model_detect", "model_report", "created"):
        conn.execute(f"ALTER TABLE bg_jobs DROP COLUMN {col}")
    conn.execute("INSERT INTO bg_jobs(scan_id,user_id,target,started,status) "
                 "VALUES('legacy1',1,'t','10:00:00','running')")
    conn.execute("INSERT INTO bg_jobs(scan_id,user_id,target,started,status) "
                 "VALUES('legacy2',1,'t','10:00:00','done')")
    conn.commit()
    conn.close()

    dbmod.init_db()

    row = dbmod._get_job("legacy1")
    assert row["stage"] == "QUEUED"
    assert row["progress"] == 0 and row["cancel_requested"] == 0
    assert dbmod._get_job("legacy2")["stage"] == "COMPLETED"
    # full column set present now
    cols = {r[1] for r in sqlite3.connect(tmp_db).execute("PRAGMA table_info(bg_jobs)")}
    assert {"stage", "progress", "checkpoint", "cancel_requested",
            "model_detect", "created"} <= cols

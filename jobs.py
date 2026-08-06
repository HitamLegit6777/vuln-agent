"""In-process job orchestration: process task registry, global scan semaphore,
create/register/cancel/status helpers, and shutdown drain.

The scan pipeline itself (research/verify/report stages) lives in
agent/runner.py; this module owns the lifecycle shell: persistence through
db.py, process-wide concurrency limits, cancellation of the asyncio task tree,
and cleanup of finished tasks so no task reference leaks.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional

import db

log = logging.getLogger("vuln-agent.jobs")

# process-wide ceiling for concurrent scans; configure() overrides
SEMAPHORE_LIMIT = 3

_sem: Optional[asyncio.Semaphore] = None
_sem_limit = SEMAPHORE_LIMIT
# scan_id -> asyncio.Task; finished tasks are dropped by a done-callback
_tasks: dict[str, asyncio.Task] = {}
_tasks_lock = asyncio.Lock()


def configure(max_concurrent: int) -> None:
    """Replace the global scan semaphore. Call before submitting tasks."""
    global _sem, _sem_limit
    _sem_limit = max(1, int(max_concurrent))
    _sem = asyncio.Semaphore(_sem_limit)


def _semaphore() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(_sem_limit)
    return _sem


async def submit(scan_id: str, user_id: int, target: str,
                 coro_factory: Callable[[], Awaitable],
                 *, model_detect: Optional[str] = None,
                 model_report: Optional[str] = None,
                 start_stage: str = "RESEARCHING") -> asyncio.Task:
    """Create the job row and run the scan behind the global semaphore.

    coro_factory() must be a zero-arg callable returning the runner awaitable;
    the runner drives its own stage transitions and checkpoint writes and ends
    with a COMPLETED (or FAILED) transition. This wrapper owns the QUEUED claim,
    the cancel-flag check, and the terminal fallback (CANCELLED on cancellation,
    FAILED on unexpected errors). Returns the registered asyncio.Task.
    """
    await db.create_job(scan_id, user_id, target,
                        model_detect=model_detect, model_report=model_report)

    async def _guarded() -> object:
        sem = _semaphore()
        async with sem:
            claimed = await db.claim_job(scan_id, user_id, to_stage=start_stage)
            if claimed is None:
                current = await db.get_job(scan_id)
                if current is None:
                    raise RuntimeError(f"job {scan_id} disappeared before start")
                if current.get("cancel_requested"):
                    raise asyncio.CancelledError()
                raise RuntimeError(f"job {scan_id} already claimed by another worker")
            try:
                return await coro_factory()
            except asyncio.CancelledError:
                await _mark_terminal(scan_id, "CANCELLED", "cancelled")
                raise
            except Exception as exc:  # noqa: BLE001 — any crash marks the job failed
                await _mark_terminal(scan_id, "FAILED", f"{type(exc).__name__}: {exc}")
                raise

    task = asyncio.create_task(_guarded())
    await register(scan_id, task)
    return task


async def submit_existing(scan_id: str, user_id: int,
                          coro_factory: Callable[[], Awaitable]) -> asyncio.Task:
    """Run an existing resumable job behind the same process-wide semaphore."""
    row = await db.get_job_for_user(scan_id, user_id)
    if row is None:
        raise ValueError(f"job {scan_id} not found or not owned")

    async def _guarded() -> object:
        async with _semaphore():
            try:
                return await coro_factory()
            except asyncio.CancelledError:
                await _mark_terminal(scan_id, "CANCELLED", "cancelled")
                raise
            except Exception as exc:
                await _mark_terminal(scan_id, "FAILED", f"{type(exc).__name__}: {exc}")
                raise

    task = asyncio.create_task(_guarded())
    await register(scan_id, task)
    return task


async def _mark_terminal(scan_id: str, stage: str, last_error: str) -> None:
    try:
        await db.transition_job(scan_id, stage, last_error=last_error)
    except ValueError:
        pass  # already terminal (e.g. runner marked COMPLETED before cancel landed)


async def register(scan_id: str, task: asyncio.Task) -> None:
    """Track a task by scan_id. Replaces a finished entry; raises on a live one."""
    async with _tasks_lock:
        old = _tasks.get(scan_id)
        if old is not None and not old.done():
            raise RuntimeError(f"job {scan_id} already registered")
        _tasks[scan_id] = task
        task.add_done_callback(_make_drop(scan_id))


def _make_drop(scan_id: str) -> Callable[[asyncio.Task], None]:
    def _drop(done_task: asyncio.Task) -> None:
        # single-threaded event loop: plain dict pop is atomic here
        if _tasks.get(scan_id) is done_task:
            _tasks.pop(scan_id, None)

    return _drop


async def cancel(scan_id: str, user_id: Optional[int] = None) -> Optional[dict]:
    """Request cancellation: DB flag + asyncio task-tree cancel. Idempotent.

    Returns the job row (None when missing / not owned). A queued-but-unclaimed
    job transitions straight to CANCELLED; an active job's task observes the
    flag (or the CancelledError) and marks itself CANCELLED.
    """
    row = await db.request_cancel(scan_id, user_id)
    if row is None:
        return None
    task = None
    async with _tasks_lock:
        task = _tasks.get(scan_id)
    if task is not None and not task.done():
        task.cancel()  # cancels the whole asyncio task tree (children included)
    if row.get("stage") == "QUEUED":
        try:
            row = await db.transition_job(scan_id, "CANCELLED", last_error="cancelled by user")
        except ValueError:
            row = await db.get_job(scan_id)  # raced with claim; task cancellation wins
    return row


async def status(scan_id: str, user_id: Optional[int] = None) -> Optional[dict]:
    """Persisted job row, or None. Ownership enforced when user_id is given."""
    if user_id is not None:
        return await db.get_job_for_user(scan_id, user_id)
    return await db.get_job(scan_id)


async def active(scan_id: str) -> bool:
    """True when a task is registered and still running."""
    async with _tasks_lock:
        task = _tasks.get(scan_id)
        return task is not None and not task.done()


async def running_count() -> int:
    """Number of live registered tasks (semaphore waiters included)."""
    async with _tasks_lock:
        return sum(1 for t in _tasks.values() if not t.done())


async def drain(timeout: float = 30.0) -> int:
    """Wait for registered tasks to finish; returns how many are still running.

    Call from post_shutdown so running scans get a chance to persist their
    final state before the loop closes.
    """
    async with _tasks_lock:
        pending = [t for t in _tasks.values() if not t.done()]
    if not pending:
        return 0
    _, still = await asyncio.wait(pending, timeout=timeout)
    return len(still)

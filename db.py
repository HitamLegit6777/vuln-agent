"""SQLite: scan history + vuln cache. Async via asyncio.to_thread (no extra dep).

Cache hooks (cache_get/cache_set) plug into scrapers.BaseScraper._cached.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from typing import Optional

from config import DATA

DB_PATH = str(DATA / "vuln.db")
_lock = asyncio.Lock()
_CACHE_TTL = 24 * 3600


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=30.0)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=30000")
    return c


def _init():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
          id TEXT PRIMARY KEY, user_id INTEGER, target TEXT, created TEXT,
          stack TEXT, findings TEXT, report TEXT
        );
        CREATE TABLE IF NOT EXISTS pocs(
          id TEXT PRIMARY KEY, scan_id TEXT, cve TEXT, path TEXT, created TEXT
        );
        CREATE TABLE IF NOT EXISTS cache(
          key TEXT PRIMARY KEY, value TEXT, ts REAL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
        CREATE TABLE IF NOT EXISTS settings(
          key TEXT PRIMARY KEY, value TEXT
        );
        """)


def init_db():
    _init()
    # light migrations (add columns if missing) — grounded context for chat agent
    with _conn() as c:
        cols = {r[1] for r in c.execute("PRAGMA table_info(scans)").fetchall()}
        if "grounded" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN grounded TEXT")
        if "chat" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN chat TEXT")  # persisted conversation JSON
    with _conn() as c:
        pcols = {r[1] for r in c.execute("PRAGMA table_info(pocs)").fetchall()}
        if "code" not in pcols:
            c.execute("ALTER TABLE pocs ADD COLUMN code TEXT")
        if "verdict" not in pcols:
            c.execute("ALTER TABLE pocs ADD COLUMN verdict TEXT")
        if "reason" not in pcols:
            c.execute("ALTER TABLE pocs ADD COLUMN reason TEXT")
        if "attempts" not in pcols:
            c.execute("ALTER TABLE pocs ADD COLUMN attempts INTEGER")
    # self-improvement tables
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS poc_patterns(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          cve TEXT, vuln_type TEXT, method TEXT, code TEXT,
          success_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0,
          waf_bypass TEXT, created TEXT, last_used TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_poc_patterns_cve ON poc_patterns(cve);
        CREATE TABLE IF NOT EXISTS learned_signatures(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          cms_name TEXT, signal_type TEXT, signal_value TEXT,
          evidence TEXT, hit_count INTEGER DEFAULT 0,
          created TEXT, last_seen TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_learned_sig_cms ON learned_signatures(cms_name);
        CREATE TABLE IF NOT EXISTS scan_knowledge(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          cms TEXT, version TEXT, key_findings TEXT, lessons TEXT,
          scan_id TEXT, created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_knowledge_cms ON scan_knowledge(cms);
        CREATE TABLE IF NOT EXISTS waf_bypasses(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          waf_name TEXT, cve TEXT, payload_variant TEXT, worked INTEGER,
          created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_waf_bypass_waf ON waf_bypasses(waf_name);
        CREATE TABLE IF NOT EXISTS user_feedback(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id TEXT, rating TEXT, note TEXT, created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_feedback_scan ON user_feedback(scan_id);
        CREATE TABLE IF NOT EXISTS bg_jobs(
          scan_id TEXT PRIMARY KEY, user_id INTEGER, target TEXT,
          started TEXT, status TEXT,
          stage TEXT, progress INTEGER DEFAULT 0, current TEXT, total INTEGER,
          checkpoint TEXT, report TEXT, report_status TEXT, last_error TEXT,
          cancel_requested INTEGER DEFAULT 0, updated TEXT,
          model_detect TEXT, model_report TEXT, created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_bg_jobs_user_status
          ON bg_jobs(user_id, status);
        CREATE TABLE IF NOT EXISTS sent_cves(
          cve TEXT PRIMARY KEY, sent_at TEXT, summary TEXT,
          severity TEXT, cvss REAL, rce_type TEXT, auth_type TEXT,
          affects TEXT, poc_status TEXT, dorks TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sent_cves_cve ON sent_cves(cve);
        """)
    # bg_jobs: additive columns for the job lifecycle machine (stage machine,
    # checkpoints, cancellation flag). Existing rows get their stage backfilled
    # from the legacy status label.
    with _conn() as c:
        jcols = {r[1] for r in c.execute("PRAGMA table_info(bg_jobs)").fetchall()}
        for name, ddl in {
            "stage": "TEXT",
            "progress": "INTEGER DEFAULT 0",
            "current": "TEXT",
            "total": "INTEGER",
            "checkpoint": "TEXT",
            "report": "TEXT",
            "report_status": "TEXT",
            "last_error": "TEXT",
            "cancel_requested": "INTEGER DEFAULT 0",
            "updated": "TEXT",
            "model_detect": "TEXT",
            "model_report": "TEXT",
            "created": "TEXT",
        }.items():
            if name not in jcols:
                c.execute(f"ALTER TABLE bg_jobs ADD COLUMN {name} {ddl}")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for r in c.execute("SELECT scan_id, status FROM bg_jobs WHERE stage IS NULL").fetchall():
            stage = _legacy_status_stage(r["status"])
            c.execute("UPDATE bg_jobs SET stage=?, updated=? WHERE scan_id=?",
                      (stage, now, r["scan_id"]))
    # Canonical private intelligence library owns its versioned schema separately.
    # Local import avoids a module cycle: library reuses this module's connection/lock.
    from library import init_library_sync
    init_library_sync()


# ---- scan history ----
def _save_scan(scan_id, user_id, target, stack, findings, report, grounded=""):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO scans(id,user_id,target,created,stack,findings,report,grounded) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (scan_id, user_id, target, time.strftime("%Y-%m-%d %H:%M:%S"),
             json.dumps(stack), json.dumps(findings), json.dumps(report), grounded),
        )


def _get_scan(scan_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(r) if r else None


def _get_scan_for_user(scan_id, user_id):
    with _conn() as c:
        r = c.execute(
            "SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id)).fetchone()
        return dict(r) if r else None


def _save_chat(scan_id, history):
    with _conn() as c:
        c.execute("UPDATE scans SET chat=? WHERE id=?", (json.dumps(history), scan_id))


def _get_chat(scan_id):
    with _conn() as c:
        r = c.execute("SELECT chat FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not r or not r["chat"]:
            return []
        try:
            return json.loads(r["chat"])
        except Exception:
            return []


def _list_scans(user_id, limit=10):
    with _conn() as c:
        rows = c.execute(
            "SELECT id,target,created FROM scans WHERE user_id=? ORDER BY rowid DESC LIMIT ?",
            (user_id, limit)).fetchall()
        return [dict(x) for x in rows]


async def save_scan(scan_id, user_id, target, stack, findings, report, grounded=""):
    async with _lock:
        await asyncio.to_thread(_save_scan, scan_id, user_id, target, stack, findings, report, grounded)


async def save_chat(scan_id, history):
    async with _lock:
        await asyncio.to_thread(_save_chat, scan_id, history)


async def get_chat(scan_id):
    async with _lock:
        return await asyncio.to_thread(_get_chat, scan_id)


async def get_scan(scan_id):
    async with _lock:
        return await asyncio.to_thread(_get_scan, scan_id)


async def get_scan_for_user(scan_id, user_id):
    async with _lock:
        return await asyncio.to_thread(_get_scan_for_user, scan_id, user_id)


async def list_scans(user_id, limit=10):
    async with _lock:
        return await asyncio.to_thread(_list_scans, user_id, limit)


# ---- poc ----
def _save_poc(scan_id, cve, path, code=""):
    import uuid
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO pocs(id,scan_id,cve,path,code,created) "
            "VALUES(?,?,?,?,?,?)",
            (uuid.uuid4().hex[:12], scan_id, cve, path, code,
             time.strftime("%Y-%m-%d %H:%M:%S")))


def _get_pocs(scan_id):
    with _conn() as c:
        rows = c.execute(
            "SELECT cve,path,code,created FROM pocs WHERE scan_id=? ORDER BY rowid DESC",
            (scan_id,)).fetchall()
        return [dict(x) for x in rows]


def _get_poc(scan_id, cve):
    with _conn() as c:
        r = c.execute(
            "SELECT cve,path,code,verdict,reason,attempts,created FROM pocs "
            "WHERE scan_id=? AND cve=? ORDER BY rowid DESC LIMIT 1",
            (scan_id, cve)).fetchone()
        return dict(r) if r else None


def _set_poc_verdict(scan_id, cve, verdict, reason, attempts):
    with _conn() as c:
        c.execute(
            "UPDATE pocs SET verdict=?, reason=?, attempts=? "
            "WHERE scan_id=? AND cve=?",
            (verdict, reason, attempts, scan_id, cve))


async def save_poc(scan_id, cve, path, code=""):
    async with _lock:
        await asyncio.to_thread(_save_poc, scan_id, cve, path, code)


async def get_pocs(scan_id):
    async with _lock:
        return await asyncio.to_thread(_get_pocs, scan_id)


async def get_poc(scan_id, cve):
    async with _lock:
        return await asyncio.to_thread(_get_poc, scan_id, cve)


async def set_poc_verdict(scan_id, cve, verdict, reason, attempts):
    async with _lock:
        await asyncio.to_thread(_set_poc_verdict, scan_id, cve, verdict, reason, attempts)


# ---- cache hooks for scrapers ----
def _cache_get_sync(key):
    with _conn() as c:
        r = c.execute("SELECT value,ts FROM cache WHERE key=?", (key,)).fetchone()
        if not r:
            return None
        if time.time() - r["ts"] > _CACHE_TTL:
            return None
        try:
            return json.loads(r["value"])
        except Exception:
            return None


_cache_writes = 0


def _cache_set_sync(key, value):
    global _cache_writes
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO cache(key,value,ts) VALUES(?,?,?)",
                  (key, json.dumps(value, default=str), time.time()))
        # opportunistic purge: every ~100 writes, delete expired rows so the
        # cache table can't grow unbounded over long uptime
        _cache_writes += 1
        if _cache_writes % 100 == 0:
            c.execute("DELETE FROM cache WHERE ts < ?", (time.time() - _CACHE_TTL,))


async def cache_get(key):
    async with _lock:
        return await asyncio.to_thread(_cache_get_sync, key)


async def cache_set(key, value):
    async with _lock:
        await asyncio.to_thread(_cache_set_sync, key, value)



# ---- runtime settings (e.g. active LLM models chosen via /model) ----
def _get_setting(key, default=""):
    with _conn() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default


def _set_setting(key, value):
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))


async def get_setting(key, default=""):
    async with _lock:
        return await asyncio.to_thread(_get_setting, key, default)


async def set_setting(key, value):
    async with _lock:
        await asyncio.to_thread(_set_setting, key, value)

# ============ SELF-IMPROVEMENT: PoC Pattern Learning ============

def _save_poc_pattern(cve, vuln_type, method, code, waf_bypass=""):
    with _conn() as c:
        existing = c.execute(
            "SELECT id, success_count FROM poc_patterns WHERE cve=? AND method=?",
            (cve, method)).fetchone()
        if existing:
            c.execute(
                "UPDATE poc_patterns SET success_count=success_count+1, "
                "last_used=?, code=? WHERE id=?",
                (time.strftime("%Y-%m-%d %H:%M:%S"), code, existing["id"]))
        else:
            c.execute(
                "INSERT INTO poc_patterns(cve,vuln_type,method,code,success_count,"
                "waf_bypass,created,last_used) VALUES(?,?,?,?,1,?,?,?)",
                (cve, vuln_type, method, code, waf_bypass,
                 time.strftime("%Y-%m-%d %H:%M:%S"),
                 time.strftime("%Y-%m-%d %H:%M:%S")))


def _get_poc_pattern(cve):
    with _conn() as c:
        r = c.execute(
            "SELECT * FROM poc_patterns WHERE cve=? AND success_count>0 "
            "ORDER BY success_count DESC LIMIT 1", (cve,)).fetchone()
        return dict(r) if r else None


def _get_poc_pattern_by_type(vuln_type, limit=3):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM poc_patterns WHERE vuln_type=? AND success_count>0 "
            "ORDER BY success_count DESC LIMIT ?", (vuln_type, limit)).fetchall()
        return [dict(x) for x in rows]


def _mark_poc_pattern_fail(cve, method):
    with _conn() as c:
        c.execute(
            "UPDATE poc_patterns SET fail_count=fail_count+1 WHERE cve=? AND method=?",
            (cve, method))


async def save_poc_pattern(cve, vuln_type, method, code, waf_bypass=""):
    async with _lock:
        await asyncio.to_thread(_save_poc_pattern, cve, vuln_type, method, code, waf_bypass)


async def get_poc_pattern(cve):
    async with _lock:
        return await asyncio.to_thread(_get_poc_pattern, cve)


async def get_poc_pattern_by_type(vuln_type, limit=3):
    async with _lock:
        return await asyncio.to_thread(_get_poc_pattern_by_type, vuln_type, limit)


async def mark_poc_pattern_fail(cve, method):
    async with _lock:
        await asyncio.to_thread(_mark_poc_pattern_fail, cve, method)


# ============ SELF-IMPROVEMENT: Learned Signatures ============

def _save_learned_sig(cms_name, signal_type, signal_value, evidence):
    with _conn() as c:
        existing = c.execute(
            "SELECT id FROM learned_signatures WHERE cms_name=? AND signal_type=? "
            "AND signal_value=?", (cms_name, signal_type, signal_value)).fetchone()
        if existing:
            c.execute(
                "UPDATE learned_signatures SET hit_count=hit_count+1, "
                "last_seen=? WHERE id=?",
                (time.strftime("%Y-%m-%d %H:%M:%S"), existing["id"]))
        else:
            c.execute(
                "INSERT INTO learned_signatures(cms_name,signal_type,signal_value,"
                "evidence,hit_count,created,last_seen) VALUES(?,?,?,?,1,?,?)",
                (cms_name, signal_type, signal_value, evidence,
                 time.strftime("%Y-%m-%d %H:%M:%S"),
                 time.strftime("%Y-%m-%d %H:%M:%S")))


def _get_learned_sigs():
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM learned_signatures WHERE hit_count>0 "
            "ORDER BY hit_count DESC").fetchall()
        return [dict(x) for x in rows]


async def save_learned_sig(cms_name, signal_type, signal_value, evidence):
    async with _lock:
        await asyncio.to_thread(_save_learned_sig, cms_name, signal_type, signal_value, evidence)


async def get_learned_sigs():
    async with _lock:
        return await asyncio.to_thread(_get_learned_sigs)


# ============ SELF-IMPROVEMENT: Knowledge Base ============

def _save_knowledge(cms, version, key_findings, lessons, scan_id):
    with _conn() as c:
        c.execute(
            "INSERT INTO scan_knowledge(cms,version,key_findings,lessons,scan_id,created) "
            "VALUES(?,?,?,?,?,?)",
            (cms, version, json.dumps(key_findings), lessons, scan_id,
             time.strftime("%Y-%m-%d %H:%M:%S")))


def _get_knowledge(cms, version=None, limit=5):
    with _conn() as c:
        if version:
            rows = c.execute(
                "SELECT * FROM scan_knowledge WHERE cms=? AND version=? "
                "ORDER BY rowid DESC LIMIT ?", (cms, version, limit)).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM scan_knowledge WHERE cms=? "
                "ORDER BY rowid DESC LIMIT ?", (cms, limit)).fetchall()
        return [dict(x) for x in rows]


def _get_all_knowledge(limit=20):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM scan_knowledge ORDER BY rowid DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(x) for x in rows]


async def save_knowledge(cms, version, key_findings, lessons, scan_id):
    async with _lock:
        await asyncio.to_thread(_save_knowledge, cms, version, key_findings, lessons, scan_id)


async def get_knowledge(cms, version=None, limit=5):
    async with _lock:
        return await asyncio.to_thread(_get_knowledge, cms, version, limit)


async def get_all_knowledge(limit=20):
    async with _lock:
        return await asyncio.to_thread(_get_all_knowledge, limit)


# ============ SELF-IMPROVEMENT: WAF Bypass Memory ============

def _save_waf_bypass(waf_name, cve, payload_variant, worked):
    with _conn() as c:
        c.execute(
            "INSERT INTO waf_bypasses(waf_name,cve,payload_variant,worked,created) "
            "VALUES(?,?,?,?,?)",
            (waf_name, cve, payload_variant, 1 if worked else 0,
             time.strftime("%Y-%m-%d %H:%M:%S")))


def _get_waf_bypasses(waf_name):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM waf_bypasses WHERE waf_name=? AND worked=1 "
            "ORDER BY rowid DESC LIMIT 5", (waf_name,)).fetchall()
        return [dict(x) for x in rows]


async def save_waf_bypass(waf_name, cve, payload_variant, worked):
    async with _lock:
        await asyncio.to_thread(_save_waf_bypass, waf_name, cve, payload_variant, worked)


async def get_waf_bypasses(waf_name):
    async with _lock:
        return await asyncio.to_thread(_get_waf_bypasses, waf_name)


# ============ SELF-IMPROVEMENT: User Feedback ============

def _save_feedback(scan_id, rating, note):
    with _conn() as c:
        c.execute(
            "INSERT INTO user_feedback(scan_id,rating,note,created) VALUES(?,?,?,?)",
            (scan_id, rating, note, time.strftime("%Y-%m-%d %H:%M:%S")))


def _get_feedback(scan_id):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM user_feedback WHERE scan_id=?", (scan_id,)).fetchall()
        return [dict(x) for x in rows]


async def save_feedback(scan_id, rating, note):
    async with _lock:
        await asyncio.to_thread(_save_feedback, scan_id, rating, note)


async def get_feedback(scan_id):
    async with _lock:
        return await asyncio.to_thread(_get_feedback, scan_id)


# ============ BG JOB PERSISTENCE (survive restart) ============
#
# Job lifecycle is a stage machine (JOB_STAGES). `status` mirrors the legacy
# running/done/interrupted labels bot.py already reads, so old readers keep
# working. transition_job enforces the strict stage machine; the legacy
# save_job/update_job writers stay lenient for old callers.

JOB_STAGES = ("QUEUED", "RESEARCHING", "VERIFYING", "REPORTING",
              "COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED")
_JOB_TERMINAL = ("COMPLETED", "CANCELLED")  # frozen: no outgoing transitions
_JOB_ACTIVE = ("QUEUED", "RESEARCHING", "VERIFYING", "REPORTING")

_STAGE_STATUS = {
    "QUEUED": "running", "RESEARCHING": "running", "VERIFYING": "running",
    "REPORTING": "running", "COMPLETED": "done", "FAILED": "failed",
    "CANCELLED": "cancelled", "INTERRUPTED": "interrupted",
}


def _legacy_status_stage(status):
    """Derive a stage from a legacy status label (backfill / legacy writers)."""
    return {
        "running": "QUEUED", "done": "COMPLETED", "failed": "FAILED",
        "cancelled": "CANCELLED", "interrupted": "INTERRUPTED",
    }.get(status, "QUEUED")


# strict transition table; self-transition is an idempotent re-mark
_JOB_NEXT = {
    "QUEUED": {"QUEUED", "RESEARCHING", "FAILED", "CANCELLED", "INTERRUPTED"},
    "RESEARCHING": {"RESEARCHING", "VERIFYING", "FAILED", "CANCELLED", "INTERRUPTED"},
    "VERIFYING": {"VERIFYING", "REPORTING", "FAILED", "CANCELLED", "INTERRUPTED"},
    "REPORTING": {"REPORTING", "COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"},
    "INTERRUPTED": {"INTERRUPTED", "RESEARCHING", "VERIFYING", "REPORTING",
                    "FAILED", "CANCELLED"},
    "FAILED": {"FAILED", "RESEARCHING", "CANCELLED"},
    "COMPLETED": {"COMPLETED"},
    "CANCELLED": {"CANCELLED"},
}


def job_stage_is_terminal(stage):
    return stage in _JOB_TERMINAL


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---- legacy writers (lenient, unchanged call semantics) ----

def _save_job(scan_id, user_id, target, started, status="running"):
    """Legacy create/upsert. Re-queues on conflict; preserves rowid and created."""
    stage = _legacy_status_stage(status)
    now = _now()
    with _conn() as c:
        c.execute(
            "INSERT INTO bg_jobs(scan_id,user_id,target,started,status,stage,"
            "created,updated,cancel_requested) VALUES(?,?,?,?,?,?,?,?,0) "
            "ON CONFLICT(scan_id) DO UPDATE SET user_id=excluded.user_id, "
            "target=excluded.target, started=excluded.started, status=excluded.status, "
            "stage=excluded.stage, updated=excluded.updated, progress=0, current=NULL, "
            "total=NULL, checkpoint=NULL, report=NULL, report_status=NULL, "
            "last_error=NULL, cancel_requested=0",
            (scan_id, user_id, target, started, status, stage, now, now))


def _update_job(scan_id, status):
    """Legacy status writer (lenient — no transition validation). Terminal
    (COMPLETED/CANCELLED) jobs are frozen: contradictory legacy writes are no-ops."""
    stage = _legacy_status_stage(status)
    with _conn() as c:
        if stage == "QUEUED":  # 'running' label write; never touch lifecycle stage
            c.execute("UPDATE bg_jobs SET status=?, updated=? WHERE scan_id=?",
                      (status, _now(), scan_id))
            return
        row = c.execute("SELECT stage FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            return
        cur = row["stage"] or "QUEUED"
        if cur in _JOB_TERMINAL and stage != cur:
            return
        c.execute("UPDATE bg_jobs SET status=?, stage=?, updated=? WHERE scan_id=?",
                  (status, stage, _now(), scan_id))


def _get_active_jobs(user_id):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM bg_jobs WHERE user_id=? AND status='running' "
            "ORDER BY rowid DESC", (user_id,)).fetchall()
        return [dict(x) for x in rows]


def _get_interrupted_jobs(user_id):
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM bg_jobs WHERE user_id=? AND status='interrupted' "
            "ORDER BY rowid DESC LIMIT 5", (user_id,)).fetchall()
        return [dict(x) for x in rows]


def _mark_all_interrupted():
    """On startup: any 'running' jobs from a previous process are dead → interrupted."""
    with _conn() as c:
        c.execute("UPDATE bg_jobs SET status='interrupted', stage='INTERRUPTED', "
                  "updated=? WHERE status='running'", (_now(),))


# ---- new job lifecycle API ----

def _create_job(scan_id, user_id, target, created=None,
                model_detect=None, model_report=None):
    """Insert a new QUEUED job. Raises ValueError if the id already exists."""
    now = created or _now()
    with _conn() as c:
        try:
            c.execute(
                "INSERT INTO bg_jobs(scan_id,user_id,target,started,status,stage,"
                "created,updated,model_detect,model_report,cancel_requested) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                (scan_id, user_id, target, now, "running", "QUEUED", now, now,
                 model_detect, model_report))
        except sqlite3.IntegrityError:
            raise ValueError(f"job {scan_id} already exists") from None
        row = c.execute("SELECT * FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(row)


def _get_job(scan_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(r) if r else None


def _get_job_for_user(scan_id, user_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM bg_jobs WHERE scan_id=? AND user_id=?",
                      (scan_id, user_id)).fetchone()
        return dict(r) if r else None


def _list_jobs(user_id=None, limit=20, status=None, stage=None):
    q = "SELECT * FROM bg_jobs"
    where, args = [], []
    if user_id is not None:
        where.append("user_id=?"); args.append(user_id)
    if status is not None:
        where.append("status=?"); args.append(status)
    if stage is not None:
        where.append("stage=?"); args.append(stage)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY rowid DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(x) for x in c.execute(q, args).fetchall()]


def _claim_job(scan_id, user_id, to_stage="RESEARCHING"):
    """Atomically move a QUEUED job to to_stage for its owner. Returns the row,
    or None when missing / not owned / not queued / cancel-requested."""
    if to_stage not in _JOB_NEXT["QUEUED"]:
        raise ValueError(f"invalid claim stage {to_stage!r}")
    with _conn() as c:
        cur = c.execute(
            "UPDATE bg_jobs SET stage=?, status='running', updated=? "
            "WHERE scan_id=? AND user_id=? AND stage='QUEUED' AND cancel_requested=0",
            (to_stage, _now(), scan_id, user_id))
        if cur.rowcount == 0:
            return None
        row = c.execute("SELECT * FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(row)


def _transition_job(scan_id, to_stage, *, status=None, progress=None, current=None,
                    total=None, checkpoint=None, report=None, report_status=None,
                    last_error=None, model_detect=None, model_report=None):
    """Strict stage transition. Raises ValueError on an invalid move; terminal
    stages are frozen. Extra fields are applied atomically with the transition."""
    if to_stage not in JOB_STAGES:
        raise ValueError(f"unknown job stage {to_stage!r}")
    sets = ["stage=?", "status=?", "updated=?"]
    args = [to_stage, status if status is not None else _STAGE_STATUS[to_stage], _now()]
    for col, val in (("progress", progress), ("current", current), ("total", total),
                     ("checkpoint", checkpoint), ("report", report),
                     ("report_status", report_status), ("last_error", last_error),
                     ("model_detect", model_detect), ("model_report", model_report)):
        if val is not None:
            sets.append(f"{col}=?")
            args.append(val)
    args.append(scan_id)
    with _conn() as c:
        r = c.execute("SELECT stage FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        if r is None:
            raise ValueError(f"job {scan_id} not found")
        cur = r["stage"] or "QUEUED"
        if to_stage not in _JOB_NEXT.get(cur, set()):
            raise ValueError(f"invalid job transition {cur} -> {to_stage}")
        c.execute(f"UPDATE bg_jobs SET {', '.join(sets)} WHERE scan_id=?", args)
        row = c.execute("SELECT * FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(row)


def _checkpoint_job(scan_id, *, progress=None, current=None, total=None,
                    checkpoint=None, report=None, report_status=None,
                    last_error=None):
    """Persist progress/checkpoint fields without changing stage."""
    sets, args = ["updated=?"], [_now()]
    for col, val in (("progress", progress), ("current", current), ("total", total),
                     ("checkpoint", checkpoint), ("report", report),
                     ("report_status", report_status), ("last_error", last_error)):
        if val is not None:
            sets.append(f"{col}=?")
            args.append(val)
    args.append(scan_id)
    with _conn() as c:
        c.execute(f"UPDATE bg_jobs SET {', '.join(sets)} WHERE scan_id=?", args)
        r = c.execute("SELECT * FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(r) if r else None


def _heartbeat_job(scan_id, *, progress=None, current=None, total=None):
    """Short liveness write; returns the row (incl. cancel_requested) or None."""
    return _checkpoint_job(scan_id, progress=progress, current=current, total=total)


def _request_cancel(scan_id, user_id=None):
    """Set the cancellation flag (idempotent). Returns the row, or None when the
    job is missing / not owned."""
    q = "UPDATE bg_jobs SET cancel_requested=1 WHERE scan_id=?"
    args = [scan_id]
    if user_id is not None:
        q += " AND user_id=?"
        args.append(user_id)
    with _conn() as c:
        cur = c.execute(q, args)
        if cur.rowcount == 0:
            return None
        row = c.execute("SELECT * FROM bg_jobs WHERE scan_id=?", (scan_id,)).fetchone()
        return dict(row)


# ---- async wrappers: writes serialize on _lock; reads use their own connection ----

async def create_job(scan_id, user_id, target, *, model_detect=None, model_report=None):
    async with _lock:
        return await asyncio.to_thread(_create_job, scan_id, user_id, target,
                                       None, model_detect, model_report)


async def get_job(scan_id):
    return await asyncio.to_thread(_get_job, scan_id)


async def get_job_for_user(scan_id, user_id):
    return await asyncio.to_thread(_get_job_for_user, scan_id, user_id)


async def list_jobs(user_id=None, limit=20, status=None, stage=None):
    return await asyncio.to_thread(_list_jobs, user_id, limit, status, stage)


async def claim_job(scan_id, user_id, to_stage="RESEARCHING"):
    async with _lock:
        return await asyncio.to_thread(_claim_job, scan_id, user_id, to_stage)


async def transition_job(scan_id, to_stage, **fields):
    async with _lock:
        return await asyncio.to_thread(_transition_job, scan_id, to_stage, **fields)


async def checkpoint_job(scan_id, **fields):
    async with _lock:
        return await asyncio.to_thread(_checkpoint_job, scan_id, **fields)


async def heartbeat_job(scan_id, *, progress=None, current=None, total=None):
    async with _lock:
        return await asyncio.to_thread(_heartbeat_job, scan_id,
                                       progress=progress, current=current, total=total)


async def request_cancel(scan_id, user_id=None):
    async with _lock:
        return await asyncio.to_thread(_request_cancel, scan_id, user_id)


async def save_job(scan_id, user_id, target, started, status="running"):
    async with _lock:
        await asyncio.to_thread(_save_job, scan_id, user_id, target, started, status)


async def update_job(scan_id, status):
    async with _lock:
        await asyncio.to_thread(_update_job, scan_id, status)


async def get_active_jobs(user_id):
    return await asyncio.to_thread(_get_active_jobs, user_id)


async def get_interrupted_jobs(user_id):
    return await asyncio.to_thread(_get_interrupted_jobs, user_id)


async def mark_all_interrupted():
    async with _lock:
        await asyncio.to_thread(_mark_all_interrupted)


# ============ VULN MONITOR: sent CVE tracking ============

def _is_cve_sent(cve):
    with _conn() as c:
        r = c.execute("SELECT 1 FROM sent_cves WHERE cve=?", (cve,)).fetchone()
        return r is not None


def _mark_cve_sent(cve, summary, severity, cvss, rce_type, auth_type, affects, poc_status, dorks):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO sent_cves(cve,sent_at,summary,severity,cvss,"
            "rce_type,auth_type,affects,poc_status,dorks) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (cve, time.strftime("%Y-%m-%d %H:%M:%S"), summary, severity, cvss,
             rce_type, auth_type, affects, poc_status, json.dumps(dorks)))


def _get_sent_cves(limit=100):
    with _conn() as c:
        rows = c.execute(
            "SELECT cve,sent_at,summary,severity,rce_type,auth_type FROM sent_cves "
            "ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [dict(x) for x in rows]


async def is_cve_sent(cve):
    async with _lock:
        return await asyncio.to_thread(_is_cve_sent, cve)


async def mark_cve_sent(cve, summary="", severity="", cvss=0, rce_type="",
                        auth_type="", affects="", poc_status="", dorks=None):
    async with _lock:
        await asyncio.to_thread(_mark_cve_sent, cve, summary, severity, cvss,
                                rce_type, auth_type, affects, poc_status, dorks or {})


async def get_sent_cves(limit=100):
    async with _lock:
        return await asyncio.to_thread(_get_sent_cves, limit)


# ============ SOURCE HEALTH (circuit breakers, persisted by source) ============

_SRC_HEALTH_TABLE = """
CREATE TABLE IF NOT EXISTS source_health(
  source TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'closed',
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  total_success INTEGER NOT NULL DEFAULT 0,
  total_failures INTEGER NOT NULL DEFAULT 0,
  total_timeouts INTEGER NOT NULL DEFAULT 0,
  total_rate_limited INTEGER NOT NULL DEFAULT 0,
  latency REAL NOT NULL DEFAULT 0,
  last_error TEXT,
  open_until REAL NOT NULL DEFAULT 0,
  last_success_at REAL NOT NULL DEFAULT 0,
  last_failure_at REAL NOT NULL DEFAULT 0,
  updated REAL NOT NULL DEFAULT 0
)"""

_src_health_ready = False


def _ensure_source_health_table():
    """Lazy table creation — keeps this additive section out of init_db (job region)."""
    global _src_health_ready
    if _src_health_ready:
        return
    with _conn() as c:
        c.execute(_SRC_HEALTH_TABLE)
    _src_health_ready = True


def _source_health_get_sync(source):
    _ensure_source_health_table()
    with _conn() as c:
        r = c.execute("SELECT * FROM source_health WHERE source=?", (source,)).fetchone()
        return dict(r) if r else None


def _source_health_set_sync(source, fields):
    _ensure_source_health_table()
    cols = ("state", "consecutive_failures", "total_success", "total_failures",
            "total_timeouts", "total_rate_limited", "latency", "last_error",
            "open_until", "last_success_at", "last_failure_at")
    data = {k: v for k, v in fields.items() if k in cols}
    data["updated"] = time.time()
    names = ", ".join(data)
    placeholders = ", ".join("?" * len(data))
    with _conn() as c:
        c.execute(
            f"INSERT INTO source_health(source, {names}) VALUES(?, {placeholders}) "
            "ON CONFLICT(source) DO UPDATE SET "
            + ", ".join(f"{k}=excluded.{k}" for k in data),
            (source, *data.values()))


async def source_health_get(source):
    async with _lock:
        return await asyncio.to_thread(_source_health_get_sync, source)


async def source_health_set(source, fields):
    async with _lock:
        await asyncio.to_thread(_source_health_set_sync, source, fields)


def _cache_get_stale_sync(key):
    """Cache value older than the TTL (fresh hits belong to cache_get)."""
    with _conn() as c:
        r = c.execute("SELECT value FROM cache WHERE key=? AND ts < ?",
                      (key, time.time() - _CACHE_TTL)).fetchone()
        if not r:
            return None
        try:
            return json.loads(r["value"])
        except Exception:
            return None


async def cache_get_stale(key):
    async with _lock:
        return await asyncio.to_thread(_cache_get_stale_sync, key)

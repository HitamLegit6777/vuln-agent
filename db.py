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
          started TEXT, status TEXT
        );
        CREATE TABLE IF NOT EXISTS sent_cves(
          cve TEXT PRIMARY KEY, sent_at TEXT, summary TEXT,
          severity TEXT, cvss REAL, rce_type TEXT, auth_type TEXT,
          affects TEXT, poc_status TEXT, dorks TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sent_cves_cve ON sent_cves(cve);
        """)
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

def _save_job(scan_id, user_id, target, started, status="running"):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO bg_jobs(scan_id,user_id,target,started,status) "
            "VALUES(?,?,?,?,?)", (scan_id, user_id, target, started, status))


def _update_job(scan_id, status):
    with _conn() as c:
        c.execute("UPDATE bg_jobs SET status=? WHERE scan_id=?", (status, scan_id))


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
    """On startup: any 'running' jobs from a previous process are dead → mark interrupted."""
    with _conn() as c:
        c.execute("UPDATE bg_jobs SET status='interrupted' WHERE status='running'")


async def save_job(scan_id, user_id, target, started, status="running"):
    async with _lock:
        await asyncio.to_thread(_save_job, scan_id, user_id, target, started, status)


async def update_job(scan_id, status):
    async with _lock:
        await asyncio.to_thread(_update_job, scan_id, status)


async def get_active_jobs(user_id):
    async with _lock:
        return await asyncio.to_thread(_get_active_jobs, user_id)


async def get_interrupted_jobs(user_id):
    async with _lock:
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

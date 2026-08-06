"""Remediation layer: compare owned scans, deterministic remediation plans, and
PoC-backed retests that reuse stored exploits through the existing runner.

Verdict enum (shared with the verdicts slice):
    EXPLOITABLE, NOT_REPRODUCED, NOT_APPLICABLE, INCONCLUSIVE, UNREACHABLE

Design rules:
- Ownership: every API takes user_id and refuses scans it does not own
  (PermissionError) or that do not exist (ValueError).
- compare(): deterministic diff of normalized verdicts between two owned scans.
- plan(): deterministic per-CVE plan enriched from the private library (fixed
  versions, diff_patch, references); persisted in rem_plans.
- retest(): reuses the stored PoC via agent.tools.t_run_poc_check — the same
  runner tool the verify phase uses — under a strict wall-clock timeout, and
  ADDS a row to rem_runs (never overwrites). A NOT EXPLOITABLE retest is
  reported as NOT_REPRODUCED, never "fixed"; an inconclusive/timeout retest
  stays INCONCLUSIVE; UNREACHABLE only on connection-evidence in the output.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Awaitable, Callable, Optional

import db as _db

_TS = "%Y-%m-%d %H:%M:%S"

VERDICTS = ("EXPLOITABLE", "NOT_REPRODUCED", "NOT_APPLICABLE", "INCONCLUSIVE",
            "UNREACHABLE")

# Default wall-clock cap per retest execution (t_run_poc_check itself caps at 90s
# inside the subprocess; this caps the whole call including scheduling).
RETEST_TIMEOUT = 120.0

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": 0}

# Explicit connection-level failure evidence. "timeout" is deliberately NOT here:
# a slow/filtered target is inconclusive, not proven unreachable.
_UNREACHABLE_HINTS = (
    "connection refused", "connection reset", "name or service not known",
    "getaddrinfo failed", "nodename nor servname", "network is unreachable",
    "no route to host", "could not resolve", "unable to connect",
    "connect call failed", "ssl: certificate verify failed",
    "connection timed out",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rem_plans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  scan_id TEXT NOT NULL,
  target TEXT DEFAULT '',
  plan TEXT DEFAULT '[]',
  summary TEXT DEFAULT '',
  created TEXT,
  UNIQUE(user_id, scan_id)
);
CREATE TABLE IF NOT EXISTS rem_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  scan_id TEXT NOT NULL,
  cve TEXT NOT NULL,
  target TEXT DEFAULT '',
  status TEXT DEFAULT 'completed',
  outcome TEXT DEFAULT 'INCONCLUSIVE',
  previous_verdict TEXT DEFAULT '',
  changed INTEGER DEFAULT 0,
  detail TEXT DEFAULT '',
  result TEXT DEFAULT '{}',
  started TEXT, finished TEXT, created TEXT
);
CREATE INDEX IF NOT EXISTS idx_rem_runs_scan ON rem_runs(user_id, scan_id, cve);
CREATE INDEX IF NOT EXISTS idx_rem_plans_scan ON rem_plans(user_id, scan_id);
"""


# --- schema init (local to this module, idempotent) --------------------------
def _ensure_schema_sync() -> None:
    with _db._conn() as c:
        c.executescript(_SCHEMA)


async def _ensure_schema() -> None:
    async with _db._lock:
        await asyncio.to_thread(_ensure_schema_sync)


async def init_remediation() -> None:
    """Idempotent schema init for remediation tables. Safe to call on every boot."""
    await _ensure_schema()


def init_remediation_sync() -> None:
    _ensure_schema_sync()


# --- small helpers -----------------------------------------------------------
def _now() -> str:
    import time
    return time.strftime(_TS)


def _as_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _sev_rank(sev: Any) -> int:
    return _SEV_RANK.get(str(sev or "").strip().upper(), 0)


def _norm_verdict(v: Any) -> str:
    """Map any pipeline label/verified value onto the shared 5-value enum.

    Everything unknown/unset lands on INCONCLUSIVE — never on a definitive
    bucket — so a missing verdict can never be misread as "safe" or "fixed".
    """
    s = str(v or "").strip().upper().replace("-", "_").replace(" ", "_")
    if s in ("EXPLOITABLE", "VERIFIED", "CONFIRMED"):
        return "EXPLOITABLE"
    if s in ("NOT_EXPLOITABLE", "NOT_REPRODUCED", "NOT_EXPLOITED", "SAFE",
             "PATCHED", "NOT_VERIFIED"):
        return "NOT_REPRODUCED"
    if s in ("NOT_AFFECTED", "NOT_APPLICABLE", "OUT_OF_RANGE", "NO_MATCH"):
        return "NOT_APPLICABLE"
    if s in ("UNREACHABLE", "DOWN", "OFFLINE", "UNRESOLVED"):
        return "UNREACHABLE"
    return "INCONCLUSIVE"


def _finding_verdict(f: dict) -> str:
    return _norm_verdict(f.get("verified") or f.get("verdict") or f.get("label"))


def _finding_item(f: dict) -> dict:
    """One normalized finding row: stable keys for compare/plan buckets."""
    return {
        "cve": str(f.get("cve") or "").strip().upper(),
        "verdict": _finding_verdict(f),
        "severity": str(f.get("severity") or "").strip() or "UNKNOWN",
        "cvss": _as_float(f.get("cvss")),
        "component": str(f.get("component") or "").strip(),
        "title": str(f.get("title") or "").strip(),
    }


def _sort_key(item: dict) -> tuple:
    """Deterministic plan/compare ordering: exploitable first, then severity,
    then CVSS, then CVE id (stable tiebreak)."""
    cvss = _as_float(item.get("cvss")) or 0.0
    expl = 1 if str(item.get("verdict") or "").upper() == "EXPLOITABLE" else 0
    return (-expl, -_sev_rank(item.get("severity")), -cvss,
            str(item.get("cve") or ""))


def _scan_findings(row: dict) -> list[dict]:
    """All finding dicts with a CVE id from a scans row (findings JSON)."""
    raw = row.get("findings") or "{}"
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        obj = {}
    if isinstance(obj, dict):
        vulns = obj.get("vulnerabilities") or obj.get("findings") or []
        if isinstance(vulns, dict):
            vulns = [vulns]
    elif isinstance(obj, list):
        vulns = obj
    else:
        vulns = []
    out: list[dict] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cve") or "").strip().upper()
        if cve:
            out.append(v)
    return out


# --- ownership ---------------------------------------------------------------
def _owned_scan_sync(scan_id: str, user_id: Any) -> dict:
    """Return the scan row iff it exists AND belongs to user_id."""
    row = _db._get_scan_for_user(scan_id, user_id)
    if row is None:
        if _db._get_scan(scan_id) is None:
            raise ValueError(f"scan not found: {scan_id}")
        raise PermissionError(f"scan {scan_id} not owned by user {user_id}")
    return row


# --- compare -----------------------------------------------------------------
def _drift_summary(added: list, removed: list, changed: list) -> str:
    parts = []
    if added:
        parts.append(f"{len(added)} added")
    if removed:
        parts.append(f"{len(removed)} removed")
    if changed:
        parts.append(f"{len(changed)} changed")
    return ", ".join(parts) or "no change"


def _compare_sync(user_id: Any, old: str, new: str) -> dict:
    old_row = _owned_scan_sync(old, user_id)
    new_row = _owned_scan_sync(new, user_id)
    old_map = {f["cve"]: _finding_item(f) for f in _scan_findings(old_row)}
    new_map = {f["cve"]: _finding_item(f) for f in _scan_findings(new_row)}
    added = [new_map[c] for c in sorted(set(new_map) - set(old_map))]
    removed = [old_map[c] for c in sorted(set(old_map) - set(new_map))]
    changed: list[dict] = []
    unchanged: list[dict] = []
    for c in sorted(set(old_map) & set(new_map)):
        o, n = old_map[c], new_map[c]
        if o["verdict"] != n["verdict"]:
            changed.append({**n, "old_verdict": o["verdict"],
                            "new_verdict": n["verdict"]})
        else:
            unchanged.append(n)
    added.sort(key=_sort_key)
    removed.sort(key=_sort_key)
    changed.sort(key=_sort_key)
    unchanged.sort(key=_sort_key)
    return {"old": old, "new": new, "added": added, "removed": removed,
            "changed": changed, "unchanged": unchanged,
            "summary": _drift_summary(added, removed, changed)}


async def compare(user_id: Any, old: str, new: str) -> dict:
    """Compare two scans owned by user_id. Verdict-normalized, deterministic."""
    await _ensure_schema()
    async with _db._lock:
        return await asyncio.to_thread(_compare_sync, user_id, old, new)


# --- plan --------------------------------------------------------------------
def _action_for(item: dict) -> str:
    verdict = str(item.get("verdict") or "").upper()
    fixed = item.get("fixed_versions") or []
    component = item.get("component") or "affected component"
    if verdict == "EXPLOITABLE":
        if fixed:
            return f"Upgrade {component} to {sorted(fixed)[-1]} (or apply vendor patch)"
        return "Apply vendor patch/update (no fixed version recorded)"
    if verdict == "NOT_REPRODUCED":
        return "Not reproduced on target — verify manually and re-test after any change"
    if verdict == "NOT_APPLICABLE":
        return "No action — component/version not affected"
    if verdict == "UNREACHABLE":
        return "Target unreachable — re-scan when reachable"
    return "Investigate — verdict inconclusive; re-scan or re-test"


def _plan_sync(user_id: Any, scan_id: str) -> dict:
    row = _owned_scan_sync(scan_id, user_id)
    target = str(row.get("target") or "")
    items: list[dict] = []
    for f in _scan_findings(row):
        item = _finding_item(f)
        item.setdefault("summary", "")
        item["fixed_versions"] = []
        item["diff_patch"] = ""
        item["references"] = []
        try:
            from library import _get_vuln_sync
            lib = _get_vuln_sync(item["cve"])
        except Exception:
            lib = None
        if lib:
            affected = lib.get("affected") or []
            fixed = sorted({str(a.get("fixed") or "").strip()
                            for a in affected if a.get("fixed")})
            refs = [lib["url"]] if lib.get("url") else []
            refs += [str(r) for r in (lib.get("poc_refs") or [])]
            item["fixed_versions"] = fixed
            item["diff_patch"] = lib.get("diff_patch") or ""
            item["references"] = sorted({r for r in refs if r})
            if not item["title"]:
                item["title"] = lib.get("title") or ""
            if item["severity"] == "UNKNOWN":
                item["severity"] = lib.get("severity") or "UNKNOWN"
            if item["cvss"] is None:
                item["cvss"] = lib.get("cvss")
            if not item["component"]:
                products = sorted({str(a.get("product") or "").strip()
                                   for a in affected if a.get("product")})
                item["component"] = products[0] if products else ""
            if not item["summary"]:
                item["summary"] = (lib.get("summary") or "")[:200]
        item["action"] = _action_for(item)
        items.append(item)
    items.sort(key=_sort_key)
    n_expl = sum(1 for i in items
                 if str(i.get("verdict") or "").upper() == "EXPLOITABLE")
    summary = (f"{len(items)} items ({n_expl} exploitable)" if items
               else "no actionable findings")
    now = _now()
    with _db._conn() as c:
        c.execute(
            "INSERT INTO rem_plans(user_id, scan_id, target, plan, summary, created)"
            " VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(user_id, scan_id) DO UPDATE SET plan=excluded.plan,"
            " summary=excluded.summary, target=excluded.target, created=excluded.created",
            (int(user_id) if user_id not in (None, "") else 0, scan_id, target,
             json.dumps(items, ensure_ascii=False), summary, now))
    return {"scan_id": scan_id, "target": target, "created": now,
            "summary": summary, "plan": items}


async def plan(user_id: Any, scan_id: str) -> dict:
    """Deterministic remediation plan for an owned scan, enriched from the
    private library and persisted in rem_plans."""
    await _ensure_schema()
    async with _db._lock:
        return await asyncio.to_thread(_plan_sync, user_id, scan_id)


# --- retest ------------------------------------------------------------------
def _parse_check_output(raw: Any) -> tuple[str, str]:
    """Parse t_run_poc_check output → (outcome, detail).

    [EXPLOITABLE]/[NOT EXPLOITABLE] markers are direct execution evidence and
    win over any ambient error text. A timeout maps to INCONCLUSIVE (no
    evidence the target is either safe or unreachable). Connection failures
    map to UNREACHABLE. Everything else is INCONCLUSIVE — the default must
    never be a definitive bucket ("no false fixed claim").
    """
    out = raw
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                out = obj.get("output") or ""
        except Exception:
            pass
    elif isinstance(raw, dict):
        out = raw.get("output") or ""
    text = str(out or "")
    m = re.search(r"\[EXPLOITABLE\]\s*(.+?)(?:\n|$)", text, re.I)
    if m:
        return "EXPLOITABLE", m.group(1).strip()[:300]
    m = re.search(r"\[NOT EXPLOITABLE\]\s*(.+?)(?:\n|$)", text, re.I)
    if m:
        return "NOT_REPRODUCED", m.group(1).strip()[:300]
    low = text.lower()
    if "timeout" in low or "timed out" in low:
        return "INCONCLUSIVE", (f"retest timeout: {text[:200]}" if text
                                else "retest produced no output")
    for hint in _UNREACHABLE_HINTS:
        if hint in low:
            return "UNREACHABLE", text[:200]
    return "INCONCLUSIVE", (text[:200] or "no verdict produced by PoC")


def _save_run_sync(user_id: Any, scan_id: str, cve: str, target: str,
                   status: str, outcome: str, previous_verdict: str,
                   changed: bool, detail: str, result: dict, started: str) -> None:
    now = _now()
    with _db._conn() as c:
        c.execute(
            "INSERT INTO rem_runs(user_id, scan_id, cve, target, status, outcome,"
            " previous_verdict, changed, detail, result, started, finished, created)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (int(user_id) if user_id not in (None, "") else 0, scan_id, cve,
             target, status, outcome, previous_verdict, 1 if changed else 0,
             detail[:4000], json.dumps(result, ensure_ascii=False), started,
             now, now))


async def _retest_one(user_id: Any, scan_id: str, cve: str, target: str,
                      started: str) -> dict:
    """Retest one CVE with its stored PoC. Returns the run dict (persisted)."""
    cve = str(cve or "").strip().upper()
    prev_poc = await _db.get_poc(scan_id, cve)
    previous_verdict = _norm_verdict((prev_poc or {}).get("verdict")) \
        if prev_poc else "INCONCLUSIVE"
    run = {"cve": cve, "previous_verdict": previous_verdict, "outcome": "INCONCLUSIVE",
           "status": "failed", "detail": "", "started": started, "finished": "",
           "fixed": False}
    if not prev_poc or not prev_poc.get("path"):
        run["detail"] = "no stored PoC for retest (generate one via /poc first)"
        run["outcome"] = "INCONCLUSIVE"
        run["changed"] = previous_verdict != "INCONCLUSIVE"
        run["finished"] = _now()
        _save_run_sync(user_id, scan_id, cve, target, run["status"],
                       run["outcome"], previous_verdict, run["changed"],
                       run["detail"], run, run["started"])
        return run
    try:
        from agent.tools import t_run_poc_check
        res = await asyncio.wait_for(t_run_poc_check(scan_id, cve, target),
                                     timeout=RETEST_TIMEOUT)
    except asyncio.TimeoutError:
        run["status"] = "timeout"
        run["outcome"] = "INCONCLUSIVE"
        run["detail"] = f"retest exceeded {RETEST_TIMEOUT:.0f}s wall-clock cap"
    except asyncio.CancelledError:
        raise
    except Exception as e:
        run["status"] = "failed"
        run["outcome"] = "INCONCLUSIVE"
        run["detail"] = f"{type(e).__name__}: {e}"
    else:
        run["outcome"], run["detail"] = _parse_check_output(res)
        run["status"] = "timeout" if run["outcome"] == "INCONCLUSIVE" and \
            "timeout" in (run["detail"] or "").lower() else "completed"
        if run["outcome"] == "NOT_REPRODUCED":
            run["detail"] = (run["detail"] or "not reproduced") + \
                " (not reproduced ≠ fixed — do not treat as patched without vendor confirmation)"
    run["changed"] = previous_verdict != run["outcome"]
    run["finished"] = _now()
    _save_run_sync(user_id, scan_id, cve, target, run["status"], run["outcome"],
                   previous_verdict, run["changed"], run["detail"], run,
                   run["started"])
    return run


async def retest(user_id: Any, scan_id: str, cve: Optional[str] = None,
                 progress: Optional[Callable[[int, int, str], Awaitable]] = None
                 ) -> dict:
    """Re-run stored PoCs against the scan target with a strict timeout.

    Additive: each CVE gets a NEW row in rem_runs; nothing is overwritten.
    - cve=None → retest every CVE in the scan that has a stored PoC.
    - cve given → retest that one (reports "no stored PoC" if absent).
    progress(done, total, message) is awaited after each CVE finishes.
    """
    await _ensure_schema()
    async with _db._lock:
        row = await asyncio.to_thread(_owned_scan_sync, scan_id, user_id)
    target = str(row.get("target") or "")
    if cve:
        cves = [str(cve).strip().upper()]
    else:
        have = await _db.get_pocs(scan_id)
        have_cves = {str(p.get("cve") or "").strip().upper() for p in have}
        cves = sorted({f["cve"] for f in _scan_findings(row)} & have_cves)
    runs: list[dict] = []
    total = len(cves)
    for i, c in enumerate(cves, start=1):
        started = _now()
        run = await _retest_one(user_id, scan_id, c, target, started)
        runs.append(run)
        if progress:
            try:
                await progress(i, total, f"retest {c}: {run['outcome']}")
            except Exception:
                pass
    return {"scan_id": scan_id, "target": target, "runs": runs}


__all__ = ["init_remediation", "init_remediation_sync", "compare", "plan",
           "retest", "VERDICTS"]

"""Security-intelligence library: canonical vulns, provenance, evidence, drift, notes.

Owns the `lib_*` schema (facts / provenance / observations / user notes stay in
separate tables) plus deterministic conceptual search (FTS5 with LIKE fallback),
JSONL idempotent export/import, atomic backup, integrity verification and an
external-source refresh queue driven by the existing scrapers.

Async API mirrors db.py: every public function is async, serializes on the
process-wide `db._lock`, and runs the sync core in `asyncio.to_thread`.
Importing this module has zero side effects (no DB touch, no network).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import time
import math
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit


def _target_key(target: Any) -> str:
    value = str(target or "").strip()[:512]
    if not value:
        return "?"
    parsed = urlsplit(value if "://" in value else "//" + value)
    host = (parsed.hostname or value).lower().rstrip(".")
    port = parsed.port
    return f"{host}:{port}" if port else host

import db as _db
from scrapers.registry import build_scrapers, get_all

_TS = "%Y-%m-%d %H:%M:%S"
_REFRESH_TTL = 7 * 86400          # refresh_due() interval
_REFRESH_DAYS = 7
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.I)

# --- redaction (obvious auth/cookie/token secrets) -------------------------
_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|authorization|auth|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|secret|token|bearer|cookie|session|"
    r"set-cookie|x-api[_-]?key)"
)
_TOK_IN_STR = re.compile(
    r"(?i)\b(authorization|set-cookie|cookie|x-api[_-]?key|api[_-]?key|"
    r"access[_-]?key|token|password|passwd|secret|bearer)\s*[:=]\s*[^\s,;&\"']+"
)
_BEARER = re.compile(r"(?i)\b(bearer)\s+[a-z0-9._~+/=-]{8,}")


def _redact(value: Any, depth: int = 0) -> Any:
    """Recursively replace obvious secrets with [REDACTED]. Idempotent."""
    if depth > 12 or value is None:
        return value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k) and v not in (None, ""):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact(v, depth + 1)
        return out
    if isinstance(value, list):
        return [_redact(x, depth + 1) for x in value]
    if isinstance(value, str):
        s = _BEARER.sub(r"\1 [REDACTED]", value)
        return _TOK_IN_STR.sub(lambda m: f"{m.group(1)}=[REDACTED]", s)
    return value


# --- connection helpers (process-wide db lock held by callers) -------------
@contextmanager
def _tx():
    c = _db._conn()
    try:
        with c:  # commit on success, rollback on error
            yield c
    finally:
        c.close()


@contextmanager
def _ro():
    c = _db._conn()
    try:
        yield c
    finally:
        c.close()


def _now() -> str:
    return time.strftime(_TS)


def _src_joiner(rows) -> list[str]:
    out = []
    for r in rows:
        for s in (r or "").split("|"):
            if s and s not in out:
                out.append(s)
    return out


# --- normalization ----------------------------------------------------------
_STOP = {
    "a", "an", "the", "and", "or", "of", "in", "on", "at", "to", "for", "with",
    "via", "by", "from", "into", "against", "between", "under", "over", "is",
    "are", "was", "were", "be", "been", "it", "its", "this", "that", "as",
    "not", "no", "do", "does", "did", "has", "have", "had", "but", "if", "then",
    "than", "so", "such", "only", "own", "same", "too", "very", "can", "will",
}


def _stem(w: str) -> str:
    if len(w) > 5 and w.endswith("ies") and not w.endswith("eies"):
        return w[:-3] + "y"
    if len(w) > 4 and w.endswith("ing"):
        return w[:-3]
    if len(w) > 4 and w.endswith("ed"):
        return w[:-2]
    if len(w) > 4 and w.endswith("es"):
        return w[:-2]
    if len(w) > 3 and w.endswith("s"):
        return w[:-1]
    return w


def _tokens(text: str) -> list[str]:
    out = []
    for t in re.findall(r"[a-z0-9][a-z0-9.\-+_]*", (text or "").lower()):
        t = _stem(t)
        if len(t) >= 2 and t not in _STOP:
            out.append(t)
    return out


def _concepts(title: str, description: str, products: list[str]) -> dict:
    return {
        "title": _tokens(title),
        "product": _tokens(" ".join(products)),
        "desc": _tokens(description or ""),
    }


def _as_float(x) -> Optional[float]:
    try:
        if x is None or x == "":
            return None
        return float(x)
    except (TypeError, ValueError):
        return None


def _norm_sev(v) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    up = s.upper()
    if up in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO", "NONE",
              "UNKNOWN", "MAJOR", "MINOR"):
        return up
    return s[:64]


def _norm_affected(affected: Any) -> list[dict]:
    """Accept AffectedRange dataclasses, dicts, or loose 'product:min..max'."""
    out = []
    if isinstance(affected, str):
        affected = [affected]
    if not isinstance(affected, (list, tuple, set)):
        return []
    for a in affected or []:
        if a is None:
            continue
        if not isinstance(a, dict):
            if hasattr(a, "__dataclass_fields__"):
                try:
                    a = {k: getattr(a, k) for k in a.__dataclass_fields__}
                except Exception:
                    continue
            else:
                s = str(a).strip()
                m = re.match(r"^([^:]+):\s*(.+)$", s)
                if m:
                    a = {"product": m.group(1).strip(), "min_inclusive": None,
                         "max_inclusive": m.group(2).strip()}
                else:
                    a = {"product": s}
        d = {
            "product": str(a.get("product", "") or "")[:256],
            "ecosystem": str(a.get("ecosystem", "") or "")[:64],
            "min_inclusive": a.get("min_inclusive") or None,
            "max_inclusive": a.get("max_inclusive") or None,
            "max_exclusive": a.get("max_exclusive") or None,
            "fixed": a.get("fixed") or None,
        }
        for k in ("min_inclusive", "max_inclusive", "max_exclusive", "fixed"):
            if d[k] is not None:
                d[k] = str(d[k])[:64]
        if d["product"]:
            out.append(d)
    return out


def _norm_refs(v: Any) -> list[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, (list, tuple, set)):
        return []
    out = []
    for r in v or []:
        if isinstance(r, dict):
            r = r.get("url") or r.get("link") or r.get("href") or ""
        s = str(r or "").strip()
        if s.startswith(("http://", "https://")) and s not in out:
            out.append(s)
    return out[:64]


def _norm_record(record: Any) -> dict:
    """Defensively normalize VulnRecord/scraper/monitor/scan-finding-like input."""
    if record is None:
        record = {}
    if not isinstance(record, dict):
        if hasattr(record, "to_dict") and callable(getattr(record, "to_dict")):
            try:
                record = record.to_dict()
            except Exception:
                record = {}
        else:
            try:  # dataclass
                from dataclasses import asdict
                record = asdict(record)
            except Exception:
                record = {}
    if not isinstance(record, dict):
        record = {}

    def get(*keys, d=""):
        for k in keys:
            v = record.get(k)
            if v not in (None, ""):
                return v
        return d

    cve = str(get("cve", "id") or "").strip().upper()
    sid = str(get("id", "cve") or "").strip()
    if not cve and sid and not _CVE_RE.match(sid):
        cve = sid.upper()
    raw = record.get("raw")
    if not isinstance(raw, dict):
        raw = {}
    title = str(get("title", "name") or "")[:512]
    description = str(get("description") or "")[:20000]
    summary = str(get("summary") or "")[:2048]
    if not summary and description:
        summary = description[:2048]
    if not title and description:
        title = description[:256]
    if not cve:
        seed = "|".join((title, description, str(record.get("url", ""))[:256]))
        cve = "ADV-" + hashlib.sha1(seed.encode("utf-8", "ignore")).hexdigest()[:12].upper()
    return {
        "canonical_id": cve,
        "cve": cve if _CVE_RE.match(cve) or _GHSA_RE.match(cve) else "",
        "id": sid if sid and sid != cve else "",
        "source": str(get("source", "source_name", "vendor") or "")[:64],
        "title": title,
        "summary": summary,
        "description": description,
        "severity": _norm_sev(get("severity")),
        "cvss": _as_float(get("cvss", "cvss_score", "base_score")),
        "published": str(get("published", "publish_date", "date", "disclosed") or "")[:64],
        "url": str(get("url", "link", "source_url", "advisory") or "")[:512],
        "poc_refs": _norm_refs(get("poc_refs", "exploit_refs", "references")),
        "diff_patch": str(get("diff_patch", "patch", "patch_url") or "")[:4096],
        "affected": _norm_affected(get("affected", "ranges", "products")),
        "raw": raw,
    }


def _kind_for(d: dict) -> str:
    if _CVE_RE.match(d["canonical_id"]) or _GHSA_RE.match(d["canonical_id"]):
        return "cve"
    if d["id"]:
        return "advisory"
    return "generic"


def _exploitable_hint(d: dict, redacted: Any) -> bool:
    if d["poc_refs"]:
        return True
    if isinstance(redacted, dict):
        if redacted.get("exploit_source"):
            return True
        for k in ("kev", "cisa_kev", "in_cisa_kev", "in_kev"):
            if redacted.get(k):
                return True
    return False


def _merge_raw(a: dict, b: dict) -> dict:
    """Merge raw dicts: extend list keys, fill missing scalars (like registry)."""
    out = dict(a or {})
    for k, v in (b or {}).items():
        if isinstance(v, list):
            cur = out.get(k)
            if isinstance(cur, list):
                merged = list(dict.fromkeys(cur + v))
                out[k] = merged
            else:
                out[k] = list(v)
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            merged = dict(out[k])
            merged.update({kk: vv for kk, vv in v.items() if kk not in merged})
            out[k] = merged
        elif k not in out and v is not None:
            out[k] = v
    return out


def _field_eq(a: Any, b: Any) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        try:
            return abs(float(a) - float(b)) < 1e-9
        except (TypeError, ValueError):
            return str(a) == str(b)
    return str(a) == str(b)


def _synth_conflict_source(existing: sqlite3.Row) -> str:
    return ""  # first-seen provenance retained; conflicts record the observer


# --- ingest core ------------------------------------------------------------
def _source_exists_sync(c: sqlite3.Connection, entity_id: str, source_name: str) -> bool:
    r = c.execute("SELECT 1 FROM lib_sources WHERE entity_id=? AND source_name=?",
                  (entity_id, source_name)).fetchone()
    return r is not None


def _reindex_row(c: sqlite3.Connection, entity_id: str) -> None:
    row = c.execute("SELECT * FROM lib_canonical WHERE id=?", (entity_id,)).fetchone()
    if not row:
        return
    prods = [r["product"] for r in c.execute(
        "SELECT DISTINCT product FROM lib_products WHERE entity_id=? AND product<>''",
        (entity_id,)).fetchall()]
    concepts = _concepts(row["title"] or "", row["description"] or "", prods)
    search_text = " ".join(x for x in
                           [row["id"], row["title"], row["summary"], row["description"]] + prods
                           if x)
    c.execute("UPDATE lib_canonical SET concepts=?, search_text=? WHERE id=?",
              (json.dumps(concepts), search_text[:40000], entity_id))
    if _FTS:
        c.execute("DELETE FROM lib_fts WHERE canonical_id=?", (entity_id,))
        c.execute(
            "INSERT INTO lib_fts(canonical_id, title, description, products, concepts, search_text)"
            " VALUES(?,?,?,?,?,?)",
            (entity_id, row["title"] or "", row["description"] or "", " ".join(prods),
             " ".join(concepts["title"] + concepts["product"] + concepts["desc"]),
             search_text[:40000]))


def _ingest_vuln_in_txn(c: sqlite3.Connection, record: Any, source_name: str = "",
                        source_url: str = "", raw: Any = None, inference: Any = None,
                        kind: Optional[str] = None, suppress_evidence: bool = False) -> dict:
    """Core upsert. Caller holds an open transaction (and the process lock)."""
    d = _norm_record(record)
    entity_id = d["canonical_id"]
    now = _now()
    source_name = (str(source_name).strip() or d["source"] or "unknown")[:64]
    source_url = (str(source_url or "").strip() or d["url"])[:512]
    redacted = _redact(raw if raw is not None else d["raw"])

    existed = _source_exists_sync(c, entity_id, source_name)
    row = c.execute("SELECT * FROM lib_canonical WHERE id=?", (entity_id,)).fetchone()
    created = False
    changed = False
    conflicts: list[dict] = []

    if row is None:
        created = True
        changed = True
        c.execute(
            "INSERT INTO lib_canonical(id, kind, title, summary, description, severity, cvss,"
            " published, url, poc_refs, diff_patch, raw, concepts, search_text, exploitable,"
            " inference, created, updated, last_refreshed)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (entity_id, kind or _kind_for(d), d["title"], d["summary"], d["description"],
             d["severity"], d["cvss"], d["published"], d["url"],
             json.dumps(d["poc_refs"]), d["diff_patch"], json.dumps(redacted), "{}", "",
             int(_exploitable_hint(d, redacted)), json.dumps(_redact(inference or {})), now, now))
    else:
        upd: dict[str, Any] = {}
        for field, val in (("title", d["title"]), ("summary", d["summary"]),
                           ("description", d["description"]), ("severity", d["severity"]),
                           ("published", d["published"]), ("url", d["url"]),
                           ("diff_patch", d["diff_patch"])):
            cur = row[field] or ""
            if val and not cur:
                upd[field] = val
            elif val and cur and not _field_eq(val, cur):
                conflicts.append({"source": source_name, "field": field, "observed": val})
        if d["cvss"] is not None:
            cur = row["cvss"]
            if cur is None:
                upd["cvss"] = d["cvss"]
            elif not _field_eq(cur, d["cvss"]):
                conflicts.append({"source": source_name, "field": "cvss",
                                  "observed": d["cvss"]})
        cur_refs = json.loads(row["poc_refs"] or "[]")
        merged_refs = list(dict.fromkeys(cur_refs + d["poc_refs"]))
        if merged_refs != cur_refs:
            upd["poc_refs"] = json.dumps(merged_refs)
        cur_raw = json.loads(row["raw"] or "{}")
        new_raw = _merge_raw(cur_raw, redacted)
        if new_raw != cur_raw:
            upd["raw"] = json.dumps(new_raw)
        if _exploitable_hint(d, redacted) and not row["exploitable"]:
            upd["exploitable"] = 1
        if upd:
            changed = True
            pairs = ", ".join(f"{k}=?" for k in upd)
            c.execute(f"UPDATE lib_canonical SET {pairs}, updated=? WHERE id=?",
                      (*upd.values(), now, entity_id))

    if existed:
        c.execute("UPDATE lib_sources SET source_url=?, raw=?, imported_at=?"
                  " WHERE entity_id=? AND source_name=?",
                  (source_url, json.dumps(redacted), now, entity_id, source_name))
    else:
        c.execute("INSERT INTO lib_sources(entity_id, source_name, source_url, raw, imported_at)"
                  " VALUES(?,?,?,?,?)",
                  (entity_id, source_name, source_url, json.dumps(redacted), now))

    # provenance observation — one per ingest (suppressed during JSONL import:
    # the exported evidence lines carry the original rows)
    if not suppress_evidence:
        c.execute(
            "INSERT INTO lib_evidence(entity_id, kind, summary, detail, source_name, source_url,"
            " user_id, tags, created) VALUES(?,?,?,?,?,?,?,?,?)",
            (entity_id, "source", (d["title"] or d["description"] or "")[:300], "",
             source_name, source_url, None, "[]", now))

    # products: per-source replace
    c.execute("DELETE FROM lib_products WHERE entity_id=? AND source_name=?",
              (entity_id, source_name))
    for a in d["affected"]:
        c.execute(
            "INSERT INTO lib_products(entity_id, source_name, product, ecosystem,"
            " min_inclusive, max_inclusive, max_exclusive, fixed) VALUES(?,?,?,?,?,?,?,?)",
            (entity_id, source_name, a["product"], a["ecosystem"], a["min_inclusive"],
             a["max_inclusive"], a["max_exclusive"], a["fixed"]))

    if created or changed:
        _reindex_row(c, entity_id)

    new_conflicts = []
    for cf in conflicts:
        duplicate = c.execute(
            "SELECT 1 FROM lib_conflicts WHERE entity_id=? AND field=? AND source_name=? "
            "AND observed=? AND resolved=0", (entity_id, cf["field"], cf["source"],
                                              str(cf["observed"]))).fetchone()
        if duplicate:
            continue
        c.execute(
            "INSERT INTO lib_conflicts(entity_id, field, source_name, observed, kept,"
            " resolved, created) VALUES(?,?,?,?,?,0,?)",
            (entity_id, cf["field"], cf["source"], str(cf["observed"]),
             str(row[cf["field"]] if row else "")[:1024], now))
        new_conflicts.append(cf)

    if inference is not None:
        inf = _redact(inference)
        if not suppress_evidence:
            c.execute(
                "INSERT INTO lib_evidence(entity_id, kind, summary, detail, source_name,"
                " source_url, user_id, tags, created) VALUES(?,?,?,?,?,?,?,?,?)",
                (entity_id, "inference", "AI inference",
                 json.dumps(inf, ensure_ascii=False)[:4000], source_name, source_url, None,
                 "[]", now))
        c.execute("UPDATE lib_canonical SET inference=?, updated=? WHERE id=?",
                  (json.dumps(inf, ensure_ascii=False), now, entity_id))
        changed = True

    return {"canonical_id": entity_id, "created": created, "updated": changed,
            "sources": _source_names(c, entity_id), "conflicts": new_conflicts}


def _ingest_vuln_sync(record: Any, source_name: str = "", source_url: str = "",
                      raw: Any = None, inference: Any = None,
                      kind: Optional[str] = None, suppress_evidence: bool = False) -> dict:
    with _tx() as c:
        return _ingest_vuln_in_txn(c, record, source_name, source_url, raw, inference,
                                   kind, suppress_evidence)


def _source_names(c: sqlite3.Connection, entity_id: str) -> list[str]:
    return [r["source_name"] for r in c.execute(
        "SELECT source_name FROM lib_sources WHERE entity_id=? ORDER BY id", (entity_id,))]


def _canonical_dict(c: sqlite3.Connection, row: sqlite3.Row) -> dict:
    cid = row["id"]
    sources = [s["source_name"] for s in c.execute(
        "SELECT source_name FROM lib_sources WHERE entity_id=? ORDER BY id", (cid,)).fetchall()]
    affected: list[dict] = []
    seen = set()
    for r in c.execute("SELECT product, ecosystem, min_inclusive, max_inclusive, max_exclusive,"
                       " fixed FROM lib_products WHERE entity_id=? ORDER BY id", (cid,)).fetchall():
        key = (r["product"], r["ecosystem"], r["min_inclusive"], r["max_inclusive"],
               r["max_exclusive"], r["fixed"])
        if key in seen:
            continue
        seen.add(key)
        affected.append({"product": r["product"], "ecosystem": r["ecosystem"],
                         "min_inclusive": r["min_inclusive"], "max_inclusive": r["max_inclusive"],
                         "max_exclusive": r["max_exclusive"], "fixed": r["fixed"]})
    ec = c.execute("SELECT COUNT(*) FROM lib_evidence WHERE entity_id=?", (cid,)).fetchone()[0]
    return {
        "canonical_id": cid,
        "title": row["title"],
        "summary": row["summary"],
        "description": row["description"],
        "severity": row["severity"],
        "cvss": row["cvss"],
        "published": row["published"],
        "sources": sources,
        "affected": affected,
        "poc_refs": json.loads(row["poc_refs"] or "[]"),
        "diff_patch": row["diff_patch"],
        "url": row["url"],
        "raw": json.loads(row["raw"] or "{}"),
        "created": row["created"],
        "updated": row["updated"],
        "evidence_count": ec,
    }


# --- schema -----------------------------------------------------------------
def init_library_sync() -> None:
    global _FTS
    with _tx() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS lib_canonical(
          id TEXT PRIMARY KEY,
          kind TEXT DEFAULT 'advisory',
          title TEXT DEFAULT '',
          summary TEXT DEFAULT '',
          description TEXT DEFAULT '',
          severity TEXT DEFAULT '',
          cvss REAL,
          published TEXT DEFAULT '',
          url TEXT DEFAULT '',
          poc_refs TEXT DEFAULT '[]',
          diff_patch TEXT DEFAULT '',
          raw TEXT DEFAULT '{}',
          concepts TEXT DEFAULT '{}',
          search_text TEXT DEFAULT '',
          exploitable INTEGER DEFAULT 0,
          inference TEXT DEFAULT '',
          created TEXT, updated TEXT, last_refreshed TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lib_canonical_sev ON lib_canonical(severity);
        CREATE INDEX IF NOT EXISTS idx_lib_canonical_upd ON lib_canonical(updated);
        CREATE INDEX IF NOT EXISTS idx_lib_canonical_expl ON lib_canonical(exploitable);

        CREATE TABLE IF NOT EXISTS lib_sources(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entity_id TEXT NOT NULL,
          source_name TEXT NOT NULL,
          source_url TEXT DEFAULT '',
          raw TEXT DEFAULT '{}',
          imported_at TEXT,
          UNIQUE(entity_id, source_name)
        );
        CREATE INDEX IF NOT EXISTS idx_lib_sources_entity ON lib_sources(entity_id);

        CREATE TABLE IF NOT EXISTS lib_products(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entity_id TEXT NOT NULL,
          source_name TEXT DEFAULT '',
          product TEXT DEFAULT '',
          ecosystem TEXT DEFAULT '',
          min_inclusive TEXT, max_inclusive TEXT, max_exclusive TEXT, fixed TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lib_products_entity ON lib_products(entity_id);
        CREATE INDEX IF NOT EXISTS idx_lib_products_name ON lib_products(product);

        CREATE TABLE IF NOT EXISTS lib_evidence(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entity_id TEXT NOT NULL,
          kind TEXT DEFAULT 'source',
          summary TEXT DEFAULT '',
          detail TEXT DEFAULT '',
          source_name TEXT DEFAULT '',
          source_url TEXT DEFAULT '',
          user_id INTEGER,
          tags TEXT DEFAULT '[]',
          created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lib_evidence_entity ON lib_evidence(entity_id);
        CREATE INDEX IF NOT EXISTS idx_lib_evidence_user ON lib_evidence(user_id);

        CREATE TABLE IF NOT EXISTS lib_targets(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          target TEXT NOT NULL,
          first_seen TEXT, last_scanned TEXT,
          UNIQUE(user_id, target)
        );
        CREATE INDEX IF NOT EXISTS idx_lib_targets_user ON lib_targets(user_id);

        CREATE TABLE IF NOT EXISTS lib_snapshots(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          target TEXT NOT NULL,
          scan_id TEXT NOT NULL,
          snapshot TEXT DEFAULT '[]',
          report TEXT DEFAULT '',
          vuln_ids TEXT DEFAULT '[]',
          exploitable INTEGER DEFAULT 0,
          created TEXT,
          UNIQUE(user_id, target, scan_id)
        );
        CREATE INDEX IF NOT EXISTS idx_lib_snapshots_utc
          ON lib_snapshots(user_id, target, created);

        CREATE TABLE IF NOT EXISTS lib_drift(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          target TEXT NOT NULL,
          from_scan_id TEXT DEFAULT '',
          to_scan_id TEXT NOT NULL,
          added TEXT DEFAULT '[]',
          removed TEXT DEFAULT '[]',
          changed TEXT DEFAULT '[]',
          summary TEXT DEFAULT '',
          created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lib_drift_scan ON lib_drift(user_id, target, to_scan_id);

        CREATE TABLE IF NOT EXISTS lib_notes(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          entity_id TEXT NOT NULL,
          note TEXT NOT NULL,
          tags TEXT DEFAULT '[]',
          created TEXT, updated TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lib_notes_entity ON lib_notes(entity_id);
        CREATE INDEX IF NOT EXISTS idx_lib_notes_user ON lib_notes(user_id);

        CREATE TABLE IF NOT EXISTS lib_tags(
          entity_id TEXT NOT NULL,
          tag TEXT NOT NULL,
          PRIMARY KEY(entity_id, tag)
        );

        CREATE TABLE IF NOT EXISTS lib_conflicts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entity_id TEXT NOT NULL,
          field TEXT NOT NULL,
          source_name TEXT DEFAULT '',
          observed TEXT DEFAULT '',
          kept TEXT DEFAULT '',
          resolved INTEGER DEFAULT 0,
          created TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lib_conflicts_entity ON lib_conflicts(entity_id);

        CREATE TABLE IF NOT EXISTS lib_refresh(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entity_id TEXT NOT NULL,
          status TEXT DEFAULT 'pending',
          error TEXT DEFAULT '',
          created TEXT, updated TEXT
        );

        CREATE TABLE IF NOT EXISTS lib_meta(
          key TEXT PRIMARY KEY, value TEXT
        );
        """)
        c.execute("INSERT OR REPLACE INTO lib_meta(key, value) VALUES('schema_version', '1')")
    _FTS = False
    try:
        with _tx() as c:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS lib_fts USING fts5("
                      "canonical_id UNINDEXED, title, description, products, concepts,"
                      " search_text, tokenize='porter unicode61')")
        _FTS = True
    except sqlite3.OperationalError:
        _FTS = False  # SQLite built without FTS5 → LIKE fallback
    if _FTS:
        with _tx() as c:
            n = c.execute("SELECT COUNT(*) FROM lib_fts").fetchone()[0]
            if n == 0:
                for row in c.execute("SELECT id FROM lib_canonical"):
                    _reindex_row(c, row["id"])


_FTS = False


# --- public API (async, db._lock serialized) --------------------------------
async def init_library() -> None:
    async with _db._lock:
        await asyncio.to_thread(init_library_sync)


async def ingest_vulnerability(record: Any, source_name: str = "", source_url: str = "",
                               raw: Any = None, inference: Any = None) -> dict:
    async with _db._lock:
        return await asyncio.to_thread(
            _ingest_vuln_sync, record, source_name, source_url, raw, inference)


# ---- scan ingestion + drift -------------------------------------------------
def _parse_findings(findings: Any) -> list[dict]:
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            return []
    if isinstance(findings, dict):
        findings = (findings.get("vulnerabilities") or findings.get("findings")
                    or [findings])
    if not isinstance(findings, list):
        findings = [findings]
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        cve = str(f.get("cve") or "").strip().upper()
        if not cve or not (_CVE_RE.match(cve) or _GHSA_RE.match(cve)):
            continue
        sig = (str(f.get("label") or ""), str(f.get("severity") or ""),
               _as_float(f.get("cvss")))
        lbl = str(f.get("label") or "").upper()
        ver = str(f.get("verified") or "").upper()
        exploitable = (lbl in ("EXPLOITABLE", "VERIFIED", "CONFIRMED")
                       or (ver in ("EXPLOITABLE", "VERIFIED", "CONFIRMED")
                           and not ver.startswith("NOT")))
        out.append({"canonical_id": cve, "finding": f, "sig": sig,
                    "exploitable": exploitable})
    return out


def _finding_sig_map(findings_json: str) -> dict[str, tuple]:
    out = {}
    try:
        for f in json.loads(findings_json or "[]"):
            if not isinstance(f, dict):
                continue
            cve = str(f.get("cve") or "").strip().upper()
            if cve:
                out[cve] = (str(f.get("label") or ""), str(f.get("severity") or ""),
                            _as_float(f.get("cvss")))
    except Exception:
        pass
    return out


def _drift_summary(added: list, removed: list, changed: list) -> str:
    parts = []
    if added:
        parts.append(f"{len(added)} added")
    if removed:
        parts.append(f"{len(removed)} removed")
    if changed:
        parts.append(f"{len(changed)} changed")
    return ", ".join(parts) or "no change"


def _ingest_scan_sync(user_id: Any, scan_id: str, target: str, findings: Any,
                      report: Any) -> dict:
    uid = int(user_id) if user_id not in (None, "") else 0
    scan_id = str(scan_id or "").strip()[:128]
    target = str(target or "").strip()[:512] or "?"
    now = _now()
    vulns = _parse_findings(findings)
    rep = _redact(report)
    rep_json = json.dumps(rep, ensure_ascii=False) if isinstance(rep, dict) else str(rep or "")
    with _tx() as c:
        t = c.execute("SELECT id FROM lib_targets WHERE user_id=? AND target=?",
                      (uid, target)).fetchone()
        if t:
            c.execute("UPDATE lib_targets SET last_scanned=? WHERE id=?", (now, t["id"]))
        else:
            c.execute("INSERT INTO lib_targets(user_id, target, first_seen, last_scanned)"
                      " VALUES(?,?,?,?)", (uid, target, now, now))
        prior = c.execute("SELECT * FROM lib_snapshots WHERE user_id=? AND target=? AND"
                          " scan_id<>? ORDER BY created DESC, id DESC LIMIT 1",
                          (uid, target, scan_id)).fetchone()
        new_ids = [v["canonical_id"] for v in vulns]
        snap_json = json.dumps([v["finding"] for v in vulns], ensure_ascii=False)
        exploitable = 1 if any(v["exploitable"] for v in vulns) else 0
        cur = c.execute(
            "INSERT OR IGNORE INTO lib_snapshots(user_id, target, scan_id, snapshot, report,"
            " vuln_ids, exploitable, created) VALUES(?,?,?,?,?,?,?,?)",
            (uid, target, scan_id, snap_json, rep_json, json.dumps(new_ids), exploitable, now))
        if cur.rowcount == 0:  # idempotent re-ingest of the same scan
            r = c.execute("SELECT id FROM lib_snapshots WHERE user_id=? AND target=?"
                          " AND scan_id=?", (uid, target, scan_id)).fetchone()
            return {"scan_id": scan_id, "target": target, "snapshot_id": r["id"],
                    "findings_count": len(new_ids), "exploitable": exploitable,
                    "drift": None, "reused": True}
        snap_id = cur.lastrowid
        drift = None
        if prior:
            old_ids = json.loads(prior["vuln_ids"] or "[]")
            old_sigs = _finding_sig_map(prior["snapshot"])
            added = [i for i in new_ids if i not in old_ids]
            removed = [i for i in old_ids if i not in new_ids]
            changed = [i for i in new_ids if i in old_ids and old_sigs.get(i) !=
                       next(v["sig"] for v in vulns if v["canonical_id"] == i)]
            if added or removed or changed:
                drift = {"added": added, "removed": removed, "changed": changed}
                c.execute(
                    "INSERT INTO lib_drift(user_id, target, from_scan_id, to_scan_id, added,"
                    " removed, changed, summary, created) VALUES(?,?,?,?,?,?,?,?,?)",
                    (uid, target, prior["scan_id"], scan_id, json.dumps(added),
                     json.dumps(removed), json.dumps(changed),
                     _drift_summary(added, removed, changed), now))
        for v in vulns:
            f = v["finding"]
            rec = {k: f.get(k) for k in
                   ("id", "cve", "title", "summary", "description", "severity", "cvss",
                    "published", "url", "poc_refs", "diff_patch", "affected")}
            _ingest_vuln_in_txn(c, rec, source_name=f"scan:{scan_id}", source_url="",
                                raw=f, inference=None, kind=None)
            c.execute(
                "INSERT INTO lib_evidence(entity_id, kind, summary, detail, source_name,"
                " source_url, user_id, tags, created) VALUES(?,?,?,?,?,?,?,?,?)",
                (v["canonical_id"], "scan",
                 f"{target}: {str(f.get('label') or f.get('severity') or 'seen')[:120]}",
                 json.dumps(_redact(f), ensure_ascii=False)[:4000], f"scan:{scan_id}", "",
                 uid, "[]", now))
    return {"scan_id": scan_id, "target": target, "snapshot_id": snap_id,
            "findings_count": len(new_ids), "exploitable": exploitable, "drift": drift}


async def ingest_scan(user_id: Any, scan_id: str, target: str, findings: Any,
                      report: Any) -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_ingest_scan_sync, user_id, scan_id, target,
                                       findings, report)


def _ingest_monitor_sync(record: Any, analysis: Any = None, detail: str = "") -> dict:
    d = _norm_record(record)
    analysis = _redact(analysis or {})
    if not isinstance(analysis, dict):
        analysis = {"raw": analysis}
    detail = str(detail or "")[:4000]
    src = d["source"] or "monitor"
    with _tx() as c:
        res = _ingest_vuln_in_txn(
            c, record, source_name=src, source_url=d["url"],
            raw={"record": d["raw"] or {}, "analysis": analysis, "detail": detail},
            inference=None, kind="monitor")
        cid = res["canonical_id"]
        summary = str(analysis.get("summary") or d["title"] or d["description"] or "")[:300]
        c.execute(
            "INSERT INTO lib_evidence(entity_id, kind, summary, detail, source_name,"
            " source_url, user_id, tags, created) VALUES(?,?,?,?,?,?,?,?,?)",
            (cid, "monitor", summary,
             json.dumps({"analysis": analysis, "detail": detail}, ensure_ascii=False)[:4000],
             src, d["url"], None, "[]", _now()))
        rce = str(analysis.get("rce_type") or "")
        if rce in ("unauth_rce", "auth_rce"):
            c.execute("UPDATE lib_canonical SET exploitable=1, updated=? WHERE id=?",
                      (_now(), cid))
        return {**res, "kind": "monitor"}


async def ingest_monitor(record: Any, analysis: Any = None, detail: str = "") -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_ingest_monitor_sync, record, analysis, detail)


# ---- search ----------------------------------------------------------------
def _fts_tokens(q: str) -> list[str]:
    toks = []
    for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9\-_.]*", q):
        if len(t) >= 2 and t not in toks:
            toks.append(t)
    return toks[:8]


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _fmt_search_rows(rows) -> list[dict]:
    out = []
    for r in rows:
        snippet = (r["description"] or r["summary"] or "")[:200]
        if len((r["description"] or r["summary"] or "")) > 200:
            snippet += "…"
        out.append({
            "canonical_id": r["canonical_id"],
            "title": r["title"],
            "severity": r["severity"],
            "cvss": r["cvss"],
            "published": r["published"],
            "sources": _src_joiner([r["srcs"]]),
            "snippet": snippet,
        })
    return out


def _search_sync(query: str, limit: int = 10) -> list[dict]:
    q = (query or "").strip()
    if not q:
        return []
    limit = max(1, int(limit))
    with _ro() as c:
        if _FTS:
            try:
                toks = _fts_tokens(q)
                if toks:
                    match = " ".join('"' + t.replace('"', '""') + '"' for t in toks)
                    rows = c.execute(
                        "SELECT c.id AS canonical_id, c.title, c.severity, c.cvss, c.published,"
                        " c.description, c.summary,"
                        " (SELECT group_concat(source_name, '|') FROM lib_sources s"
                        "  WHERE s.entity_id = c.id) AS srcs"
                        " FROM lib_fts f JOIN lib_canonical c ON c.id = f.canonical_id"
                        " WHERE lib_fts MATCH ? ORDER BY bm25(lib_fts) LIMIT ?",
                        (match, limit)).fetchall()
                    return _fmt_search_rows(rows)
            except sqlite3.OperationalError:
                pass  # fall through to LIKE
        esc = _like_escape(q)
        pat = f"%{esc}%"
        rows = c.execute(
            "SELECT c.id AS canonical_id, c.title, c.severity, c.cvss, c.published,"
            " c.description, c.summary,"
            " (SELECT group_concat(source_name, '|') FROM lib_sources s"
            "  WHERE s.entity_id = c.id) AS srcs"
            " FROM lib_canonical c WHERE c.search_text LIKE ? ESCAPE '\\'"
            " ORDER BY CASE WHEN c.id LIKE ? ESCAPE '\\' THEN 0"
            " WHEN c.search_text LIKE ? ESCAPE '\\' THEN 1 ELSE 2 END, c.updated DESC LIMIT ?",
            (pat, pat, pat, limit)).fetchall()
        return _fmt_search_rows(rows)


async def search(query: str, limit: int = 10, user_id: Any = None) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_search_sync, query, limit)


def _recent_sync(limit: int = 10) -> list[dict]:
    limit = max(1, int(limit))
    with _ro() as c:
        rows = c.execute(
            "SELECT id AS canonical_id, title, severity, cvss, published, updated,"
            " (SELECT group_concat(source_name, '|') FROM lib_sources s"
            "  WHERE s.entity_id = c.id) AS srcs"
            " FROM lib_canonical c ORDER BY updated DESC, id DESC LIMIT ?", (limit,)).fetchall()
        return [{"canonical_id": r["canonical_id"], "title": r["title"],
                 "severity": r["severity"], "cvss": r["cvss"], "published": r["published"],
                 "updated": r["updated"], "sources": _src_joiner([r["srcs"]])} for r in rows]


async def recent(limit: int = 10) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_recent_sync, limit)


def _exploitable_sync(limit: int = 10) -> list[dict]:
    limit = max(1, int(limit))
    with _ro() as c:
        rows = c.execute(
            "SELECT id AS canonical_id, title, severity, cvss, published, updated,"
            " (SELECT group_concat(source_name, '|') FROM lib_sources s"
            "  WHERE s.entity_id = c.id) AS srcs"
            " FROM lib_canonical c WHERE exploitable=1"
            " ORDER BY cvss IS NULL, cvss DESC, updated DESC LIMIT ?", (limit,)).fetchall()
        return [{"canonical_id": r["canonical_id"], "title": r["title"],
                 "severity": r["severity"], "cvss": r["cvss"], "published": r["published"],
                 "updated": r["updated"], "exploitable": 1,
                 "sources": _src_joiner([r["srcs"]])} for r in rows]


async def exploitable(limit: int = 10) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_exploitable_sync, limit)


# ---- lookups ---------------------------------------------------------------
def _get_vuln_sync(canonical_id: str) -> Optional[dict]:
    cid = str(canonical_id or "").strip().upper()
    if not cid:
        return None
    with _ro() as c:
        row = c.execute("SELECT * FROM lib_canonical WHERE id=?", (cid,)).fetchone()
        return _canonical_dict(c, row) if row else None


async def get_vulnerability(canonical_id: str) -> Optional[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_get_vuln_sync, canonical_id)


def _concept_weights(concepts: dict) -> Counter:
    cw: Counter = Counter()
    cw.update({t: 3 for t in concepts.get("title", [])})
    cw.update({t: 2 for t in concepts.get("product", [])})
    cw.update({t: 1 for t in concepts.get("desc", [])})
    return cw


def _related_sync(canonical_id_or_query: str, limit: int = 5) -> list[dict]:
    """Deterministic conceptual retrieval: local concept normalization + idf-weighted
    token similarity (no external vectors). Same-technique siblings rank above
    records that merely share a common vendor/product token."""
    q = str(canonical_id_or_query or "").strip()
    if not q:
        return []
    limit = max(1, int(limit))
    with _ro() as c:
        rows = c.execute("SELECT id, title, severity, concepts FROM lib_canonical").fetchall()
        if not rows:
            return []
        target = next((r for r in rows if r["id"] == q.upper()), None) \
            if (len(q) <= 64 and not q[0].isspace()) else None
        exclude = None
        if target:
            exclude = target["id"]
            concepts = json.loads(target["concepts"] or "{}")
        else:
            concepts = _concepts(q, q, [])
        qw = _concept_weights(concepts)
        if not qw:
            return []
        corpus: list[tuple[sqlite3.Row, Counter]] = []
        df: Counter = Counter()
        for r in rows:
            cw = _concept_weights(json.loads(r["concepts"] or "{}"))
            corpus.append((r, cw))
            df.update(set(cw))
        n = len(corpus)

        def idf(tok: str) -> float:
            return math.log(1.0 + n / (1.0 + df[tok]))

        qw_idf = {t: w * idf(t) for t, w in qw.items()}
        qnorm = math.sqrt(sum(qw_idf.values()))
        if qnorm <= 0:
            return []
        results = []
        for r, cw in corpus:
            cid = r["id"]
            if cid == exclude:
                continue
            cw_idf = {t: w * idf(t) for t, w in cw.items()}
            overlap = 0.0
            shared_concepts = 0
            for t, w in qw_idf.items():
                if t in cw_idf:
                    overlap += min(w, cw_idf[t])
                    shared_concepts += 1
            if overlap <= 0:
                continue
            cnorm = math.sqrt(sum(cw_idf.values()))
            score = overlap / (qnorm * cnorm) if cnorm > 0 else 0.0
            if score < 0.3 and shared_concepts < 2:
                continue  # lone shared vendor token is not relatedness
            shared_products = set(concepts.get("product", [])) & set(
                json.loads(r["concepts"] or "{}").get("product", []))
            score += 0.1 * len(shared_products)
            results.append({"canonical_id": cid, "title": r["title"],
                            "severity": r["severity"], "score": round(float(score), 4)})
        return results[:limit]


async def related(canonical_id_or_query: str, limit: int = 5) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_related_sync, canonical_id_or_query, limit)


def _target_history_sync(user_id: Any, target: str, limit: int = 10) -> list[dict]:
    uid = int(user_id) if user_id not in (None, "") else 0
    query_key = _target_key(target)
    limit = max(1, int(limit))
    with _ro() as c:
        candidates = c.execute(
            "SELECT * FROM lib_snapshots WHERE user_id=? ORDER BY created DESC, id DESC",
            (uid,)).fetchall()
        snaps = [s for s in candidates if _target_key(s["target"]) == query_key][:limit]
        out = []
        for s in snaps:
            drift = None
            d = c.execute("SELECT added, removed, changed FROM lib_drift WHERE user_id=? AND"
                          " target=? AND to_scan_id=? ORDER BY id DESC LIMIT 1",
                          (uid, s["target"], s["scan_id"])).fetchone()
            if d:
                drift = ([{"type": "added", "cve": x} for x in json.loads(d["added"] or "[]")] +
                         [{"type": "removed", "cve": x} for x in json.loads(d["removed"] or "[]")] +
                         [{"type": "changed", "cve": x} for x in json.loads(d["changed"] or "[]")])
            report = s["report"]
            if report and report.lstrip().startswith(("{", "[")):
                try:
                    report = json.loads(report)
                except Exception:
                    pass
            out.append({
                "snapshot_id": s["id"],
                "scan_id": s["scan_id"],
                "target": s["target"],
                "created": s["created"],
                "findings_count": len(json.loads(s["vuln_ids"] or "[]")),
                "exploitable": s["exploitable"],
                "report": report,
                "drift": drift or None,
            })
        return out


async def target_history(user_id: Any, target: str, limit: int = 10) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_target_history_sync, user_id, target, limit)


def _norm_entity_id(entity_id: str) -> str:
    e = str(entity_id or "").strip()
    if not e:
        return ""
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9\-_:.]*$", e):
        return e.upper()
    return "target:" + e


def _ev_row(r: sqlite3.Row) -> dict:
    return {"id": r["id"], "entity_id": r["entity_id"], "kind": r["kind"],
            "summary": r["summary"], "detail": r["detail"],
            "source_name": r["source_name"], "source_url": r["source_url"],
            "user_id": r["user_id"], "tags": json.loads(r["tags"] or "[]"),
            "created": r["created"]}


def _get_evidence_sync(entity_id: str, user_id: Any = None, limit: int = 20) -> list[dict]:
    eid = _norm_entity_id(entity_id)
    if not eid:
        return []
    limit = max(1, int(limit))
    with _ro() as c:
        if user_id is None:
            rows = c.execute("SELECT * FROM lib_evidence WHERE entity_id=? ORDER BY id DESC"
                             " LIMIT ?", (eid, limit)).fetchall()
        else:
            rows = c.execute("SELECT * FROM lib_evidence WHERE entity_id=? AND user_id=?"
                             " ORDER BY id DESC LIMIT ?",
                             (eid, int(user_id), limit)).fetchall()
        return [_ev_row(r) for r in rows]


async def get_evidence(entity_id: str, user_id: Any = None, limit: int = 20) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_get_evidence_sync, entity_id, user_id, limit)


# ---- notes -----------------------------------------------------------------
def _add_note_sync(user_id: Any, entity_id: str, note: str, tags: Any = None) -> dict:
    uid = int(user_id) if user_id not in (None, "") else 0
    eid = _norm_entity_id(entity_id)
    note = str(note or "").strip()
    if not note:
        raise ValueError("note cannot be empty")
    tags = list(dict.fromkeys(str(t).strip()[:64] for t in (tags or []) if str(t).strip()))[:32]
    now = _now()
    with _tx() as c:
        cur = c.execute("INSERT INTO lib_notes(user_id, entity_id, note, tags, created, updated)"
                        " VALUES(?,?,?,?,?,?)", (uid, eid, note, json.dumps(tags), now, now))
        for t in tags:
            c.execute("INSERT OR IGNORE INTO lib_tags(entity_id, tag) VALUES(?,?)", (eid, t))
    return {"id": cur.lastrowid, "entity_id": eid, "created": now}


async def add_note(user_id: Any, entity_id: str, note: str, tags: Any = None) -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_add_note_sync, user_id, entity_id, note, tags)


# ---- stats -----------------------------------------------------------------
def _stats_sync(user_id: Any = None) -> dict:
    with _ro() as c:
        counts = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("lib_canonical", "lib_sources", "lib_evidence", "lib_targets",
                            "lib_snapshots", "lib_notes", "lib_conflicts")}
        distinct_sources = c.execute(
            "SELECT COUNT(DISTINCT source_name) FROM lib_sources").fetchone()[0]
        by_severity = {}
        for r in c.execute("SELECT COALESCE(NULLIF(UPPER(severity), ''), 'UNSPECIFIED') sev,"
                           " COUNT(*) n FROM lib_canonical GROUP BY sev"):
            by_severity[r["sev"]] = r["n"]
        cutoff = time.strftime(_TS, time.localtime(time.time() - _REFRESH_TTL))
        due = c.execute("SELECT COUNT(*) FROM lib_canonical WHERE last_refreshed IS NULL OR"
                        " last_refreshed < ?", (cutoff,)).fetchone()[0]
    return {
        "vulnerabilities": counts["lib_canonical"],
        "sources": distinct_sources,
        "evidence": counts["lib_evidence"],
        "targets": counts["lib_targets"],
        "snapshots": counts["lib_snapshots"],
        "notes": counts["lib_notes"],
        "conflicts": counts["lib_conflicts"],
        "by_severity": by_severity,
        "due_for_refresh": due,
    }


async def stats(user_id: Any = None) -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_stats_sync, user_id)


# ---- export / import -------------------------------------------------------
def _export_sync(user_id: Any = None) -> str:
    lines: list[str] = []
    now = _now()
    with _ro() as c:
        for row in c.execute("SELECT * FROM lib_canonical ORDER BY id"):
            base = _canonical_dict(c, row)
            srcs = c.execute("SELECT source_name, source_url, raw FROM lib_sources WHERE"
                             " entity_id=? ORDER BY id", (row["id"],)).fetchall()
            if srcs:
                for s in srcs:
                    line = {"type": "vulnerability", "ts": now, **base,
                            "source_name": s["source_name"], "source_url": s["source_url"],
                            "raw": json.loads(s["raw"] or "{}")}
                    lines.append(json.dumps(line, ensure_ascii=False))
            else:
                line = {"type": "vulnerability", "ts": now, **base, "source_name": "",
                        "source_url": "", "raw": {}}
                lines.append(json.dumps(line, ensure_ascii=False))
        for r in c.execute("SELECT * FROM lib_evidence ORDER BY id"):
            lines.append(json.dumps({"type": "evidence", "ts": now, **_ev_row(r)},
                                    ensure_ascii=False))
        for r in c.execute("SELECT * FROM lib_targets ORDER BY id"):
            lines.append(json.dumps({"type": "target", "ts": now, "user_id": r["user_id"],
                                     "target": r["target"], "first_seen": r["first_seen"],
                                     "last_scanned": r["last_scanned"]}, ensure_ascii=False))
        for r in c.execute("SELECT * FROM lib_snapshots ORDER BY id"):
            lines.append(json.dumps({"type": "snapshot", "ts": now, "user_id": r["user_id"],
                                     "target": r["target"], "scan_id": r["scan_id"],
                                     "created": r["created"],
                                     "snapshot": json.loads(r["snapshot"] or "[]"),
                                     "report": r["report"],
                                     "vuln_ids": json.loads(r["vuln_ids"] or "[]"),
                                     "exploitable": r["exploitable"]}, ensure_ascii=False))
        for r in c.execute("SELECT * FROM lib_notes ORDER BY id"):
            if user_id is None or r["user_id"] == int(user_id):
                lines.append(json.dumps({"type": "note", "ts": now, "user_id": r["user_id"],
                                         "entity_id": r["entity_id"], "note": r["note"],
                                         "tags": json.loads(r["tags"] or "[]"),
                                         "created": r["created"]}, ensure_ascii=False))
        for r in c.execute("SELECT * FROM lib_conflicts ORDER BY id"):
            lines.append(json.dumps({"type": "conflict", "ts": now,
                                     "entity_id": r["entity_id"], "field": r["field"],
                                     "source_name": r["source_name"], "observed": r["observed"],
                                     "kept": r["kept"], "created": r["created"]},
                                    ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


async def export_jsonl(user_id: Any = None) -> str:
    async with _db._lock:
        return await asyncio.to_thread(_export_sync, user_id)


def _import_jsonl_sync(text: str, user_id: Any = None) -> dict:
    imported = 0
    skipped = 0
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            skipped += 1
            continue
        t = obj.get("type")
        try:
            if t == "vulnerability":
                eid = str(obj.get("canonical_id") or "").strip().upper()
                sn = str(obj.get("source_name") or "").strip()
                if not eid:
                    skipped += 1
                    continue
                rec = {"cve": eid, "id": eid, "title": obj.get("title"),
                       "summary": obj.get("summary"), "description": obj.get("description"),
                       "severity": obj.get("severity"), "cvss": obj.get("cvss"),
                       "published": obj.get("published"), "url": obj.get("url"),
                       "poc_refs": obj.get("poc_refs"), "diff_patch": obj.get("diff_patch"),
                       "affected": obj.get("affected"), "raw": obj.get("raw") or {}}
                with _tx() as c:
                    if _source_exists_sync(c, eid, sn or "unknown"):
                        skipped += 1
                    else:
                        _ingest_vuln_in_txn(c, rec, source_name=sn,
                                            source_url=obj.get("source_url", ""),
                                            raw=obj.get("raw"), suppress_evidence=True)
                        imported += 1
            elif t == "evidence":
                eid = _norm_entity_id(obj.get("entity_id", ""))
                created = obj.get("created") or _now()
                kind = str(obj.get("kind") or "source")[:32]
                summary = str(obj.get("summary") or "")[:300]
                with _tx() as c:
                    dup = c.execute("SELECT 1 FROM lib_evidence WHERE entity_id=? AND kind=?"
                                    " AND summary=? AND source_name=?",
                                    (eid, kind, summary,
                                     str(obj.get("source_name") or "")[:64])).fetchone()
                    if dup:
                        skipped += 1
                    else:
                        c.execute(
                            "INSERT INTO lib_evidence(entity_id, kind, summary, detail,"
                            " source_name, source_url, user_id, tags, created)"
                            " VALUES(?,?,?,?,?,?,?,?,?)",
                            (eid, kind, summary, str(obj.get("detail") or "")[:4000],
                             str(obj.get("source_name") or "")[:64],
                             str(obj.get("source_url") or "")[:512], obj.get("user_id"),
                             json.dumps(obj.get("tags") or []), created))
                        imported += 1
            elif t == "note":
                uid = int(obj.get("user_id") if obj.get("user_id") is not None
                          else (user_id if user_id is not None else 0))
                eid = _norm_entity_id(obj.get("entity_id", ""))
                note = str(obj.get("note") or "")
                created = obj.get("created") or _now()
                if not note:
                    skipped += 1
                    continue
                with _tx() as c:
                    dup = c.execute("SELECT 1 FROM lib_notes WHERE user_id=? AND entity_id=?"
                                    " AND note=? AND created=?",
                                    (uid, eid, note, created)).fetchone()
                    if dup:
                        skipped += 1
                    else:
                        c.execute("INSERT INTO lib_notes(user_id, entity_id, note, tags,"
                                  " created, updated) VALUES(?,?,?,?,?,?)",
                                  (uid, eid, note, json.dumps(obj.get("tags") or []),
                                   created, created))
                        for tg in obj.get("tags") or []:
                            c.execute("INSERT OR IGNORE INTO lib_tags(entity_id, tag)"
                                      " VALUES(?,?)", (eid, str(tg)[:64]))
                        imported += 1
            elif t == "target":
                uid = int(obj.get("user_id") if obj.get("user_id") is not None
                          else (user_id if user_id is not None else 0))
                with _tx() as c:
                    cur = c.execute("INSERT OR IGNORE INTO lib_targets(user_id, target,"
                                    " first_seen, last_scanned) VALUES(?,?,?,?)",
                                    (uid, str(obj.get("target") or "")[:512],
                                     obj.get("first_seen") or _now(),
                                     obj.get("last_scanned") or _now()))
                    if cur.rowcount:
                        imported += 1
                    else:
                        skipped += 1
            elif t == "snapshot":
                uid = int(obj.get("user_id") if obj.get("user_id") is not None
                          else (user_id if user_id is not None else 0))
                with _tx() as c:
                    cur = c.execute(
                        "INSERT OR IGNORE INTO lib_snapshots(user_id, target, scan_id, snapshot,"
                        " report, vuln_ids, exploitable, created) VALUES(?,?,?,?,?,?,?,?)",
                        (uid, str(obj.get("target") or "")[:512],
                         str(obj.get("scan_id") or "")[:128],
                         json.dumps(obj.get("snapshot") or [], ensure_ascii=False),
                         json.dumps(obj.get("report") or {}, ensure_ascii=False)
                         if isinstance(obj.get("report"), (dict, list)) else str(obj.get("report") or ""),
                         json.dumps(obj.get("vuln_ids") or []), 1 if obj.get("exploitable") else 0,
                         obj.get("created") or _now()))
                    if cur.rowcount:
                        imported += 1
                    else:
                        skipped += 1
            elif t == "conflict":
                with _tx() as c:
                    dup = c.execute("SELECT 1 FROM lib_conflicts WHERE entity_id=? AND field=?"
                                    " AND source_name=? AND observed=? AND kept=? AND created=?",
                                    (str(obj.get("entity_id") or "")[:128],
                                     str(obj.get("field") or "")[:64],
                                     str(obj.get("source_name") or "")[:64],
                                     str(obj.get("observed") or "")[:1024],
                                     str(obj.get("kept") or "")[:1024],
                                     obj.get("created") or _now())).fetchone()
                    if dup:
                        skipped += 1
                    else:
                        c.execute("INSERT INTO lib_conflicts(entity_id, field, source_name,"
                                  " observed, kept, resolved, created) VALUES(?,?,?,?,?,0,?)",
                                  (str(obj.get("entity_id") or "")[:128],
                                   str(obj.get("field") or "")[:64],
                                   str(obj.get("source_name") or "")[:64],
                                   str(obj.get("observed") or "")[:1024],
                                   str(obj.get("kept") or "")[:1024],
                                   obj.get("created") or _now()))
                        imported += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return {"imported": imported, "skipped": skipped}


async def import_jsonl(text: str, user_id: Any = None) -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_import_jsonl_sync, text, user_id)


# ---- backup / integrity ----------------------------------------------------
def _backup_sync(path: Any = None) -> dict:
    if not path:
        path = str(Path(_db.DB_PATH).parent /
                   f"library-backup-{time.strftime('%Y%m%d-%H%M%S')}.db")
    path = str(path)
    src = _db._conn()
    dst = sqlite3.connect(path)
    try:
        with dst:
            src.backup(dst)  # consistent online snapshot, WAL-safe
    finally:
        dst.close()
        src.close()
    return {"path": path, "bytes": os.path.getsize(path)}


async def backup(path: Any = None) -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_backup_sync, path)


def _verify_sync() -> dict:
    problems: list[str] = []
    integrity = "ok"
    row_checks = {"orphan_sources": 0, "orphan_products": 0, "orphan_evidence": 0}
    try:
        with _ro() as c:
            ic = c.execute("PRAGMA integrity_check").fetchone()[0]
            if ic != "ok":
                integrity = "error"
                problems.append(f"integrity_check: {ic}")
            if integrity == "ok":
                for tbl in ("lib_sources", "lib_products", "lib_evidence"):
                    n = c.execute(f"SELECT COUNT(*) FROM {tbl} WHERE entity_id NOT IN"
                                  " (SELECT id FROM lib_canonical)").fetchone()[0]
                    row_checks[f"orphan_{tbl.removeprefix('lib_')}"] = n
                    if n:
                        problems.append(f"{tbl}: {n} orphan rows")
                if _FTS:
                    fts_n = c.execute("SELECT COUNT(*) FROM lib_fts").fetchone()[0]
                    can_n = c.execute("SELECT COUNT(*) FROM lib_canonical").fetchone()[0]
                    if fts_n != can_n:
                        problems.append(f"fts rows {fts_n} != canonical rows {can_n}")
    except sqlite3.Error as e:
        integrity = "error"
        problems.append(str(e))
    return {"ok": not problems, "integrity_check": integrity, "problems": problems,
            "row_checks": row_checks}


async def verify_integrity() -> dict:
    async with _db._lock:
        return await asyncio.to_thread(_verify_sync)


# ---- external refresh ------------------------------------------------------
def _record_refresh_sync(entity_id: str, status: str, error: str = "") -> None:
    now = _now()
    with _tx() as c:
        c.execute("INSERT INTO lib_refresh(entity_id, status, error, created, updated)"
                  " VALUES(?,?,?,?,?)", (entity_id, status, error, now, now))


def _add_days(ts: Optional[str], days: int) -> str:
    if not ts:
        return _now()
    try:
        t = time.mktime(time.strptime(ts, _TS))
        return time.strftime(_TS, time.localtime(t + days * 86400))
    except (ValueError, OverflowError):
        return ts


def _refresh_due_sync(limit: int = 5) -> list[dict]:
    limit = max(1, int(limit))
    cutoff = time.strftime(_TS, time.localtime(time.time() - _REFRESH_TTL))
    with _ro() as c:
        rows = c.execute(
            "SELECT id, title, last_refreshed FROM lib_canonical"
            " WHERE last_refreshed IS NULL OR last_refreshed < ?"
            " ORDER BY COALESCE(last_refreshed, '0000-00-00 00:00:00') ASC LIMIT ?",
            (cutoff, limit)).fetchall()
        out = []
        for r in rows:
            lr = r["last_refreshed"]
            src = c.execute("SELECT source_name FROM lib_sources WHERE entity_id=?"
                            " ORDER BY id LIMIT 1", (r["id"],)).fetchone()
            out.append({
                "canonical_id": r["id"],
                "title": r["title"],
                "source": src["source_name"] if src else "",
                "last_refreshed": lr,
                "next_refresh": _add_days(lr, _REFRESH_DAYS) if lr else _now(),
            })
        return out


async def refresh_due(limit: int = 5) -> list[dict]:
    async with _db._lock:
        return await asyncio.to_thread(_refresh_due_sync, limit)


async def refresh_vulnerability(canonical_id: str) -> dict:
    """Fetch fresh records from external scrapers and re-ingest (same-source
    updates in place, conflicts recorded). Network happens outside the lock."""
    cid = str(canonical_id or "").strip().upper()
    if not cid:
        return {"refreshed": False, "reason": "empty canonical id", "stale": False}
    async with _db._lock:
        await asyncio.to_thread(_record_refresh_sync, cid, "pending")
    try:
        scrapers = build_scrapers(cache_get=_db.cache_get, cache_set=_db.cache_set)
        records = await get_all(scrapers, cid)
    except Exception as e:  # network / parser failure → keep stale data
        async with _db._lock:
            await asyncio.to_thread(_record_refresh_sync, cid, "failed",
                                    f"{type(e).__name__}: {e}")
        return {"refreshed": False, "reason": f"{type(e).__name__}: {e}", "stale": True,
                "canonical_id": cid}
    if not records:
        async with _db._lock:
            await asyncio.to_thread(_record_refresh_sync, cid, "failed", "no records")
        return {"refreshed": False, "reason": "no records returned by sources", "stale": True,
                "canonical_id": cid}

    def _apply() -> list[dict]:
        results = []
        with _tx() as c:
            for r in records:
                d = _norm_record(r)
                if not (d["cve"] or d["id"]):
                    continue
                # A successful same-source refresh is authoritative for mutable fields.
                src = d["source"] or "scraper"
                if _source_exists_sync(c, d["canonical_id"], src):
                    c.execute(
                        "UPDATE lib_canonical SET title=COALESCE(NULLIF(?,''),title), "
                        "summary=COALESCE(NULLIF(?,''),summary), "
                        "description=COALESCE(NULLIF(?,''),description), "
                        "severity=COALESCE(NULLIF(?,''),severity), cvss=COALESCE(?,cvss), "
                        "published=COALESCE(NULLIF(?,''),published), updated=? WHERE id=?",
                        (d["title"], d["summary"], d["description"], d["severity"], d["cvss"],
                         d["published"], _now(), d["canonical_id"]))
                results.append(_ingest_vuln_in_txn(
                    c, r, source_name=d["source"] or "scraper", source_url=d["url"],
                    raw=d["raw"] or None, inference=None, kind=None))
            c.execute("UPDATE lib_canonical SET last_refreshed=? WHERE id=?", (_now(), cid))
            _record_refresh_in_txn(c, cid, "done")
        return results

    async with _db._lock:
        results = await asyncio.to_thread(_apply)
    return {"refreshed": True, "canonical_id": cid, "fetched": len(records),
            "ingested": results}


def _record_refresh_in_txn(c: sqlite3.Connection, entity_id: str, status: str,
                           error: str = "") -> None:
    now = _now()
    c.execute("INSERT INTO lib_refresh(entity_id, status, error, created, updated)"
              " VALUES(?,?,?,?,?)", (entity_id, status, error, now, now))


__all__ = [
    "init_library", "ingest_vulnerability", "ingest_scan", "ingest_monitor",
    "search", "recent", "exploitable", "get_vulnerability", "related",
    "target_history", "get_evidence", "stats", "add_note", "export_jsonl",
    "import_jsonl", "backup", "verify_integrity", "refresh_vulnerability",
    "refresh_due",
]

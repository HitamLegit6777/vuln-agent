"""Agent tools — grounded actions the LLM can invoke.

Every tool returns a *string* (or JSON-string) the LLM observes. Tools never invent data:
detection uses real HTTP evidence; vuln data comes from scrapers w/ exact ranges.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

import httpx
from bs4 import BeautifulSoup

import config
from detect.cms import detect_stack, to_signals
from scrapers.registry import build_scrapers, search_all, get_all

_scrapers = None
_http: Optional[httpx.AsyncClient] = None


def _scrapers_obj():
    global _scrapers
    if _scrapers is None:
        try:
            from db import cache_get, cache_set
            _scrapers = build_scrapers(cache_get=cache_get, cache_set=cache_set)
        except Exception:
            _scrapers = build_scrapers()
    return _scrapers


async def _httpc() -> httpx.AsyncClient:
    global _http
    if _http is None:
        _http = httpx.AsyncClient(
            headers={"User-Agent": config.USER_AGENT},
            timeout=config.HTTP_TIMEOUT, follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10,
                                keepalive_expiry=30.0),
        )
    return _http


async def t_detect_stack(url: str) -> str:
    """Probe target → CMS + components + services with versions + evidence.
    SELF-IMPROVEMENT: loads learned signatures from prior scans, saves new detections."""
    # load learned signatures from DB (patterns discovered in prior scans)
    learned_sigs = []
    try:
        from db import get_learned_sigs
        learned_sigs = await get_learned_sigs()
    except Exception:
        pass
    s = await detect_stack(url, await _httpc(), learned_sigs=learned_sigs)
    from detect.waf import waf_summary, waf_detail, may_mask_verdict
    # SELF-IMPROVEMENT: save new detection signals to learned_signatures DB
    if s.cms:
        try:
            from db import save_learned_sig
            for ev_str in (s.evidence or []):
                # parse evidence string to extract signal type + value
                if "generator=" in ev_str:
                    val = ev_str.split("generator=", 1)[1].strip()
                    await save_learned_sig(s.cms, "generator", val[:100], ev_str)
                elif ev_str.startswith("/"):
                    await save_learned_sig(s.cms, "path", ev_str[:100], ev_str)
                elif "cookie" in ev_str.lower():
                    await save_learned_sig(s.cms, "cookie", ev_str[:100], ev_str)
        except Exception:
            pass
    out = {
        "url": s.url, "cms": s.cms, "cms_version": s.cms_version,
        "evidence": s.evidence,
        "components": [{"name": c.name, "type": c.type, "version": c.version, "evidence": c.evidence}
                       for c in s.components],
        "services": [{"name": c.name, "version": c.version, "evidence": c.evidence}
                     for c in s.services],
        "waf": waf_detail(s.waf),
        "waf_summary": waf_summary(s.waf),
        "waf_may_mask": may_mask_verdict(s.waf),
        "signals": to_signals(s),
        "notes": s.notes,
    }
    return json.dumps(out, indent=2, ensure_ascii=False)


async def t_search_vuln(query: str, version: Optional[str] = None) -> str:
    """Search all vuln sources for a product/CVE. NO cap — returns ALL matched CVEs.
    Auto-enriches exact ranges via cve5 for CVEs missing them, so the match label
    (VULNERABLE/NOT_AFFECTED/UNCONFIRMED) is computed automatically — the agent does
    NOT need to version_match each CVE manually."""
    scrapers = _scrapers_obj()
    recs = await search_all(scrapers, query, version)
    cve5 = next((s for s in scrapers if s.name == "cve5"), None)
    # enrich: any CVE record without affected ranges -> pull exact ranges from cve5 (reachable)
    if version and cve5:
        for r in recs:
            if r.cve and not r.affected:
                try:
                    d = await cve5.get(r.cve)
                    if d and d.affected:
                        r.affected = d.affected
                        if d.description and not r.description:
                            r.description = d.description
                        if d.cvss and not r.cvss:
                            r.cvss = d.cvss; r.severity = d.severity or r.severity
                        if d.poc_refs:
                            r.poc_refs = list(dict.fromkeys(r.poc_refs + d.poc_refs))
                        if d.diff_patch and not r.diff_patch:
                            r.diff_patch = d.diff_patch
                except Exception:
                    pass
    rows = []
    for r in recs:  # NO cap — all results
        rows.append({
            "cve": r.cve, "id": r.id, "source": r.source, "title": r.title,
            "severity": r.severity, "cvss": r.cvss,
            "ranges": len(r.affected), "poc_refs": len(r.poc_refs),
            "diff_patch": bool(r.diff_patch),
            "match": r.is_vulnerable(version) if version else None,
            "url": r.url,
        })
    return json.dumps({"query": query, "version": version, "count": len(recs),
                       "results": rows}, indent=2, ensure_ascii=False)


async def t_fetch_cve_detail(cve: str) -> str:
    """Full grounded context for a CVE (description, ranges, patch, PoC, exploit code)."""
    recs = await get_all(_scrapers_obj(), cve)
    if not recs:
        return f"No detail found for {cve} across sources."
    # if multiple distinct CVEs, join
    blocks = [r.to_ai_context() for r in recs[:3]]
    return "\n\n========\n\n".join(blocks)


async def t_version_match(cve: str, version: str) -> str:
    """Decide if a specific installed version is vulnerable. Label + reasoning."""
    recs = await get_all(_scrapers_obj(), cve)
    if not recs:
        return json.dumps({"cve": cve, "version": version,
                           "label": "UNKNOWN", "reason": "no data in any source"})
    decided = []
    for r in recs:
        v = r.is_vulnerable(version)
        decided.append({"source": r.source, "label": _label(v),
                        "ranges": [{"min>=": a.min_inclusive, "max<=": a.max_inclusive,
                                    "max<": a.max_exclusive, "fixed": a.fixed,
                                    "eco": a.ecosystem} for a in r.affected]})
    # aggregate: any True → VULNERABLE; any False and no True → NOT AFFECTED; else UNKNOWN
    labels = [d["label"] for d in decided]
    if "VULNERABLE" in labels:
        final = "VULNERABLE"
    elif "NOT_AFFECTED" in labels:
        final = "NOT_AFFECTED"
    else:
        final = "UNKNOWN"
    return json.dumps({"cve": cve, "version": version, "label": final,
                       "per_source": decided}, indent=2, ensure_ascii=False)


def _label(v) -> str:
    if v is True:
        return "VULNERABLE"
    if v is False:
        return "NOT_AFFECTED"
    return "UNKNOWN"


async def t_webfetch(url: str, max_chars: int = 10000) -> str:
    """Fetch a URL and return cleaned text. For Cloudflare-protected pages,
    automatically falls back to headless browser (Playwright) to bypass JS challenge."""
    try:
        r = await (await _httpc()).get(url)
        if r.status_code >= 400:
            return f"HTTP {r.status_code}"
        ct = r.headers.get("content-type", "")
        text = r.text
        # Check for Cloudflare challenge (202 + JS required)
        if r.status_code == 202 or "JavaScript is disabled" in text or "challenge" in text[:500].lower():
            return await _playwright_fetch(url, max_chars)
        if "html" in ct:
            text = BeautifulSoup(r.text, "lxml").get_text(" ", strip=True)
        return text[:max_chars]
    except Exception as e:
        # If httpx fails, try Playwright (might be CF challenge)
        try:
            return await _playwright_fetch(url, max_chars)
        except Exception:
            return f"ERR {type(e).__name__}: {e}"


async def _playwright_fetch(url: str, max_chars: int = 10000, timeout: float = 45.0) -> str:
    """Fetch a URL using headless Chromium (bypasses Cloudflare JS challenge).
    Bounded by wait_for + browser.close() in finally (no Chromium leak on failure)."""
    import asyncio
    def _sync_fetch():
        from playwright.sync_api import sync_playwright
        from bs4 import BeautifulSoup
        browser = None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                import time
                time.sleep(3)  # wait for CF challenge to resolve
                html = page.content()
                soup = BeautifulSoup(html, "lxml")
                return soup.get_text(" ", strip=True)[:max_chars]
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync_fetch), timeout=timeout)
    except asyncio.TimeoutError:
        return "ERR playwright timeout"


async def t_save_poc(scan_id: str, cve: str, code: str, filename: str = "") -> str:
    """Save a generated PoC script to disk + db (so chat agent can read it back). Returns path."""
    safe_cve = re.sub(r"[^A-Za-z0-9_-]", "_", cve or "vuln")
    # sanitize the LLM-supplied filename — strip dirs/separators so it can NEVER escape config.POC
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename or "")
    safe_name = safe_name.lstrip(".").strip("/\\")
    fname = safe_name or f"poc_{scan_id}_{safe_cve}.py"
    path = (config.POC / fname).resolve()
    if path.parent != config.POC.resolve():
        path = config.POC / f"poc_{scan_id}_{safe_cve}.py"
    path.write_text(code, encoding="utf-8")
    try:
        from db import save_poc
        await save_poc(scan_id, cve, str(path), code)
    except Exception:
        pass
    return json.dumps({"path": str(path), "cve": cve, "lines": code.count(chr(10)) + 1})


async def t_list_pocs(scan_id: str) -> str:
    """List PoC scripts generated for a scan (cve, path, code preview)."""
    try:
        from db import get_pocs
        rows = await get_pocs(scan_id)
    except Exception as e:
        return f"ERR {e}"
    out = [{"cve": r.get("cve"), "path": r.get("path"),
            "lines": (r.get("code") or "").count(chr(10)) + 1,
            "preview": (r.get("code") or "")[:400]} for r in rows]
    return json.dumps({"scan_id": scan_id, "count": len(out), "pocs": out},
                      indent=2, ensure_ascii=False)


async def t_get_poc(scan_id: str, cve: str) -> str:
    """Return the full PoC script code the agent generated for a CVE in this scan."""
    try:
        from db import get_poc
        r = await get_poc(scan_id, cve)
    except Exception as e:
        return f"ERR {e}"
    if not r:
        return f"No PoC found for {cve} in scan {scan_id}."
    return json.dumps({"cve": r.get("cve"), "path": r.get("path"),
                       "code": r.get("code") or ""}, ensure_ascii=False)


async def t_mitre_lookup(technique_id: str) -> str:
    """Look up a MITRE ATT&CK technique (e.g. T1190, T1059.004) -> description,
    procedure examples (real threat-actor usage), and mitigations. Source: attack.mitre.org."""
    tid = re.sub(r"[^A-Za-z0-9.]", "", (technique_id or "").strip())
    if not tid:
        return "ERR: no technique id"
    path = tid.replace(".", "/")
    # fetch RAW html (not stripped) so we can parse selectors
    try:
        r = await (await _httpc()).get(f"https://attack.mitre.org/techniques/{path}/", timeout=15.0)
        if r.status_code >= 400:
            return f"MITRE {tid}: HTTP {r.status_code}"
        html = r.text
    except Exception as e:
        return f"MITRE {tid}: ERR {type(e).__name__}: {e}"
    soup = BeautifulSoup(html, "lxml")
    desc = ""
    d = soup.select_one(".description-body")
    if d:
        desc = d.get_text(" ", strip=True)
    # procedure examples (real-world usage by threat actors)
    procs: list[str] = []
    for h2 in soup.find_all("h2"):
        if "Procedure Examples" in h2.get_text():
            tbl = h2.find_next("table")
            if tbl:
                for row in (tbl.select("tbody tr") or [])[:5]:
                    cells = row.find_all("td")
                    if len(cells) >= 3:
                        procs.append(f"{cells[0].get_text(strip=True)} / {cells[1].get_text(strip=True)}: {cells[2].get_text(' ', strip=True)[:120]}")
            break
    # mitigations
    mits: list[str] = []
    for h2 in soup.find_all("h2"):
        if "Mitigation" in h2.get_text():
            tbl = h2.find_next("table")
            if tbl:
                for row in (tbl.select("tbody tr") or [])[:5]:
                    cells = row.find_all("td")
                    if len(cells) >= 2:
                        mits.append(f"{cells[0].get_text(strip=True)}: {cells[1].get_text(' ', strip=True)[:120]}")
            break
    out = [f"[MITRE ATT&CK] {tid}", f"Description: {desc[:500]}"]
    if procs:
        out.append("Procedure examples (real-world usage):")
        out.extend(f"  - {p}" for p in procs)
    if mits:
        out.append("Mitigations:")
        out.extend(f"  - {m}" for m in mits)
    return "\n".join(out)


async def t_run_poc_check(scan_id: str, cve: str, target: str) -> str:
    """Run the saved PoC's --check mode against the target and return its real output
    (incl. the [EXPLOITABLE]/[NOT EXPLOITABLE] verdict line). This is GROUNDED verification —
    the verdict comes from actual execution, not LLM claim.
    Auto-normalizes target URL scheme (https/http) if not provided."""
    import asyncio as _aio
    # auto-scheme: ensure target has http:// or https://
    target = (target or "").strip()
    if target and not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        from db import get_poc
        r = await get_poc(scan_id, cve)
    except Exception as e:
        return f"ERR db: {e}"
    if not r or not r.get("path"):
        return "No PoC saved yet. Call save_poc first, then run_poc_check."
    path = r["path"]
    # ensure file exists (restore from db code if missing)
    if not os.path.exists(path) and r.get("code"):
        config.POC.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(r["code"])
    if not os.path.exists(path):
        return f"PoC file missing: {path}"
    try:
        proc = await _aio.create_subprocess_exec(
            "python3", path, "--target", target, "--check",
            stdout=_aio.subprocess.PIPE, stderr=_aio.subprocess.PIPE)
        stdout, stderr = await _aio.wait_for(proc.communicate(), timeout=90)
        out = (stdout.decode(errors="replace") or "") + "\n[stderr]\n" + (stderr.decode(errors="replace") or "")
        return json.dumps({"returncode": proc.returncode, "output": out[:6000]},
                          ensure_ascii=False)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        # kill the orphaned python3 process — a cancel from an outer wait_for (e.g.
        # verify's 600s cap) would otherwise leave it hammering the target forever
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return json.dumps({"returncode": -1, "output": "TIMEOUT after 90s"}, ensure_ascii=False)
    except Exception as e:
        return f"ERR run: {type(e).__name__}: {e}"


# tool registry: name -> (fn, arg names, description)
TOOLS = {
    "detect_stack": (t_detect_stack, ["url"],
        "Probe a website target. Returns CMS, installed plugins/themes/services with versions and evidence. Call FIRST."),
    "search_vuln": (t_search_vuln, ["query", "version"],
        "Search all vuln DBs (NVD, OSV, GitHub Advisory, ExploitDB, Wordfence, KEV, PoC-GitHub, ...) for a product name or CVE. Pass installed version to auto-label match."),
    "fetch_cve_detail": (t_fetch_cve_detail, ["cve"],
        "Get full grounded context for one CVE: description, affected ranges, patch/diff URL, PoC refs, exploit source code."),
    "version_match": (t_version_match, ["cve", "version"],
        "Decide if an installed version is VULNERABLE / NOT_AFFECTED / UNKNOWN against a CVE's exact ranges."),
    "webfetch": (t_webfetch, ["url", "max_chars"],
        "Fetch any URL as cleaned text. Use to read advisories, PoC pages, vendor bulletins."),
    "save_poc": (t_save_poc, ["scan_id", "cve", "code", "filename"],
        "Save a generated PoC script (.py) to disk + db. Pass the full code. Returns file path."),
    "list_pocs": (t_list_pocs, ["scan_id"],
        "List PoC scripts you (the agent) generated for a scan — cve, path, code preview. Use to recall your own PoCs."),
    "get_poc": (t_get_poc, ["scan_id", "cve"],
        "Return the FULL PoC script code you generated for a CVE in a scan. Use when asked to show/explain a PoC you made."),
    "run_poc_check": (t_run_poc_check, ["scan_id", "cve", "target"],
        "Run the saved PoC's --check mode against the target → real output incl. [EXPLOITABLE]/[NOT EXPLOITABLE] verdict. "
        "Use to VERIFY exploitability from actual execution (not your own claim). If NOT EXPLOITABLE, analyze the output "
        "and try a different method/payload/endpoint, then save_poc + run_poc_check again. Do NOT give up after one try."),
    "mitre_lookup": (t_mitre_lookup, ["technique_id"],
        "Look up a MITRE ATT&CK technique (e.g. T1190 exploit public-facing app, T1059 command exec, T1078 valid accounts, "
        "T1505.003 web shell) → description, real-world threat-actor procedure examples, mitigations. Use to add attack-scenario "
        "context to a CVE/finding (map the vuln type to a technique id)."),
}


async def dispatch(name: str, args: dict) -> str:
    if name not in TOOLS:
        return f"unknown tool: {name}"
    fn, params, _ = TOOLS[name]
    call_args = {k: args.get(k) for k in params if k in args and args.get(k) is not None}
    try:
        return await fn(**call_args)
    except Exception as e:
        return f"tool {name} ERR {type(e).__name__}: {e}"


async def close_all():
    global _http, _scrapers
    if _http is not None:
        await _http.aclose(); _http = None
    if _scrapers is not None:
        for s in _scrapers:
            try:
                await s.close()
            except Exception:
                pass
        _scrapers = None  # force rebuild — closed clients must not be reused

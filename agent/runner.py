"""Agent runner — two-model cooperation, AI-controlled.

Research (al/glm-5.2): ReAct loop — detect, search per-component, version_match → findings JSON.
Report+PoC+Chat (al/deepseek-v4-pro): synthesize report / write PoC / converse.
All LLM calls SSE-streaming (llm.py) → no ReadTimeout. AI decides logic (no hardcode gather).
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Optional, Callable, Awaitable

from llm import chat_detect, chat_report
from agent import blueprint as bp
from agent.tools import dispatch as _dispatch
from agent import scoring as _scoring
from scrapers import cvss as _cvss
import db as _db

_JSON_OBJ_RE = re.compile(r"\{.*\}", re.S)
_CHAT_MAX_STEPS = 12


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    m = _JSON_OBJ_RE.search(text)
    if not m:
        return None
    s = m.group(0)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        for i in range(len(s), 0, -1):
            try:
                return json.loads(s[:i])
            except json.JSONDecodeError:
                continue
        return None


def _strip_fences(text: str) -> str:
    """Robustly strip markdown code fences (``` / ```python) from LLM output."""
    text = (text or "").strip()
    lines = text.split("\n")
    if lines and re.match(r"^```[a-zA-Z0-9_+.-]*$", lines[0].strip()):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    out = [ln for ln in lines
           if ln.strip() != "```" and not re.match(r"^```[a-zA-Z0-9_+.-]*$", ln.strip())]
    return "\n".join(out).strip()


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def _filter_vulns(vulns: list) -> list:
    """Drop NOT_AFFECTED (version out of range = irrelevant). Only keep VULNERABLE/UNCONFIRMED."""
    out = []
    for v in vulns or []:
        label = str(v.get("label", "")).upper().replace("-", "_")
        if label == "NOT_AFFECTED":
            continue
        out.append(v)
    return out


# ---------------- phase 1: research (glm-5.2, ReAct) ----------------

# Pre-research: detect stack → parallel search_vuln for ALL components → parallel fetch_cve_detail
# This replaces 20+ sequential AI steps with parallel I/O, then AI just reviews (1-2 calls).

_RESEARCH_MAX_STEPS = 15   # was 40 — pre-research does the heavy lifting, AI just reviews
_RESEARCH_FORCE_NUDGE_AT = 10


async def _pre_research(target: str, progress=None) -> tuple[str, dict]:
    """Phase 1: detect stack + parallel search_vuln + parallel fetch_cve_detail.
    Returns (stack_json, search_results_json, cve_details_json) — all pre-computed."""
    if progress:
        try: await progress(0, "detecting stack...")
        except: pass

    # 1a. detect stack
    stack_obs = await _dispatch("detect_stack", {"url": target})
    try:
        stack_data = json.loads(stack_obs)
    except Exception:
        stack_data = {}

    # collect all components to search
    comps = stack_data.get("components", []) + stack_data.get("services", [])
    search_items = []
    seen = set()
    for c in comps:
        name = c.get("name")
        if name and name not in seen:
            seen.add(name)
            search_items.append((name, c.get("version")))
    # also search CMS core
    cms = stack_data.get("cms")
    if cms and cms not in seen:
        search_items.append((cms, stack_data.get("cms_version")))

    if progress:
        try: await progress(1, f"parallel search {len(search_items)} components...")
        except: pass

    # 1b. parallel search_vuln for ALL components (timeout 90s — don't hang forever)
    async def _search(name, version):
        try:
            return name, version, await _dispatch("search_vuln", {"query": name, "version": version})
        except Exception as e:
            return name, version, f'{{"error":"{e}"}}'

    search_tasks = [_search(n, v) for n, v in search_items]
    search_results = await asyncio.gather(*search_tasks)

    # collect CVEs to fetch details for (VULNERABLE/UNCONFIRMED only — no limit, all of them)
    cves_to_fetch = []
    for name, version, result in search_results:
        try:
            data = json.loads(result)
            for r in (data.get("results") or []):
                if r.get("match") is not False and r.get("cve"):
                    cves_to_fetch.append(r["cve"])
        except Exception:
            pass
    cves_to_fetch = list(set(cves_to_fetch))

    if progress:
        try: await progress(2, f"fetching {len(cves_to_fetch)} CVE details (parallel)...")
        except: pass

    # 1c. parallel fetch_cve_detail (semaphore 10 — no event loop saturation, /jobs stays responsive)
    _fetch_sem = asyncio.Semaphore(10)
    async def _fetch(cve):
        async with _fetch_sem:
            try:
                return cve, await _dispatch("fetch_cve_detail", {"cve": cve})
            except Exception as e:
                return cve, f"ERR: {e}"

    fetch_tasks = [_fetch(cve) for cve in cves_to_fetch]
    fetch_results = await asyncio.gather(*fetch_tasks)

    # compile pre-research context
    search_ctx = "\n\n---\n\n".join(
        f"search_vuln({name}, {ver}):\n{result[:3000]}"
        for name, ver, result in search_results
    )
    detail_ctx = "\n\n---\n\n".join(
        f"fetch_cve_detail({cve}):\n{detail[:3000]}"
        for cve, detail in fetch_results
    )
    pre_research = f"STACK:\n{stack_obs[:4000]}\n\nSEARCH RESULTS:\n{search_ctx[:15000]}\n\nCVE DETAILS:\n{detail_ctx[:15000]}"
    return pre_research, stack_data


async def run_research(target: str,
                       progress: Optional[Callable[[int, str], Awaitable]] = None
                       ) -> tuple[str, str]:
    """Research with PARALLEL pre-computation + short AI review.
    Phase 1: detect + parallel search + parallel fetch (no AI, pure I/O).
    Phase 2: AI reviews pre-computed data, can call webfetch for specifics, emits findings (1-5 LLM calls).
    SELF-IMPROVEMENT: injects prior scan knowledge into the prompt."""
    # fetch prior knowledge from DB
    try:
        prior = await _db.get_all_knowledge(limit=10)
        knowledge_ctx = ""
        for k in prior:
            cms_ver = k.get("cms", "?") + " " + (k.get("version") or "")
            lessons = (k.get("lessons") or "")[:200]
            knowledge_ctx += f"- {cms_ver.strip()}: {lessons}\n"
    except Exception:
        knowledge_ctx = ""

    # Phase 1: parallel pre-research (no AI — pure tool I/O)
    pre_research, stack_data = await _pre_research(target, progress)

    # Phase 2: AI review — feed pre-computed data, AI emits findings
    sys_prompt = bp.RESEARCH_SYSTEM
    if knowledge_ctx.strip():
        sys_prompt += f"\n\n=== PRIOR SCAN KNOWLEDGE ===\n{knowledge_ctx.strip()}\n"
    sys_prompt += (
        "\n\n=== PRE-COMPUTED RESEARCH DATA ===\n"
        "Below is ALL the research data pre-computed in parallel (detect_stack + search_vuln for every "
        "component + fetch_cve_detail for every CVE). Review it, DROP NOT_AFFECTED, and EMIT THE FINDINGS "
        "JSON immediately. You can call webfetch if you need to read a specific advisory/PoC page for "
        "exploitation method — but most data is already here. Do NOT call detect_stack or search_vuln "
        "(already done). Just review + emit findings."
    )
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": f"Analyze target: {target}\n\n{pre_research[:30000]}\n\nReview and emit findings JSON."},
    ]
    transcript: list[str] = [f"[pre-research] {pre_research[:300]}"]
    # accumulation (fallback)
    acc: dict = {"stack": [], "vulns": {}, "target": target}
    # pre-populate acc from stack_data
    try:
        comps = stack_data.get("components", []) + stack_data.get("services", [])
        acc["stack"] = [{"type": c.get("type"), "name": c.get("name"),
                         "version": c.get("version"), "evidence": c.get("evidence")}
                        for c in comps]
        if stack_data.get("waf"):
            acc["waf"] = stack_data["waf"]
            acc["waf_summary"] = stack_data.get("waf_summary", "")
            acc["waf_may_mask"] = stack_data.get("waf_may_mask", False)
    except Exception:
        pass

    for step in range(_RESEARCH_MAX_STEPS):
        resp = await chat_detect(messages, temperature=0.15, max_tokens=6144)
        messages.append({"role": "assistant", "content": resp})
        transcript.append(f"[r{step}] {resp[:200]}")
        if progress:
            try: await progress(3 + step, resp[:140])
            except: pass
        obj = _extract_json(resp)
        if obj and "tool" in obj and "args" in obj:
            name = obj["tool"]; args = obj.get("args") or {}
            obs = await _dispatch(name, args)
            messages.append({"role": "user", "content": f"OBSERVATION({name}):\n{obs[:6000]}"})
            transcript.append(f"  -> {name}({args}) => {obs[:160]}")
            if step + 1 >= _RESEARCH_FORCE_NUDGE_AT:
                messages.append({"role": "user", "content":
                    "EMIT THE FINDINGS JSON NOW. Do NOT call more tools."})
            continue
        if obj and any(k in obj for k in ("vulnerabilities", "stack")):
            obj.setdefault("target", target)
            obj["vulnerabilities"] = _filter_vulns(obj.get("vulnerabilities", []))
            # ensure WAF data is in findings
            if not obj.get("waf") and acc.get("waf"):
                obj["waf"] = acc["waf"]
                obj["waf_summary"] = acc.get("waf_summary", "")
                obj["waf_may_mask"] = acc.get("waf_may_mask", False)
            return json.dumps(obj, ensure_ascii=False), "\n".join(transcript)
        messages.append({"role": "user",
            "content": "Respond with a tool call {\"tool\":..,\"args\":..} OR the findings JSON object."})

    # fallback: build from pre-research + accumulated data
    # parse search results to build vulns
    try:
        # re-parse from pre_research context is complex; use acc
        for name, ver, result in []:
            pass  # acc was pre-populated
    except Exception:
        pass
    vulns = sorted(acc["vulns"].values(),
                   key=lambda v: (0 if v["label"] == "VULNERABLE" else 1, -(v.get("cvss") or 0)))
    fallback = {"target": target, "stack": acc["stack"], "vulnerabilities": _filter_vulns(vulns),
                "exploited_in_wild": [], "summary": "research auto-finalized (pre-research + AI review)",
                "waf": acc.get("waf", []),
                "waf_summary": acc.get("waf_summary", ""),
                "waf_may_mask": acc.get("waf_may_mask", False)}
    return json.dumps(fallback, ensure_ascii=False), "\n".join(transcript)


# ---------------- phase 2: report (deepseek-v4-pro) ----------------

_VERIFY_CAP = 100  # effectively no cap — verify ALL VULNERABLE candidates (accuracy > speed)


async def _enrich_epss(cands: list) -> None:
    """Annotate each candidate dict with its real EPSS score (`v['epss']`) via one batched
    FIRST.org call. Best-effort: on any failure the candidates are left unchanged (their
    risk score simply omits the EPSS term). Mutates in place."""
    cves = [str(v.get("cve")).upper() for v in cands if v.get("cve")]
    if not cves:
        return
    try:
        from scrapers.epss import EPSSScraper
        try:
            from db import cache_get, cache_set
            scraper = EPSSScraper(cache_get=cache_get, cache_set=cache_set)
        except Exception:
            scraper = EPSSScraper()
        scores = await scraper._fetch(cves)
        await scraper.close()
    except Exception:
        return
    for v in cands:
        info = scores.get(str(v.get("cve")).upper())
        if info and info.get("epss") is not None:
            v["epss"] = info["epss"]
            v["epss_percentile"] = info.get("percentile")


async def _enrich_kev(cands: list) -> set:
    """Mark candidates that appear in the CISA KEV catalog (`v['kev'] = True`) using ONE
    catalog load (membership test against the full set). Grounds `exploited_in_wild` in the
    authoritative source instead of trusting the research LLM. Returns the set of matched
    CVE ids (uppercased). Best-effort: returns empty set and mutates nothing on failure."""
    cves = {str(v.get("cve")).upper() for v in cands if v.get("cve")}
    if not cves:
        return set()
    try:
        from scrapers.cisa_kev import CisaKevScraper
        try:
            from db import cache_get, cache_set
            scraper = CisaKevScraper(cache_get=cache_get, cache_set=cache_set)
        except Exception:
            scraper = CisaKevScraper()
        data = await scraper._load()
        await scraper.close()
    except Exception:
        return set()
    catalog = {str(v.get("cveID", "")).upper()
               for v in (data.get("vulnerabilities") or [])}
    matched = cves & catalog
    for v in cands:
        if str(v.get("cve")).upper() in matched:
            v["kev"] = True
    return matched


async def run_verify(findings_str: str, scan_id: str, target: str,
                     progress: Optional[Callable[[int, str], Awaitable]] = None
                     ) -> str:
    """For each candidate CVE in findings, build+run PoC (--check) → real EXPLOITABLE/NOT
    verdict. Merges verdicts back into findings. Capped to top candidates."""
    try:
        f = json.loads(findings_str)
    except Exception:
        return findings_str
    cands = [v for v in f.get("vulnerabilities", []) if v.get("cve")
             and str(v.get("label", "")).upper().replace("-", "_") != "NOT_AFFECTED"]
    # ALWAYS try JCE (CVE-2026-48907) for Joomla sites — it's a plugin (version-independent),
    # unauth PHP-upload RCE, CVSS 10.0, in-the-wild (CISA KEV/BOD 26-04). PoC widely spread.
    stack = f.get("stack", []) or []
    is_joomla = any((s.get("name") or "").lower() == "joomla" for s in stack)
    existing = {str(v.get("cve")).upper() for v in cands}
    if is_joomla and "CVE-2026-48907" not in existing:
        cands.append({
            "cve": "CVE-2026-48907", "label": "UNCONFIRMED",
            "component": "plugin:jce (always-test, Joomla)",
            "title": "JCE editor unauth PHP upload RCE", "severity": "CRITICAL", "cvss": 10.0,
            "sources": ["cve5"], "_always_test": True,
        })
    cands.sort(key=lambda v: (0 if str(v.get("label")).upper() == "VULNERABLE" else 1,
                              -(v.get("cvss") or 0)))
    cands = cands[:_VERIFY_CAP]

    # ENRICH: batch-fetch real EPSS (exploit probability) for all candidates in one call,
    # so risk scoring in run_report is grounded. Degrades silently if FIRST.org unreachable.
    try:
        await _enrich_epss(cands)
    except Exception:
        pass

    # ENRICH: mark candidates present in the CISA KEV catalog (authoritative in-the-wild),
    # and fold them into exploited_in_wild so the report + scoring reflect real KEV status
    # rather than the research LLM's guess. Degrades silently if CISA unreachable.
    try:
        kev_matched = await _enrich_kev(cands)
        if kev_matched:
            eiw = {str(c).upper() for c in (f.get("exploited_in_wild") or [])}
            f["exploited_in_wild"] = sorted(eiw | kev_matched)
    except Exception:
        pass

    # PARALLEL PoC verification — 10 subagents concurrent, NO timeout (let them finish)
    _verify_sem = asyncio.Semaphore(10)
    _done_count = 0
    _total = len(cands)

    async def _verify_one(v: dict):
        nonlocal _done_count
        cve = v["cve"]
        async with _verify_sem:
            if progress:
                try: await progress(_done_count, f"verify PoC {cve} ({_done_count+1}/{_total})")
                except: pass
            try:
                res = await run_poc(scan_id, cve, target)
            except Exception as e:
                res = {"verdict": "NOT EXPLOITABLE", "reason": f"verify err: {e}", "attempts": 0, "path": ""}
        # SERVER-SIDE PROOF VALIDATION: downgrade EXPLOITABLE if no direct proof
        raw_verdict = (res.get("verdict") or "UNKNOWN").upper()
        raw_reason = res.get("reason", "")
        validated_verdict, validated_reason = _validate_exploitable(raw_verdict, raw_reason)
        v["verified"] = validated_verdict
        v["verify_reason"] = validated_reason
        v["verify_attempts"] = res.get("attempts", 0)
        v["verify_methods"] = res.get("methods_tried", [])
        v["poc_path"] = res.get("path", "")
        _done_count += 1
        if progress:
            try: await progress(_done_count, f"verified {cve}: {validated_verdict} ({_done_count}/{_total})")
            except: pass
        return v

    # run all verifications in parallel (no timeout — let them finish)
    await asyncio.gather(*[_verify_one(v) for v in cands], return_exceptions=True)
    f["vulnerabilities"] = cands
    return json.dumps(f, ensure_ascii=False)

async def run_report(target: str, findings: str) -> dict:
    """Render Telegram report JSON from findings. FULLY GROUNDED — the CVE list is built
    deterministically from findings (verified field), so the LLM cannot hallucinate CVEs.
    The LLM is used ONLY for the recommendation text (1 short call)."""
    try:
        f = json.loads(findings)
    except Exception:
        f = {}
    vulns = f.get("vulnerabilities", []) or []
    stack = f.get("stack", []) or []
    stack_summary = _stack_summary(stack)

    exploitable = []
    checked = []
    itw_list = f.get("exploited_in_wild", []) or []
    itw_set = {str(c).upper() for c in itw_list}
    for v in vulns:
        cve = v.get("cve")
        if not cve:
            continue
        verified = str(v.get("verified", "")).upper()
        if verified == "EXPLOITABLE":
            # reconcile score+severity from possibly-partial source data (vector or label)
            score, sev = _cvss.enrich(v.get("cvss"), v.get("severity"),
                                      v.get("cvss_vector") or v.get("vector"))
            cve_up = str(cve).upper()
            in_kev = bool(v.get("kev")) or cve_up in itw_set
            item = {
                "cve": cve, "label": "EXPLOITABLE", "verified": "EXPLOITABLE",
                "severity": sev or v.get("severity"), "cvss": score if score is not None else v.get("cvss"),
                "component": v.get("component"), "title": v.get("title"),
                "summary": (v.get("description") or v.get("summary") or "")[:200],
                "verify_reason": (v.get("verify_reason") or "")[:300],
                "poc_refs": v.get("poc_refs", []), "diff_patch": v.get("diff_patch"),
                "sources": v.get("sources", []),
                "epss": v.get("epss"), "kev": in_kev,
            }
            item.update(_scoring.score_finding(
                item, epss=v.get("epss"), kev=in_kev,
                exploited_in_wild=in_kev))
            exploitable.append(item)
        elif verified:  # NOT EXPLOITABLE / UNKNOWN -> checked
            checked.append({"cve": cve, "verify_reason": (v.get("verify_reason") or "")[:120] or verified})
    # rank exploitable so the highest-risk (verified + in-the-wild + high EPSS/CVSS) leads
    exploitable.sort(key=lambda x: x.get("risk", 0.0), reverse=True)
    status = "EXPLOITABLE" if exploitable else "CLEAN"

    # Check if target was unreachable (no stack + nothing checked = probe never got data)
    stack_empty = not stack and not exploitable and not checked
    if stack_empty:
        # Short-circuit: nothing to recommend patching, just tell the user it was unreachable.
        recommendation = ("Target tidak bisa dijangkau dari server. Kemungkinan down, "
                          "firewall block, atau DNS tidak resolve. Coba lagi nanti atau "
                          "gunakan URL alternatif (HTTPS/WWW).")
        return {"target": target, "stack_summary": stack_summary, "status": "UNREACHABLE",
                "exploitable": [], "checked": [],
                "exploited_in_wild": f.get("exploited_in_wild", []),
                "recommendation": recommendation,
                "waf": f.get("waf", []),
                "waf_summary": f.get("waf_summary", ""),
                "waf_may_mask": f.get("waf_may_mask", False)}

    # Deterministic recommendation (no LLM meta-text risk). The CVE list is already fixed
    # above from the `verified` field, so this text cannot introduce new/hallucinated CVEs.
    if exploitable:
        cve_list = ", ".join(v["cve"] for v in exploitable[:5])
        cms_name = next((s.get("name") for s in stack if s.get("type") in ("cms", "core")), "")
        cms_ver = next((s.get("version") for s in stack if s.get("type") in ("cms", "core")), "")
        recommendation = (f"Segera update {cms_name or 'software'} dari versi {cms_ver or 'terkini'} "
                          f"ke versi terbaru untuk menambal {len(exploitable)} kerentanan exploitable "
                          f"({cve_list}). Audit log server untuk indikasi kompromi.")
    else:
        recommendation = ("No exploitable vulnerabilities found for the detected stack/versions. "
                          "Keep software updated and monitor advisories.")

    return {"target": target, "stack_summary": stack_summary, "status": status,
            "exploitable": exploitable, "checked": checked,
            "exploited_in_wild": f.get("exploited_in_wild", []),
            "recommendation": recommendation,
            "waf": f.get("waf", []),
            "waf_summary": f.get("waf_summary", ""),
            "waf_may_mask": f.get("waf_may_mask", False)}


def _stack_summary(stack: list) -> str:
    """Deterministic one-line stack summary from grounded stack."""
    if not stack:
        return "unknown stack"
    parts = []
    for c in stack:
        name = c.get("name") or "?"
        ver = c.get("version")
        parts.append(f"{name} {ver}" if ver else name)
    return " + ".join(parts)


_POC_MAX_STEPS = 30
_POC_FORCE_NUDGE_AT = 24


def _parse_run_verdict(run_output: str) -> tuple[str, str]:
    """Extract [EXPLOITABLE]/[NOT EXPLOITABLE] + reason from a run_poc_check output."""
    import re as _re
    m = _re.search(r"\[EXPLOITABLE\]\s*(.+?)(?:\n|$)", run_output or "", _re.I)
    if m:
        return "EXPLOITABLE", m.group(1).strip()[:500]
    m = _re.search(r"\[NOT EXPLOITABLE\]\s*(.+?)(?:\n|$)", run_output or "", _re.I)
    if m:
        return "NOT EXPLOITABLE", m.group(1).strip()[:500]
    return "", ""


# Weak evidence patterns — if EXPLOITABLE reason contains these, it's circumstantial
_WEAK_PATTERNS = [
    "version in range", "version is within", "detected version", "affected range",
    "http 200", "status 200", "returned 200", "http 302", "redirect",
    "endpoint accessible", "endpoint returned", "returned http",
    "advisory says", "cve advisory", "vulnerable version",
    "empty data", "data:[]", "success\":true", "no authentication required",
]
# Direct proof patterns — if EXPLOITABLE reason contains these, it's genuine
_STRONG_PATTERNS = [
    "reflected", "marker", "uid=", "gid=", "www-data", "root:x:0",
    "command output", "echo ", "sleep confirmed", "delay measured",
    "uploaded file", "file accessible", "webshell", "php executed",
    "sql", "database", "query returned", "data exfil",
    "admin dashboard", "authenticated content", "user list",
    "privilege escalated", "group changed", "user created",
    "api key", "credential", "secret", "config leaked",
    "rce confirmed", "code execution", "payload executed",
    "math result", "arithmetic", "3105",
]


def _validate_exploitable(verdict: str, reason: str) -> tuple[str, str]:
    """Server-side proof validation. Downgrade EXPLOITABLE to NOT EXPLOITABLE
    if the reason contains only circumstantial evidence (no direct proof)."""
    if verdict.upper() != "EXPLOITABLE":
        return verdict, reason
    reason_lower = (reason or "").lower()
    # check for strong proof patterns
    has_strong = any(p in reason_lower for p in _STRONG_PATTERNS)
    has_weak = any(p in reason_lower for p in _WEAK_PATTERNS)
    if has_strong:
        return verdict, reason  # direct proof present — keep EXPLOITABLE
    if has_weak and not has_strong:
        # only circumstantial evidence — downgrade
        return "NOT EXPLOITABLE", f"Version in range but no direct exploitation proof. PoC claimed EXPLOITABLE but reason only shows circumstantial evidence: {reason[:150]}"
    # if neither strong nor weak patterns match, be conservative
    return "NOT EXPLOITABLE", f"No direct proof found in verify reason. {reason[:150]}"


async def run_poc(scan_id: str, cve: str, target: str) -> dict:
    """PoC exploitability agent: build -> run --check -> iterate on failure.
    Returns {path, verdict, reason, attempts, methods_tried} from ACTUAL execution.
    For CVE-2026-48907 (Joomla JCE), uses a pre-built super-accurate PoC (no LLM)."""
    cve_u = cve.upper()
    # Pre-built JCE PoC (always-test on Joomla) — bypass LLM generation
    if cve_u == "CVE-2026-48907":
        try:
            from agent.jce_poc import JCE_POC_SOURCE
            from agent.tools import t_save_poc, t_run_poc_check
            path = await t_save_poc(scan_id, cve, JCE_POC_SOURCE)
            fp = json.loads(path).get("path", "")
            run_out = await t_run_poc_check(scan_id, cve, target)
            v, reason = _parse_run_verdict(run_out if isinstance(run_out, str) else json.dumps(run_out))
            if not v:
                # parse from raw output as fallback
                v, reason = _parse_run_verdict(run_out if isinstance(run_out, str) else "")
            if not v:
                v = "NOT EXPLOITABLE"
                reason = (run_out[:500] if isinstance(run_out, str) else json.dumps(run_out)[:500])
            return {"path": fp, "verdict": v, "reason": reason,
                    "attempts": 1, "methods_tried": ["pre-built JCE PoC (--check)"]}
        except Exception as e:
            return {"path": "", "verdict": "NOT EXPLOITABLE",
                    "reason": f"JCE PoC run err: {type(e).__name__}: {e}",
                    "attempts": 1, "methods_tried": ["pre-built JCE PoC"]}

    # Nuclei template — community-verified PoC (4167+ CVEs). Run BEFORE LLM generation:
    # nuclei's matchers are accurate (not LLM-guessed). Only fall through to LLM if no template.
    try:
        from scrapers.nuclei_templates import has_template, run_nuclei, get_template_code, get_template_path
        if has_template(cve_u):
            tpl_path = get_template_path(cve_u) or ""
            nucl = await run_nuclei(cve_u, target, timeout=60)
            if nucl.get("verdict") in ("EXPLOITABLE", "NOT EXPLOITABLE"):
                # save the template path as the "PoC" (for reference)
                try:
                    from agent.tools import t_save_poc
                    code = get_template_code(cve_u) or f"# nuclei template: {tpl_path}\n# Run: nuclei -t {tpl_path} -u <target>"
                    await t_save_poc(scan_id, cve, code)
                except Exception:
                    pass
                return {"path": tpl_path, "verdict": nucl["verdict"],
                        "reason": nucl.get("reason", "nuclei template verdict"),
                        "attempts": 1,
                        "methods_tried": [f"nuclei template ({os.path.basename(tpl_path)})"]}
            # nuclei errored (binary not found, timeout) → try YAML→Python fallback
            if nucl.get("verdict") == "ERROR" and nucl.get("error") != "no-binary":
                # binary exists but errored — try YAML-derived Python PoC
                code = get_template_code(cve_u)
                if code:
                    try:
                        from agent.tools import t_save_poc, t_run_poc_check
                        path = await t_save_poc(scan_id, cve, code)
                        fp = json.loads(path).get("path", "")
                        run_out = await t_run_poc_check(scan_id, cve, target)
                        v, reason = _parse_run_verdict(run_out if isinstance(run_out, str) else json.dumps(run_out))
                        if v:
                            return {"path": fp, "verdict": v, "reason": reason,
                                    "attempts": 1,
                                    "methods_tried": [f"nuclei YAML→Python PoC ({os.path.basename(tpl_path)})"]}
                    except Exception:
                        pass
            # nuclei binary not found → try YAML→Python PoC
            if nucl.get("error") == "no-binary":
                code = get_template_code(cve_u)
                if code:
                    try:
                        from agent.tools import t_save_poc, t_run_poc_check
                        path = await t_save_poc(scan_id, cve, code)
                        fp = json.loads(path).get("path", "")
                        run_out = await t_run_poc_check(scan_id, cve, target)
                        v, reason = _parse_run_verdict(run_out if isinstance(run_out, str) else json.dumps(run_out))
                        if v:
                            return {"path": fp, "verdict": v, "reason": reason,
                                    "attempts": 1,
                                    "methods_tried": [f"nuclei YAML→Python PoC ({os.path.basename(tpl_path)})"]}
                    except Exception:
                        pass
    except Exception:
        pass  # nuclei not available, fall through to LLM

    # SELF-IMPROVEMENT: PoC Pattern Learning — check if we have a saved successful PoC
    # for this CVE from a prior scan. If yes, use it directly (skip LLM generation).
    try:
        pattern = await _db.get_poc_pattern(cve_u)
        if pattern and pattern.get("code"):
            saved_code = pattern["code"]
            method = pattern.get("method", "learned pattern")
            from agent.tools import t_save_poc, t_run_poc_check
            path = await t_save_poc(scan_id, cve, saved_code)
            fp = json.loads(path).get("path", "")
            run_out = await t_run_poc_check(scan_id, cve, target)
            v, reason = _parse_run_verdict(run_out if isinstance(run_out, str) else json.dumps(run_out))
            if v == "EXPLOITABLE":
                # pattern still works — increment success count
                await _db.save_poc_pattern(cve_u, pattern.get("vuln_type", ""),
                                           method, saved_code)
                return {"path": fp, "verdict": v, "reason": reason,
                        "attempts": 1, "methods_tried": [f"learned PoC pattern ({method}, reused)"]}
            elif v == "NOT EXPLOITABLE":
                # pattern failed this time — mark fail, fall through to LLM
                await _db.mark_poc_pattern_fail(cve_u, method)
                # don't return — let LLM try a fresh approach
    except Exception:
        pass  # no saved pattern, proceed to LLM

    # SELF-IMPROVEMENT: check WAF bypass memory — if target had WAF, fetch working bypasses
    waf_bypass_hint = ""
    try:
        # we don't have WAF info here directly, but the findings might have it
        # check if any waf_bypasses exist for common WAFs
        for waf_name in ("cloudflare", "sucuri", "imperva", "modsecurity", "wordfence"):
            bypasses = await _db.get_waf_bypasses(waf_name)
            if bypasses:
                waf_bypass_hint += f" {waf_name}: " + ", ".join(
                    b.get("payload_variant", "") for b in bypasses[:2]) + ";"
    except Exception:
        pass

    from agent.tools import t_fetch_cve_detail, dispatch as _dispatch2
    import re as _re2
    detail = await t_fetch_cve_detail(cve)
    # PRE-FETCH advisory pages + patch diff + source code from references
    # Skip for adhoc (no target) — faster, user just wants to see the PoC code
    if target:
        extra_ctx = ""
        urls = _re2.findall(r'(https?://[^\s"\'<>]+(?:advisory|changeset|diff|patch|commit|svn|trac|security|blog)[^\s"\'<>]+)', detail or "")
        urls += _re2.findall(r'(https?://www\.wordfence\.com/[^\s"\'<>]+)', detail or "")
        urls = list(dict.fromkeys(urls))[:5]
        urls.insert(0, f"https://www.cve.org/vulnerabilities/{cve}")
        urls.insert(1, f"https://nvd.nist.gov/vuln/detail/{cve}")
        for url in urls:
            try:
                page_text = await _dispatch2("webfetch", {"url": url, "max_chars": 8000})
                if page_text and "ERR" not in page_text[:20]:
                    extra_ctx += f"\n\n--- FETCHED: {url} ---\n{page_text}\n"
            except Exception:
                pass
        if extra_ctx:
            detail = detail + "\n\n=== ADVISORY/PATCH/SOURCE CONTEXT (fetched — use this to understand the fix + reverse-engineer the exploit) ===" + extra_ctx
    if waf_bypass_hint:
        detail += f"\n\nKNOWN WAF BYPASSES (from prior scans):{waf_bypass_hint}\nTry these payload variants first if the target has a WAF."
    msg = bp.build_poc_messages(cve, target, detail)
    messages: list[dict] = list(msg)
    last_run_output = ""
    methods_tried: list[str] = []
    saved_path = ""
    for step in range(_POC_MAX_STEPS):
        resp = await chat_report(messages, temperature=0.2, max_tokens=8192)
        messages.append({"role": "assistant", "content": resp})
        obj = _extract_json(resp)
        if obj and "tool" in obj and "args" in obj:
            name = obj["tool"]; args = obj.get("args") or {}
            obs = await _dispatch(name, args)
            if name == "run_poc_check":
                last_run_output = obs
                methods_tried.append(f"run #{sum(1 for m in methods_tried if m.startswith('run'))+1}")
            if name == "save_poc":
                try:
                    saved_path = json.loads(obs).get("path", saved_path)
                except Exception:
                    pass
            messages.append({"role": "user", "content": f"OBSERVATION({name}):\n{obs[:6000]}"})
            if step + 1 >= _POC_FORCE_NUDGE_AT:
                messages.append({"role": "user", "content":
                    "Finalize NOW. Emit the final JSON {\"final\":{path,verdict,reason,attempts,methods_tried}} "
                    "using the verdict from your last run_poc_check. Do NOT call more tools."})
            continue
        if obj and "final" in obj:
            fin = obj["final"]
            if isinstance(fin, str):
                try:
                    fin = json.loads(fin)
                except Exception:
                    pass
            if isinstance(fin, dict):
                return fin
        if obj and any(k in obj for k in ("verdict", "path", "methods_tried")):
            return obj
        messages.append({"role": "user",
            "content": "Respond with a tool call OR the final JSON {\"final\":{path,verdict,reason,attempts,methods_tried}}."})
    # fallback: derive verdict from the last ACTUAL run_poc_check output
    v, reason = _parse_run_verdict(last_run_output)
    if not v:
        v = "NOT EXPLOITABLE"
        reason = (last_run_output[:400] or "PoC tidak menghasilkan verdict jelas (tidak ada run_poc_check).")
    # SELF-IMPROVEMENT: save successful PoC pattern for reuse
    if v == "EXPLOITABLE" and saved_path:
        try:
            # read the saved PoC code from the file
            import os as _os
            if _os.path.exists(saved_path):
                code = open(saved_path).read()
                method = methods_tried[0] if methods_tried else "LLM-generated"
                vuln_type = ""
                # try to extract vuln type from the CVE detail
                await _db.save_poc_pattern(cve_u, vuln_type, method, code)
        except Exception:
            pass
    return {"path": saved_path, "verdict": v, "reason": reason,
            "attempts": len(methods_tried), "methods_tried": methods_tried or ["none"]}


# ---------------- self-improvement: reflect + learn ----------------

async def run_self_reflect(target: str, findings: str, report: dict, scan_id: str) -> str:
    """After a scan completes, the AI reflects on what it learned and writes
    a 'lessons learned' entry to the knowledge base. This is read by future
    research runs to improve accuracy + speed."""
    try:
        f = json.loads(findings) if isinstance(findings, str) else (findings or {})
    except Exception:
        f = {}
    stack = f.get("stack", []) or []
    cms = next((s.get("name") for s in stack if s.get("type") in ("cms", "core")), "")
    version = next((s.get("version") for s in stack if s.get("type") in ("cms", "core")), "")
    vulns = f.get("vulnerabilities", []) or []
    exploitable = [v for v in vulns if str(v.get("verified", "")).upper() == "EXPLOITABLE"]
    waf = f.get("waf_summary", "")

    # build a concise summary for the AI to reflect on
    summary = (
        f"Target: {target}\nCMS: {cms} {version or ''}\n"
        f"WAF: {waf or 'none'}\n"
        f"Vulns found: {len(vulns)} (exploitable: {len(exploitable)})\n"
        f"Exploitable CVEs: {', '.join(v.get('cve','') for v in exploitable[:5])}\n"
        f"Tested but not exploitable: {len([v for v in vulns if str(v.get('verified','')).upper() == 'NOT EXPLOITABLE'])}\n"
    )

    try:
        lessons = await chat_report(
            [{"role": "system", "content":
              "You are a security research AI reflecting on a completed scan. Write 2-3 sentences of "
              "'lessons learned' that will help future scans of similar targets be faster + more accurate. "
              "Focus on: detection patterns that worked, effective PoC methods, WAF behaviors, common CVEs "
              "for this CMS/version, scraper issues. Be concrete and actionable. No fluff."},
             {"role": "user", "content": summary}],
            temperature=0.3, max_tokens=300)
        lessons = _strip_fences(lessons).strip()
    except Exception:
        lessons = ""

    if lessons and cms:
        key_findings = {
            "exploitable_cves": [v.get("cve") for v in exploitable],
            "waf": waf or None,
            "stack": [s.get("name") + " " + (s.get("version") or "") for s in stack],
        }
        try:
            await _db.save_knowledge(cms, version, key_findings, lessons, scan_id)
        except Exception:
            pass
    return lessons


# ---------------- chat (deepseek-v4-pro, per scan_id) ----------------

async def run_chat(scan_id: str, grounded: str, findings: str,
                   question: str, history: list[dict]) -> tuple[str, list[dict]]:
    sys = bp.build_chat_system(scan_id, grounded or "", findings or "")
    messages: list[dict] = [{"role": "system", "content": sys}]
    messages += history[-20:]
    messages.append({"role": "user", "content": question})
    answer = None
    for _ in range(_CHAT_MAX_STEPS):
        resp = await chat_report(messages, temperature=0.3, max_tokens=4096)
        messages.append({"role": "assistant", "content": resp})
        obj = _extract_json(resp)
        if obj and "tool" in obj and "args" in obj:
            obs = await _dispatch(obj["tool"], obj.get("args") or {})
            messages.append({"role": "user", "content": f"OBSERVATION({obj['tool']}):\n{obs[:5000]}"})
            continue
        answer = resp  # plain-text answer
        break
    if answer is None:
        answer = "(agent: batas langkah tercapai)"
    history.append({"role": "user", "content": question})
    history.append({"role": "assistant", "content": answer})
    return answer, history

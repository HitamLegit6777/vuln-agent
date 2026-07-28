"""Vuln Monitor — hourly check for new CVEs from feed scrapers.

Every 1 hour:
  1. Fetch latest CVEs from feed sources (wordfence RSS, CISA KEV, watchtowr, PoC-in-GitHub)
  2. Filter out already-sent CVEs (DB check)
  3. For each new CVE (max 5/hour):
     a. fetch_cve_detail (parallel)
     b. AI analysis (deepseek): summary, RCE chain, auth type, dorks
     c. Check nuclei template
     d. Format + send Telegram report to admin
     e. Mark as sent

No duplicates — each CVE sent only once.
Dorks generated for: Shodan, FOFA, Hunter.how (different format per source).
Works for all CMS: WP, Joomla, Magento, PHP, nginx, etc.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import httpx

from llm import chat_report
import db
from config import ALLOWED_USER_IDS

log = logging.getLogger("vuln-monitor")

_MONITOR_INTERVAL = 86400  # 24 hours
_MAX_NEW_PER_CYCLE = 5   # max 5 new CVEs per hour (avoid spam)

# Feed sources — scrapers that return recent CVEs without needing a specific query
# Covers ALL major web products: CMS, servers, languages, frameworks, panels
_FEED_QUERIES = [
    # CMS
    "wordpress", "joomla", "magento", "drupal", "prestashop", "vbulletin",
    "concrete5", "typo3", "opencart", "ghost", "grav",
    # Web servers + languages
    "php", "nginx", "apache", "iis", "lighttpd", "tomcat",
    # Frameworks
    "laravel", "django", "rails", "express", "next.js", "spring",
    # Panels + tools
    "cpanel", "plesk", "jenkins", "gitlab", "jira", "wordpress-plugin",
    # Runtimes + DBs
    "node.js", "redis", "mysql", "postgresql", "mongodb",
]


class VulnMonitor:
    def __init__(self, bot=None):
        self.bot = bot
        self.admin_id = ALLOWED_USER_IDS[0] if ALLOWED_USER_IDS else None
        self._running = False
        self._task = None

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        log.info("vuln monitor started (interval=%ds, admin=%s)", _MONITOR_INTERVAL, self.admin_id)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self):
        # first run: immediate (no delay)
        while self._running:
            try:
                await self._check_cycle()
            except Exception as e:
                log.exception("monitor cycle error: %s", e)
            await asyncio.sleep(_MONITOR_INTERVAL)

    async def _check_cycle(self):
        """One monitoring cycle: fetch feeds → filter new → analyze → send."""
        if not self.admin_id or not self.bot:
            return

        log.info("monitor cycle: fetching feeds...")
        # 1. Fetch latest CVEs from feed scrapers (parallel)
        new_cves = await self._fetch_feed_cves()

        # 2. Filter out already-sent
        new_cves = [c for c in new_cves if not await db.is_cve_sent(c["cve"])]
        if not new_cves:
            log.info("monitor: no new CVEs this cycle")
            return

        # 3. Limit to max per cycle
        new_cves = new_cves[:_MAX_NEW_PER_CYCLE]
        log.info("monitor: %d new CVEs to analyze", len(new_cves))

        # 4. Process each CVE (sequential to avoid LLM overload)
        for cve_info in new_cves:
            try:
                await self._process_cve(cve_info)
            except Exception as e:
                log.exception("monitor: error processing %s: %s", cve_info.get("cve"), e)

    async def _fetch_feed_cves(self) -> list[dict]:
        """Fetch latest CVEs from feed-based scrapers. Returns list of {cve, title, severity, cvss, source}.

        PRIMARY source: Wordfence threat-intel DB listing (cloak browser) — lists ALL recent WP CVEs.
        SECONDARY: search_all across 30+ product queries (CMS/servers/frameworks/panels/DBs)."""
        from scrapers.registry import build_scrapers, search_all
        from scrapers.wordfence import WordfenceScraper
        import time as _time
        scrapers = build_scrapers()
        current_year = str(_time.gmtime().tm_year)  # e.g. "2026"

        seen: set[str] = set()
        all_cves: list[dict] = []

        # 1. PRIMARY: Wordfence threat-intel DB listing (all recent CVEs, year >= 2026)
        #    This catches CVEs that RSS misses (e.g. CVE-2026-5524 not in blog RSS feed)
        try:
            wf = WordfenceScraper()
            wf_recs = await wf.fetch_recent(pages=3)
            for r in wf_recs:
                if r.cve and r.cve not in seen and f"-{current_year}-" in r.cve:
                    seen.add(r.cve)
                    all_cves.append({"cve": r.cve, "title": r.title, "severity": r.severity,
                                     "cvss": r.cvss, "source": r.source, "query": "wf-threat-intel"})
            log.info("monitor: wordfence threat-intel → %d CVEs", len(wf_recs))
        except Exception as e:
            log.error("monitor: wordfence fetch_recent error: %s", e)

        # 2. SECONDARY: parallel search across product terms (semaphore 2 — keep event loop responsive)
        _search_sem = asyncio.Semaphore(2)
        async def _search(query):
            async with _search_sem:
                try:
                    recs = await search_all(scrapers, query)
                    return [{"cve": r.cve, "title": r.title, "severity": r.severity,
                             "cvss": r.cvss, "source": r.source, "query": query}
                            for r in recs if r.cve]
                except Exception:
                    return []

        tasks = [_search(q) for q in _FEED_QUERIES]
        results = await asyncio.gather(*tasks)

        for batch in results:
            for cve_info in batch:
                cve = cve_info["cve"]
                if not cve or cve in seen:
                    continue
                # only current year CVEs (e.g. CVE-2026-xxxxx)
                if f"-{current_year}-" in cve:
                    seen.add(cve)
                    all_cves.append(cve_info)

        # sort by CVSS (highest first)
        all_cves.sort(key=lambda x: -(x.get("cvss") or 0))
        return all_cves

    async def _process_cve(self, cve_info: dict):
        """Analyze one CVE: fetch detail + fetch advisory/diff/source → AI analysis → send.
        Yields to event loop after each step so bot stays responsive."""
        cve = cve_info["cve"]

        # a. fetch CVE detail
        from agent.tools import dispatch as _dispatch
        detail = await _dispatch("fetch_cve_detail", {"cve": cve})
        await asyncio.sleep(0.5)  # yield to event loop

        # a2. PRE-FETCH advisory pages + patch diff + source code from references in detail
        # This gives the AI MUCH more context for analysis
        extra_ctx = ""
        import re as _re
        urls = _re.findall(r'(https?://[^\s"\'<>]+(?:advisory|changeset|diff|patch|commit|svn|trac|security|blog)[^\s"\'<>]+)', detail or "")
        # also grab wordfence advisory URLs
        urls += _re.findall(r'(https?://www\.wordfence\.com/[^\s"\'<>]+)', detail or "")
        urls = list(dict.fromkeys(urls))[:5]  # dedupe, limit 5
        # also fetch cve.org + NVD pages for this CVE
        urls.insert(0, f"https://www.cve.org/vulnerabilities/{cve}")
        urls.insert(1, f"https://nvd.nist.gov/vuln/detail/{cve}")
        for url in urls:
            try:
                page_text = await _dispatch("webfetch", {"url": url, "max_chars": 8000})
                if page_text and "ERR" not in page_text[:20]:
                    extra_ctx += f"\n\n--- FETCHED: {url} ---\n{page_text}\n"
            except Exception:
                pass
            await asyncio.sleep(0.3)  # yield
        if extra_ctx:
            detail = detail + "\n\n=== ADVISORY/PATCH/SOURCE CONTEXT (fetched) ===" + extra_ctx

        # b. check nuclei template
        poc_status = "N/A"
        poc_path = ""
        try:
            from scrapers.nuclei_templates import has_template, get_template_path
            if has_template(cve):
                poc_status = "nuclei template available"
                poc_path = get_template_path(cve) or ""
            else:
                poc_status = "no template (use /poc to generate)"
        except Exception:
            pass
        await asyncio.sleep(0.3)  # yield

        # c. AI analysis (1 LLM call)
        analysis = await self._ai_analyze(cve, detail, cve_info)
        await asyncio.sleep(0.3)  # yield

        # d. format + send Telegram report
        report = self._format_report(cve, cve_info, analysis, poc_status, poc_path, detail)
        if self.bot and self.admin_id:
            from telegram.constants import ParseMode
            # split if too long
            for i, chunk in enumerate(self._split_msg(report)):
                try:
                    await self.bot.send_message(
                        self.admin_id, chunk, parse_mode=ParseMode.HTML,
                        disable_web_page_preview=True)
                except Exception as e:
                    log.error("monitor: send error: %s", e)

        # e. mark as sent
        await db.mark_cve_sent(
            cve, analysis.get("summary", ""), cve_info.get("severity", ""),
            cve_info.get("cvss", 0), analysis.get("rce_type", ""),
            analysis.get("auth_type", ""), analysis.get("affects", ""),
            poc_status, analysis.get("dorks", {}))

    async def _ai_analyze(self, cve: str, detail: str, cve_info: dict) -> dict:
        """AI analysis: summary, RCE chain, auth type, dorks. 1 LLM call.
        Gets FULL CVE detail (description, affected ranges, references, patch URL)."""
        title = cve_info.get("title", "")
        prompt = f"""Analyze this CVE and output JSON only (no prose, no fences, no thinking).

CVE: {cve}
Title: {title}
Severity: {cve_info.get('severity', '')} CVSS: {cve_info.get('cvss', '')}

FULL CVE DETAIL + ADVISORY/PATCH/SOURCE (read carefully — extract ALL info, no truncation):
{detail}

Based on the detail above, output this JSON:
{{
  "summary": "Cara kerja vuln dalam 2-3 kalimat (Bahasa Indonesia). Jelaskan: (1) apa pemicunya, (2) apa dampaknya, (3) versi affected. Contoh: 'Plugin X versi <=Y rentan terhadap auth bypass karena... Penyerang tanpa autentikasi dapat... Memengaruhi versi A-B.'",
  "rce_chain": "Apakah bisa di-chain ke RCE? Baca description — jika disebutkan 'PHP execution', 'code execution', 'upload plugin', 'command execution', maka YES. Jelaskan chain-nya step by step. Atau 'Tidak bisa chain ke RCE' jika jelas bukan RCE.",
  "rce_type": "unauth_rce (RCE tanpa login) | auth_rce (RCE butuh login/admin) | no_rce (bukan RCE — XSS, info disclosure, dll)",
  "auth_type": "unauth (exploit tanpa login) | authenticated (butuh user login) | admin (butuh admin)",
  "affects": "Product + version range affected. Contoh: 'UpdraftPlus WordPress Plugin <= 1.26.4 (3M+ installations)'",
  "dorks": {{
    "shodan": "Shodan dork spesifik utk product ini. Format: http.html:\\"plugin-slug\\" atau product:\\"Product Name\\"",
    "fofa": "FOFA dork. Format: body=\\"plugin-slug\\" atau app=\\"Product Name\\"",
    "hunter_how": "Hunter.how dork. Format: web.body=\\"plugin-slug\\""
  }}
}}

CRITICAL RULES:
- Read the FULL description text above — extract auth type, RCE potential, affected versions from it.
- If description says 'unauthenticated' → auth_type = 'unauth'
- If description says 'PHP execution', 'code execution', 'arbitrary code', 'upload plugin', 'command execution' → rce_type = unauth_rce or auth_rce (based on auth_type)
- If description says 'authentication bypass' → can chain to RCE (auth bypass → admin → upload → RCE)
- affects MUST include product name + version range from the 'Affected ranges' section
- dorks MUST be specific to THIS product (not generic 'WordPress')
- summary MUST be in Bahasa Indonesia, 2-3 sentences, concrete"""

        try:
            resp = await chat_report(
                [{"role": "system", "content": "You are a vulnerability analyst. Read the CVE description carefully. Output JSON only. Extract ALL fields from the description text — never return 'unknown' if the info is in the description."},
                 {"role": "user", "content": prompt}],
                temperature=0.2, max_tokens=2000)
            # extract JSON
            import re
            m = re.search(r"\{.*\}", resp, re.S)
            if m:
                result = json.loads(m.group(0))
                # keyword-based fallback: if AI returned "unknown", infer from title
                title_lower = (cve_info.get("title") or "").lower()
                detail_lower = (detail or "").lower()[:5000]
                combined = title_lower + " " + detail_lower
                if result.get("auth_type") in ("unknown", "", None):
                    if "unauth" in combined or "unauthenticated" in combined:
                        result["auth_type"] = "unauth"
                    elif "admin" in combined or "authenticated" in combined or "auth " in combined:
                        result["auth_type"] = "authenticated"
                if result.get("rce_type") in ("no_rce", "unknown", "", None):
                    if "rce" in combined or "remote code execution" in combined or "command injection" in combined:
                        result["rce_type"] = result.get("auth_type", "unknown") + "_rce" if result.get("auth_type") != "unknown" else "unauth_rce"
                    elif "authentication bypass" in combined or "auth bypass" in combined:
                        # auth bypass CAN chain to RCE (admin → upload → RCE)
                        result["rce_type"] = "auth_rce"
                        if not result.get("rce_chain") or result.get("rce_chain") == "Unknown":
                            result["rce_chain"] = "Auth bypass → admin access → upload malicious plugin/theme → PHP execution → RCE"
                    elif "sql injection" in combined or "sqli" in combined:
                        result["rce_type"] = "auth_rce"
                        if not result.get("rce_chain") or result.get("rce_chain") == "Unknown":
                            result["rce_chain"] = "SQLi → SELECT INTO OUTFILE → write webshell → execute → RCE"
                    elif "file upload" in combined or "arbitrary file" in combined:
                        result["rce_type"] = "unauth_rce" if result.get("auth_type") == "unauth" else "auth_rce"
                        if not result.get("rce_chain") or result.get("rce_chain") == "Unknown":
                            result["rce_chain"] = "Arbitrary file upload → upload PHP with marker → access uploaded file → RCE"
                    # NOTE: "broken authentication" alone does NOT imply RCE chain
                    # Only flag RCE if there's explicit RCE/auth-bypass/SQLi/upload indicators
                if not result.get("affects") or result.get("affects") == "":
                    result["affects"] = cve_info.get("title", "")[:200]
                if not result.get("summary") or result.get("summary") == "" or len(result.get("summary","")) < 50:
                    result["summary"] = cve_info.get("title", "") + ". " + (detail[:300] if detail else "")
                # CONSISTENCY CHECK: rce_type must match rce_chain
                rce_chain_lower = (result.get("rce_chain") or "").lower()
                if "tidak bisa" in rce_chain_lower or "no rce" in rce_chain_lower or "cannot" in rce_chain_lower or "not chain" in rce_chain_lower:
                    result["rce_type"] = "no_rce"
                elif result.get("rce_type") == "no_rce" and ("can chain" in rce_chain_lower or "bisa chain" in rce_chain_lower or "rce" in rce_chain_lower):
                    result["rce_type"] = result.get("auth_type", "unknown") + "_rce" if result.get("auth_type") != "unknown" else "unauth_rce"
                return result
        except Exception as e:
            log.error("monitor: AI analyze error: %s", e)
        return {"summary": cve_info.get("title", ""), "rce_chain": "Unknown",
                "rce_type": "no_rce", "auth_type": "unknown",
                "affects": "", "dorks": {}}

    def _format_report(self, cve: str, cve_info: dict, analysis: dict,
                       poc_status: str, poc_path: str, detail: str) -> str:
        """Format Telegram HTML report for a new CVE."""
        import html, re, time as _time

        sev = (cve_info.get("severity") or "?").upper()
        if sev == "?" or not sev:
            cvss_val = cve_info.get("cvss") or 0
            if cvss_val >= 9: sev = "CRITICAL"
            elif cvss_val >= 7: sev = "HIGH"
            elif cvss_val >= 4: sev = "MEDIUM"
            elif cvss_val > 0: sev = "LOW"
            else:
                title_lower = (cve_info.get("title") or "").lower()
                if "critical" in title_lower: sev = "CRITICAL"
                elif "high" in title_lower or "rce" in title_lower or "auth bypass" in title_lower: sev = "HIGH"
                else: sev = "MEDIUM"
        cvss = cve_info.get("cvss", "")
        cvss_str = f" (CVSS {cvss})" if cvss else ""

        # parse publish date from detail + calculate days ago
        pub_date = ""
        days_ago = ""
        pm = re.search(r'Published:\s*(\d{4}-\d{2}-\d{2})', detail or "")
        if pm:
            pub_date = pm.group(1)
            try:
                from datetime import datetime
                pub_dt = datetime.strptime(pub_date, "%Y-%m-%d")
                now = datetime.now()
                diff = (now - pub_dt).days
                if diff == 0:
                    days_ago = " (hari ini)"
                elif diff == 1:
                    days_ago = " (1 hari yg lalu)"
                else:
                    days_ago = f" ({diff} hari yg lalu)"
            except Exception:
                pass

        rce_type = analysis.get("rce_type", "unknown")
        rce_emoji = {"unauth_rce": "🔴", "auth_rce": "🟠", "no_rce": "⚪"}.get(rce_type, "❓")
        auth_type = analysis.get("auth_type", "unknown")

        dorks = analysis.get("dorks", {})
        shodan = dorks.get("shodan", "")
        fofa = dorks.get("fofa", "")
        hunter = dorks.get("hunter_how", "")

        # extract patch/diff URL from detail
        import re
        patch_url = ""
        pm = re.search(r"(https://[^\s\"]+(?:diff|patch|commit|compare)[^\s\"]*)", detail or "")
        if pm:
            patch_url = pm.group(1)

        lines = [
            f"🚨 <b>NEW VULN: {html.escape(cve)}</b>",
            f"<b>Severity:</b> {sev}{cvss_str}",
        ]
        if pub_date:
            lines.append(f"<b>Published:</b> {pub_date}{days_ago}")
        lines += [
            f"<b>Affected:</b> {html.escape(analysis.get('affects') or cve_info.get('title', '-'))[:200]}",
            f"<b>Auth:</b> {html.escape(auth_type)}",
            f"<b>RCE:</b> {rce_emoji} {html.escape(rce_type)}",
            f"<b>Chain:</b> {html.escape(analysis.get('rce_chain', '-'))[:300]}",
            "",
            f"<b>Cara kerja:</b>",
            html.escape(analysis.get("summary", "-"))[:1000],
            "",
        ]

        if shodan or fofa or hunter:
            lines.append("<b>Dorks:</b>")
            if shodan:
                lines.append(f'  <b>Shodan:</b> <code>{html.escape(shodan)}</code>')
            if fofa:
                lines.append(f'  <b>FOFA:</b> <code>{html.escape(fofa)}</code>')
            if hunter:
                lines.append(f'  <b>Hunter:</b> <code>{html.escape(hunter)}</code>')
            lines.append("")

        lines.append(f"<b>PoC:</b> {html.escape(poc_status)}")
        if patch_url:
            lines.append(f'<b>Patch:</b> <a href="{html.escape(patch_url)}">diff</a>')

        lines.append("")
        lines.append(f"<i>Gunakan</i> <code>/poc adhoc {cve}</code> <i>utk generate+test PoC.</i>")

        return "\n".join(lines)

    def _split_msg(self, text: str, limit: int = 3500) -> list[str]:
        if len(text) <= limit:
            return [text]
        out, cur = [], ""
        for para in text.split("\n"):
            if len(cur) + len(para) > limit:
                if cur:
                    out.append(cur)
                cur = para
            else:
                cur = (cur + "\n" + para) if cur else para
        if cur:
            out.append(cur)
        return out

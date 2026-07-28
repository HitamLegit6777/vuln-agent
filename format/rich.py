"""Telegram rich-message (HTML) renderer for vuln reports.

parse_mode=HTML. Auto-splits at ~3500 chars to stay under Telegram's 4096 limit.
No emojis. Every value html-escaped.
"""
from __future__ import annotations

import html
import re
from typing import Optional

from bs4 import BeautifulSoup, NavigableString, Tag

# Telegram HTML allows only: b i u s code pre a blockquote tg-spoiler (span class)
_TG_ALLOWED = {"b", "i", "u", "s", "code", "pre", "blockquote", "a"}


def tg_sanitize(text: str) -> str:
    """Make LLM HTML output Telegram-safe. Whitelist tags, br/p→newline,
    strong→b, em→i, escape all text incl. inside code/pre."""
    if not text:
        return ""
    soup = BeautifulSoup(text, "lxml")
    out: list[str] = []

    def walk(node):
        for child in node.children:
            if isinstance(child, NavigableString):
                out.append(html.escape(str(child)))
                continue
            if not isinstance(child, Tag):
                continue
            name = child.name.lower()
            if name == "br":
                out.append("\n")
            elif name in ("p", "div", "li", "tr"):
                out.append("\n"); walk(child); out.append("\n")
            elif name in ("h1", "h2", "h3", "h4", "h5", "h6"):
                out.append("\n<b>"); walk(child); out.append("</b>\n")
            elif name == "strong" or name == "b":
                out.append("<b>"); walk(child); out.append("</b>")
            elif name == "em" or name == "i":
                out.append("<i>"); walk(child); out.append("</i>")
            elif name in _TG_ALLOWED:
                if name == "a":
                    href = child.get("href", "") or ""
                    if href:
                        out.append(f'<a href="{html.escape(href, quote=True)}">')
                        walk(child); out.append("</a>")
                    else:
                        walk(child)
                else:
                    out.append(f"<{name}>"); walk(child); out.append(f"</{name}>")
            else:
                walk(child)  # unwrap unknown tags, keep text

    body = soup.body if soup.body is not None else soup
    walk(body)
    text = "".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text

SEV_TAG = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "MODERATE": "MEDIUM",
}


def _e(s) -> str:
    return html.escape(str(s) if s is not None else "")


def _sev_line(v: dict) -> str:
    sev = (v.get("severity") or "UNKNOWN").upper()
    sev = SEV_TAG.get(sev, sev)
    cvss = v.get("cvss")
    label = (v.get("label") or "UNKNOWN").upper()
    label_tag = {"VULNERABLE": "VULNERABLE", "NOT_AFFECTED": "NOT AFFECTED"}.get(label, label)
    cvss_str = f" CVSS {cvss}" if cvss else ""
    line = f"[{_e(sev)}{_e(cvss_str)}] <b>{_e(label_tag)}</b>"
    # deterministic risk band (from agent.scoring) — priority at a glance
    band = v.get("risk_band")
    risk = v.get("risk")
    if band:
        risk_str = f" {risk:.0f}" if isinstance(risk, (int, float)) else ""
        line += f" · <b>RISK {_e(band)}{_e(risk_str)}</b>"
    epss = v.get("epss")
    if isinstance(epss, (int, float)):
        line += f" · EPSS {epss:.0%}"
    return line


def render_report(report: dict, scan_id: str) -> list[str]:
    """Return list of HTML message chunks. Binary EXPLOITABLE/CLEAN status."""
    parts: list[str] = []
    target = report.get("target", "?")
    status = (report.get("status") or "UNKNOWN").upper()
    if status == "UNREACHABLE":
        status_line = "<b>STATUS: TARGET UNREACHABLE</b>"
    elif status == "EXPLOITABLE":
        status_line = "<b>STATUS: EXPLOITABLE</b>"
    else:
        status_line = "<b>STATUS: CLEAN</b>"
    head = (f"<b>Vuln Scan Report</b>\n"
            f"{status_line}\n"
            f"<b>Target:</b> {_e(target)}\n"
            f"<b>Scan ID:</b> <code>{_e(scan_id)}</code>\n")
    ss = report.get("stack_summary")
    if ss:
        head += f"<b>Stack:</b> {_e(ss)}\n"
    waf_summary = report.get("waf_summary")
    if waf_summary:
        head += f"<b>WAF/CDN:</b> {_e(waf_summary)}\n"
        if report.get("waf_may_mask"):
            head += ("<b>WARNING:</b> WAF aktif — PoC --check mungkin diblok (false NOT EXPLOITABLE). "
                     "Verdict = CLEAN mungkin ter-masked.\n")
    eiw = report.get("exploited_in_wild") or []
    if eiw:
        head += f"<b>In-the-wild (KEV):</b> {', '.join(_e(c) for c in eiw)}\n"
    parts.append(head)

    exploitable = report.get("exploitable") or []
    checked = report.get("checked") or []

    if status == "EXPLOITABLE" and exploitable:
        parts.append(f"\n<b>Exploitable ({len(exploitable)}):</b>")
        for i, v in enumerate(exploitable, 1):
            block = (f"\n<b>{i}. {_e(v.get('cve'))}</b> {_sev_line(v)}\n"
                     f"<b>Component:</b> {_e(v.get('component') or '-')}\n"
                     f"<b>Title:</b> {_e(v.get('title') or '-')}\n"
                     f"<b>Summary:</b> {_e(v.get('summary') or '-')}\n"
                     f"<b>Verified:</b> {_e(v.get('verify_reason') or '-')}\n")
            refs = v.get("poc_refs") or []
            if refs:
                block += "<b>PoC:</b> " + " | ".join(
                    f'<a href="{_e(u)}">link{n+1}</a>' for n, u in enumerate(refs[:3])
                ) + "\n"
            dp = v.get("diff_patch")
            if dp:
                block += f'<b>Patch:</b> <a href="{_e(dp)}">diff</a>\n'
            srcs = v.get("sources") or []
            if srcs:
                block += f"<b>Sources:</b> {_e(', '.join(srcs))}\n"
            parts.append(block)
    else:
        parts.append("\n<i>No exploitable vulnerabilities confirmed (CLEAN).</i>")

    if checked:
        parts.append(f"\n<b>Tested but not exploitable ({len(checked)}):</b>")
        for c in checked:
            parts.append(f"  <code>{_e(c.get('cve'))}</code> — {_e(c.get('verify_reason') or '-')}")

    rec = report.get("recommendation")
    if rec:
        parts.append(f"\n<b>Recommendation</b>\n{_e(rec)}")

    parts.append(f"\n<i>PoC sudah dibuild+test saat scan. Klik</i> <b>Get PoC</b> <i>utk ambil script.</i>")
    return _split(parts)


def _split(parts: list[str], limit: int = 3500) -> list[str]:
    msgs: list[str] = []
    cur = ""
    for p in parts:
        if len(cur) + len(p) > limit:
            msgs.append(cur)
            cur = ""
        cur += p
    if cur:
        msgs.append(cur)
    return msgs


def render_poc_notice(path: str, cve: str, scan_id: str) -> str:
    return (f"<b>PoC generated</b>\n<b>CVE:</b> {_e(cve)}\n"
            f"<b>Scan:</b> <code>{_e(scan_id)}</code>\n"
            f"<b>File:</b> <code>{_e(path)}</code>\n"
            f"<i>Default mode is --check (verification-only). "
            f"Run with --exploit only against owned targets.</i>")


def render_poc_verdict(cve: str, verdict: str, reason: str,
                       attempts: int = 0, methods: list = None) -> str:
    v = (verdict or "UNKNOWN").upper()
    tag = "EXPLOITABLE" if v.startswith("EXPLOIT") else v
    line = f"<b>Exploitability:</b> <b>{_e(tag)}</b>"
    if attempts:
        line += f"  <i>(attempts: {attempts})</i>"
    line += "\n"
    if reason:
        line += f"<b>Reason:</b> {_e(reason)}\n"
    if methods:
        line += "<b>Methods tried:</b> " + " · ".join(_e(m) for m in methods) + "\n"
    return (f"<b>PoC verification</b> · {_e(cve)}\n{line}"
            f"<i>Verdict diatas berasal dari eksekusi nyata script PoC (--check), "
            f"bukan klaim AI.</i>")

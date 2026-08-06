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
    if v.get("kev"):
        line += " · <b>KEV</b>"
    return line


def render_report(report: dict, scan_id: str) -> list[str]:
    """Render structured Bot API 10.2 rich HTML; legacy conversion is centralized."""
    target = report.get("target", "?")
    status = (report.get("status") or "INCONCLUSIVE").upper()
    labels = {
        "EXPLOITABLE": "EXPLOITABLE",
        "NO_EXPLOIT_REPRODUCED": "NO EXPLOIT REPRODUCED",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "UNREACHABLE": "TARGET UNREACHABLE",
    }
    coverage = report.get("verdict_coverage", report.get("coverage"))
    confidence = report.get("confidence")
    rows = [
        ["Status", f"<b>{_e(labels.get(status, status))}</b>"],
        ["Target", f"<code>{_e(target)}</code>"],
        ["Scan", f"<code>{_e(scan_id)}</code>"],
    ]
    if isinstance(coverage, (int, float)):
        rows.append(["Coverage", f"{coverage:.0%}"])
    if isinstance(confidence, (int, float)):
        rows.append(["Confidence", f"{confidence:.0%}"])
    if report.get("stack_summary"):
        rows.append(["Stack", _e(report["stack_summary"])])
    if report.get("waf_summary"):
        rows.append(["WAF/CDN", _e(report["waf_summary"])])
    table = "<table bordered striped>" + "".join(
        f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"
    parts = [f"<h1>Vulnerability Scan Report</h1>{table}<hr/>"]
    if report.get("waf_may_mask"):
        parts.append("<blockquote><b>Warning:</b> WAF may mask active checks; blocked tests are INCONCLUSIVE, never clean.</blockquote>")
    exploitable = report.get("exploitable") or []
    checked = report.get("checked") or []
    inconclusive = report.get("inconclusive") or []
    not_applicable = report.get("not_applicable") or []
    if exploitable:
        parts.append(f"<h2>Confirmed exploitable ({len(exploitable)})</h2>")
        for v in exploitable:
            body = (f"<p>{_sev_line(v)}<br/><b>Component:</b> {_e(v.get('component') or '-')}<br/>"
                    f"<b>Title:</b> {_e(v.get('title') or '-')}<br/>"
                    f"<b>Proof:</b> {_e(v.get('verify_reason') or '-')}</p>")
            parts.append(f"<details open><summary><b>{_e(v.get('cve'))}</b></summary>{body}</details>")
    else:
        parts.append("<p><i>No exploit was confirmed. This does not mean the target is vulnerability-free.</i></p>")
    if checked:
        parts.append(f"<h2>Not reproduced ({len(checked)})</h2><ul>" + "".join(
            f"<li><code>{_e(v.get('cve'))}</code> — {_e(v.get('verify_reason') or '-')}</li>" for v in checked) + "</ul>")
    if inconclusive:
        parts.append(f"<h2>Inconclusive ({len(inconclusive)})</h2><ul>" + "".join(
            f"<li><code>{_e(v.get('cve'))}</code> — {_e(v.get('verify_reason') or '-')}</li>" for v in inconclusive) + "</ul>")
    if not_applicable:
        parts.append(f"<details><summary>Not applicable ({len(not_applicable)})</summary><ul>" + "".join(
            f"<li><code>{_e(v.get('cve'))}</code> — {_e(v.get('verify_reason') or '-')}</li>" for v in not_applicable) + "</ul></details>")
    if report.get("recommendation"):
        parts.append(f"<h2>Recommendation</h2><p>{_e(report['recommendation'])}</p>")
    parts.append("<footer>PoCs were built and checked during this scan. Use Get PoC to retrieve artifacts.</footer>")
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

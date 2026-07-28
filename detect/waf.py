"""WAF/CDN/proxy detection — identify protective layers that may mask PoC verdicts.

When a WAF is active, PoC --check requests may be blocked (403/406/429/WAF block page)
producing a false NOT EXPLOITABLE. We detect the layer and flag it so the report
can note "WAF active — verdict may be masked".

Design principle: **over-detect is safe, under-detect is dangerous**.
- False positive (detect WAF when absent) → harmless cautionary note.
- False negative (miss WAF) → false NOT EXPLOITABLE → wrong report.

So we detect via THREE independent signals and combine:
  1. Header/cookie signatures (high confidence, specific WAF name)
  2. Body block-page patterns (medium confidence, WAF-specific HTML)
  3. Response-code heuristic (low confidence, but catches unknown WAFs:
     403/406/429 on a normal homepage GET = something is blocking)

Also distinguishes:
  - WAF (active blocking layer) → may_mask_verdict = True
  - CDN (passive caching, e.g. Cloudflare proxy w/o WAF rules) → note but less concern
  - proxy (Varnish/HAProxy, transparent) → informational

Supported WAFs/CDNs (40+ signatures):
  Cloudflare, Sucuri (CloudProxy + plugin), Imperva/Incapsula, Akamai (Kona),
  Fastly, AWS CloudFront/WAF, F5 BIG-IP ASM, Citrix Netscaler, ModSecurity,
  Wordfence, iThemes Security, BulletProof, AIOWPS, WebARX, DDoS-Guard, Qrator,
  DataDome, PerimeterX/HUMAN, Kasada, Reblaze, Distil, Wallarm, Edgecast,
  StackPath/Highwinds, Pantheon, WP Engine, Kinsta, Flywheel, Shopify CDN,
  Varnish, HAProxy, Barracuda, Fortinet, Tencent, Yunfeng (Yundun), Qiniu.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class WAFResult:
    name: str = ""           # cloudflare | sucuri | imperva | wordfence | datadome | ...
    kind: str = ""           # waf | cdn | proxy
    evidence: str = ""       # the exact header/cookie/body that matched
    confidence: str = "high" # high (specific header) | medium (cookie/body) | low (heuristic)


# ---- 1. HEADER SIGNATURES (high confidence) ----
# (header_name_lower, (waf_name, kind))
# Checked against lowercase-keyed headers dict.
_HEADER_EXACT = {
    # Cloudflare
    "cf-ray": ("cloudflare", "cdn"),
    "cf-cache-status": ("cloudflare", "cdn"),
    "cf-mitigated": ("cloudflare", "waf"),
    "cf-worker": ("cloudflare", "cdn"),
    # Sucuri
    "x-sucuri-id": ("sucuri", "waf"),
    "x-sucuri-cache": ("sucuri", "waf"),
    # Imperva / Incapsula
    "x-iinfo": ("imperva", "waf"),
    "x-imperva": ("imperva", "waf"),
    # Akamai
    "akamai-grn": ("akamai", "cdn"),
    "x-akamai-transformed": ("akamai", "cdn"),
    "x-akamai-request-id": ("akamai", "cdn"),
    "x-akamai-features": ("akamai", "waf"),
    "akamai-bip-time": ("akamai", "waf"),
    # Fastly
    "x-fastly-request-id": ("fastly", "cdn"),
    # AWS
    "x-amz-cf-id": ("aws-cloudfront", "cdn"),
    "x-amzn-trace-id": ("aws-waf", "waf"),
    "x-amz-cf-pop": ("aws-cloudfront", "cdn"),
    # Edgecast
    "ec-region": ("edgecast", "cdn"),
    "x-ec-debug": ("edgecast", "cdn"),
    # DDoS-Guard
    "x-ddos-guard": ("ddos-guard", "waf"),
    # Qrator
    "x-qrator": ("qrator", "waf"),
    "x-qrator-trace": ("qrator", "waf"),
    # StackPath
    "x-sp-url": ("stackpath", "cdn"),
    "x-sp-host": ("stackpath", "cdn"),
    # DataDome (JS-challenge WAF — very hard to bypass)
    "x-datadome": ("datadome", "waf"),
    "x-datadome-cid": ("datadome", "waf"),
    "x-dd-b": ("datadome", "waf"),
    # PerimeterX / HUMAN (JS-challenge WAF)
    "x-px3": ("perimeterx", "waf"),
    "x-px3-cap": ("perimeterx", "waf"),
    "x-px3-t": ("perimeterx", "waf"),
    # Kasada (JS-challenge WAF)
    "x-kasada-proxy": ("kasada", "waf"),
    "kp-d:": ("kasada", "waf"),
    # Reblaze
    "x-reblaze": ("reblaze", "waf"),
    "rb-zid": ("reblaze", "waf"),
    # Distil
    "x-distil-cs": ("distil", "waf"),
    "x-distil-request-id": ("distil", "waf"),
    # Wallarm
    "x-wallarm": ("wallarm", "waf"),
    "x-wallarm-status": ("wallarm", "waf"),
    # Shopify
    "x-shopid": ("shopify-cdn", "cdn"),
    "x-shopify-stage": ("shopify-cdn", "cdn"),
    # Varnish
    "x-varnish": ("varnish", "proxy"),
    "x-cache-hits": ("varnish", "proxy"),
    # CDN generic
    "x-cdn": ("cdn-generic", "cdn"),
    "x-edge-ip": ("cdn-generic", "cdn"),
    "x-edge-location": ("cdn-generic", "cdn"),
    # Tencent Cloud
    "x-tencent-cdn": ("tencent-cdn", "cdn"),
    # Yundun (Alibaba Cloud WAF)
    "x-yundun-id": ("yundun", "waf"),
    "x-yundun-detect": ("yundun", "waf"),
    # Qiniu CDN
    "x-qiniu": ("qiniu-cdn", "cdn"),
    # Fortinet
    "x-fortinet": ("fortinet", "waf"),
    # Barracuda
    "x-barracuda-load-balance": ("barracuda", "waf"),
}

# Server header value patterns
_SERVER_PATTERNS = [
    (re.compile(r"^cloudflare\b", re.I), ("cloudflare", "cdn")),
    (re.compile(r"sucuri", re.I), ("sucuri", "waf")),
    (re.compile(r"cloudproxy", re.I), ("sucuri", "waf")),
    (re.compile(r"imperva", re.I), ("imperva", "waf")),
    (re.compile(r"incapsula", re.I), ("imperva", "waf")),
    (re.compile(r"akamaighost", re.I), ("akamai", "cdn")),
    (re.compile(r"bigip", re.I), ("f5-bigip", "waf")),
    (re.compile(r"mod_?security", re.I), ("modsecurity", "waf")),
    (re.compile(r"ddos-?guard", re.I), ("ddos-guard", "waf")),
    (re.compile(r"qrator", re.I), ("qrator", "waf")),
    (re.compile(r"\bvarnish\b", re.I), ("varnish", "proxy")),
    (re.compile(r"cloudfront", re.I), ("aws-cloudfront", "cdn")),
    (re.compile(r"edgecast", re.I), ("edgecast", "cdn")),
    (re.compile(r"pantheon", re.I), ("pantheon", "cdn")),
    (re.compile(r"wpengine", re.I), ("wpengine", "cdn")),
    (re.compile(r"kinsta", re.I), ("kinsta", "cdn")),
    (re.compile(r"flywheel", re.I), ("flywheel", "cdn")),
    (re.compile(r"reblaze", re.I), ("reblaze", "waf")),
    (re.compile(r"distil", re.I), ("distil", "waf")),
    (re.compile(r"wallarm", re.I), ("wallarm", "waf")),
    (re.compile(r"fortinet|fortiweb", re.I), ("fortinet", "waf")),
    (re.compile(r"barracuda", re.I), ("barracuda", "waf")),
    (re.compile(r"yundun", re.I), ("yundun", "waf")),
    (re.compile(r"tencent", re.I), ("tencent-cdn", "cdn")),
]

# Via header patterns
_VIA_PATTERNS = [
    (re.compile(r"\bvarnish\b", re.I), ("varnish", "proxy")),
    (re.compile(r"cloudfront", re.I), ("aws-cloudfront", "cdn")),
    (re.compile(r"akamai", re.I), ("akamai", "cdn")),
    (re.compile(r"ns-cache|netscaler", re.I), ("citrix-netscaler", "waf")),
    (re.compile(r"cloudflare\.net", re.I), ("cloudflare", "cdn")),
    (re.compile(r"\bhaproxy\b", re.I), ("ha-proxy", "proxy")),
    (re.compile(r"sucuri", re.I), ("sucuri", "waf")),
    (re.compile(r"reblaze", re.I), ("reblaze", "waf")),
]

# ---- 2. COOKIE SIGNATURES (medium confidence) ----
_COOKIE_PATTERNS = [
    (re.compile(r"__cfduid|__cf_bm|cf_clearance|__cf_chl", re.I), ("cloudflare", "waf", "medium")),
    (re.compile(r"sucuri_cloudproxy_uuid|sucuri_sucuri", re.I), ("sucuri", "waf", "medium")),
    (re.compile(r"incap_ses|visid_incap|nlbi_|rehi=|__utmvc", re.I), ("imperva", "waf", "medium")),
    (re.compile(r"BIGipServer", re.I), ("f5-bigip", "waf", "medium")),
    (re.compile(r"__ddos_guard|ddos_guard", re.I), ("ddos-guard", "waf", "medium")),
    (re.compile(r"qrator_jsid|qrator_ssid", re.I), ("qrator", "waf", "medium")),
    (re.compile(r"datadome|_dd_s|dd_cookie", re.I), ("datadome", "waf", "medium")),
    (re.compile(r"_px|pxcts|pxhd|perimeterx", re.I), ("perimeterx", "waf", "medium")),
    (re.compile(r"SERVERID", re.I), ("ha-proxy", "proxy", "low")),
    (re.compile(r"PSMobile.*?wt_zcp", re.I), ("imperva", "waf", "low")),
]

# ---- 3. BODY BLOCK-PAGE PATTERNS (medium-low confidence) ----
# These are SPECIFIC WAF block page strings (not generic "forbidden" which is too broad).
_BODY_PATTERNS = [
    # Cloudflare
    (re.compile(r"cf-error-details|cf_error_details|cloudflare ray id:|attention required.{0,100}cloudflare", re.I),
     ("cloudflare", "waf", "medium")),
    # Sucuri
    (re.compile(r"sucuri website firewall|access denied.{0,30} Sucuri|sucuri\.net.*blocked", re.I),
     ("sucuri", "waf", "medium")),
    # Imperva/Incapsula
    (re.compile(r"incapsula incident|incap_ses|the incident id is|supported request method", re.I),
     ("imperva", "waf", "medium")),
    # ModSecurity
    (re.compile(r"Mod_Security|mod_security|ModSecurity.*rule|transaction set", re.I),
     ("modsecurity", "waf", "medium")),
    # AWS WAF
    (re.compile(r"request blocked by aws waf|aws.?waf.*blocked", re.I),
     ("aws-waf", "waf", "medium")),
    # Wordfence (WP plugin WAF)
    (re.compile(r"generated by wordfence|wordfence.*security|this response was generated by wordfence", re.I),
     ("wordfence", "waf", "high")),
    # iThemes Security (WP plugin)
    (re.compile(r"ithemes security.*blocked|better wp security", re.I),
     ("ithemes-security", "waf", "medium")),
    # DataDome
    (re.compile(r"datadome\.co|dd.*challenge|bot protection|please solve the captcha", re.I),
     ("datadome", "waf", "medium")),
    # PerimeterX / HUMAN
    (re.compile(r"perimeterx|px-captcha|press.{0,5}hold|human challenge", re.I),
     ("perimeterx", "waf", "medium")),
    # Kasada
    (re.compile(r"kasada|interstitial challenge|bot mitigation", re.I),
     ("kasada", "waf", "low")),
    # Reblaze
    (re.compile(r"reblaze.*blocked|reblaze proxy|access denied.*reblaze", re.I),
     ("reblaze", "waf", "medium")),
    # Distil
    (re.compile(r"distil.*captcha|distil networks|pardon our dust.*distil", re.I),
     ("distil", "waf", "medium")),
    # DDoS-Guard
    (re.compile(r"ddos-?guard.*blocked|ddos guard protection", re.I),
     ("ddos-guard", "waf", "medium")),
    # F5
    (re.compile(r"the requested url was rejected.*big-?ip|BIG-?IP.*rejected", re.I),
     ("f5-bigip", "waf", "medium")),
    # Barracuda
    (re.compile(r"barracuda.*blocked|firewall.*barracuda", re.I),
     ("barracuda", "waf", "low")),
    # Generic WAF (very conservative — requires "firewall" or "waf" + "blocked")
    (re.compile(r"(web application firewall|waf).{0,60}(blocked|denied|rejected)", re.I),
     ("waf-generic", "waf", "low")),
]

# Status codes that indicate WAF blocking on a normal GET
_BLOCK_STATUS = {403, 406, 418, 429, 503}

# WordPress plugin WAFs detectable via body/headers on the site itself (not just block pages)
_WP_WAF_BODY_PATTERNS = [
    (re.compile(r"wp-content/plugins/wordfence|wordfence.*waf|wf.*hash", re.I),
     ("wordfence", "waf", "high")),
    (re.compile(r"wp-content/plugins/better-wp-security|ithemes-security", re.I),
     ("ithemes-security", "waf", "medium")),
    (re.compile(r"wp-content/plugins/bulletproof-security", re.I),
     ("bulletproof-security", "waf", "medium")),
    (re.compile(r"wp-content/plugins/all-in-one-wp-security|aiowps", re.I),
     ("aiowps", "waf", "medium")),
    (re.compile(r"wp-content/plugins/webarx", re.I),
     ("webarx", "waf", "medium")),
    (re.compile(r"wp-content/plugins/sucuri-scanner", re.I),
     ("sucuri-plugin", "waf", "medium")),
]


def detect_waf(headers: dict, body: str = "", status: int = 0) -> list[WAFResult]:
    """Detect WAF/CDN/proxy layers from HTTP response. Returns all detected layers.

    headers: lowercase-keyed dict.
    body: response body (first ~200KB is enough).
    status: HTTP status code (403/406/429 on normal GET = likely WAF).
    """
    results: list[WAFResult] = []
    seen: set[str] = set()

    def _add(name: str, kind: str, evidence: str, confidence: str = "high"):
        key = f"{name}:{kind}"
        if key in seen:
            return
        seen.add(key)
        results.append(WAFResult(name=name, kind=kind, evidence=evidence, confidence=confidence))

    # 1. Exact header signatures
    for h, val in headers.items():
        h_lower = h.lower()
        val_str = str(val) if val else ""
        if h_lower in _HEADER_EXACT:
            name, kind = _HEADER_EXACT[h_lower]
            _add(name, kind, f"{h_lower}: {val_str[:60]}")
        # x-served-by: cache-xxx (Fastly)
        elif h_lower == "x-served-by" and "cache-" in val_str.lower():
            _add("fastly", "cdn", f"{h_lower}: {val_str[:60]}")
        # x-cache: Hit/Miss from CloudFront
        elif h_lower == "x-cache" and "cloudfront" in val_str.lower():
            _add("aws-cloudfront", "cdn", f"{h_lower}: {val_str[:60]}")
        # x-akamai-* catch-all
        elif h_lower.startswith("x-akamai-"):
            _add("akamai", "cdn", f"{h_lower}: {val_str[:60]}")
        # x-qrator-* catch-all
        elif h_lower.startswith("x-qrator"):
            _add("qrator", "waf", f"{h_lower}: {val_str[:60]}")
        # x-px3 (PerimeterX)
        elif h_lower.startswith("x-px3"):
            _add("perimeterx", "waf", f"{h_lower}: {val_str[:60]}")
        # x-distil-* catch-all
        elif h_lower.startswith("x-distil"):
            _add("distil", "waf", f"{h_lower}: {val_str[:60]}")
        # x-shopify-* catch-all
        elif h_lower.startswith("x-shopify") or h_lower == "x-shopid":
            _add("shopify-cdn", "cdn", f"{h_lower}: {val_str[:60]}")

    # 2. Server header value patterns
    srv = headers.get("server", "")
    if srv:
        for pat, (name, kind) in _SERVER_PATTERNS:
            if pat.search(srv):
                _add(name, kind, f"Server: {srv[:80]}")
                break

    # 3. Via header
    via = headers.get("via", "")
    if via:
        for pat, (name, kind) in _VIA_PATTERNS:
            if pat.search(via):
                _add(name, kind, f"Via: {via[:80]}")
                break

    # 4. Cookie patterns
    cookie_str = headers.get("set-cookie", "")
    if cookie_str:
        for pat, (name, kind, conf) in _COOKIE_PATTERNS:
            if pat.search(cookie_str):
                _add(name, kind, f"cookie: {pat.pattern[:40]}", conf)

    # 5. Body block-page patterns (specific WAF signatures)
    if body:
        for pat, (name, kind, conf) in _BODY_PATTERNS:
            if pat.search(body[:10000]):
                _add(name, kind, f"body: {pat.pattern[:40]}", conf)
        # WordPress plugin WAFs (detectable from normal page, not just block page)
        for pat, (name, kind, conf) in _WP_WAF_BODY_PATTERNS:
            if pat.search(body[:10000]):
                _add(name, kind, f"body: {pat.pattern[:40]}", conf)

    # 5b. CDN-with-possible-WAF: major CDNs commonly bundle WAF rules even without
    # explicit WAF headers. Cloudflare (WAF on all plans), AWS CloudFront (AWS WAF
    # commonly attached), Akamai (Kona), Fastly (Fastly WAF). Flag as low-confidence
    # WAF so may_mask_verdict returns True → report warns about possible masking.
    _cdn_names = {r.name for r in results if r.kind == "cdn"}
    _cdn_waf_map = {
        "cloudflare": "Cloudflare CDN detected — WAF rules commonly enabled (may block PoC)",
        "aws-cloudfront": "CloudFront CDN detected — AWS WAF may be attached (may block PoC)",
        "akamai": "Akamai CDN detected — Kona WAF may be enabled (may block PoC)",
        "fastly": "Fastly CDN detected — Fastly WAF may be enabled (may block PoC)",
    }
    for cdn, note in _cdn_waf_map.items():
        if cdn in _cdn_names:
            _add(f"{cdn}-waf", "waf", note, "low")

    # 6. Response-code heuristic — catches UNKNOWN WAFs
    # A 403/406/429 on a normal homepage GET strongly suggests a WAF/proxy
    # is blocking (even if we couldn't identify the specific product).
    if status in _BLOCK_STATUS:
        body_lower = (body or "")[:5000].lower()
        # only flag if there's some block-related keyword in body (avoid false positive
        # on sites that genuinely return 403 for other reasons like auth-required)
        block_kw = any(w in body_lower for w in (
            "block", "denied", "firewall", "forbidden", "security", "waf",
            "challenge", "captcha", "verify", "human", "bot", "protected",
            "rejected", "suspicious", "request", "access"))
        if block_kw and not any(r.kind == "waf" for r in results):
            _add("waf-unknown", "waf",
                 f"HTTP {status} + block-page keywords (specific WAF not identified)", "low")
        elif not block_kw and status in (403, 429) and not results:
            # 403/429 with no WAF signature and no block keywords — still suspicious
            _add("waf-unknown", "waf",
                 f"HTTP {status} on normal GET (no WAF signature found — may be WAF or auth-required)",
                 "low")

    return results


def waf_summary(results: list[WAFResult]) -> str:
    """One-line summary for the report."""
    if not results:
        return ""
    wafs = [r for r in results if r.kind == "waf"]
    cdns = [r for r in results if r.kind == "cdn"]
    parts = []
    if wafs:
        parts.append("WAF: " + ", ".join(sorted(set(r.name for r in wafs))))
    if cdns:
        parts.append("CDN: " + ", ".join(sorted(set(r.name for r in cdns))))
    return " | ".join(parts)


def may_mask_verdict(results: list[WAFResult]) -> bool:
    """True if a WAF is detected — PoC --check may get false NOT EXPLOITABLE.
    CDN-only (no WAF) returns False — CDN caching rarely blocks exploit requests."""
    return any(r.kind == "waf" for r in results)


def waf_detail(results: list[WAFResult]) -> list[dict]:
    """Detailed list for the report (name, kind, evidence, confidence)."""
    return [{"name": r.name, "kind": r.kind, "evidence": r.evidence,
             "confidence": r.confidence} for r in results]

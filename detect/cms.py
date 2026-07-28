"""CMS fingerprint + component enumeration. Grounded: every version comes with evidence.

Supported: WordPress, Joomla, Drupal, Grav, Ghost. WP gets plugin/theme enumeration
via wp-content paths + readme.txt/style.css.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .probe import ProbeResult, find_meta_generator
from .waf import detect_waf, waf_summary, may_mask_verdict, WAFResult

_gen = find_meta_generator


@dataclass
class Component:
    name: str
    type: str            # plugin | theme | core
    version: Optional[str] = None
    evidence: str = ""   # the URL/snippet that proves it


@dataclass
class StackRecord:
    url: str = ""
    cms: Optional[str] = None            # wordpress | joomla | drupal | grav | ghost | magento | ...
    cms_version: Optional[str] = None
    components: list[Component] = field(default_factory=list)
    services: list[Component] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    waf: list[WAFResult] = field(default_factory=list)  # detected WAF/CDN layers


_WP_PLUGIN_RE = re.compile(r'wp-content/plugins/([a-z0-9_\-]+)', re.I)
_WP_THEME_RE = re.compile(r'wp-content/themes/([a-z0-9_\-]+)', re.I)
_WP_VER_RE = re.compile(r'WordPress\s+([0-9][0-9.\-]+)', re.I)
_README_STABLE = re.compile(r'Stable tag:\s*([0-9][0-9.\-x]+)', re.I)
_THEME_VER = re.compile(r'Version:\s*([0-9][0-9.\-]+)', re.I)


def _identify_cms(p: ProbeResult, learned_sigs: list = None) -> tuple[Optional[str], Optional[str], list[str]]:
    """Return (cms, version, evidence). Pure signal matching.
    SELF-IMPROVEMENT: also checks learned signatures from prior scans."""
    ev: list[str] = []
    gen = _gen(p.body) or p.generator_header
    body = p.body
    cookies = " ".join(p.cookies).lower()
    learned_sigs = learned_sigs or []

    # WordPress — require REAL evidence (asset paths / generator / wp-json JSON content).
    # Bare 200 on /wp-json/ or /xmlrpc.php is NOT enough: many CMS (OJS, Joomla) route unknown
    # paths to a 200 catch-all. Check that /wp-json/ returns actual JSON (not HTML).
    wpjson_aux = p.aux.get("/wp-json/")
    wpjson_real = False
    if wpjson_aux:
        wpjson_body = wpjson_aux[1] if len(wpjson_aux) > 1 else ""
        # real wp-json returns JSON starting with { and containing "routes" or "namespace"
        wpjson_real = (wpjson_body.strip().startswith("{") and
                       ("routes" in wpjson_body or "namespace" in wpjson_body))
    if ("wp-content/plugins/" in body or "wp-content/themes/" in body
            or "wp-includes" in body
            or "wordpress" in gen.lower() or "wp-settings" in cookies
            or wpjson_real):
        ver = None
        m = _WP_VER_RE.search(gen) or _WP_VER_RE.search(body)
        if m:
            ver = m.group(1)
        # feed generator: <generator>https://wordpress/?v=5.9.3</generator>
        fm = re.search(r'wordpress/\?v=([0-9][0-9.]+)', body, re.I)
        if fm and not ver:
            ver = fm.group(1)
        ev.append(f"generator={gen or 'n/a'}")
        if wpjson_real:
            ev.append("/wp-json/ JSON reachable")
        return "wordpress", ver, ev

    # Joomla
    if "joomla" in gen.lower() or "/components/com_" in body or "/media/jui/" in body \
            or "/administrator/manifests/files/joomla.xml" in p.aux:
        ver = None
        m = re.search(r'Joomla!\s*([0-9][0-9.]+)', gen, re.I)
        if m:
            ver = m.group(1)
        # parse version from the manifest file (already probed in aux)
        if not ver:
            mf = p.aux.get("/administrator/manifests/files/joomla.xml")
            if mf:
                vm = re.search(r'<version>\s*([0-9][0-9.]+)\s*</version>', mf[1], re.I)
                if vm:
                    ver = vm.group(1)
                    ev.append(f"manifest version={ver}")
        ev.append(f"generator={gen}")
        return "joomla", ver, ev

    # Drupal
    if "drupal" in gen.lower() or p.generator_header.lower().startswith("drupal") \
            or "/sites/default/files/" in body or "drupal.js" in body:
        m = re.search(r'Drupal\s*([0-9][0-9.]+)', gen + " " + p.generator_header, re.I)
        ev.append(f"generator={gen or p.generator_header}")
        return "drupal", (m.group(1) if m else None), ev

    # Grav
    if "grav" in gen.lower():
        m = re.search(r'Grav\s*v?([0-9][0-9.]+)', gen, re.I)
        return "grav", (m.group(1) if m else None), [f"generator={gen}"]

    # Ghost
    if "ghost" in gen.lower() or "x-ghost-cache-status" in p.headers:
        return "ghost", None, [f"generator={gen}"]

    # ---- expanded CMS coverage ----

    # OJS (Open Journal Systems) — academic journal platform by PKP
    if "open journal systems" in gen.lower() or "lib/pkp/" in body or "pkp_structure" in body:
        m = re.search(r'Open Journal Systems\s*([0-9][0-9.]+)', gen, re.I)
        ev_s = [f"generator={gen}"] if gen else []
        if "lib/pkp/" in body:
            ev_s.append("lib/pkp/ path in body")
        if "pkp_structure" in body:
            ev_s.append("pkp_structure class in body")
        return "ojs", (m.group(1) if m else None), ev_s

    # Magento (Adobe)
    if "magento" in gen.lower() or "/skin/frontend/" in body or "/js/mage/" in body \
            or "mage-cache" in cookies or "x-magento-vary" in p.headers:
        ver = None
        m = re.search(r'Magento\s*([0-9][0-9.]+)', gen, re.I)
        if m:
            ver = m.group(1)
        ev_s = [f"generator={gen}"] if gen else []
        if "/skin/frontend/" in body:
            ev_s.append("/skin/frontend/ path in body")
        if "mage-cache" in cookies:
            ev_s.append("cookie mage-cache")
        return "magento", ver, ev_s

    # PrestaShop
    if "prestashop" in gen.lower() or ("x-powered-by" in p.headers and "prestashop" in p.headers["x-powered-by"].lower()) \
            or ("/modules/" in body and "prestashop" in body.lower()):
        ver = None
        m = re.search(r'PrestaShop\s*/?\s*([0-9][0-9.]+)', gen, re.I)
        if m:
            ver = m.group(1)
        ev_s = [f"generator={gen}"] if gen else []
        if "prestashop" in p.headers.get("x-powered-by", "").lower():
            ev_s.append(f"X-Powered-By: {p.headers['x-powered-by']}")
        return "prestashop", ver, ev_s

    # TYPO3
    if "typo3" in gen.lower() or "/typo3conf/" in body or "/fileadmin/" in body or "/typo3/" in body:
        ver = None
        m = re.search(r'TYPO3\s*CMS?\s*([0-9][0-9.]+)', gen, re.I)
        if m:
            ver = m.group(1)
        ev_s = [f"generator={gen}"] if gen else []
        if "/typo3conf/" in body:
            ev_s.append("/typo3conf/ path")
        return "typo3", ver, ev_s

    # concrete5
    if "concrete5" in gen.lower() or "/concrete/js/" in body or "/packages/concrete5" in body:
        ver = None
        m = re.search(r'concrete5\s*([0-9][0-9.]+)', gen, re.I)
        if m:
            ver = m.group(1)
        return "concrete5", ver, [f"generator={gen}"]

    # Craft CMS
    if "craft cms" in gen.lower() or "craft cms" in p.headers.get("x-powered-by", "").lower():
        return "craft-cms", None, [f"generator={gen} or X-Powered-By"]

    # Contao
    if "contao" in gen.lower():
        m = re.search(r'Contao\s*([0-9][0-9.]+)', gen, re.I)
        return "contao", (m.group(1) if m else None), [f"generator={gen}"]

    # MODX
    if "modx" in gen.lower():
        m = re.search(r'MODX\s*([0-9][0-9.]+)', gen, re.I)
        return "modx", (m.group(1) if m else None), [f"generator={gen}"]

    # vBulletin
    if "vbulletin" in gen.lower() or "vbulletin_global.js" in body or ("/forum/" in body and "vbulletin" in body.lower()):
        m = re.search(r'vBulletin\s*([0-9][0-9.]+)', gen, re.I)
        ev_s = [f"generator={gen}"] if gen else []
        if "vbulletin_global.js" in body:
            ev_s.append("vbulletin_global.js in body")
        return "vbulletin", (m.group(1) if m else None), ev_s

    # OpenCart
    if "opencart" in p.headers.get("x-powered-by", "").lower() or "/catalog/view/" in body \
            or "/system/library/" in body:
        m = re.search(r'OpenCart\s*([0-9][0-9.]+)', p.headers.get("x-powered-by", ""), re.I)
        ev_s = []
        if "opencart" in p.headers.get("x-powered-by", "").lower():
            ev_s.append(f"X-Powered-By: {p.headers['x-powered-by']}")
        if "/catalog/view/" in body:
            ev_s.append("/catalog/view/ path")
        return "opencart", (m.group(1) if m else None), ev_s

    # osCommerce
    if "oscommerce" in gen.lower() or "oscsid" in cookies:
        m = re.search(r'osCommerce\s*([0-9][0-9.]+)', gen, re.I)
        ev_s = [f"generator={gen}"] if gen else []
        if "oscsid" in cookies:
            ev_s.append("cookie osCsid")
        return "oscommerce", (m.group(1) if m else None), ev_s

    # WHMCS
    if "whmcs" in p.headers.get("x-powered-by", "").lower() or ("whmcs" in body.lower() and "/whmcs/" in body):
        return "whmcs", None, [f"X-Powered-By: {p.headers.get('x-powered-by', '')}"]

    # Nextcloud
    if "nextcloud" in p.headers.get("x-powered-by", "").lower() or "/ocs/" in body:
        ver = None
        m = re.search(r'Nextcloud\s*([0-9][0-9.]+)', p.headers.get("x-powered-by", ""), re.I)
        if m:
            ver = m.group(1)
        return "nextcloud", ver, [f"X-Powered-By: {p.headers['x-powered-by']}"]

    # Umbraco
    if "umbraco" in gen.lower() or "/umbraco/" in body:
        return "umbraco", None, [f"generator={gen}"]

    # Bolt CMS
    if "bolt" in gen.lower() and "bolt.cm" in gen.lower():
        return "bolt-cms", None, [f"generator={gen}"]

    # Shopify (SaaS — no CVEs but detection matters for stack context)
    if "x-shopid" in p.headers or "cdn.shopify.com" in body or "shopify.theme" in body.lower():
        ev_s = []
        if "x-shopid" in p.headers:
            ev_s.append(f"X-ShopId: {p.headers['x-shopid'][:40]}")
        if "cdn.shopify.com" in body:
            ev_s.append("cdn.shopify.com in body")
        return "shopify", None, ev_s

    # Wix (SaaS)
    if "x-wix-request-meta" in p.headers or "static.wixstatic.com" in body:
        return "wix", None, ["X-Wix header / wixstatic.com in body"]

    # Squarespace (SaaS)
    if "x-squarespace" in p.headers or ("squarespace" in body.lower() and "squarespace.com" in body):
        return "squarespace", None, ["X-Squarespace header"]

    # Static site generators (no CVEs but detection)
    if "hugo" in gen.lower():
        return "hugo", None, [f"generator={gen}"]
    if "jekyll" in gen.lower():
        return "jekyll", None, [f"generator={gen}"]
    if "gatsby" in gen.lower() or "___gatsby" in body:
        return "gatsby", None, [f"generator={gen}"]

    # JS frameworks (no CVEs but stack context)
    if "__NEXT_DATA__" in body or "next.js" in p.headers.get("x-powered-by", "").lower():
        return "nextjs", None, ["__NEXT_DATA__ in body"]
    if "__NUXT__" in body:
        return "nuxt", None, ["__NUXT__ in body"]

    # SELF-IMPROVEMENT: check learned signatures from prior scans
    # (patterns that were discovered in previous scans and saved to DB)
    for sig in learned_sigs:
        sig_type = sig.get("signal_type", "")
        sig_val = sig.get("signal_value", "")
        cms_name = sig.get("cms_name", "")
        if not sig_val or not cms_name:
            continue
        matched = False
        if sig_type == "generator" and sig_val.lower() in gen.lower():
            matched = True
        elif sig_type == "path" and sig_val in body:
            matched = True
        elif sig_type == "header" and sig_val.lower() in str(p.headers).lower():
            matched = True
        elif sig_type == "cookie" and sig_val.lower() in cookies:
            matched = True
        if matched:
            return cms_name, None, [f"learned signature: {sig_type}={sig_val[:40]}"]

    return None, None, ev


async def _enumerate_wp(p: ProbeResult, client) -> list[Component]:
    comps: list[Component] = []
    seen_p: set[str] = set()
    for m in _WP_PLUGIN_RE.finditer(p.body):
        slug = m.group(1).lower()
        if slug in seen_p:
            continue
        seen_p.add(slug)
        ev_url = f"/wp-content/plugins/{slug}/"
        ver = None
        comp = Component(name=slug, type="plugin", version=ver, evidence=ev_url)
        comps.append(comp)
    seen_t: set[str] = set()
    for m in _WP_THEME_RE.finditer(p.body):
        slug = m.group(1).lower()
        if slug in seen_t:
            continue
        seen_t.add(slug)
        comps.append(Component(name=slug, type="theme", evidence=f"/wp-content/themes/{slug}/"))
    # enrich versions via on-demand fetches (readme.txt / style.css). Use ORIGIN as base
    # (final_url may include a routed path that breaks wp-content file paths).
    from urllib.parse import urlparse as _up
    _pu = _up(p.final_url or p.url)
    base = f"{_pu.scheme}://{_pu.netloc}"
    for c in comps:
        if c.type == "plugin":
            try:
                r = await client.get(f"{base}/wp-content/plugins/{c.name}/readme.txt", timeout=10.0)
                if r.status_code < 404:
                    rm = _README_STABLE.search(r.text)
                    if rm:
                        c.version = rm.group(1)
                        c.evidence = f"readme.txt stable_tag={c.version}"
            except Exception:
                pass
        elif c.type == "theme":
            try:
                r = await client.get(f"{base}/wp-content/themes/{c.name}/style.css", timeout=10.0)
                if r.status_code < 404:
                    tm = _THEME_VER.search(r.text[:2000])
                    if tm:
                        c.version = tm.group(1)
                        c.evidence = f"style.css Version={c.version}"
            except Exception:
                pass
    return comps


def _parse_product(header_val: str) -> tuple[str, Optional[str]]:
    """Server/X-Powered-By → (product, version). e.g. 'nginx/1.25.3'→('nginx','1.25.3')."""
    v = (header_val or "").strip()
    m = re.match(r'\s*([A-Za-z][A-Za-z0-9._-]*)\s*/?\s*([0-9][0-9.]*)?', v)
    if not m:
        return v.lower() or "unknown", None
    prod = m.group(1).lower()
    ver = m.group(2)
    # normalize common names
    prod = {"microsoft-iis": "iis", "express": "express"}.get(prod, prod)
    return prod, ver


def _services(p: ProbeResult) -> list[Component]:
    out: list[Component] = []
    srv = p.server
    if srv:
        prod, ver = _parse_product(srv)
        out.append(Component(name=prod, type="service", version=ver,
                             evidence=f"Server: {srv}"))
    pb = p.powered_by
    if pb:
        prod, ver = _parse_product(pb)
        # avoid duplicating web-server product
        if not any(s.name == prod for s in out):
            out.append(Component(name=prod, type="service", version=ver,
                                 evidence=f"X-Powered-By: {pb}"))
    via = p.headers.get("via", "")
    if via:
        prod, ver = _parse_product(via)
        if prod not in ("unknown",) and not any(s.name == prod for s in out):
            out.append(Component(name=prod, type="service", version=ver,
                                 evidence=f"Via: {via}"))
    return out


async def detect_stack(url: str, client=None, learned_sigs: list = None) -> StackRecord:
    from .probe import probe
    own = client is None
    if own:
        import httpx
        client = httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0"}, timeout=15.0, follow_redirects=True)
    p = await probe(url, client)
    rec = StackRecord(url=p.final_url or url, evidence=[])
    if p.error:
        rec.notes.append(f"probe error: {p.error}")
        if own:
            await client.aclose()
        return rec
    rec.services = _services(p)
    # WAF/CDN detection (from the same probe response — no extra request)
    rec.waf = detect_waf(p.headers, p.body, p.status)
    if rec.waf:
        waf_names = waf_summary(rec.waf)
        rec.notes.append(f"WAF/CDN detected: {waf_names}")
    cms, ver, ev = _identify_cms(p, learned_sigs or [])
    rec.cms = cms
    rec.cms_version = ver
    rec.evidence.extend(ev)
    if cms == "wordpress":
        rec.components = await _enumerate_wp(p, client)
        if rec.cms_version:
            rec.components.insert(0, Component(name="wordpress", type="core",
                                               version=rec.cms_version,
                                               evidence="generator meta / feed"))
    # non-CMS: ensure services carry the load
    if own:
        await client.aclose()
    return rec


def to_signals(s: StackRecord) -> list[dict]:
    """Flatten stack → list of {label, product, version} for vuln queries."""
    out = []
    if s.cms:
        out.append({"label": "cms", "product": s.cms, "version": s.cms_version})
    for c in s.components:
        out.append({"label": c.type, "product": c.name, "version": c.version})
    for c in s.services:
        out.append({"label": "service", "product": c.name, "version": c.version})
    for w in s.waf:
        out.append({"label": "waf", "product": w.name, "version": None})
    return out

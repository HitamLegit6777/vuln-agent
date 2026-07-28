"""HTTP probe — gather raw evidence (headers/body/auxiliary endpoints).

Grounded: returns ONLY what the server actually sends. No inference.
ponytail: no active exploitation here; just GET + parse. ceiling: HEAD/OPTIONS fingerprint.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
HEADERS = {"User-Agent": UA, "Accept": "text/html,application/json,*/*;q=0.8"}


@dataclass
class ProbeResult:
    url: str = ""
    final_url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    # auxiliary endpoint probes (path -> (status, snippet))
    aux: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def server(self) -> str:
        return (self.headers.get("server") or self.headers.get("Server") or "").strip()

    @property
    def powered_by(self) -> str:
        return (self.headers.get("x-powered-by") or self.headers.get("X-Powered-By") or "").strip()

    @property
    def generator_header(self) -> str:
        return (self.headers.get("x-generator") or self.headers.get("X-Generator") or "").strip()

    @property
    def cookies(self) -> list[str]:
        return self.headers.get("set-cookie", "").split(",") if self.headers.get("set-cookie") else []


AUX_PATHS = [
    "/robots.txt", "/readme.html", "/readme.txt",
    "/wp-json/", "/wp-json/wp/v2/users",
    "/feed/", "/rss/", "/atom.xml",
    "/xmlrpc.php", "/license.txt", "/CHANGELOG.txt",
    "/administrator/manifests/files/joomla.xml", "/api/index.php/v1/",
    "/core/install.php", "/sites/default/files/",
]


def _norm(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


async def probe(url: str, client: Optional[httpx.AsyncClient] = None) -> ProbeResult:
    url = _norm(url)
    own = client is None
    if own:
        client = httpx.AsyncClient(headers=HEADERS, timeout=15.0, follow_redirects=True)
    res = ProbeResult(url=url)
    try:
        r = await client.get(url)
        res.final_url = str(r.url)
        res.status = r.status_code
        res.headers = {k.lower(): v for k, v in r.headers.items()}
        res.body = r.text[:200000]
    except Exception as e:
        res.error = f"{type(e).__name__}: {e}"
        # HTTPS fallback: if HTTP failed, try HTTPS
        if url.startswith("http://"):
            https_url = "https://" + url[7:]
            try:
                r = await client.get(https_url)
                res.final_url = str(r.url)
                res.status = r.status_code
                res.headers = {k.lower(): v for k, v in r.headers.items()}
                res.body = r.text[:200000]
                res.error = None  # HTTPS worked
            except Exception as e2:
                res.error = f"{type(e).__name__}: {e} (HTTPS also failed: {type(e2).__name__})"
        if res.error and own:
            await client.aclose()
        if res.error:
            return res

    # auxiliary probes (best-effort). Use the ORIGIN (scheme://host) as base, not final_url,
    # because final_url may include a routed path (e.g. /index.php/th/) that breaks file paths.
    from urllib.parse import urlparse
    parsed = urlparse(res.final_url or url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in AUX_PATHS:
        try:
            ar = await client.get(base + path, timeout=10.0)
            if ar.status_code < 404:
                res.aux[path] = (ar.status_code, ar.text[:4000])
        except Exception:
            continue
    if own:
        await client.aclose()
    return res


def find_meta_generator(html: str) -> str:
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', html, re.I)
    return m.group(1).strip() if m else ""

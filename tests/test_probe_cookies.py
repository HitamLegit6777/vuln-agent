"""Tests for detect.probe cookie handling + detect.cms cookie-based fingerprinting.

httpx collapses multiple Set-Cookie response headers into a single comma-joined
string via `.get()`. Splitting THAT on ',' mangles any cookie whose value contains a
comma (e.g. `Expires=Wed, 09 Jun 2027`). probe now captures the real per-cookie list
via `Headers.get_list`, exposed through `ProbeResult.cookies`.
"""
import asyncio
import contextlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

from detect.probe import probe, ProbeResult


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        self.send_response(200)
        # Two cookies; the first has a comma inside the Expires attribute.
        self.send_header("Set-Cookie",
                         "wordpress_logged_in_x=1; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Path=/")
        self.send_header("Set-Cookie", "PHPSESSID=deadbeef; Path=/")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>hello</body></html>")


@contextlib.contextmanager
def _server():
    port = _free_port()
    httpd = HTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        httpd.shutdown()


def test_probe_cookies_not_mangled_by_comma():
    async def run():
        with _server() as url:
            async with httpx.AsyncClient() as client:
                return await probe(url, client)
    res = asyncio.run(run())
    cookies = res.cookies
    # Exactly two cookies, and the Expires comma did NOT create a spurious third entry.
    assert len(cookies) == 2, cookies
    assert any(c.startswith("wordpress_logged_in_x=") for c in cookies), cookies
    assert any(c.startswith("PHPSESSID=") for c in cookies), cookies
    # The full Expires value must be intact inside the first cookie.
    assert any("Expires=Wed, 09 Jun 2027" in c for c in cookies), cookies


def test_cookies_property_fallback_when_no_raw():
    # Old-style result with only a flat set-cookie header still yields something usable.
    r = ProbeResult(headers={"set-cookie": "a=1; Path=/"})
    assert r.cookies == ["a=1; Path=/"]


def test_wordpress_detected_via_cookie():
    # wp-settings cookie is one of the WordPress signals in detect.cms._identify_cms.
    from detect.cms import _identify_cms
    p = ProbeResult(body="<html></html>",
                    raw_cookies=["wp-settings-1=foo; Path=/",
                                 "wp-settings-time-1=123; Path=/"])
    cms, ver, ev = _identify_cms(p)
    assert cms == "wordpress", (cms, ev)

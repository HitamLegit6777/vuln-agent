"""Tests for llm.chat_stream timeout enforcement.

The streaming client promised a hard wall-clock timeout (via asyncio.wait_for) and a
read timeout, but a past version awaited the stream coroutine directly with
httpx read-timeout = None -> the `timeout` parameter was dead and a router that hung
mid-stream would hang forever. These tests pin that the hard timeout actually fires.
"""
import asyncio

import pytest

import llm


class _FakeStreamResp:
    status_code = 200

    def __init__(self, mode):
        self._mode = mode

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def aread(self):
        return b""

    async def aiter_lines(self):
        if self._mode == "hang_silent":
            # never yields a line, just sleeps well past the deadline
            await asyncio.sleep(30)
            return
        if self._mode == "trickle_forever":
            # keeps sending keep-alive-ish lines forever (no [DONE])
            while True:
                await asyncio.sleep(0.01)
                yield ":"  # comment line, ignored by parser


class _FakeClient:
    def __init__(self, mode):
        self._mode = mode

    def stream(self, *a, **kw):
        return _FakeStreamResp(self._mode)


def _install_fake(monkeypatch, mode):
    monkeypatch.setattr(llm, "_client_obj", lambda: _FakeClient(mode))


def test_hard_timeout_fires_on_silent_hang(monkeypatch):
    _install_fake(monkeypatch, "hang_silent")

    async def run():
        # timeout=1s must raise fast, not wait 30s
        return await llm.chat_stream("m", [{"role": "user", "content": "hi"}], timeout=1)

    import time
    t0 = time.time()
    with pytest.raises(RuntimeError) as ei:
        asyncio.run(run())
    elapsed = time.time() - t0
    assert "timeout" in str(ei.value).lower()
    assert elapsed < 5, f"took {elapsed:.1f}s — hard timeout did not fire"


def test_hard_timeout_fires_on_trickle_without_done(monkeypatch):
    _install_fake(monkeypatch, "trickle_forever")

    async def run():
        return await llm.chat_stream("m", [{"role": "user", "content": "hi"}], timeout=1)

    import time
    t0 = time.time()
    with pytest.raises(RuntimeError):
        asyncio.run(run())
    elapsed = time.time() - t0
    assert elapsed < 5, f"took {elapsed:.1f}s — wait_for did not bound a trickling stream"

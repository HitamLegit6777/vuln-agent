"""9router LLM client (OpenAI-compatible). Streaming-first to avoid ReadTimeout
on reasoning models (deepseek-v4-pro emits reasoning_content before content).

Models: MODEL_DETECT (al/glm-5.2), MODEL_REPORT (al/deepseek-v4-pro).
"""
from __future__ import annotations

import json
from typing import Optional
import contextvars

import httpx

from config import ROUTER_BASE, ROUTER_KEY, LLM_TIMEOUT, MODEL_DETECT, MODEL_REPORT

# runtime model overrides — set via bot /model command, persisted in db settings.
# Fall back to config values when never switched.
_detect_model: Optional[str] = None
_report_model: Optional[str] = None
_job_models: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "vuln_agent_job_models", default=None)


def bind_models(models: Optional[dict] = None):
    """Bind immutable model ids to the current task and its child tasks."""
    snapshot = dict(models or get_models())
    return _job_models.set(snapshot)


def reset_models(token) -> None:
    _job_models.reset(token)

_client: Optional[httpx.AsyncClient] = None


def _detect() -> str:
    bound = _job_models.get()
    return (bound or {}).get("detect") or _detect_model or MODEL_DETECT


def _report() -> str:
    bound = _job_models.get()
    return (bound or {}).get("report") or _report_model or MODEL_REPORT


def get_models() -> dict:
    return {"detect": _detect(), "report": _report()}


def set_models(detect: Optional[str] = None, report: Optional[str] = None) -> None:
    """Override active models at runtime (persist separately via db).
    Pass None to keep current, '' to reset to config default."""
    global _detect_model, _report_model
    if detect is not None:
        _detect_model = detect or None
    if report is not None:
        _report_model = report or None


async def load_models_from_db():
    """Restore persisted model choices at startup."""
    try:
        import db as _db
        d = await _db.get_setting("model_detect", "")
        r = await _db.get_setting("model_report", "")
        set_models(d or None, r or None)
    except Exception:
        pass


async def fetch_available_models() -> list[str]:
    """Query the router for available model ids (used by /model command)."""
    try:
        r = await _client_obj().get("/models", timeout=30.0)
        if r.status_code >= 400:
            return []
        data = r.json()
        return [m.get("id", "") for m in (data.get("data") or []) if m.get("id")]
    except Exception:
        return []


def _client_obj() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=ROUTER_BASE,
            headers={"Authorization": f"Bearer {ROUTER_KEY}", "Content-Type": "application/json"},
            timeout=httpx.Timeout(LLM_TIMEOUT, connect=15.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10,
                                keepalive_expiry=30.0),
        )
    return _client


async def chat_stream(model: str, messages: list[dict], temperature: float = 0.2,
                      max_tokens: int = 8192, timeout: int = 600) -> str:
    """Streaming chat → accumulates `content` deltas (drops reasoning_content).
    Streaming keeps the connection alive → no ReadTimeout on long reasoning.
    HARD timeout via asyncio.wait_for — kills the call if the router hangs mid-stream."""
    import asyncio
    payload = {
        "model": model, "messages": messages, "temperature": temperature,
        "max_tokens": max_tokens, "stream": True,
        # some 9router upstreams (deepseek-v4-flash) 400 without stream_options
        "stream_options": {"include_usage": True},
    }
    parts: list[str] = []
    reasoning: list[str] = []
    try:
        # read timeout: if no byte arrives for `read_timeout`s the stream is killed
        # (router hung mid-response). hard timeout via wait_for = overall wall-clock
        # limit (the `timeout` param). Both are now actually enforced.
        read_timeout = min(300.0, float(timeout))  # reasoning models can think >120s before first token

        async def _do_stream():
            async with _client_obj().stream(
                "POST", "/chat/completions", json=payload,
                timeout=httpx.Timeout(read_timeout, connect=15.0, write=30.0, pool=30.0),
            ) as r:
                if r.status_code >= 400:
                    body = await r.aread()
                    # 5xx / 524 (Cloudflare origin timeout) are transient — retryable
                    if r.status_code >= 500:
                        raise httpx.RemoteProtocolError(f"router {r.status_code}: {body[:200]!r}")
                    raise RuntimeError(f"router {r.status_code}: {body[:300]!r}")
                async for line in r.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        obj = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    ch = ((obj.get("choices") or [{}])[0].get("delta") or {})
                    if ch.get("content"):
                        parts.append(ch["content"])
                    if ch.get("reasoning_content"):
                        reasoning.append(ch["reasoning_content"])
        # transient router failures (ReadTimeout/ConnectError/5xx) are retried with
        # backoff, but only when nothing was streamed yet — partial answers are kept
        _RETRIES = 3
        _attempt = 0
        while True:
            _attempt += 1
            try:
                await asyncio.wait_for(_do_stream(), timeout=timeout)
                break  # stream completed
            except httpx.TransportError as e:
                if parts or reasoning or _attempt >= _RETRIES:
                    if not parts and not reasoning:
                        raise RuntimeError(f"stream HTTP error: {type(e).__name__}: {e}")
                    break
                await asyncio.sleep(2.0 * _attempt)
            except asyncio.TimeoutError:
                raise RuntimeError(f"LLM timeout after {timeout}s (router hung — no response)")
    except asyncio.TimeoutError:
        # hard timeout — return partial result if we have any
        if not parts and not reasoning:
            raise RuntimeError(f"LLM timeout after {timeout}s (router hung — no response)")
    except httpx.HTTPError as e:
        if not parts:
            raise RuntimeError(f"stream HTTP error: {type(e).__name__}: {e}")
    except RuntimeError:
        if not parts:
            raise
    content = "".join(parts)
    if not content and reasoning:
        return "".join(reasoning)
    return content


async def chat(model: str, messages: list[dict], temperature: float = 0.2,
               max_tokens: int = 4096, timeout: Optional[int] = None) -> str:
    """Streaming chat (alias, robust for reasoning models)."""
    return await chat_stream(model, messages, temperature, max_tokens,
                             timeout=timeout or LLM_TIMEOUT)


async def chat_detect(messages, temperature=0.15, max_tokens=4096) -> str:
    return await chat_stream(_detect(), messages, temperature, max_tokens, timeout=600)


async def chat_report(messages, temperature=0.2, max_tokens=8192) -> str:
    return await chat_stream(_report(), messages, temperature, max_tokens, timeout=900)


async def close():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None

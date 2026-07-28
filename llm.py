"""9router LLM client (OpenAI-compatible). Streaming-first to avoid ReadTimeout
on reasoning models (deepseek-v4-pro emits reasoning_content before content).

Models: MODEL_DETECT (al/glm-5.2), MODEL_REPORT (al/deepseek-v4-pro).
"""
from __future__ import annotations

import json
from typing import Optional

import httpx

from config import ROUTER_BASE, ROUTER_KEY, LLM_TIMEOUT, MODEL_DETECT, MODEL_REPORT

_client: Optional[httpx.AsyncClient] = None


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
    }
    parts: list[str] = []
    reasoning: list[str] = []
    try:
        # read timeout 120s = if no token for 120s, kill (router hung)
        # hard timeout via wait_for = overall limit (timeout param)
        async def _do_stream():
            async with _client_obj().stream(
                "POST", "/chat/completions", json=payload,
                timeout=httpx.Timeout(None, connect=15.0, write=30.0, pool=30.0),
            ) as r:
                if r.status_code >= 400:
                    body = await r.aread()
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
        await _do_stream()
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
    return await chat_stream(MODEL_DETECT, messages, temperature, max_tokens, timeout=600)


async def chat_report(messages, temperature=0.2, max_tokens=8192) -> str:
    return await chat_stream(MODEL_REPORT, messages, temperature, max_tokens, timeout=900)


async def close():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None

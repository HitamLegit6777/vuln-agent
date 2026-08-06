"""Centralized Telegram rich-message sender (Bot API 10.2 ``sendRichMessage``).

Single chokepoint for every bot/monitor text response:

- Rich path: ``sendRichMessage`` with ``InputRichMessage.html`` (official contract:
  exactly one of ``html`` / ``markdown`` / ``blocks``, we always use ``html``).
  Dispatched via ``bot.sendRichMessage`` when the installed python-telegram-bot
  exposes it, otherwise via ``bot._post("sendRichMessage", payload)`` or raw HTTP
  through ``bot.request.post`` (multipart, same as ptb's own requests).
- Legacy path: ``sendMessage`` with ``parse_mode=HTML`` (safe subset) when the
  server/library lacks rich support. Downgrade is feature-detected and permanent
  per bot (cached): an unknown-method 404 costs exactly one failed call, then the
  bot stays on the legacy path for the rest of the process.

All untrusted HTML is sanitized to the rich-HTML allowlist (headings, paragraphs,
footer, hr, lists, blockquote/aside+cite, tables, details/summary,
mark/sub/sup/spoiler, time/math) while unsafe attrs, unsafe URLs and media tags
are rejected. Messages are chunked under both mode limits and every value is
html-escaped. No emojis.

Drafts (``sendRichMessageDraft``) are intentionally not implemented — optional.
"""
from __future__ import annotations

import html
import re
from typing import Any, Optional

from bs4 import BeautifulSoup, NavigableString, Tag

# ------------------------------------------------------------------ limits (official)
RICH_HTML_LIMIT = 32768  # InputRichMessage.html UTF-8 chars (Bot API "Rich Message Limits")
LEGACY_LIMIT = 4096      # sendMessage text cap
CHUNK_LIMIT = 3500       # per-message ceiling, safe under BOTH modes
MAX_BLOCKS = 500         # block elements (incl. list items, table rows, details) per message
MAX_NEST = 16            # formatting nesting depth
MAX_TABLE_COLS = 20      # columns per table row

# Rich HTML tag -> emitted tag. Legacy aliases (strong/em/ins/strike/del) are
# normalized to their rich equivalents; everything else on this map keeps its name.
_TAG_MAP = {
    "b": "b", "strong": "b", "i": "i", "em": "i", "u": "u", "ins": "u",
    "s": "s", "strike": "s", "del": "s", "code": "code", "pre": "pre",
    "mark": "mark", "sub": "sub", "sup": "sup", "tg-spoiler": "tg-spoiler",
    "a": "a", "cite": "cite",
    "h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "h5": "h5", "h6": "h6",
    "p": "p", "footer": "footer", "hr": "hr", "br": "br",
    "ul": "ul", "ol": "ol", "li": "li", "input": "input",
    "blockquote": "blockquote", "aside": "aside",
    "table": "table", "caption": "caption", "tr": "tr", "th": "th", "td": "td",
    "details": "details", "summary": "summary",
    "tg-time": "tg-time", "tg-math": "tg-math", "tg-math-block": "tg-math-block",
    "tg-reference": "tg-reference",
}

_BLOCK_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "pre", "footer", "hr", "ul", "ol",
    "li", "blockquote", "aside", "table", "caption", "tr", "th", "td",
    "details", "summary", "tg-math-block",
}
_EMPTY_TAGS = {"hr", "br", "input"}

# Media / interactive content — rejected outright (security contract).
_MEDIA_TAGS = {
    "img", "video", "audio", "figure", "figcaption", "tg-map", "tg-collage",
    "tg-slideshow", "tg-emoji", "iframe", "embed", "object", "canvas", "svg",
}
_SKIP_TAGS = {"script", "style", "template"}

_SAFE_HREF_RE = re.compile(
    r"^(?:https?://[^\s<>\"']+"
    r"|mailto:[^\s<>\"']+"
    r"|tel:[^\s<>\"']+"
    r"|tg://user\?id=[0-9]+"
    r"|#[A-Za-z0-9_-]+)$",
    re.I,
)
_ANCHOR_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_INT_RE = re.compile(r"^\d+$")
_ALIGN = {"left", "center", "right"}
_VALIGN = {"top", "middle", "bottom"}
_OL_TYPE = {"1", "a", "A", "i", "I"}
_LANG_RE = re.compile(r"^language-[A-Za-z0-9_+-]+$")
_TIME_FORMAT_RE = re.compile(r"^[A-Za-z0-9_%+:. -]+$")

_METHOD_NOT_FOUND_RE = re.compile(
    r"(?i)method[^.]*?(?:not found|not available|doesn'?t exist|not supported|404)"
    r"|(?:not found|404).{0,40}method"
)


def _e(s) -> str:
    return html.escape(str(s) if s is not None else "")


# ------------------------------------------------------------------ capability
# Feature-detect rich support per bot (keyed by token). Downgrade is permanent:
# once a bot hits an unknown-method error the flag flips to False and is never
# re-probed (a 404 on every message would be spammy and slow).
_capability: dict[str, bool] = {}


def _bot_key(bot) -> str:
    return getattr(bot, "token", None) or f"anon:{id(bot)}"


def rich_supported(bot) -> bool:
    """True if the bot can reach ``sendRichMessage``. Cached per bot token."""
    key = _bot_key(bot)
    if key in _capability:
        return _capability[key]
    ok = (
        callable(getattr(bot, "sendRichMessage", None))
        or callable(getattr(bot, "_post", None))
        or callable(getattr(bot, "request", None))
    )
    _capability[key] = ok
    return ok


def downgrade_rich(bot) -> None:
    """Permanently disable the rich path for this bot (method-not-found)."""
    _capability[_bot_key(bot)] = False


def reset_capability_cache() -> None:
    """Forget all cached capability flags (tests, hot-reload)."""
    _capability.clear()


def _is_method_not_found(exc: Exception) -> bool:
    """Distinguish 'endpoint unknown' errors from ordinary BadRequests.

    Telegram answers unknown methods with HTTP 404 / 'method not found'. We must
    never downgrade on e.g. 'message is not found' (edit of a deleted message),
    so the match requires the word 'method' (or the 404 status) near the not-found
    marker, or the ptb ``EndPointNotFound`` exception class.
    """
    if exc.__class__.__name__ in ("EndPointNotFound", "NotFound"):
        return True
    msg = str(exc) or ""
    if not msg:
        return False
    low = msg.lower()
    if "404" in low and ("not found" in low or "method" in low):
        return True
    return bool(_METHOD_NOT_FOUND_RE.search(low))


# ------------------------------------------------------------------ sanitize (rich)
def _safe_attrs(tag: str, node: Tag) -> str:
    """Rebuild allowlisted attributes for a tag; everything else is dropped."""
    parts: list[str] = []
    if tag == "a":
        href = node.get("href", "")
        if href and _SAFE_HREF_RE.match(str(href)):
            parts.append(f'href="{_e(href)}"')
        name = node.get("name", "")
        if name and _ANCHOR_RE.match(str(name)):
            parts.append(f'name="{_e(name)}"')
    elif tag == "code":
        cls = node.get("class")
        if isinstance(cls, list):
            cls = " ".join(cls)
        cls = str(cls or "")
        if _LANG_RE.match(cls):
            parts.append(f'class="{_e(cls)}"')
    elif tag == "ol":
        start = node.get("start")
        if _INT_RE.match(str(start or "")):
            parts.append(f'start="{start}"')
        t = node.get("type")
        if t in _OL_TYPE:
            parts.append(f'type="{_e(t)}"')
        if "reversed" in node.attrs:
            parts.append("reversed")
    elif tag == "li":
        value = node.get("value")
        if _INT_RE.match(str(value or "")):
            parts.append(f'value="{value}"')
    elif tag == "input":
        if node.get("type") == "checkbox":
            parts.append('type="checkbox"')
            if "checked" in node.attrs:
                parts.append("checked")
    elif tag == "table":
        for flag in ("bordered", "striped"):
            if flag in node.attrs:
                parts.append(flag)
    elif tag in ("th", "td"):
        for attr in ("colspan", "rowspan"):
            v = node.get(attr)
            if _INT_RE.match(str(v or "")) and 1 <= int(v) <= MAX_TABLE_COLS:
                parts.append(f'{attr}="{v}"')
        if node.get("align") in _ALIGN:
            parts.append(f'align="{node.get("align")}"')
        if node.get("valign") in _VALIGN:
            parts.append(f'valign="{node.get("valign")}"')
    elif tag == "details":
        if "open" in node.attrs:
            parts.append("open")
    elif tag == "tg-time":
        unix = node.get("unix")
        if _INT_RE.match(str(unix or "")):
            parts.append(f'unix="{unix}"')
        fmt = node.get("format")
        if fmt and _TIME_FORMAT_RE.match(str(fmt)):
            parts.append(f'format="{_e(fmt)}"')
    elif tag == "tg-reference":
        name = node.get("name")
        if name and _ANCHOR_RE.match(str(name)):
            parts.append(f'name="{_e(name)}"')
    return (" " + " ".join(parts)) if parts else ""


def sanitize_rich(text: str, footer: Optional[str] = None) -> str:
    """Whitelist-clean untrusted HTML to the rich-HTML subset (InputRichMessage.html).

    Keeps: headings, p, pre/code, footer, hr, br, ul/ol/li (checkbox task lists),
    blockquote/aside + cite, table/caption/tr/th/td, details/summary, a[href|name],
    mark/sub/sup/s, tg-spoiler, tg-time, tg-math(-block), tg-reference.
    Rejects: media tags (img/video/audio/figure/tg-map/...), unsafe URLs
    (javascript:, data:, vbscript:), event handlers and every other attribute.
    `footer` (optional) is appended as a <footer> block.
    """
    if not text:
        return ""
    soup = BeautifulSoup(text, "lxml")
    out: list[str] = []
    blocks = 0
    cells_in_row = [0]

    def push_block(open_tag: str, close_tag: str, node: Tag, depth: int) -> None:
        nonlocal blocks
        if blocks >= MAX_BLOCKS:
            walk(node, depth)  # beyond block budget — unwrap, keep text
            return
        blocks += 1
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append(open_tag)
        walk(node, depth + 1)
        out.append(close_tag)
        out.append("\n")

    def walk(node, depth: int) -> None:
        nonlocal blocks
        for child in node.children:
            if isinstance(child, NavigableString):
                out.append(html.escape(str(child)))
                continue
            if not isinstance(child, Tag):
                continue
            name = child.name.lower()
            if name in _SKIP_TAGS:
                continue
            if name in _MEDIA_TAGS:
                # Reject media elements, but keep caption text (e.g. <figcaption>).
                walk(child, depth)
                continue
            tag = _TAG_MAP.get(name)
            if tag is None or depth >= MAX_NEST:
                walk(child, depth)  # unwrap unknown / too-deep content
                continue
            attrs = _safe_attrs(tag, child)

            if tag in _EMPTY_TAGS:
                if tag == "hr":
                    push_block("<hr/>", "", child, depth)
                elif tag == "br":
                    out.append("<br/>")
                elif tag == "input":
                    out.append(f"<input{attrs}/>")
                continue

            if tag in ("tg-math", "tg-math-block"):
                out.append(f"<{tag}{attrs}>")
                walk(child, depth + 1)
                out.append(f"</{tag}>")
                if tag == "tg-math-block":
                    out.append("\n")
                continue

            if tag == "pre":
                # <pre><code class="language-x">…</code></pre> keeps the language hint
                code = None
                kids = [c for c in child.children if isinstance(c, Tag) and c.name.lower() == "code"]
                if len(kids) == 1 and not any(
                    isinstance(c, NavigableString) and str(c).strip() for c in child.children
                ):
                    code = kids[0]
                if code is not None:
                    push_block(
                        f"<pre><code{_safe_attrs('code', code)}>",
                        "</code></pre>",
                        code,
                        depth,
                    )
                else:
                    push_block("<pre>", "</pre>", child, depth)
                continue

            if tag == "tr":
                # cap columns per row (official limit: 20)
                cells_in_row[0] = 0
                push_block("<tr>", "</tr>", child, depth)
                continue

            if tag in ("th", "td"):
                if cells_in_row[0] >= MAX_TABLE_COLS:
                    walk(child, depth)
                    continue
                cells_in_row[0] += 1

            if tag == "a" and not attrs:
                walk(child, depth)  # link without href/name — plain text
                continue

            if tag in _BLOCK_TAGS:
                push_block(f"<{tag}{attrs}>", f"</{tag}>", child, depth)
            else:
                out.append(f"<{tag}{attrs}>")
                walk(child, depth + 1)
                out.append(f"</{tag}>")

    body = soup.body if soup.body is not None else soup
    walk(body, 0)
    text = "".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if footer:
        text += f"\n<footer>{_e(footer)}</footer>\n"
    return text


# ------------------------------------------------------------------ legacy conversion
# Legacy parse_mode=HTML subset: b i u s code pre a blockquote tg-spoiler.
_LEGACY_ALLOWED = {"b", "i", "u", "s", "code", "pre", "blockquote", "tg-spoiler"}


def to_legacy_html(text: str) -> str:
    """Convert rich HTML (or arbitrary HTML) to Telegram legacy-safe HTML.

    Output only contains: b i u s code pre a blockquote tg-spoiler + escaped text.
    Headings become bold lines, tables become text rows, details flatten to a bold
    summary, mark becomes bold, sub/sup/time/math keep their text, media is dropped.
    """
    if not text:
        return ""
    soup = BeautifulSoup(text, "lxml")
    out: list[str] = []
    ol_stack: list[int] = []

    def walk(node) -> None:
        for child in node.children:
            if isinstance(child, NavigableString):
                out.append(html.escape(str(child)))
                continue
            if not isinstance(child, Tag):
                continue
            name = child.name.lower()
            if name in _SKIP_TAGS:
                continue
            if name in _MEDIA_TAGS:
                walk(child)  # drop the element, keep any caption text
                continue
            if name == "br":
                out.append("\n")
                continue
            if name in ("p", "div", "li", "tr", "summary", "caption", "blockquote"):
                out.append("\n")
                if name == "blockquote":
                    _blockquote(child)
                else:
                    walk(child)
                out.append("\n")
                continue
            if name in ("h1", "h2", "h3", "h4", "h5", "h6", "details"):
                out.append("\n<b>")
                walk(child)
                out.append("</b>\n")
                continue
            if name == "hr":
                out.append("\n────────────\n")
                continue
            if name in ("footer", "aside"):
                out.append("\n<i>")
                walk(child)
                out.append("</i>\n")
                continue
            if name == "cite":
                out.append(" (")
                walk(child)
                out.append(")")
                continue
            if name in ("ul", "ol"):
                if name == "ol":
                    ol_stack.append(1)
                walk(child)
                if name == "ol":
                    ol_stack.pop()
                out.append("\n")
                continue
            if name in ("table", "thead", "tbody", "tfoot"):
                walk(child)
                continue
            if name == "input":
                out.append("[x] " if "checked" in child.attrs else "[ ] ")
                continue
            if name == "strong" or name == "b":
                out.append("<b>"); walk(child); out.append("</b>")
                continue
            if name == "em" or name == "i":
                out.append("<i>"); walk(child); out.append("</i>")
                continue
            if name in ("u", "ins"):
                out.append("<u>"); walk(child); out.append("</u>")
                continue
            if name in ("s", "strike", "del"):
                out.append("<s>"); walk(child); out.append("</s>")
                continue
            if name == "mark":
                out.append("<b>"); walk(child); out.append("</b>")  # no highlight in legacy
                continue
            if name == "tg-spoiler":
                out.append("<tg-spoiler>"); walk(child); out.append("</tg-spoiler>")
                continue
            if name == "code":
                out.append("<code>"); walk(child); out.append("</code>")
                continue
            if name == "pre":
                out.append("\n<pre>"); walk(child); out.append("</pre>\n")
                continue
            if name == "a":
                href = str(child.get("href", "") or "")
                if _SAFE_HREF_RE.match(href):
                    out.append(f'<a href="{_e(href)}">')
                    walk(child)
                    out.append("</a>")
                else:
                    walk(child)  # unsafe link — plain text
                continue
            # sub/sup/time/math/tg-reference/li counters and everything unknown:
            walk(child)

    def _blockquote(node) -> None:
        """Legacy blockquotes can't nest and need '>' per line — render into a temp
        buffer, then prefix every line."""
        before = len(out)
        walk(node)
        lines = "".join(out[before:]).split("\n")
        del out[before:]
        for i, line in enumerate(lines):
            out.append(f"> {line}" if line.strip() else ">")

    body = soup.body if soup.body is not None else soup
    walk(body)
    text = "".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


# ------------------------------------------------------------------ chunking
_TAG_RE = re.compile(r"<[^>]+>")


def _split_blocks(text: str) -> list[str]:
    """Split HTML at depth-0 boundaries (newlines / after closing tags).

    Every returned block is balanced at tag depth 0, so concatenating any prefix of
    the list never breaks a tag across messages.
    """
    blocks: list[str] = []
    cur: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "<":
            m = _TAG_RE.match(text, i)
            if m:
                raw = m.group(0)
                inner = raw[1:-1].strip()
                closing = inner.startswith("/")
                if closing:
                    depth = max(0, depth - 1)
                    cur.append(raw)
                    if depth == 0:
                        cur.append("\n")
                        blocks.append("".join(cur))
                        cur = []
                    i = m.end()
                    continue
                if not (inner.endswith("/") or inner in ("!--", "")):
                    depth += 1
                cur.append(raw)
                i = m.end()
                continue
        cur.append(c)
        if c == "\n" and depth == 0:
            blocks.append("".join(cur))
            cur = []
        i += 1
    if cur:
        blocks.append("".join(cur))
    return blocks


def chunk_html(text: str, limit: int = CHUNK_LIMIT) -> list[str]:
    """Split sanitized HTML into chunks of at most `limit` chars on block boundaries.

    Never breaks a tag across messages. A single oversized block (e.g. a very long
    <pre>) is hard-split as a last resort — sanitized input only hits this for
    pathological content.
    """
    if not text:
        return []
    if len(text) <= limit:
        return [text]
    blocks = _split_blocks(text)
    msgs: list[str] = []
    cur = ""
    for b in blocks:
        if len(b) > limit:
            if cur:
                msgs.append(cur)
                cur = ""
            for i in range(0, len(b), limit):
                msgs.append(b[i:i + limit])
            continue
        if len(cur) + len(b) > limit:
            msgs.append(cur)
            cur = b
        else:
            cur += b
    if cur:
        msgs.append(cur)
    return msgs


# ------------------------------------------------------------------ payload builders
def build_rich_message(
    text: str,
    *,
    footer: Optional[str] = None,
    skip_entity_detection: bool = False,
) -> dict:
    """InputRichMessage contract: exactly one of html/markdown/blocks — always html.

    Sanitizes `text` (and optional `footer`, appended as a <footer> block).
    """
    clean = sanitize_rich(text)
    if footer:
        clean += f"\n<footer>{_e(footer)}</footer>\n"
    msg: dict[str, Any] = {"html": clean}
    if skip_entity_detection:
        msg["skip_entity_detection"] = True
    return msg


def build_payload(
    chat_id,
    text: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
    reply_parameters=None,
    message_thread_id=None,
    disable_notification: Optional[bool] = None,
    protect_content: Optional[bool] = None,
    skip_entity_detection: bool = False,
) -> dict:
    """sendRichMessage payload contract. Optional params are omitted when None."""
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "rich_message": build_rich_message(
            text, footer=footer, skip_entity_detection=skip_entity_detection
        ),
    }
    for key, val in (
        ("reply_markup", reply_markup),
        ("reply_parameters", reply_parameters),
        ("message_thread_id", message_thread_id),
        ("disable_notification", disable_notification),
        ("protect_content", protect_content),
    ):
        if val is not None:
            payload[key] = val
    return payload


# ------------------------------------------------------------------ transport
class _RichUnavailable(Exception):
    """Internal: rich endpoint unknown — caller must downgrade and retry legacy."""


async def _post_rich(bot, endpoint: str, payload: dict) -> Any:
    """Dispatch to the official method (ptb), else bot._post, else raw HTTP."""
    if endpoint == "sendRichMessage":
        native = getattr(bot, "sendRichMessage", None)
        if callable(native):
            return await native(**payload)
    elif endpoint == "editMessageText":
        native = getattr(bot, "editMessageText", None)
        if callable(native):
            return await native(**payload)
    post = getattr(bot, "_post", None)
    if callable(post):
        return await post(endpoint, payload)
    # raw HTTP through ptb's Request (multipart, mirrors _do_post)
    request = getattr(bot, "request", None)
    url = getattr(bot, "base_url", None)
    if request is not None and callable(getattr(request, "post", None)) and url:
        from telegram.request import RequestData
        from telegram.request._requestparameter import RequestParameter

        rd = RequestData(parameters=[RequestParameter.from_input(k, v) for k, v in payload.items()])
        return await request.post(url=f"{url}/{endpoint}", request_data=rd)
    raise RuntimeError(f"no transport for {endpoint}: bot lacks sendRichMessage/_post/request")


async def _send_legacy(
    bot,
    chat_id,
    seg: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
    reply_parameters=None,
    message_thread_id=None,
    disable_notification: Optional[bool] = None,
    protect_content: Optional[bool] = None,
    disable_web_page_preview: bool = True,
) -> Any:
    from telegram.constants import ParseMode

    if footer:
        seg += f"\n<footer>{_e(footer)}</footer>"
    safe = to_legacy_html(seg) or " "
    kwargs: dict[str, Any] = {
        "chat_id": chat_id,
        "text": safe,
        "parse_mode": ParseMode.HTML,
        "disable_web_page_preview": disable_web_page_preview,
    }
    if reply_markup is not None:
        kwargs["reply_markup"] = reply_markup
    if reply_parameters is not None:
        kwargs["reply_parameters"] = reply_parameters
    if message_thread_id is not None:
        kwargs["message_thread_id"] = message_thread_id
    if disable_notification is not None:
        kwargs["disable_notification"] = disable_notification
    if protect_content is not None:
        kwargs["protect_content"] = protect_content
    return await bot.send_message(**kwargs)


async def _send_one(
    bot,
    chat_id,
    seg: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
    reply_parameters=None,
    message_thread_id=None,
    disable_notification: Optional[bool] = None,
    protect_content: Optional[bool] = None,
    disable_web_page_preview: bool = True,
) -> Any:
    if not rich_supported(bot):
        return await _send_legacy(
            bot, chat_id, seg, footer=footer, reply_markup=reply_markup,
            reply_parameters=reply_parameters, message_thread_id=message_thread_id,
            disable_notification=disable_notification, protect_content=protect_content,
            disable_web_page_preview=disable_web_page_preview,
        )
    payload = build_payload(
        chat_id, seg, footer=footer, reply_markup=reply_markup,
        reply_parameters=reply_parameters, message_thread_id=message_thread_id,
        disable_notification=disable_notification, protect_content=protect_content,
    )
    try:
        return await _post_rich(bot, "sendRichMessage", payload)
    except Exception as exc:  # noqa: BLE001 — downgrade is a transport-level concern
        if _is_method_not_found(exc):
            raise _RichUnavailable(exc) from exc
        raise


async def send_rich(
    bot,
    chat_id,
    text: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
    reply_parameters=None,
    message_thread_id=None,
    disable_notification: Optional[bool] = None,
    protect_content: Optional[bool] = None,
    disable_web_page_preview: bool = True,
    chunk: bool = True,
) -> list:
    """Send a rich message (with automatic legacy fallback). Returns one result per
    chunk (use the last element for the final message). The keyboard and reply
    parameters are attached to the LAST chunk only.
    """
    clean = sanitize_rich(text) or " "
    body = chunk_html(clean, CHUNK_LIMIT) if chunk else [clean]
    results: list[Any] = []
    last = len(body) - 1
    for i, seg in enumerate(body):
        seg_footer = footer if i == last else None
        kb = reply_markup if i == last else None
        rp = reply_parameters if i == last else None
        try:
            res = await _send_one(
                bot, chat_id, seg, footer=seg_footer, reply_markup=kb, reply_parameters=rp,
                message_thread_id=message_thread_id,
                disable_notification=disable_notification, protect_content=protect_content,
                disable_web_page_preview=disable_web_page_preview,
            )
        except _RichUnavailable:
            downgrade_rich(bot)
            res = await _send_legacy(
                bot, chat_id, seg, footer=seg_footer, reply_markup=kb, reply_parameters=rp,
                message_thread_id=message_thread_id,
                disable_notification=disable_notification, protect_content=protect_content,
                disable_web_page_preview=disable_web_page_preview,
            )
        results.append(res)
    return results


async def send_html(
    bot,
    chat_id,
    text: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
    reply_parameters=None,
    message_thread_id=None,
    disable_notification: Optional[bool] = None,
    protect_content: Optional[bool] = None,
    disable_web_page_preview: bool = True,
    chunk: bool = True,
) -> list:
    """Force the legacy path (sendMessage, parse_mode=HTML) regardless of capability."""
    safe = to_legacy_html(text) or " "
    body = chunk_html(safe, CHUNK_LIMIT) if chunk else [safe]
    results: list[Any] = []
    last = len(body) - 1
    for i, seg in enumerate(body):
        results.append(await _send_legacy(
            bot, chat_id, seg, footer=footer if i == last else None,
            reply_markup=reply_markup if i == last else None,
            reply_parameters=reply_parameters if i == last else None,
            message_thread_id=message_thread_id,
            disable_notification=disable_notification, protect_content=protect_content,
            disable_web_page_preview=disable_web_page_preview,
        ))
    return results


async def reply_rich(
    message_or_update,
    bot,
    text: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
    reply_parameters=None,
    chunk: bool = True,
    disable_web_page_preview: bool = True,
) -> list:
    """Reply to a ptb Update or Message (auto reply_parameters from the message
    unless one is passed). Returns one result per chunk."""
    msg = getattr(message_or_update, "effective_message", None) or message_or_update
    if reply_parameters is None and msg is not None and getattr(msg, "chat_id", None):
        message_id = getattr(msg, "message_id", None)
        if message_id is not None:
            reply_parameters = {"message_id": message_id}
    return await send_rich(
        bot, msg.chat_id, text, footer=footer, reply_markup=reply_markup,
        reply_parameters=reply_parameters, chunk=chunk,
        disable_web_page_preview=disable_web_page_preview,
    )


async def edit_rich(
    message,
    text: str,
    *,
    footer: Optional[str] = None,
    reply_markup=None,
) -> Any:
    """Edit an existing message: editMessageText with rich_message when supported,
    else legacy message.edit_text(parse_mode=HTML). Single result."""
    bot = message.get_bot() if hasattr(message, "get_bot") else None
    if bot is not None and rich_supported(bot):
        payload: dict[str, Any] = {
            "chat_id": message.chat_id,
            "message_id": message.message_id,
            "rich_message": build_rich_message(text, footer=footer),
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            return await _post_rich(bot, "editMessageText", payload)
        except _RichUnavailable:
            downgrade_rich(bot)
        except Exception as exc:  # noqa: BLE001
            if not _is_method_not_found(exc):
                raise
            downgrade_rich(bot)
    safe = to_legacy_html(text)
    if footer:
        safe += f"\n<i>{_e(footer)}</i>"
    return await message.edit_text(safe or " ", parse_mode="HTML", reply_markup=reply_markup)


__all__ = [
    "RICH_HTML_LIMIT", "LEGACY_LIMIT", "CHUNK_LIMIT", "MAX_BLOCKS", "MAX_NEST",
    "MAX_TABLE_COLS",
    "sanitize_rich", "to_legacy_html", "chunk_html",
    "build_rich_message", "build_payload",
    "rich_supported", "downgrade_rich", "reset_capability_cache",
    "send_rich", "send_html", "reply_rich", "edit_rich",
]

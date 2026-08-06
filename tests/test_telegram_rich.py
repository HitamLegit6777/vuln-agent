import asyncio
from types import SimpleNamespace

import telegram_rich as tr


def run(coro):
    return asyncio.run(coro)


class FakeBot:
    token = "token"
    def __init__(self, rich=True):
        self.rich = rich
        self.rich_calls = []
        self.legacy_calls = []
    async def _post(self, endpoint, data):
        self.rich_calls.append((endpoint, data))
        if not self.rich:
            raise RuntimeError("Method not found: sendRichMessage")
        return {"ok": True}
    async def send_message(self, **kwargs):
        self.legacy_calls.append(kwargs)
        return kwargs


def test_rich_payload_and_keyboard():
    tr.reset_capability_cache()
    bot = FakeBot()
    keyboard = {"inline_keyboard": []}
    run(tr.send_rich(bot, 7, "<h1>Report</h1><table><tr><td>OK</td></tr></table>",
                     reply_markup=keyboard))
    assert bot.rich_calls[0][0] == "sendRichMessage"
    payload = bot.rich_calls[0][1]
    assert payload["rich_message"]["html"].startswith("<h1>")
    assert payload["reply_markup"] == keyboard


def test_method_not_found_downgrades_permanently():
    tr.reset_capability_cache()
    bot = FakeBot(rich=False)
    run(tr.send_rich(bot, 7, "<h2>Hello</h2>"))
    assert bot.legacy_calls and "Hello" in bot.legacy_calls[0]["text"]
    first = len(bot.rich_calls)
    run(tr.send_rich(bot, 7, "<p>Again</p>"))
    assert len(bot.rich_calls) == first
    assert len(bot.legacy_calls) == 2


def test_sanitizes_unsafe_media_and_attributes():
    safe = tr.sanitize_rich('<script>x</script><h1 onclick="x">A</h1><img src="file:///x"><a href="javascript:x">bad</a>')
    assert "script" not in safe and "onclick" not in safe and "img" not in safe
    assert "javascript:" not in safe and "<h1>A</h1>" in safe


def test_rich_structures_survive_and_legacy_converts():
    src = "<details><summary>Proof</summary><table><tr><th>K</th><td>V</td></tr></table></details>"
    safe = tr.sanitize_rich(src)
    assert "<details>" in safe and "<table>" in safe
    legacy = tr.to_legacy_html(safe)
    assert "Proof" in legacy and "K" in legacy and "V" in legacy
    assert "<details" not in legacy and "<table" not in legacy


def test_chunking_bounds_messages():
    chunks = tr.chunk_html("<p>" + ("word " * 2000) + "</p>", limit=500)
    assert len(chunks) > 1
    assert all(len(chunk) <= 500 for chunk in chunks)

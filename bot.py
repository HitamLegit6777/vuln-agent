"""Telegram bot entry. Commands: /scan /poc /report /history /sources.

Uses rich HTML messages + inline buttons. Whitelist-gated.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import (Application, CommandHandler, CallbackQueryHandler,
                          MessageHandler, ContextTypes, filters)

import config
import db
from agent import runner
from agent import tools as agent_tools
from agent.monitor import VulnMonitor
from format import rich

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vuln-agent")


def _gate(update: Update) -> bool:
    user = update.effective_user
    if not user or not config.allowed(user.id):
        return False
    return True


async def _unauthorized(update: Update):
    await update.effective_message.reply_text(
        "Unauthorized. Your Telegram user ID is not whitelisted.")


def _main_kb(scan_id: str, vulns: list) -> InlineKeyboardMarkup:
    rows = []
    cves = [v.get("cve") for v in vulns if v.get("cve")]
    if cves:
        rows.append([InlineKeyboardButton(f"Get PoC ({len(cves)})",
                                          callback_data=f"pocs:{scan_id}")])
    rows.append([InlineKeyboardButton("Chat (tanya AI)", callback_data=f"chat:{scan_id}")])
    rows.append([
        InlineKeyboardButton("Re-scan", callback_data=f"rescan:{scan_id}"),
        InlineKeyboardButton("History", callback_data="history"),
    ])
    return InlineKeyboardMarkup(rows)


def _poc_menu_kb(scan_id: str, vulns: list) -> InlineKeyboardMarkup:
    rows = []
    for v in vulns:
        cve = v.get("cve")
        if not cve:
            continue
        sev = (v.get("severity") or "?").upper()[:4]
        # findings use `label` (VULNERABLE/UNCONFIRMED); reports use `verified`
        # (EXPLOITABLE/NOT EXPLOITABLE). Show whichever is present.
        label = (v.get("verified") or v.get("label") or "?").upper()[:4]
        rows.append([InlineKeyboardButton(f"{cve} [{sev} {label}]",
                                          callback_data=f"poc:{scan_id}:{cve}")])
    rows.append([InlineKeyboardButton("« back", callback_data=f"back:{scan_id}")])
    return InlineKeyboardMarkup(rows)


# per-user active chat session: user_id -> scan_id
_active_chat: dict[int, str] = {}

# background scan jobs: user_id -> {scan_id: {"target":..,"started":..,"done":bool}}
_active_jobs: dict[int, dict[str, dict]] = {}
_MAX_JOBS_PER_USER = 3

def _prune_active_jobs():
    """Drop finished jobs so _active_jobs can't grow unbounded across a long bot uptime.
    Keeps the last 10 done entries per user for /jobs context, prunes the rest."""
    for uid, jobs in list(_active_jobs.items()):
        done = [(sid, j) for sid, j in jobs.items() if j.get("done")]
        if len(done) > 10:
            for sid, _ in sorted(done, key=lambda x: x[1].get("started", ""))[:len(done) - 10]:
                jobs.pop(sid, None)
        if not jobs:
            _active_jobs.pop(uid, None)

# vuln monitor
_monitor: VulnMonitor = None


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    await update.effective_message.reply_html(
        "<b>vuln-agent</b>\n"
        "AI vulnerability scanner for Telegram.\n\n"
        "<b>Commands:</b>\n"
        "<code>/scan &lt;url&gt;</code> — detect stack + find vulns (background)\n"
        "<code>/jobs</code> — liat scan yg lagi jalan\n"
        "<code>/poc &lt;scan_id&gt; &lt;CVE&gt;</code> — generate PoC script\n"
        "<code>/chat &lt;scan_id&gt; [pertanyaan]</code> — ngobrol dgn AI ttg scan\n"
        "<code>/end</code> — keluar mode chat\n"
        "<code>/report &lt;scan_id&gt;</code> — re-send a saved report\n"
        "<code>/history</code> — list your scans\n"
        "<code>/sources</code> — list vuln DB sources\n"
        "<code>/feedback &lt;scan_id&gt; good|bad|wrong</code> — rate a scan (self-improvement)\n"
        "<code>/knowledge</code> — liat knowledge yg bot udah pelajarin\n"
        "<code>/model [detect|report &lt;id&gt;|list|reset]</code> — switch AI model\n"
        "<code>/monitor on|off|list|check</code> — vuln monitor (hourly new CVE alerts)")


async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await update.effective_message.reply_html("Usage: <code>/scan &lt;url&gt;</code>")
    target = ctx.args[0]
    user_id = update.effective_user.id
    # cap concurrent jobs per user — prune BEFORE setdefault (BUG 3: setdefault-then-
    # prune orphans a fresh user's dict) and reserve the slot BEFORE any await
    # (BUG 2: TOCTOU — two concurrent /scan could both pass the cap check)
    _prune_active_jobs()
    user_jobs = _active_jobs.setdefault(user_id, {})
    active = [sid for sid, j in user_jobs.items() if not j.get("done")]
    if len(active) >= _MAX_JOBS_PER_USER:
        return await update.effective_message.reply_html(
            f"<i>Kamu udah punya {len(active)} scan jalan. Tunggu salah satu selesai "
            f"atau lihat</i> <code>/jobs</code><i>.</i>")
    scan_id = runner.new_scan_id()
    started = time.strftime("%H:%M:%S")
    # reserve the slot synchronously (no await between check and write)
    user_jobs[scan_id] = {"target": target, "started": started, "done": False}
    msg = await update.effective_message.reply_html(
        f"<i>Scan dimulai (background)</i> <code>{_e(target)}</code>\n"
        f"Scan ID: <code>{scan_id}</code>\n"
        f"<i>Bot tetap bisa dipakai selama scan. Liat</i> <code>/jobs</code>")
    # persist to DB (survive restart)
    try:
        await db.save_job(scan_id, user_id, target, started, "running")
    except Exception:
        pass
    # fire-and-forget background task
    asyncio.create_task(_run_scan_bg(update, ctx.bot, user_id, target, scan_id, msg))


async def _run_scan_bg(update: Update, bot, user_id: int, target: str, scan_id: str, msg):
    """Background scan: research → verify → report. Sends result when done. Bot stays usable."""
    async def progress(step: int, snippet: str):
        if step % 2 and step > 0:
            return
        try:
            tag = snippet.replace("\n", " ").strip()[:60]
            await msg.edit_html(
                f"<i>Scanning (bg)</i> <code>{_e(target)}</code>\n"
                f"Scan ID: <code>{scan_id}</code>\n<i>step {step}: {tag}</i>")
        except Exception:
            pass
    try:
        findings_str, _t = await runner.run_research(target, progress=progress)
        findings_str = await runner.run_verify(findings_str, scan_id, target, progress=progress)
        report = await runner.run_report(target, findings_str)
        try:
            findings_obj = json.loads(findings_str) if isinstance(findings_str, str) else findings_str
        except Exception:
            findings_obj = {"raw": findings_str}
        await db.save_scan(scan_id, user_id, target,
                           findings_obj.get("stack", []), findings_obj, report,
                           grounded=findings_str)
        # SELF-IMPROVEMENT: AI reflects on the scan and writes lessons learned
        try:
            lessons = await runner.run_self_reflect(target, findings_str, scan_id)
            if lessons:
                log.info("self-reflect: %s", lessons[:100])
        except Exception:
            pass
        kb = _main_kb(scan_id, _report_cves(report))
        chunks = rich.render_report(report, scan_id)
        try:
            await msg.delete()
        except Exception:
            pass
        for i, ch in enumerate(chunks):
            if i == len(chunks) - 1:
                await bot.send_message(user_id, ch, parse_mode=ParseMode.HTML,
                                       reply_markup=kb, disable_web_page_preview=True)
            else:
                await bot.send_message(user_id, ch, parse_mode=ParseMode.HTML,
                                       disable_web_page_preview=True)
        # mark the job done — WITHOUT this the cap permanently blocks the user after
        # 3 finished scans, /jobs shows everything as running, and memory grows unbounded
        _active_jobs.setdefault(user_id, {}).setdefault(scan_id, {})["done"] = True
        _prune_active_jobs()
        try:
            await db.update_job(scan_id, "done")
        except Exception:
            pass
    except Exception as e:
        log.exception("scan bg failed")
        kind = type(e).__name__
        hint = ""
        if "Timeout" in kind or "timeout" in str(e).lower():
            hint = " (LLM/scrape timeout)"
        try:
            await bot.send_message(user_id, f"Scan {scan_id} failed: {kind}: {e}{hint}",
                                   parse_mode=ParseMode.HTML)
        except Exception:
            pass
        _active_jobs.setdefault(user_id, {}).setdefault(scan_id, {})["done"] = True
        _prune_active_jobs()
        try:
            await db.update_job(scan_id, "done")
        except Exception:
            pass


async def cmd_poc(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if len(ctx.args) < 1:
        return await update.effective_message.reply_html(
            "Usage: <code>/poc &lt;scan_id&gt; &lt;CVE&gt;</code>  (or <code>/poc &lt;CVE&gt;</code>)")
    scan_id, cve = "", ctx.args[0]
    force = False
    if len(ctx.args) >= 2:
        scan_id, cve = ctx.args[0], ctx.args[1]
    if len(ctx.args) >= 3 and ctx.args[2].lower() in ("force", "f", "regen"):
        force = True
    if not scan_id:
        scan_id = "adhoc"
    # target from the scan row (needed to run --check exploitability)
    row = await db.get_scan(scan_id) if scan_id != "adhoc" else None
    target = row["target"] if row else ""
    msg = await update.effective_message.reply_html(f"<i>Generating PoC for</i> <code>{_e(cve)}</code>…")
    try:
        # cache: send existing + stored verdict (skip regenerate) unless force
        existing = await db.get_poc(scan_id, cve)
        if existing and existing.get("path") and existing.get("code") and not force:
            fp = existing["path"]
            if not os.path.exists(fp):
                Path(fp).write_text(existing["code"], encoding="utf-8")
            await msg.delete()
            if existing.get("verdict"):
                await update.effective_message.reply_html(
                    rich.render_poc_verdict(cve, existing["verdict"], existing.get("reason") or "",
                                            existing.get("attempts") or 0)
                    + "\n<i>(cached — script lama, skip regenerate. /poc scan cve force utk bikin ulang)</i>",
                    disable_web_page_preview=True)
            else:
                await update.effective_message.reply_html(
                    rich.render_poc_notice(fp, cve, scan_id)
                    + "\n<i>(cached — belum ada verdict. /poc scan cve force utk verify)</i>",
                    disable_web_page_preview=True)
            with open(fp, "rb") as f:
                await update.effective_message.reply_document(
                    document=f, filename=fp.split("/")[-1], caption=f"PoC for {cve} (cached)")
            return
        # generate via agent loop (write -> run --check -> iterate) — bounded:
        # the LLM loop is 30 steps × 900s; without a cap an adhoc /poc could run hours
        result = await asyncio.wait_for(runner.run_poc(scan_id, cve, target), timeout=900)
        fp = result.get("path", "")
        verdict = result.get("verdict", "UNKNOWN")
        reason = result.get("reason", "")
        attempts = result.get("attempts", 0)
        methods = result.get("methods_tried", [])
        # persist verdict on the saved PoC row
        if fp:
            try:
                await db.set_poc_verdict(scan_id, cve, verdict, reason, attempts)
            except Exception:
                pass
        await msg.delete()
        await update.effective_message.reply_html(
            rich.render_poc_verdict(cve, verdict, reason, attempts, methods),
            disable_web_page_preview=True)
        if fp and os.path.exists(fp):
            with open(fp, "rb") as f:
                await update.effective_message.reply_document(
                    document=f, filename=fp.split("/")[-1], caption=f"PoC for {cve}")
        else:
            await update.effective_message.reply_html(
                "<i>(PoC file belum tersimpan — agent mungkin belum panggil save_poc. Coba /poc force.)</i>")
    except Exception as e:
        log.exception("poc failed")
        kind = type(e).__name__
        hint = ""
        if "Timeout" in kind or "timeout" in str(e).lower():
            hint = " (LLM timeout generate kode — coba lagi, model reasoning lambat)"
        try:
            await msg.edit_text(f"PoC failed: {kind}: {e}{hint}")
        except Exception:
            await update.effective_message.reply_text(f"PoC failed: {kind}: {e}{hint}")


async def cmd_report(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await update.effective_message.reply_html("Usage: <code>/report &lt;scan_id&gt;</code>")
    row = await db.get_scan(ctx.args[0])
    if not row:
        return await update.effective_message.reply_text("Scan not found.")
    report = json.loads(row["report"]) if row.get("report") else {}
    chunks = rich.render_report(report, row["id"])
    for ch in chunks:
        await update.effective_message.reply_html(ch, disable_web_page_preview=True)


async def cmd_history(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    rows = await db.list_scans(update.effective_user.id)
    if not rows:
        return await update.effective_message.reply_text("No scans yet.")
    lines = ["<b>Your scans:</b>"]
    for r in rows:
        lines.append(f"<code>{r['id']}</code> — {_e(r['target'])} ({r['created']})")
    await update.effective_message.reply_html("\n".join(lines))


async def cmd_sources(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    from scrapers.registry import build_scrapers
    srcs = [s.name for s in build_scrapers()]
    # nuclei templates (PoC DB, not a scraper)
    try:
        from scrapers.nuclei_templates import _load_index
        n = len(_load_index())
        srcs.append(f"nuclei-templates ({n} CVEs)")
    except Exception:
        pass
    await update.effective_message.reply_html(
        "<b>Vuln sources:</b>\n<code>" + "\n".join(srcs) + "</code>")


async def cmd_feedback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Rate a scan result — helps the bot learn (self-improvement feedback loop)."""
    if not _gate(update):
        return await _unauthorized(update)
    if len(ctx.args) < 2:
        return await update.effective_message.reply_html(
            "Usage: <code>/feedback &lt;scan_id&gt; good|bad|wrong [note]</code>\n"
            "<i>good = accurate, bad = missed something, wrong = false positive</i>")
    scan_id = ctx.args[0]
    rating = ctx.args[1].lower()
    note = " ".join(ctx.args[2:]) if len(ctx.args) > 2 else ""
    if rating not in ("good", "bad", "wrong"):
        return await update.effective_message.reply_html(
            "Rating must be: <code>good</code>, <code>bad</code>, or <code>wrong</code>")
    await db.save_feedback(scan_id, rating, note)
    await update.effective_message.reply_html(
        f"<b>Feedback saved</b>\nScan: <code>{_e(scan_id)}</code>\nRating: <b>{rating}</b>"
        + (f"\nNote: {_e(note)}" if note else "")
        + "\n<i>Bot akan gunakan ini utk improve akurasi scan selanjutnya.</i>")


async def cmd_knowledge(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Show accumulated knowledge from prior scans (self-improvement memory)."""
    if not _gate(update):
        return await _unauthorized(update)
    rows = await db.get_all_knowledge(limit=10)
    if not rows:
        return await update.effective_message.reply_text("No knowledge accumulated yet.")
    lines = ["<b>Learned knowledge (last 10 scans):</b>\n"]
    for r in rows:
        cms = r.get("cms", "?")
        ver = r.get("version") or ""
        lessons = (r.get("lessons") or "")[:150]
        lines.append(f"<b>{_e(cms)} {_e(ver)}</b>: {_e(lessons)}")
    await update.effective_message.reply_html("\n".join(lines), disable_web_page_preview=True)


async def cmd_monitor(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Toggle vuln monitor on/off, or list sent CVEs."""
    global _monitor
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        status = "ON" if (_monitor and _monitor._running) else "OFF"
        await update.effective_message.reply_html(
            f"<b>Vuln Monitor: {status}</b>\n"
            f"Interval: 1 hour\n"
            f"Max new CVEs/cycle: 5\n"
            f"Sources: wordfence, cisa_kev, watchtowr, poc_github, patchstack, osv\n\n"
            f"<code>/monitor on</code> — start monitor\n"
            f"<code>/monitor off</code> — stop monitor\n"
            f"<code>/monitor list</code> — list sent CVEs\n"
            f"<code>/monitor check</code> — run one cycle now")
        return
    cmd = ctx.args[0].lower()
    if cmd == "on":
        if _monitor and _monitor._running:
            return await update.effective_message.reply_text("Monitor sudah ON.")
        _monitor = VulnMonitor(bot=ctx.bot)
        await _monitor.start()
        await update.effective_message.reply_html("Vuln Monitor ON. Cek tiap 1 jam. Report akan dikirim ke sini.")
    elif cmd == "off":
        if _monitor:
            await _monitor.stop()
        await update.effective_message.reply_text("Vuln Monitor OFF")
    elif cmd == "list":
        rows = await db.get_sent_cves(limit=20)
        if not rows:
            return await update.effective_message.reply_text("Belum ada CVE terkirim.")
        lines = [f"<b>Sent CVEs ({len(rows)}):</b>\n"]
        for r in rows:
            sev = r.get("severity", "?")[:4]
            rce = r.get("rce_type", "?")[:8]
            auth = r.get("auth_type", "?")[:5]
            lines.append(f"<code>{r['cve']}</code> [{sev}] RCE:{rce} Auth:{auth} ({r.get('sent_at','')})")
        await update.effective_message.reply_html("\n".join(lines), disable_web_page_preview=True)
    elif cmd == "check":
        if not _monitor:
            _monitor = VulnMonitor(bot=ctx.bot)
        await update.effective_message.reply_html("<i>Running monitor cycle now...</i>")
        await _monitor._check_cycle()
    else:
        await update.effective_message.reply_text("Usage: /monitor on|off|list|check")


async def cmd_chat(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Enter chat mode for a scan, or one-shot question: /chat <scan_id> [question...]"""
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await update.effective_message.reply_html(
            "Usage: <code>/chat &lt;scan_id&gt; [pertanyaan]</code>\n"
            "Tanpa pertanyaan → masuk mode chat (ketik bebas). <code>/end</code> utk keluar.")
    scan_id = ctx.args[0]
    question = " ".join(ctx.args[1:]).strip()
    row = await db.get_scan(scan_id)
    if not row:
        return await update.effective_message.reply_text("Scan ID tidak ditemukan.")
    _active_chat[update.effective_user.id] = scan_id
    if question:
        await _do_chat(update, scan_id, question)
    else:
        await update.effective_message.reply_html(
            f"Mode chat aktif utk scan <code>{_e(scan_id)}</code> ({_e(row.get('target'))}).\n"
            f"Ketik pertanyaan apa saja. <code>/end</code> utk keluar.")


async def cmd_end(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    _active_chat.pop(update.effective_user.id, None)
    await update.effective_message.reply_html("Mode chat ditutup.")


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Free-text → route to chat agent if user has an active scan session."""
    if not _gate(update):
        return
    uid = update.effective_user.id
    scan_id = _active_chat.get(uid)
    if not scan_id:
        return  # not in chat mode; ignore (or could reply hint)
    await _do_chat(update, scan_id, update.effective_message.text)


_chat_locks: dict[int, asyncio.Lock] = {}  # per-user chat serialization (lost-update guard)


async def _do_chat(update: Update, scan_id: str, question: str):
    row = await db.get_scan(scan_id)
    if not row:
        return await update.effective_message.reply_text("Scan ID tidak ditemukan.")
    uid = update.effective_user.id
    lock = _chat_locks.setdefault(uid, asyncio.Lock())
    msg = await update.effective_message.reply_html("<i>🤖 thinking…</i>")
    try:
        # serialize get→run→save — two rapid messages must not overwrite each other's history
        async with lock:
            history = await db.get_chat(scan_id)
            answer, history = await runner.run_chat(
                scan_id, row.get("grounded") or "", row.get("findings") or "",
                question, history)
            await db.save_chat(scan_id, history)
        try:
            await msg.delete()
        except Exception:
            pass
        # sanitize LLM HTML to Telegram-safe subset, then split
        safe = rich.tg_sanitize(answer) or "(empty)"
        for chunk in _split_html(safe, 3500):
            await update.effective_message.reply_html(chunk, disable_web_page_preview=True)
    except Exception as e:
        log.exception("chat failed")
        kind = type(e).__name__
        try:
            await msg.edit_text(f"Chat error: {kind}: {e}")
        except Exception:
            await update.effective_message.reply_text(f"Chat error: {kind}: {e}")


def _split_html(text: str, limit: int = 3500) -> list[str]:
    """Split long HTML for Telegram, never cutting mid-tag and keeping every chunk
    balanced. A stack tracks open tags: when a boundary lands inside a span, the
    pushed chunk gets the closing tags appended and the next chunk is re-opened.
    Falls back to a hard character split for single over-long paragraphs."""
    _TAGS = ("b", "i", "code", "em", "strong", "u", "s", "pre", "a", "blockquote")
    if len(text) <= limit:
        return [text]

    def _open_tags(s: str) -> list:
        stack = []
        for m in re.finditer(r"<(/?)(%s)[ >]" % "|".join(_TAGS), s, re.I):
            closing, tag = m.group(1), m.group(2).lower()
            if closing:
                if stack and stack[-1] == tag:
                    stack.pop()
            else:
                stack.append(tag)
        return stack

    out, cur = [], ""
    for para in text.split("\n\n"):
        if not para:
            continue
        if len(cur) + len(para) + 2 <= limit:
            cur = (cur + "\n\n" + para) if cur else para
            continue
        # boundary — close open tags on the pushed chunk, reopen on the next
        if cur:
            open_now = _open_tags(cur)
            out.append(cur + "".join(f"</{t}>" for t in reversed(open_now)))
            cur = "".join(f"<{t}>" for t in open_now) + para
        else:
            # single paragraph larger than limit — hard split at a safe point
            cur = para
            while len(cur) > limit:
                cut = cur.rfind(" ", 0, limit)
                cut = cut if cut > 0 else limit
                piece = cur[:cut]
                open_now = _open_tags(piece)
                out.append(piece + "".join(f"</{t}>" for t in reversed(open_now)))
                cur = "".join(f"<{t}>" for t in open_now) + cur[cut:].lstrip()
    if cur:
        out.append(cur)
    return out


async def cmd_jobs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    uid = update.effective_user.id
    # check in-memory (running) + DB (running + interrupted)
    jobs_mem = _active_jobs.get(uid, {})
    active_mem = [(sid, j) for sid, j in jobs_mem.items() if not j.get("done")]
    try:
        active_db = await db.get_active_jobs(uid)
    except Exception:
        active_db = []
    try:
        interrupted = await db.get_interrupted_jobs(uid)
    except Exception:
        interrupted = []
    # merge: in-memory takes priority (live status)
    mem_sids = {sid for sid, _ in active_mem}
    active = list(active_mem)
    for j in active_db:
        if j["scan_id"] not in mem_sids:
            active.append((j["scan_id"], {"target": j["target"], "started": j["started"]}))
    if not active and not interrupted:
        return await update.effective_message.reply_html("<i>Tidak ada scan berjalan.</i>")
    lines = []
    if active:
        lines.append("<b>Scan berjalan:</b>")
        for sid, j in active:
            lines.append(f"<code>{_e(sid)}</code> — {_e(j.get('target'))} (mulai {j.get('started')})")
    if interrupted:
        lines.append(f"\n<b>Scan terputus (bot restart):</b>")
        for j in interrupted:
            lines.append(f"<code>{_e(j['scan_id'])}</code> — {_e(j['target'])} (mulai {j.get('started')}) "
                        f"<i>(interrupted — coba re-scan)</i>")
    await update.effective_message.reply_html("\n".join(lines))


async def on_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    q = update.callback_query
    await q.answer()
    data = q.data
    if data.startswith("poc:"):
        _, scan_id, cve = data.split(":", 2)
        ctx.args = [scan_id, cve]
        await cmd_poc(update, ctx)
    elif data.startswith("pocs:"):
        _, scan_id = data.split(":", 1)
        row = await db.get_scan(scan_id)
        report = json.loads(row["report"]) if row and row.get("report") else {}
        await q.edit_message_reply_markup(
            reply_markup=_poc_menu_kb(scan_id, _report_cves(report)))
    elif data.startswith("back:"):
        _, scan_id = data.split(":", 1)
        row = await db.get_scan(scan_id)
        report = json.loads(row["report"]) if row and row.get("report") else {}
        await q.edit_message_reply_markup(
            reply_markup=_main_kb(scan_id, _report_cves(report)))
    elif data.startswith("chat:"):
        _, scan_id = data.split(":", 1)
        _active_chat[update.effective_user.id] = scan_id
        row = await db.get_scan(scan_id)
        tgt = _e(row.get("target")) if row else "?"
        await q.message.reply_html(
            f"Mode chat aktif utk scan <code>{_e(scan_id)}</code> ({tgt}).\n"
            f"Ketik pertanyaan apa saja. <code>/end</code> utk keluar.")
    elif data.startswith("rescan:"):
        _, scan_id = data.split(":", 1)
        row = await db.get_scan(scan_id)
        if row:
            ctx.args = [row["target"]]
            await cmd_scan(update, ctx)
    elif data == "history":
        await cmd_history(update, ctx)
    elif data.startswith("model:"):
        parts = data.split(":", 2)
        if parts[1] == "reset":
            from llm import set_models
            set_models(detect="", report="")
            await db.set_setting("model_detect", "")
            await db.set_setting("model_report", "")
            await q.message.reply_html("<b>Model reset ke default config.</b>")
        elif len(parts) == 3:
            from llm import set_models
            role, model_id = parts[1], parts[2]
            if role in ("detect", "report"):
                set_models(**{role: model_id})
                await db.set_setting(f"model_{role}", model_id)
                await q.message.reply_html(
                    f"<b>Model {role} →</b> <code>{_e(model_id)}</code>")


def _e(s):
    import html
    return html.escape(str(s) if s is not None else "")


def _report_cves(report: dict) -> list:
    """All actionable CVEs from a rendered report: exploitable first, then checked.

    The report schema stores verified findings under `exploitable` and tested-but-safe
    ones under `checked` (never `vulns`). Both are offered for PoC retrieval so the user
    can pull the script for anything the agent looked at.
    """
    if not isinstance(report, dict):
        return []
    out: list = []
    seen: set = set()
    for bucket in ("exploitable", "checked", "vulns"):
        for v in report.get(bucket, []) or []:
            cve = v.get("cve")
            if cve and cve not in seen:
                seen.add(cve)
                out.append(v)
    return out


async def cmd_model(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """View / switch the active LLM models (detect + report) from the provider."""
    if not _gate(update):
        return await _unauthorized(update)
    from llm import get_models, set_models, fetch_available_models
    cur = get_models()
    args = [a for a in (ctx.args or [])]
    if len(args) == 2 and args[0].lower() in ("detect", "report"):
        role, model_id = args[0].lower(), args[1]
        # validate against the provider list — a typo would silently break every LLM call
        models = await fetch_available_models()
        if models and model_id not in models:
            return await update.effective_message.reply_html(
                f"<b>Model tidak ditemukan di provider:</b> <code>{_e(model_id)}</code>\n"
                f"<i>Gunakan</i> <code>/model list</code> <i>utk liat model yg tersedia.</i>")
        if role == "detect":
            set_models(detect=model_id)
            await db.set_setting("model_detect", model_id)
        else:
            set_models(report=model_id)
            await db.set_setting("model_report", model_id)
        return await update.effective_message.reply_html(
            f"<b>Model {role} →</b> <code>{_e(model_id)}</code>\n"
            f"<i>Berlaku untuk scan berikutnya.</i>")
    if len(args) == 1 and args[0].lower() in ("list", "reset"):
        if args[0].lower() == "reset":
            set_models(detect="", report="")
            await db.set_setting("model_detect", "")
            await db.set_setting("model_report", "")
            return await update.effective_message.reply_html(
                "<b>Model reset ke default config.</b>")
        # list = fall through to full listing
    # fetch provider models
    models = await fetch_available_models()
    if not models:
        return await update.effective_message.reply_html(
            "<b>Model saat ini:</b>\n"
            f"detect: <code>{_e(cur['detect'])}</code>\n"
            f"report: <code>{_e(cur['report'])}</code>\n\n"
            "<i>Provider tidak merespon /models — coba lagi nanti.</i>")
    # filter to relevant prefixes (al/* and common combos), cap display
    short = [m for m in models if m.startswith(("al/", "co/"))][:40]
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton(f"🔍 detect: {_e(m)}", callback_data=f"model:detect:{m}")]
        for m in short[:15]
    ] + [
        [InlineKeyboardButton(f"📝 report: {_e(m)}", callback_data=f"model:report:{m}")]
        for m in short[15:30]
    ] + [[InlineKeyboardButton("↩️ Reset default", callback_data="model:reset")]])
    await update.effective_message.reply_html(
        f"<b>Model aktif:</b>\n"
        f"detect: <code>{_e(cur['detect'])}</code>\n"
        f"report: <code>{_e(cur['report'])}</code>\n\n"
        f"<i>Pilih model (dari provider, {len(short)} tampil):</i>\n"
        f"<code>/model detect &lt;id&gt;</code> atau <code>/model report &lt;id&gt;</code>",
        reply_markup=kb)


def main():
    config.assert_configured()
    db.init_db()
    # mark any orphaned jobs from previous process as interrupted
    try:
        import asyncio as _aio
        _aio.run(db.mark_all_interrupted())
    except Exception:
        pass
    # restore persisted model choices, then start vuln monitor
    async def _post_init(application):
        global _monitor
        try:
            from llm import load_models_from_db
            await load_models_from_db()
        except Exception:
            pass
        _monitor = VulnMonitor(bot=application.bot)
        await _monitor.start()

    app = (Application.builder()
           .token(config.TELEGRAM_BOT_TOKEN)
           .concurrent_updates(True)
           .post_init(_post_init)
           .build())
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("jobs", cmd_jobs))
    app.add_handler(CommandHandler("poc", cmd_poc))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("model", cmd_model))
    app.add_handler(CommandHandler("feedback", cmd_feedback))
    app.add_handler(CommandHandler("knowledge", cmd_knowledge))
    app.add_handler(CommandHandler("monitor", cmd_monitor))
    app.add_handler(CommandHandler("chat", cmd_chat))
    app.add_handler(CommandHandler("end", cmd_end))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(CallbackQueryHandler(on_callback))
    log.info("vuln-agent bot starting…")
    app.run_polling()


if __name__ == "__main__":
    main()

"""Telegram bot entry. Commands: /scan /jobs /cancel /resume /retry /poc /report
/history /sources /feedback /knowledge /monitor /model /library /chat /end
/remediate /compare /retest.

Durable concurrent scans run behind the global jobs semaphore (jobs.py) with
per-stage DB checkpoints (research → verify → report) so interrupted scans can
/resume from the last completed stage. Every textual response routes through
the telegram_rich helper (Bot API 10.2 sendRichMessage with legacy fallback);
only document sends and callback answers go direct.
"""
from __future__ import annotations

import asyncio
import io
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

# ------------------------------------------------------------------ telegram_rich
# Every textual bot message routes through the helper below. The sibling
# telegram_rich module owns the raw Bot API (sendRichMessage / legacy fallback,
# sanitize, chunking); the helpers here are the bot-side integration layer.
try:
    import telegram_rich as _tr
except Exception:  # sibling module absent — bootstrap shim below keeps bot alive
    _tr = None

# rich-only block tags stripped by the bootstrap shim (never in the rich path)
_RICH_ONLY_TAGS = re.compile(
    r"</?(?:h[1-6]|ul|ol|li|table|caption|tr|th|td|details|summary|footer|"
    r"aside|cite|hr|p)\b[^>]*>", re.I)


async def _rich_reply(update_or_message, bot, text, **kw):
    """Reply to an Update/Message with rich text (sanitize + chunk + fallback
    owned by telegram_rich). Returns one result per chunk (last = final msg)."""
    if _tr is not None:
        return await _tr.reply_rich(update_or_message, bot, text, **kw)
    msg = getattr(update_or_message, "effective_message", None) or update_or_message
    return [await getattr(msg, "reply_html")(_RICH_ONLY_TAGS.sub("", text),
                                             disable_web_page_preview=True, **kw)]


async def _rich_send(bot, chat_id, text, **kw):
    """Send rich text to a chat id. Returns one result per chunk."""
    if _tr is not None:
        return await _tr.send_rich(bot, chat_id, text, **kw)
    return [await getattr(bot, "send_message")(
        chat_id, _RICH_ONLY_TAGS.sub("", text), parse_mode=ParseMode.HTML,
        disable_web_page_preview=True, **kw)]


async def _rich_edit(message, text, **kw):
    """Edit a message with rich text. Single result."""
    if _tr is not None:
        return await _tr.edit_rich(message, text, **kw)
    return await getattr(message, "edit_text")(_RICH_ONLY_TAGS.sub("", text),
                                               parse_mode=ParseMode.HTML, **kw)


def _rich_ol(items: list, ordered: bool = True) -> str:
    """Rich list block (legacy fallback strips the tags, text survives)."""
    tag = "ol" if ordered else "ul"
    return f"<{tag}>\n" + "\n".join(f"<li>{i}</li>" for i in items) + f"\n</{tag}>"


def _rich_table(headers: list, rows: list) -> str:
    """Minimal rich <table> block. Cell content must be pre-escaped."""
    out = ["<table>",
           "<tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>"]
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>")
    out.append("</table>")
    return "\n".join(out)


def _jobs_mod():
    """Lazy handle to the jobs sibling module (absent → plain background tasks)."""
    try:
        import jobs as _m
        return _m
    except Exception:
        return None


def _remediation_mod():
    """Lazy handle to the remediation sibling module."""
    try:
        import remediation as _m
        return _m
    except Exception:
        return None


def _gate(update: Update) -> bool:
    user = update.effective_user
    if not user or not config.allowed(user.id):
        return False
    return True


async def _unauthorized(update: Update, bot=None):
    if bot is None:
        try:
            bot = update.get_bot()
        except Exception:
            return
    msg = getattr(update, "effective_message", None) or update
    await _rich_reply(msg, bot,
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

# background scan jobs: user_id -> {scan_id: {"target":.., "started":.., "done":bool,
# "task": asyncio.Task, "stage": str}}. The task refs are held STRONGLY so
# post_shutdown can cancel/drain every live scan.
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


def _mark_job_done(scan_id: str, status: str):
    """Flip the in-memory job slot to done (frees the per-user cap) and drop the
    finished task ref. Terminal DB state is written by the pipeline/wrapper."""
    for uid, jobs in _active_jobs.items():
        if scan_id in jobs:
            entry = jobs[scan_id]
            entry["done"] = True
            entry["status"] = status
            entry.pop("task", None)
    _prune_active_jobs()


# vuln monitor
_monitor: VulnMonitor = None


# ------------------------------------------------------------------ job pipeline
# Scan execution persists a checkpoint after research and after verify, so an
# interrupted scan resumes from the last completed stage instead of restarting.
# checkpoint stores a small envelope {"stage", "findings"} — the stage records
# which pipeline phase produced the findings snapshot (immutable provenance).

def _env(stage: str, findings: str) -> str:
    return json.dumps({"stage": stage, "findings": findings}, ensure_ascii=False)


async def _load_checkpoint(scan_id: str):
    """Findings snapshot from the last completed pipeline stage (or None)."""
    try:
        job = await db.get_job(scan_id)
    except Exception:
        return None
    raw = (job or {}).get("checkpoint") or ""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if isinstance(data, str):
        return data  # legacy bare-findings checkpoint
    if isinstance(data, dict) and isinstance(data.get("findings"), str):
        return data["findings"]
    return None


def _resume_stage(row: dict) -> str:
    """Stage to start an interrupted/failed scan at: the phase AFTER the last
    checkpointed one (falls back to full research)."""
    raw = (row or {}).get("checkpoint") or ""
    env_stage = None
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                env_stage = data.get("stage")
        except Exception:
            env_stage = None
    return {"RESEARCHING": "VERIFYING", "VERIFYING": "REPORTING"}.get(env_stage,
                                                                      "RESEARCHING")


_FWD = {"QUEUED": "RESEARCHING", "RESEARCHING": "VERIFYING", "VERIFYING": "REPORTING"}


async def _ensure_stage(scan_id: str, target: str) -> bool:
    """Move the job row to `target` (idempotent self-transition allowed). FAILED
    rows re-open via RESEARCHING (the only legal exit), then walk forward."""
    try:
        await db.transition_job(scan_id, target)
        return True
    except ValueError:
        pass
    try:
        job = await db.get_job(scan_id)
    except Exception:
        return False
    cur = (job or {}).get("stage") or "QUEUED"
    if cur == "FAILED":
        try:
            await db.transition_job(scan_id, "RESEARCHING")
            cur = "RESEARCHING"
        except Exception:
            return False
    while cur in _FWD and cur != target:
        try:
            await db.transition_job(scan_id, _FWD[cur])
            cur = _FWD[cur]
        except ValueError:
            return False
    return cur == target


async def _job_transition(scan_id: str, to_stage: str, **fields):
    """Stage-machine transition; legacy status mirror when the row predates it."""
    try:
        return await db.transition_job(scan_id, to_stage, **fields)
    except Exception:
        status = {"VERIFYING": "running", "REPORTING": "running",
                  "COMPLETED": "done", "FAILED": "failed",
                  "CANCELLED": "cancelled"}.get(to_stage, "running")
        try:
            return await db.update_job(scan_id, status)
        except Exception:
            return None


def _scan_progress_html(target: str, scan_id: str, step: int, tag: str) -> str:
    return (f"<i>Scanning (bg)</i> <code>{_e(target)}</code>\n"
            f"Scan ID: <code>{scan_id}</code>\n<i>step {step}: {_e(tag)}</i>")


def _scan_factory(bot, user_id: int, target: str, scan_id: str, msg,
                  start_stage: str = "RESEARCHING"):
    """Zero-arg coro factory for jobs.submit — drives the whole pipeline."""
    async def _run():
        await _run_scan_coro(bot, user_id, target, scan_id, msg,
                             start_stage=start_stage)
    return _run


async def _start_scan_job(*, bot, user_id: int, target: str, scan_id: str, msg,
                          start_stage: str = "RESEARCHING") -> asyncio.Task:
    """Register a fresh scan behind the global jobs semaphore (durable row, task
    registry for drain). Falls back to a plain background task when the jobs
    sibling module is absent."""
    jobs = _jobs_mod()
    if jobs is not None and hasattr(jobs, "submit"):
        from llm import get_models
        models = get_models()
        # Model snapshot at job start: ids are serialized on the job row
        # (bg_jobs.model_detect/model_report) as immutable metadata. The runner
        # coroutine re-binds them per-job via llm.bind_models (contextvar), so a
        # scan keeps the models it started with even if the operator switches
        # mid-flight. Runs through the legacy fallback path skip the binding.
        return await jobs.submit(scan_id, user_id, target,
                                 _scan_factory(bot, user_id, target, scan_id, msg,
                                               start_stage),
                                 model_detect=models["detect"],
                                 model_report=models["report"],
                                 start_stage=start_stage)
    try:
        await db.save_job(scan_id, user_id, target,
                          time.strftime("%Y-%m-%d %H:%M:%S"), "running")
    except Exception:
        pass
    return asyncio.create_task(
        _run_scan_coro(bot, user_id, target, scan_id, msg, start_stage))


async def _resume_scan_job(*, bot, user_id: int, target: str, scan_id: str, msg,
                           start_stage: str) -> asyncio.Task:
    """Resume an existing scan behind the same global semaphore as fresh scans."""
    jobs = _jobs_mod()
    factory = _scan_factory(bot, user_id, target, scan_id, msg, start_stage)
    if jobs is not None and hasattr(jobs, "submit_existing"):
        return await jobs.submit_existing(scan_id, user_id, factory)
    task = asyncio.create_task(factory())
    if jobs is not None and hasattr(jobs, "register"):
        try:
            await jobs.register(scan_id, task)
        except Exception:
            log.warning("resume: could not register %s for drain", scan_id)
    return task


async def _run_scan_coro(bot, user_id: int, target: str, scan_id: str, msg,
                         start_stage: str = "RESEARCHING"):
    """Durable scan pipeline with checkpoints and immutable per-job model ids."""
    model_token = None
    try:
        row = await db.get_job(scan_id)
        from llm import bind_models
        model_token = bind_models({
            "detect": (row or {}).get("model_detect"),
            "report": (row or {}).get("model_report"),
        })
    except Exception:
        model_token = None
    async def progress(step: int, snippet: str):
        if step % 2 and step > 0:
            return
        tag = snippet.replace("\n", " ").strip()[:60]
        try:
            await _rich_edit(msg, _scan_progress_html(target, scan_id, step, tag))
        except Exception:
            pass
        try:
            await db.checkpoint_job(scan_id, progress=tag, current=step)
        except Exception:
            pass

    findings = None
    try:
        await _ensure_stage(scan_id, start_stage)
        if start_stage in ("VERIFYING", "REPORTING"):
            findings = await _load_checkpoint(scan_id)
        if start_stage == "REPORTING":
            verified = findings
            if verified is None:
                # checkpoint lost/legacy — rebuild the whole chain
                findings, _t = await runner.run_research(target, progress=progress)
                await _job_transition(scan_id, "VERIFYING",
                                      checkpoint=_env("RESEARCHING", findings))
                verified = await runner.run_verify(findings, scan_id, target,
                                                   progress=progress)
                await _job_transition(scan_id, "REPORTING",
                                      checkpoint=_env("VERIFYING", verified))
        else:
            if findings is None:
                findings, _t = await runner.run_research(target, progress=progress)
                await _job_transition(scan_id, "VERIFYING",
                                      checkpoint=_env("RESEARCHING", findings))
            verified = await runner.run_verify(findings, scan_id, target,
                                               progress=progress)
            await _job_transition(scan_id, "REPORTING",
                                  checkpoint=_env("VERIFYING", verified))

        report = await runner.run_report(target, verified)
        try:
            findings_obj = json.loads(verified) if isinstance(verified, str) else (verified or {})
        except Exception:
            findings_obj = {"raw": verified}
        await db.save_scan(scan_id, user_id, target,
                           findings_obj.get("stack", []), findings_obj, report,
                           grounded=verified or "")
        # Persist canonical facts, target snapshot, drift and per-target evidence.
        # The scan itself remains successful if the private library is unavailable.
        try:
            from library import ingest_scan
            await ingest_scan(user_id, scan_id, target, findings_obj, report)
        except Exception:
            log.exception("private library scan ingest failed")
        # SELF-IMPROVEMENT: AI reflects on the scan and writes lessons learned
        try:
            lessons = await runner.run_self_reflect(target, verified or "", scan_id)
            if lessons:
                log.info("self-reflect: %s", lessons[:100])
        except Exception:
            pass
        try:
            await _job_transition(scan_id, "COMPLETED",
                                  report=json.dumps(report, ensure_ascii=False),
                                  report_status=report.get("status"))
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
                await _rich_send(bot, user_id, ch, reply_markup=kb)
            else:
                await _rich_send(bot, user_id, ch)
        if model_token is not None:
            from llm import reset_models
            reset_models(model_token)
        _mark_job_done(scan_id, "done")
    except asyncio.CancelledError:
        # /cancel or shutdown — jobs.submit persists the terminal CANCELLED row;
        # mirror it through the lenient legacy writer and free the in-memory cap.
        _mark_job_done(scan_id, "cancelled")
        try:
            await db.update_job(scan_id, "cancelled")
        except Exception:
            pass
        if model_token is not None:
            from llm import reset_models
            reset_models(model_token)
        raise
    except Exception as e:
        log.exception("scan bg failed")
        kind = type(e).__name__
        hint = ""
        if "Timeout" in kind or "timeout" in str(e).lower():
            hint = " (LLM/scrape timeout)"
        try:
            await _rich_send(bot, user_id,
                             f"Scan <code>{scan_id}</code> failed: "
                             f"<code>{_e(kind)}</code>: {_e(e)}{hint}\n"
                             f"<i>Ulangi dari checkpoint:</i> <code>/retry {scan_id}</code>")
        except Exception:
            pass
        try:
            await _job_transition(scan_id, "FAILED", last_error=f"{kind}: {e}"[:500])
        except Exception:
            pass
        _mark_job_done(scan_id, "failed")
        if model_token is not None:
            from llm import reset_models
            reset_models(model_token)


# ------------------------------------------------------------------ commands

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    parts = [
        "<h2>vuln-agent</h2>\n<p>AI vulnerability scanner untuk Telegram.</p>",
        "<h3>Scan &amp; jobs</h3>",
        _rich_ol([
            "<code>/scan &lt;url&gt;</code> — detect stack + find vulns (background)",
            "<code>/jobs</code> — daftar scan &amp; status",
            "<code>/cancel &lt;scan_id&gt;</code> — batalkan scan berjalan",
            "<code>/resume &lt;scan_id&gt;</code> — lanjutkan scan terputus (dari checkpoint)",
            "<code>/retry &lt;scan_id&gt; [research|verify|report]</code> — ulangi scan gagal dari tahap tertentu",
        ]),
        "<h3>Hasil scan</h3>",
        _rich_ol([
            "<code>/report &lt;scan_id&gt;</code> — kirim ulang report",
            "<code>/poc &lt;scan_id&gt; &lt;CVE&gt;</code> — generate PoC script",
            "<code>/remediate &lt;scan_id&gt;</code> — rencana mitigasi",
            "<code>/compare &lt;old_scan&gt; &lt;new_scan&gt;</code> — bandingkan 2 scan",
            "<code>/retest &lt;scan_id&gt; [CVE]</code> — retest PoC (verifikasi ulang)",
            "<code>/history</code> — list scan kamu",
        ]),
        "<h3>AI &amp; intel</h3>",
        _rich_ol([
            "<code>/chat &lt;scan_id&gt; [pertanyaan]</code> — ngobrol dgn AI ttg scan",
            "<code>/end</code> — keluar mode chat",
            "<code>/model [detect|report &lt;id&gt;|list|reset]</code> — ganti model AI",
            "<code>/knowledge</code> — knowledge yg bot udah pelajarin",
            "<code>/feedback &lt;scan_id&gt; good|bad|wrong</code> — rate hasil scan",
            "<code>/sources</code> — list sumber vuln DB",
            "<code>/monitor on|off|list|check</code> — monitor CVE baru (hourly)",
            "<code>/library [stats|search|cve|related|target|evidence|recent|exploitable|note|refresh|export|verify]</code> — intel library pribadi",
        ]),
    ]
    await _rich_reply(update, ctx.bot, "\n".join(parts))


async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot, "Usage: <code>/scan &lt;url&gt;</code>")
    target = ctx.args[0]
    user_id = update.effective_user.id
    # cap concurrent jobs per user — prune BEFORE setdefault (BUG 3: setdefault-then-
    # prune orphans a fresh user's dict) and reserve the slot BEFORE any await
    # (BUG 2: TOCTOU — two concurrent /scan could both pass the cap check)
    _prune_active_jobs()
    user_jobs = _active_jobs.setdefault(user_id, {})
    active = [sid for sid, j in user_jobs.items() if not j.get("done")]
    if len(active) >= _MAX_JOBS_PER_USER:
        return await _rich_reply(update, ctx.bot,
            f"<i>Kamu udah punya {len(active)} scan jalan. Tunggu salah satu selesai "
            f"atau lihat</i> <code>/jobs</code><i>.</i>")
    scan_id = runner.new_scan_id()
    started = time.strftime("%H:%M:%S")
    # reserve the slot synchronously (no await between check and write)
    user_jobs[scan_id] = {"target": target, "started": started, "done": False,
                          "stage": "RESEARCHING"}
    msg = (await _rich_reply(update, ctx.bot,
        f"<i>Scan dimulai (background)</i> <code>{_e(target)}</code>\n"
        f"Scan ID: <code>{scan_id}</code>\n"
        f"<i>Bot tetap bisa dipakai selama scan. Liat</i> <code>/jobs</code>"))[-1]
    try:
        task = await _start_scan_job(bot=ctx.bot, user_id=user_id, target=target,
                                     scan_id=scan_id, msg=msg)
    except Exception as e:
        log.exception("scan submit failed")
        user_jobs[scan_id]["done"] = True
        _prune_active_jobs()
        return await _rich_reply(update, ctx.bot,
            f"Scan <code>{_e(scan_id)}</code> gagal dijadwalkan: "
            f"<code>{_e(type(e).__name__)}</code>: {_e(e)}")
    user_jobs[scan_id]["task"] = task  # strong task ref (drain/cancel on shutdown)


async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot, "Usage: <code>/cancel &lt;scan_id&gt;</code>")
    scan_id = ctx.args[0]
    uid = update.effective_user.id
    jobs = _jobs_mod()
    row = None
    if jobs is not None and hasattr(jobs, "cancel"):
        try:
            row = await jobs.cancel(scan_id, uid)
        except Exception:
            log.exception("cancel failed")
            row = await db.get_job_for_user(scan_id, uid)
    else:
        row = await db.get_job_for_user(scan_id, uid)
        if row:
            for jobs_map in _active_jobs.values():
                entry = jobs_map.get(scan_id)
                if entry and entry.get("task") and not entry["task"].done():
                    entry["task"].cancel()
                    break
    if not row:
        return await _rich_reply(update, ctx.bot, "Scan not found or not owned by you.")
    stage = row.get("stage") or row.get("status") or "?"
    terminal = stage in ("COMPLETED", "CANCELLED")
    await _rich_reply(update, ctx.bot,
        f"<b>{'Sudah terminal' if terminal else 'Cancel requested'}</b> utk scan "
        f"<code>{_e(scan_id)}</code> (<code>{_e(stage)}</code>).")


async def cmd_resume(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Resume an interrupted scan from its persisted checkpoint (skips completed stages)."""
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/resume &lt;scan_id&gt;</code> — lanjutkan scan terputus dari checkpoint")
    scan_id = ctx.args[0]
    uid = update.effective_user.id
    row = await db.get_job_for_user(scan_id, uid)
    if not row:
        return await _rich_reply(update, ctx.bot, "Scan not found or not owned by you.")
    stage = row.get("stage") or ""
    if stage in ("COMPLETED", "CANCELLED"):
        return await _rich_reply(update, ctx.bot,
            f"Scan <code>{_e(scan_id)}</code> sudah <b>{_e(stage.lower())}</b>.")
    jobs = _jobs_mod()
    if stage in ("RESEARCHING", "VERIFYING", "REPORTING", "QUEUED") \
            and jobs is not None and await jobs.active(scan_id):
        return await _rich_reply(update, ctx.bot, "Scan sudah berjalan.")
    user_jobs = _active_jobs.setdefault(uid, {})
    entry = user_jobs.get(scan_id)
    if entry is not None and not entry.get("done"):
        return await _rich_reply(update, ctx.bot, "Scan sudah berjalan.")
    start = _resume_stage(row)
    # reserve the slot synchronously — two concurrent /resume can't double-start
    user_jobs[scan_id] = {"target": row.get("target") or "",
                          "started": row.get("started") or "",
                          "done": False, "stage": start}
    msg = (await _rich_reply(update, ctx.bot,
        f"<i>Resuming scan</i> <code>{_e(scan_id)}</code> "
        f"<i>dari tahap</i> <code>{start}</code><i>…</i>"))[-1]
    try:
        task = await _resume_scan_job(bot=ctx.bot, user_id=uid,
                                      target=row.get("target") or "",
                                      scan_id=scan_id, msg=msg, start_stage=start)
    except Exception as e:
        log.exception("resume failed")
        _mark_job_done(scan_id, "failed")
        return await _rich_reply(update, ctx.bot,
            f"Resume gagal: <code>{_e(type(e).__name__)}</code>: {_e(e)}")
    user_jobs[scan_id]["task"] = task


_STAGE_ARG = {"research": "RESEARCHING", "verify": "VERIFYING", "report": "REPORTING"}


async def cmd_retry(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Re-run a failed scan: from the checkpoint by default, or from an explicit stage."""
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/retry &lt;scan_id&gt; [research|verify|report]</code>")
    scan_id = ctx.args[0]
    requested = _STAGE_ARG.get(ctx.args[1].lower()) if len(ctx.args) > 1 else None
    if len(ctx.args) > 1 and requested is None:
        return await _rich_reply(update, ctx.bot,
            "Tahap harus salah satu dari: <code>research</code>, <code>verify</code>, <code>report</code>")
    uid = update.effective_user.id
    row = await db.get_job_for_user(scan_id, uid)
    if not row:
        return await _rich_reply(update, ctx.bot, "Scan not found or not owned by you.")
    stage = row.get("stage") or ""
    if stage in ("COMPLETED", "CANCELLED"):
        return await _rich_reply(update, ctx.bot,
            f"Scan <code>{_e(scan_id)}</code> sudah <b>{_e(stage.lower())}</b> — buat scan baru utk ulangi.")
    jobs = _jobs_mod()
    if stage in ("RESEARCHING", "VERIFYING", "REPORTING", "QUEUED") \
            and jobs is not None and await jobs.active(scan_id):
        return await _rich_reply(update, ctx.bot, "Scan sudah berjalan.")
    user_jobs = _active_jobs.setdefault(uid, {})
    entry = user_jobs.get(scan_id)
    if entry is not None and not entry.get("done"):
        return await _rich_reply(update, ctx.bot, "Scan sudah berjalan.")
    start = requested or _resume_stage(row)
    user_jobs[scan_id] = {"target": row.get("target") or "",
                          "started": row.get("started") or "",
                          "done": False, "stage": start}
    msg = (await _rich_reply(update, ctx.bot,
        f"<i>Retry scan</i> <code>{_e(scan_id)}</code> "
        f"<i>dari tahap</i> <code>{start}</code><i>…</i>"))[-1]
    try:
        task = await _resume_scan_job(bot=ctx.bot, user_id=uid,
                                      target=row.get("target") or "",
                                      scan_id=scan_id, msg=msg, start_stage=start)
    except Exception as e:
        log.exception("retry failed")
        _mark_job_done(scan_id, "failed")
        return await _rich_reply(update, ctx.bot,
            f"Retry gagal: <code>{_e(type(e).__name__)}</code>: {_e(e)}")
    user_jobs[scan_id]["task"] = task


async def cmd_poc(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if len(ctx.args) < 1:
        return await _rich_reply(update, ctx.bot,
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
    row = (await db.get_scan_for_user(scan_id, update.effective_user.id)
           if scan_id != "adhoc" else None)
    if scan_id != "adhoc" and not row:
        return await _rich_reply(update, ctx.bot, "Scan not found or not owned by you.")
    target = row["target"] if row else ""
    msg = (await _rich_reply(update, ctx.bot,
        f"<i>Generating PoC for</i> <code>{_e(cve)}</code>…"))[-1]
    try:
        # cache: send existing + stored verdict (skip regenerate) unless force
        existing = await db.get_poc(scan_id, cve)
        if existing and existing.get("path") and existing.get("code") and not force:
            fp = existing["path"]
            if not os.path.exists(fp):
                Path(fp).write_text(existing["code"], encoding="utf-8")
            await msg.delete()
            if existing.get("verdict"):
                await _rich_reply(update, ctx.bot,
                    rich.render_poc_verdict(cve, existing["verdict"], existing.get("reason") or "",
                                            existing.get("attempts") or 0)
                    + "\n<i>(cached — script lama, skip regenerate. /poc scan cve force utk bikin ulang)</i>")
            else:
                await _rich_reply(update, ctx.bot,
                    rich.render_poc_notice(fp, cve, scan_id)
                    + "\n<i>(cached — belum ada verdict. /poc scan cve force utk verify)</i>")
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
        await _rich_reply(update, ctx.bot,
            rich.render_poc_verdict(cve, verdict, reason, attempts, methods))
        if fp and os.path.exists(fp):
            with open(fp, "rb") as f:
                await update.effective_message.reply_document(
                    document=f, filename=fp.split("/")[-1], caption=f"PoC for {cve}")
        else:
            await _rich_reply(update, ctx.bot,
                "<i>(PoC file belum tersimpan — agent mungkin belum panggil save_poc. Coba /poc force.)</i>")
    except Exception as e:
        log.exception("poc failed")
        kind = type(e).__name__
        hint = ""
        if "Timeout" in kind or "timeout" in str(e).lower():
            hint = " (LLM timeout generate kode — coba lagi, model reasoning lambat)"
        try:
            await _rich_edit(msg, f"PoC failed: {_e(kind)}: {_e(e)}{hint}")
        except Exception:
            await _rich_reply(update, ctx.bot, f"PoC failed: {_e(kind)}: {_e(e)}{hint}")


async def cmd_report(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot, "Usage: <code>/report &lt;scan_id&gt;</code>")
    row = await db.get_scan_for_user(ctx.args[0], update.effective_user.id)
    if not row:
        return await _rich_reply(update, ctx.bot, "Scan not found.")
    report = json.loads(row["report"]) if row.get("report") else {}
    chunks = rich.render_report(report, row["id"])
    for ch in chunks:
        await _rich_reply(update, ctx.bot, ch)


async def cmd_history(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    rows = await db.list_scans(update.effective_user.id)
    if not rows:
        return await _rich_reply(update, ctx.bot, "No scans yet.")
    items = [f"<code>{_e(r['id'])}</code> — {_e(r['target'])} ({r['created']})"
             for r in rows]
    await _rich_reply(update, ctx.bot, "<h3>Your scans</h3>\n" + _rich_ol(items))


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
    await _rich_reply(update, ctx.bot,
        "<h3>Vuln sources</h3>\n" + _rich_ol([f"<code>{_e(s)}</code>" for s in srcs]))


async def cmd_feedback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Rate a scan result — helps the bot learn (self-improvement feedback loop)."""
    if not _gate(update):
        return await _unauthorized(update)
    if len(ctx.args) < 2:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/feedback &lt;scan_id&gt; good|bad|wrong [note]</code>\n"
            "<i>good = accurate, bad = missed something, wrong = false positive</i>")
    scan_id = ctx.args[0]
    rating = ctx.args[1].lower()
    note = " ".join(ctx.args[2:]) if len(ctx.args) > 2 else ""
    if rating not in ("good", "bad", "wrong"):
        return await _rich_reply(update, ctx.bot,
            "Rating must be: <code>good</code>, <code>bad</code>, or <code>wrong</code>")
    await db.save_feedback(scan_id, rating, note)
    await _rich_reply(update, ctx.bot,
        f"<b>Feedback saved</b>\nScan: <code>{_e(scan_id)}</code>\nRating: <b>{rating}</b>"
        + (f"\nNote: {_e(note)}" if note else "")
        + "\n<i>Bot akan gunakan ini utk improve akurasi scan selanjutnya.</i>")


async def cmd_knowledge(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Show accumulated knowledge from prior scans (self-improvement memory)."""
    if not _gate(update):
        return await _unauthorized(update)
    rows = await db.get_all_knowledge(limit=10)
    if not rows:
        return await _rich_reply(update, ctx.bot, "No knowledge accumulated yet.")
    items = []
    for r in rows:
        cms = r.get("cms", "?")
        ver = r.get("version") or ""
        lessons = (r.get("lessons") or "")[:150]
        items.append(f"<b>{_e(cms)} {_e(ver)}</b>: {_e(lessons)}")
    await _rich_reply(update, ctx.bot,
        "<h3>Learned knowledge (last 10 scans)</h3>\n" + _rich_ol(items, ordered=False))


async def cmd_monitor(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Toggle vuln monitor on/off, or list sent CVEs."""
    global _monitor
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        status = "ON" if (_monitor and _monitor._running) else "OFF"
        await _rich_reply(update, ctx.bot,
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
            return await _rich_reply(update, ctx.bot, "Monitor sudah ON.")
        _monitor = VulnMonitor(bot=ctx.bot)
        await _monitor.start()
        await _rich_reply(update, ctx.bot,
            "Vuln Monitor ON. Cek tiap 1 jam. Report akan dikirim ke sini.")
    elif cmd == "off":
        if _monitor:
            await _monitor.stop()
        await _rich_reply(update, ctx.bot, "Vuln Monitor OFF")
    elif cmd == "list":
        rows = await db.get_sent_cves(limit=20)
        if not rows:
            return await _rich_reply(update, ctx.bot, "Belum ada CVE terkirim.")
        items = []
        for r in rows:
            sev = r.get("severity", "?")[:4]
            rce = r.get("rce_type", "?")[:8]
            auth = r.get("auth_type", "?")[:5]
            items.append(f"<code>{r['cve']}</code> [{sev}] RCE:{rce} Auth:{auth} ({r.get('sent_at','')})")
        await _rich_reply(update, ctx.bot,
            f"<h3>Sent CVEs ({len(rows)})</h3>\n" + _rich_ol(items, ordered=False))
    elif cmd == "check":
        if not _monitor:
            _monitor = VulnMonitor(bot=ctx.bot)
        await _rich_reply(update, ctx.bot, "<i>Running monitor cycle now...</i>")
        await _monitor._check_cycle()
    else:
        await _rich_reply(update, ctx.bot, "Usage: /monitor on|off|list|check")


async def cmd_chat(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Enter chat mode for a scan, or one-shot question: /chat <scan_id> [question...]"""
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/chat &lt;scan_id&gt; [pertanyaan]</code>\n"
            "Tanpa pertanyaan → masuk mode chat (ketik bebas). <code>/end</code> utk keluar.")
    scan_id = ctx.args[0]
    question = " ".join(ctx.args[1:]).strip()
    row = await db.get_scan_for_user(scan_id, update.effective_user.id)
    if not row:
        return await _rich_reply(update, ctx.bot, "Scan ID tidak ditemukan.")
    _active_chat[update.effective_user.id] = scan_id
    if question:
        await _do_chat(update, ctx.bot, scan_id, question)
    else:
        await _rich_reply(update, ctx.bot,
            f"Mode chat aktif utk scan <code>{_e(scan_id)}</code> ({_e(row.get('target'))}).\n"
            f"Ketik pertanyaan apa saja. <code>/end</code> utk keluar.")


async def cmd_end(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    _active_chat.pop(update.effective_user.id, None)
    await _rich_reply(update, ctx.bot, "Mode chat ditutup.")


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Free-text → route to chat agent if user has an active scan session."""
    if not _gate(update):
        return
    uid = update.effective_user.id
    scan_id = _active_chat.get(uid)
    if not scan_id:
        return  # not in chat mode; ignore (or could reply hint)
    await _do_chat(update, ctx.bot, scan_id, update.effective_message.text)


_chat_locks: dict[int, asyncio.Lock] = {}  # per-user chat serialization (lost-update guard)


async def _do_chat(update: Update, bot, scan_id: str, question: str):
    row = await db.get_scan_for_user(scan_id, update.effective_user.id)
    if not row:
        return await _rich_reply(update, bot, "Scan ID tidak ditemukan.")
    uid = update.effective_user.id
    lock = _chat_locks.setdefault(uid, asyncio.Lock())
    msg = (await _rich_reply(update, bot, "<i>🤖 thinking…</i>"))[-1]
    try:
        # serialize get→run→save — two rapid messages must not overwrite each other's history
        async with lock:
            history = await db.get_chat(scan_id)
            answer, history = await runner.run_chat(
                scan_id, row.get("grounded") or "", row.get("findings") or "",
                question, history, user_id=uid)
            await db.save_chat(scan_id, history)
        try:
            await msg.delete()
        except Exception:
            pass
        # reply_rich sanitizes LLM HTML to the safe subset and chunks
        await _rich_reply(update, bot, answer or "(empty)")
    except Exception as e:
        log.exception("chat failed")
        kind = type(e).__name__
        try:
            await _rich_edit(msg, f"Chat error: {_e(kind)}: {_e(e)}")
        except Exception:
            await _rich_reply(update, bot, f"Chat error: {_e(kind)}: {_e(e)}")


async def cmd_jobs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    uid = update.effective_user.id
    try:
        rows = await db.list_jobs(user_id=uid, limit=20)
    except Exception:
        rows = []
    if not rows:
        return await _rich_reply(update, ctx.bot, "<i>Tidak ada scan (aktif/riwayat).</i>")
    table_rows = []
    acts = []
    for j in rows:
        sid = j.get("scan_id", "?")
        stage = j.get("stage") or j.get("status") or "?"
        progress = (j.get("progress") or "")[:40]
        started = j.get("started") or j.get("created") or ""
        table_rows.append([
            f"<code>{_e(sid)}</code>",
            _e(j.get("target") or ""),
            f"<b>{_e(stage)}</b>",
            _e(progress),
            _e(started),
        ])
        if stage in ("QUEUED", "RESEARCHING", "VERIFYING", "REPORTING"):
            acts.append(f"<code>/cancel {_e(sid)}</code>")
        elif stage == "INTERRUPTED":
            acts.append(f"<code>/resume {_e(sid)}</code>")
        elif stage == "FAILED":
            acts.append(f"<code>/retry {_e(sid)}</code>")
    parts = ["<h2>Jobs</h2>",
             _rich_table(["Scan ID", "Target", "Stage", "Progress", "Mulai"], table_rows)]
    if acts:
        parts.append("<p><b>Actions:</b> " + " · ".join(acts[:8]) + "</p>")
    await _rich_reply(update, ctx.bot, "\n".join(parts))


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
        row = await db.get_scan_for_user(scan_id, update.effective_user.id)
        if not row:
            return await _rich_reply(q.message, ctx.bot, "Scan not found or not owned by you.")
        report = json.loads(row["report"]) if row and row.get("report") else {}
        await q.edit_message_reply_markup(
            reply_markup=_poc_menu_kb(scan_id, _report_cves(report)))
    elif data.startswith("back:"):
        _, scan_id = data.split(":", 1)
        row = await db.get_scan_for_user(scan_id, update.effective_user.id)
        if not row:
            return await _rich_reply(q.message, ctx.bot, "Scan not found or not owned by you.")
        report = json.loads(row["report"]) if row and row.get("report") else {}
        await q.edit_message_reply_markup(
            reply_markup=_main_kb(scan_id, _report_cves(report)))
    elif data.startswith("chat:"):
        _, scan_id = data.split(":", 1)
        row = await db.get_scan_for_user(scan_id, update.effective_user.id)
        if not row:
            return await _rich_reply(q.message, ctx.bot, "Scan not found or not owned by you.")
        _active_chat[update.effective_user.id] = scan_id
        tgt = _e(row.get("target"))
        await _rich_reply(q.message, ctx.bot,
            f"Mode chat aktif utk scan <code>{_e(scan_id)}</code> ({tgt}).\n"
            f"Ketik pertanyaan apa saja. <code>/end</code> utk keluar.")
    elif data.startswith("rescan:"):
        _, scan_id = data.split(":", 1)
        row = await db.get_scan_for_user(scan_id, update.effective_user.id)
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
            await _rich_reply(q.message, ctx.bot, "<b>Model reset ke default config.</b>")
        elif len(parts) == 3:
            role, model_id = parts[1], parts[2]
            if await _select_model(role, model_id):
                await _rich_reply(q.message, ctx.bot,
                    f"<b>Model {role} →</b> <code>{_e(model_id)}</code>")
            else:
                await _rich_reply(q.message, ctx.bot,
                    f"<b>Model tidak valid / provider unavailable:</b> <code>{_e(model_id)}</code>")


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


async def _select_model(role: str, model_id: str) -> bool:
    """Persist + activate a provider-validated model id."""
    if role not in ("detect", "report") or not model_id:
        return False
    from llm import set_models, fetch_available_models
    models = await fetch_available_models()
    if not models or model_id not in models:
        return False
    set_models(**{role: model_id})
    await db.set_setting(f"model_{role}", model_id)
    return True


async def cmd_model(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """View / switch the active LLM models (detect + report) from the provider."""
    if not _gate(update):
        return await _unauthorized(update)
    from llm import get_models, set_models, fetch_available_models
    cur = get_models()
    args = list(ctx.args or [])
    if len(args) == 2 and args[0].lower() in ("detect", "report"):
        role, model_id = args[0].lower(), args[1]
        if not await _select_model(role, model_id):
            return await _rich_reply(update, ctx.bot,
                f"<b>Model tidak ditemukan / provider unavailable:</b> <code>{_e(model_id)}</code>\n"
                f"<i>Gunakan</i> <code>/model list</code> <i>utk liat model yg tersedia.</i>")
        return await _rich_reply(update, ctx.bot,
            f"<b>Model {role} →</b> <code>{_e(model_id)}</code>\n"
            f"<i>Berlaku untuk scan berikutnya.</i>")
    if len(args) == 1 and args[0].lower() in ("list", "reset"):
        if args[0].lower() == "reset":
            set_models(detect="", report="")
            await db.set_setting("model_detect", "")
            await db.set_setting("model_report", "")
            return await _rich_reply(update, ctx.bot,
                "<b>Model reset ke default config.</b>")
    models = await fetch_available_models()
    if not models:
        return await _rich_reply(update, ctx.bot,
            "<b>Model saat ini:</b>\n"
            f"detect: <code>{_e(cur['detect'])}</code>\n"
            f"report: <code>{_e(cur['report'])}</code>\n\n"
            "<i>Provider tidak merespon /models — coba lagi nanti.</i>")
    short = [m for m in models if m.startswith(("al/", "co/"))][:40]
    buttons = []
    for model_id in short[:15]:
        data = f"model:detect:{model_id}"
        if len(data.encode("utf-8")) <= 64:
            buttons.append([InlineKeyboardButton(f"🔍 detect: {model_id}", callback_data=data)])
    for model_id in short[15:30]:
        data = f"model:report:{model_id}"
        if len(data.encode("utf-8")) <= 64:
            buttons.append([InlineKeyboardButton(f"📝 report: {model_id}", callback_data=data)])
    buttons.append([InlineKeyboardButton("↩️ Reset default", callback_data="model:reset")])
    await _rich_reply(update, ctx.bot,
        f"<b>Model aktif:</b>\n"
        f"detect: <code>{_e(cur['detect'])}</code>\n"
        f"report: <code>{_e(cur['report'])}</code>\n\n"
        f"<i>Pilih model (dari provider, {len(short)} tampil):</i>\n"
        f"<code>/model detect &lt;id&gt;</code> atau <code>/model report &lt;id&gt;</code>",
        reply_markup=InlineKeyboardMarkup(buttons))


# ============ /library — private intelligence library UI ============

_LIB_HELP = (
    "<h2>Library Vuln Intelligence</h2>"
    "<p>Knowledge base pribadi: hasil scan, monitor CVE, dan intel dari sumber eksternal.</p>\n"
    "<h3>Subcommands</h3>\n"
    + _rich_ol([
        "<code>/library stats</code> — ringkasan isi library",
        "<code>/library search &lt;query&gt;</code> — cari vulnerability (semantic)",
        "<code>/library cve &lt;CVE-ID&gt;</code> — detail satu vulnerability",
        "<code>/library related &lt;CVE-ID|query&gt;</code> — vulnerability mirip/terkait",
        "<code>/library target &lt;url|host&gt;</code> — riwayat scan target milik kamu",
        "<code>/library evidence &lt;CVE-ID&gt;</code> — evidence/bukti utk CVE (milik kamu)",
        "<code>/library recent [n]</code> — vulnerability terbaru (default 10)",
        "<code>/library exploitable</code> — yang ber-status exploitable (by CVSS)",
        "<code>/library note &lt;CVE-ID&gt; &lt;catatan&gt;</code> — catatan pribadi",
        "<code>/library refresh [CVE-ID]</code> — refresh data (yg overdue / satu CVE)",
        "<code>/library export</code> — export semua data sebagai JSONL (file)",
        "<code>/library verify</code> — verifikasi integritas DB library",
    ]))


def _library_module():
    """Lazy import of root library.py — stays importable while the module bootstraps."""
    try:
        import library as _lib
        return _lib
    except Exception:
        return None


async def _lib(fn_name: str, *args, **kw):
    """Call one async library function by name. Raises clear errors when unavailable."""
    lib = _library_module()
    if lib is None:
        raise RuntimeError("library module tidak tersedia")
    fn = getattr(lib, fn_name, None)
    if fn is None:
        raise LookupError(f"library.{fn_name}() belum diimplementasikan")
    return await fn(*args, **kw)


def _vrow(v: dict) -> str:
    """One compact HTML line for a vulnerability row."""
    cid = v.get("canonical_id") or v.get("id") or v.get("cve") or "?"
    sev = (v.get("severity") or "UNKNOWN").upper()
    line = f"<code>{_e(cid)}</code> [<b>{_e(sev)}</b>"
    cvss = v.get("cvss")
    if isinstance(cvss, (int, float)):
        line += f" {cvss}"
    line += "]"
    title = v.get("title") or v.get("summary") or "-"
    line += f" {_e(str(title))[:120]}"
    if v.get("kev") or v.get("in_kev"):
        line += " · <b>KEV</b>"
    if v.get("exploitable"):
        line += " · <b>EXPLOITABLE</b>"
    upd = v.get("updated") or v.get("published")
    if upd:
        line += f"\n<i>{_e(str(upd))}</i>"
    return line


def _vdetail(v: dict) -> list[str]:
    """Full detail for one vulnerability → list of HTML blocks."""
    cid = v.get("canonical_id") or v.get("id") or v.get("cve") or "?"
    sev = (v.get("severity") or "UNKNOWN").upper()
    head = f"<b>{_e(cid)}</b>  [{_e(sev)}"
    cvss = v.get("cvss")
    if isinstance(cvss, (int, float)):
        head += f" CVSS {cvss}"
    epss = v.get("epss")
    if isinstance(epss, (int, float)):
        head += f" · EPSS {epss:.0%}"
    head += "]"
    if v.get("kev") or v.get("in_kev"):
        head += " · <b>KEV</b>"
    if v.get("exploitable"):
        head += " · <b>EXPLOITABLE</b>"
    parts = [head]
    for label, key in (("Title", "title"), ("Summary", "summary"),
                       ("Description", "description"), ("Affects", "affects"),
                       ("Component", "component"), ("Status", "status"),
                       ("PoC", "poc_status")):
        val = v.get(key)
        if val:
            parts.append(f"<b>{label}:</b> {_e(str(val))[:600]}")
    refs = v.get("references") or v.get("refs") or v.get("urls")
    if refs:
        if not isinstance(refs, list):
            refs = [refs]
        links = [f'<a href="{_e(u)}">link{i+1}</a>'
                 for i, u in enumerate(refs[:5]) if str(u).startswith("http")]
        if links:
            parts.append("<b>References:</b> " + " | ".join(links))
    srcs = v.get("sources")
    if srcs:
        if isinstance(srcs, str):
            srcs = [srcs]
        parts.append(f"<b>Sources:</b> {_e(', '.join(str(s) for s in srcs[:5]))}")
    upd = v.get("updated")
    if upd:
        parts.append(f"<b>Updated:</b> {_e(str(upd))}")
    return parts


def _erow(e: dict) -> str:
    """One compact HTML line for an evidence/observation row."""
    kind = e.get("kind") or e.get("type") or "observation"
    detail = e.get("detail") or e.get("content") or e.get("note") or e.get("value") or "-"
    src = e.get("source") or e.get("source_name") or ""
    ts = e.get("observed_at") or e.get("created") or e.get("created_at") or ""
    line = f"<b>{_e(str(kind))}</b>"
    if src:
        line += f" · {_e(str(src))}"
    if ts:
        line += f" · {_e(str(ts))}"
    line += f"\n{_e(str(detail))[:400]}"
    return line


def _srow(r: dict) -> str:
    """One compact HTML line for a scan-history row."""
    sid = r.get("scan_id") or r.get("id") or "?"
    tgt = r.get("target") or "-"
    ts = r.get("created") or r.get("created_at") or r.get("observed_at") or ""
    status = r.get("status") or ""
    line = f"<code>{_e(sid)}</code> — {_e(str(tgt))}"
    if status:
        line += f" ({_e(str(status))})"
    if ts:
        line += f" · {_e(str(ts))}"
    summary = r.get("summary") or r.get("report_status") or ""
    if summary:
        line += f"\n<i>{_e(str(summary))[:150]}</i>"
    return line


async def _send_html(update: Update, bot, text: str):
    """Send HTML text through the rich helper (sanitize + auto-split inside)."""
    await _rich_reply(update, bot, text)


async def cmd_library(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _gate(update):
        return await _unauthorized(update)
    args = list(ctx.args or [])
    if not args:
        return await _rich_reply(update, ctx.bot, _LIB_HELP)
    sub = args[0].lower()
    uid = update.effective_user.id
    handlers = {
        "stats": _lib_stats, "search": _lib_search, "cve": _lib_cve,
        "related": _lib_related, "target": _lib_target, "evidence": _lib_evidence,
        "recent": _lib_recent, "exploitable": _lib_exploitable, "note": _lib_note,
        "refresh": _lib_refresh, "export": _lib_export, "verify": _lib_verify,
    }
    fn = handlers.get(sub)
    if fn is None:
        return await _rich_reply(update, ctx.bot,
            f"Subcommand tidak dikenal: <code>{_e(sub)}</code>\n\n{_LIB_HELP}")
    try:
        await fn(update, uid, args[1:], ctx.bot)
    except Exception as e:
        log.exception("library %s failed", sub)
        await _rich_reply(update, ctx.bot,
            f"<b>Library error ({sub}):</b> {_e(type(e).__name__)}: {_e(e)}")


async def _lib_stats(update: Update, uid: int, args: list, bot):
    st = await _lib("stats", uid)
    if not isinstance(st, dict):
        return await _rich_reply(update, bot, f"<b>Library stats:</b> {_e(st)}")
    items = []
    for k, v in st.items():
        if isinstance(v, (list, dict)):
            v = json.dumps(v, ensure_ascii=False)[:300]
        items.append(f"<b>{_e(str(k))}:</b> {_e(v)}")
    await _send_html(update, bot, "<h2>Library stats</h2>\n" + _rich_ol(items, ordered=False))


async def _lib_search(update: Update, uid: int, args: list, bot):
    if not args:
        return await _rich_reply(update, bot,
            "Usage: <code>/library search &lt;query&gt;</code>")
    query = " ".join(args)
    rows = await _lib("search", query, 10) or []
    if not rows:
        return await _rich_reply(update, bot,
            f"<i>Tidak ada hasil utk</i> <code>{_e(query)}</code><i>.</i>")
    await _send_html(update, bot,
        f"<h3>Search: {_e(query)} ({len(rows)} hasil)</h3>\n" + _rich_ol([_vrow(v) for v in rows]))


async def _lib_cve(update: Update, uid: int, args: list, bot):
    if not args:
        return await _rich_reply(update, bot,
            "Usage: <code>/library cve &lt;CVE-ID&gt;</code>\n"
            "<i>Contoh:</i> <code>/library cve CVE-2024-1234</code>")
    cid = args[0].upper()
    v = await _lib("get_vulnerability", cid)
    if not v:
        return await _rich_reply(update, bot,
            f"<i>Vulnerability tidak ditemukan:</i> <code>{_e(cid)}</code>")
    parts = _vdetail(v)
    blocks = [parts[0]] + [f"<p>{p}</p>" for p in parts[1:]]
    await _send_html(update, bot, "\n".join(blocks))


async def _lib_related(update: Update, uid: int, args: list, bot):
    if not args:
        return await _rich_reply(update, bot,
            "Usage: <code>/library related &lt;CVE-ID | query&gt;</code>")
    q = " ".join(args)
    if q.upper().startswith("CVE-"):
        q = q.upper()
    rows = await _lib("related", q, 5) or []
    if not rows:
        return await _rich_reply(update, bot,
            f"<i>Tidak ada CVE terkait utk</i> <code>{_e(q)}</code><i>.</i>")
    await _send_html(update, bot,
        f"<h3>Terkait: {_e(q)}</h3>\n" + _rich_ol([_vrow(v) for v in rows]))


async def _lib_target(update: Update, uid: int, args: list, bot):
    if not args:
        return await _rich_reply(update, bot,
            "Usage: <code>/library target &lt;url|host&gt;</code> — riwayat scan target milik kamu")
    tgt = " ".join(args)
    rows = await _lib("target_history", uid, tgt, 10) or []
    if not rows:
        return await _rich_reply(update, bot,
            f"<i>Belum ada scan utk</i> <code>{_e(tgt)}</code><i> milik kamu.</i>")
    await _send_html(update, bot,
        f"<h3>Riwayat target: {_e(tgt)} ({len(rows)})</h3>\n" + _rich_ol([_srow(r) for r in rows]))


async def _lib_evidence(update: Update, uid: int, args: list, bot):
    if not args:
        return await _rich_reply(update, bot,
            "Usage: <code>/library evidence &lt;CVE-ID&gt;</code> — evidence milik kamu utk CVE tsb")
    cid = args[0].upper()
    rows = await _lib("get_evidence", cid, uid, 20) or []
    if not rows:
        return await _rich_reply(update, bot,
            f"<i>Belum ada evidence utk</i> <code>{_e(cid)}</code><i> (data milik kamu).</i>")
    await _send_html(update, bot,
        f"<h3>Evidence: {_e(cid)} ({len(rows)})</h3>\n" + _rich_ol([_erow(r) for r in rows]))


async def _lib_recent(update: Update, uid: int, args: list, bot):
    n = 10
    if args:
        try:
            n = max(1, min(int(args[0]), 50))
        except ValueError:
            return await _rich_reply(update, bot,
                "Usage: <code>/library recent [n]</code>  (n = jumlah, maks 50)")
    rows = await _lib("recent", n) or []
    if not rows:
        return await _rich_reply(update, bot, "<i>Library masih kosong.</i>")
    await _send_html(update, bot,
        f"<h3>Vulnerability terbaru ({len(rows)})</h3>\n" + _rich_ol([_vrow(v) for v in rows]))


async def _lib_exploitable(update: Update, uid: int, args: list, bot):
    rows = await _lib("exploitable", 10) or []
    if not rows:
        return await _rich_reply(update, bot,
            "<i>Belum ada vulnerability exploitable.</i>")
    await _send_html(update, bot,
        f"<h3>Exploitable (by CVSS, {len(rows)})</h3>\n" + _rich_ol([_vrow(v) for v in rows]))


async def _lib_note(update: Update, uid: int, args: list, bot):
    if len(args) < 2:
        return await _rich_reply(update, bot,
            "Usage: <code>/library note &lt;CVE-ID&gt; &lt;catatan&gt;</code>\n"
            "<i>Simpan catatan pribadi yg terhubung ke entity di library.</i>")
    entity = args[0].upper()
    note = " ".join(args[1:])
    res = await _lib("add_note", uid, entity, note)
    extra = ""
    if isinstance(res, dict):
        extra = " " + ", ".join(f"{k}={_e(v)}" for k, v in list(res.items())[:4])
    elif isinstance(res, str) and res:
        extra = " " + _e(res[:100])
    await _rich_reply(update, bot,
        f"<b>Catatan disimpan</b>\nEntity: <code>{_e(entity)}</code>\nNote: {_e(note[:300])}{extra}")


async def _lib_refresh(update: Update, uid: int, args: list, bot):
    if args:
        cid = args[0].upper()
        res = await _lib("refresh_vulnerability", cid)
        detail = f"\n<i>{_e(str(res)[:200])}</i>" if res else ""
        return await _rich_reply(update, bot,
            f"<b>Refresh:</b> <code>{_e(cid)}</code>{detail}")
    due = await _lib("refresh_due", 5) or []
    if not due:
        return await _rich_reply(update, bot,
            "<i>Tidak ada vulnerability yg perlu di-refresh.</i>")
    await _send_html(update, bot,
        f"<h3>Refresh berjalan utk {len(due)} CVE</h3>\n" + _rich_ol([_vrow(v) for v in due]))


async def _lib_export(update: Update, uid: int, args: list, bot):
    text = await _lib("export_jsonl", uid)
    if not text:
        return await _rich_reply(update, bot,
            "<i>Library kosong — tidak ada data utk export.</i>")
    data = text.encode("utf-8")
    await update.effective_message.reply_document(
        document=io.BytesIO(data),
        filename="library_export.jsonl",
        caption=f"Library export JSONL — {len(data)} bytes, {len(text.splitlines())} baris")


async def _lib_verify(update: Update, uid: int, args: list, bot):
    res = await _lib("verify_integrity")
    if isinstance(res, dict):
        ok = res.get("ok") or res.get("valid")
        items = [f"<b>Integritas library: {'OK' if ok else 'MASALAH'}</b>"]
        for k, v in res.items():
            items.append(f"{_e(str(k))}: {_e(v)}")
        await _send_html(update, bot, "\n".join(items))
    else:
        await _rich_reply(update, bot, f"<b>Integritas library:</b> {_e(res)}")


# ============ /remediate /compare /retest — remediation (sibling module) ============

def _render_plan(res: dict) -> str:
    parts = ["<h2>Remediation Plan</h2>"]
    parts.append(f"<p>Scan: <code>{_e(res.get('scan_id'))}</code> · "
                 f"Target: <code>{_e(res.get('target'))}</code></p>")
    summary = res.get("summary")
    if summary:
        parts.append(f"<p><i>{_e(summary)}</i></p>")
    items = res.get("plan") or []
    if not items:
        parts.append("<p><i>Tidak ada item dalam plan.</i></p>")
        return "\n".join(parts)
    rows = []
    for it in items:
        rows.append([
            f"<code>{_e(it.get('cve') or '?')}</code>",
            _e(it.get("severity") or "?"),
            f"<b>{_e(it.get('verdict') or '?')}</b>",
            _e((it.get("action") or "")[:80]),
        ])
    parts.append(_rich_table(["CVE", "Severity", "Verdict", "Action"], rows))
    details = []
    for it in items:
        body = []
        if it.get("title"):
            body.append(f"<p><b>{_e(it['title'])}</b></p>")
        if it.get("summary"):
            body.append(f"<p>{_e(it['summary'])}</p>")
        fixed = it.get("fixed_versions") or []
        if fixed:
            body.append(f"<p><b>Fixed versions:</b> {_e(', '.join(str(f) for f in fixed))}</p>")
        if it.get("diff_patch"):
            body.append(f'<p><b>Patch:</b> <a href="{_e(it["diff_patch"])}">diff</a></p>')
        refs = it.get("references") or []
        if refs:
            links = " | ".join(f'<a href="{_e(u)}">link{i+1}</a>'
                               for i, u in enumerate(refs[:5]) if str(u).startswith("http"))
            if links:
                body.append(f"<p><b>References:</b> {links}</p>")
        if body:
            details.append(f"<details><summary>{_e(it.get('cve') or '?')}</summary>\n"
                           + "\n".join(body) + "\n</details>")
    if details:
        parts.append("\n".join(details))
    return "\n".join(parts)


def _render_compare(res: dict) -> str:
    parts = ["<h2>Compare Scans</h2>",
             f"<p>Old: <code>{_e(res.get('old'))}</code> → "
             f"New: <code>{_e(res.get('new'))}</code></p>"]
    summary = res.get("summary")
    if summary:
        parts.append(f"<p><i>{_e(summary)}</i></p>")
    for label, key in (("Added", "added"), ("Removed", "removed"), ("Changed", "changed")):
        items = res.get(key) or []
        if not items:
            continue
        rows = []
        for it in items:
            ver = it.get("verdict") or "?"
            if key == "changed":
                ver = f"{it.get('old_verdict')} → {it.get('new_verdict')}"
            rows.append([f"<code>{_e(it.get('cve') or '?')}</code>",
                         _e(it.get("severity") or "?"), _e(ver)])
        parts.append(f"<h3>{label} ({len(items)})</h3>"
                     + _rich_table(["CVE", "Severity", "Verdict"], rows))
    unchanged = res.get("unchanged") or []
    if unchanged:
        cves = ", ".join(f"<code>{_e(x.get('cve') or '?')}</code>" for x in unchanged)
        parts.append(f"<h3>Unchanged ({len(unchanged)})</h3><p>{cves}</p>")
    return "\n".join(parts)


def _render_retest(res: dict) -> str:
    parts = ["<h2>Retest Results</h2>",
             f"<p>Scan: <code>{_e(res.get('scan_id'))}</code> · "
             f"Target: <code>{_e(res.get('target'))}</code></p>"]
    runs = res.get("runs") or []
    if not runs:
        parts.append("<p><i>Tidak ada run.</i></p>")
        return "\n".join(parts)
    rows = []
    for r in runs:
        rows.append([
            f"<code>{_e(r.get('cve') or '?')}</code>",
            _e(r.get("previous_verdict") or "?"),
            f"<b>{_e(r.get('outcome') or '?')}</b>",
            _e(r.get("status") or "?"),
            "YES" if r.get("changed") else "no",
        ])
    parts.append(_rich_table(["CVE", "Sebelum", "Outcome", "Status", "Changed"], rows))
    return "\n".join(parts)


async def cmd_remediate(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Build a deterministic remediation plan for an owned scan."""
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/remediate &lt;scan_id&gt;</code>")
    mod = _remediation_mod()
    if mod is None:
        return await _rich_reply(update, ctx.bot, "Remediation module belum tersedia.")
    scan_id = ctx.args[0]
    msg = (await _rich_reply(update, ctx.bot,
        f"<i>Menyusun plan utk</i> <code>{_e(scan_id)}</code><i>…</i>"))[-1]
    try:
        res = await mod.plan(update.effective_user.id, scan_id)
    except (ValueError, PermissionError) as e:
        return await _rich_edit(msg, f"{_e(e)}")
    except Exception as e:
        log.exception("remediate failed")
        try:
            await _rich_edit(msg, f"<b>Remediation error:</b> {_e(type(e).__name__)}: {_e(e)}")
        except Exception:
            await _rich_reply(update, ctx.bot,
                f"<b>Remediation error:</b> {_e(type(e).__name__)}: {_e(e)}")
        return
    try:
        await msg.delete()
    except Exception:
        pass
    await _rich_reply(update, ctx.bot, _render_plan(res))


async def cmd_compare(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Compare two owned scans (added/removed/changed findings)."""
    if not _gate(update):
        return await _unauthorized(update)
    if len(ctx.args) < 2:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/compare &lt;old_scan_id&gt; &lt;new_scan_id&gt;</code>")
    mod = _remediation_mod()
    if mod is None:
        return await _rich_reply(update, ctx.bot, "Remediation module belum tersedia.")
    old, new = ctx.args[0], ctx.args[1]
    try:
        res = await mod.compare(update.effective_user.id, old, new)
    except (ValueError, PermissionError) as e:
        return await _rich_reply(update, ctx.bot, f"{_e(e)}")
    except Exception as e:
        log.exception("compare failed")
        return await _rich_reply(update, ctx.bot,
            f"<b>Compare error:</b> {_e(type(e).__name__)}: {_e(e)}")
    await _rich_reply(update, ctx.bot, _render_compare(res))


async def cmd_retest(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Re-run stored PoCs for a scan (optionally one CVE) against the live target."""
    if not _gate(update):
        return await _unauthorized(update)
    if not ctx.args:
        return await _rich_reply(update, ctx.bot,
            "Usage: <code>/retest &lt;scan_id&gt; [CVE]</code>")
    mod = _remediation_mod()
    if mod is None:
        return await _rich_reply(update, ctx.bot, "Remediation module belum tersedia.")
    scan_id = ctx.args[0]
    cve = ctx.args[1].upper() if len(ctx.args) > 1 else None
    msg = (await _rich_reply(update, ctx.bot,
        f"<i>Retest dimulai utk</i> <code>{_e(scan_id)}</code><i>…</i>"))[-1]

    async def progress(done: int, total: int, m: str):
        try:
            await _rich_edit(msg, f"<i>Retest {done}/{total}: {_e(m)}</i>")
        except Exception:
            pass

    try:
        res = await mod.retest(update.effective_user.id, scan_id, cve, progress=progress)
    except (ValueError, PermissionError) as e:
        return await _rich_edit(msg, f"{_e(e)}")
    except Exception as e:
        log.exception("retest failed")
        try:
            await _rich_edit(msg, f"<b>Retest error:</b> {_e(type(e).__name__)}: {_e(e)}")
        except Exception:
            await _rich_reply(update, ctx.bot,
                f"<b>Retest error:</b> {_e(type(e).__name__)}: {_e(e)}")
        return
    try:
        await msg.delete()
    except Exception:
        pass
    await _rich_reply(update, ctx.bot, _render_retest(res))


# ------------------------------------------------------------------ main

def main():
    config.assert_configured()
    db.init_db()
    # mark any orphaned jobs from previous process as interrupted (resumable)
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
        # remediation tables — idempotent schema init
        try:
            mod = _remediation_mod()
            if mod is not None and hasattr(mod, "init_remediation"):
                await mod.init_remediation()
        except Exception:
            pass
        # library tables — idempotent. db.init_db() also calls it; keep this so the
        # bot works even if that hook is missing.
        try:
            lib = _library_module()
            if lib is not None:
                init = getattr(lib, "init_library", None)
                if init:
                    await init()
        except Exception:
            log.exception("library init failed")
        _monitor = VulnMonitor(bot=application.bot)
        await _monitor.start()

    async def _post_shutdown(application):
        """Stop the monitor, drain/cancel scan jobs, close HTTP clients."""
        global _monitor
        if _monitor is not None:
            try:
                await _monitor.stop()
            except Exception:
                log.exception("monitor stop failed")
        jobs = _jobs_mod()
        still = 0
        if jobs is not None and hasattr(jobs, "drain"):
            try:
                # grace window: live scans get a chance to persist their terminal stage
                still = await jobs.drain(timeout=30)
            except Exception:
                log.exception("jobs drain failed")
        # tasks still running after the grace window: cancel the task trees; the
        # jobs wrapper persists the terminal CANCELLED row for each
        for jobs_map in _active_jobs.values():
            for j in jobs_map.values():
                task = j.get("task")
                if task is not None and not task.done():
                    try:
                        task.cancel()
                    except Exception:
                        pass
        if still:
            await asyncio.sleep(2)  # let cancelled tasks write their terminal state
        try:
            await agent_tools.close_all()
        except Exception:
            pass
        try:
            from llm import close as _llm_close
            await _llm_close()
        except Exception:
            pass

    app = (Application.builder()
           .token(config.TELEGRAM_BOT_TOKEN)
           .concurrent_updates(True)
           .post_init(_post_init)
           .post_shutdown(_post_shutdown)
           .build())
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("jobs", cmd_jobs))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("resume", cmd_resume))
    app.add_handler(CommandHandler("retry", cmd_retry))
    app.add_handler(CommandHandler("poc", cmd_poc))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("model", cmd_model))
    app.add_handler(CommandHandler("feedback", cmd_feedback))
    app.add_handler(CommandHandler("knowledge", cmd_knowledge))
    app.add_handler(CommandHandler("monitor", cmd_monitor))
    app.add_handler(CommandHandler("library", cmd_library))
    app.add_handler(CommandHandler("chat", cmd_chat))
    app.add_handler(CommandHandler("end", cmd_end))
    app.add_handler(CommandHandler("remediate", cmd_remediate))
    app.add_handler(CommandHandler("compare", cmd_compare))
    app.add_handler(CommandHandler("retest", cmd_retest))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(CallbackQueryHandler(on_callback))
    log.info("vuln-agent bot starting…")
    app.run_polling()


if __name__ == "__main__":
    main()

# vuln-agent

AI-powered vulnerability scanner + exploit-research assistant for Telegram.

`vuln-agent` takes a target URL, **discovers** its software stack, cross-references **14 vulnerability sources**, reasons over the findings with an LLM agent, and **proves exploitability** by running real PoCs against the target — all from a Telegram chat. It also runs a **vuln monitor** that pushes new CVE alerts (≤14 days old) to your admin chat.

> **Ethical use only.** This tool performs active exploitation checks against the target you provide. Only scan systems you own or have explicit permission to test.

---

## Features

- **Pure discovery pipeline** — no hardcoded CVEs. Every finding comes from: `detect_stack → search_vuln → fetch_cve_detail → version_match → run_poc_check`.
- **Real exploit verification** — PoCs are run as subprocesses against the live target (`--check` mode, non-destructive). Verdicts are validated server-side (circumstantial evidence is downgraded).
- **14 vulnerability sources** — CVE 5.0 (MITRE), NVD, OSV, GitHub Advisory, ExploitDB, Wordfence, Patchstack, WPScan, CISA KEV, PoC-in-GitHub, WatchTowr, EPSS, BleepingComputer, Joomla Security.
- **Nuclei templates** — 4,200+ community-verified templates checked first (fast + accurate), with a YAML→Python fallback when the binary is missing.
- **Aggregate caching** — repeat lookups are served from SQLite (15.9s cold → 0.0s cached). No re-scrape during bot uptime.
- **Vuln monitor** — hourly CVE alerts (6h interval, 14-day recency window), deduped, with AI-written summaries + Shodan/FOFA/Hunter dorks.
- **Self-improvement** — learns detection signatures, PoC patterns, WAF bypasses, and per-CMS lessons across scans.
- **Switch AI models from Telegram** — `/model` lists provider models and swaps detect/report models at runtime (persisted).
- **Multi-model cooperation** — a fast detect model (ReAct research) + a report/PoC model, both streamed with hard timeouts + retries.
- **Private intelligence library** — canonical CVE/advisory facts with source provenance, conflict tracking, FTS5 + deterministic related search, per-target evidence/drift, notes/tags, JSONL import/export, integrity checks, backups, and continuous stale-record refresh.

---

## Architecture

```
Telegram bot (bot.py)
  ├── /scan        → background task: run_research → run_verify → run_report
  │                   │
  │                   ├── _pre_research (parallel I/O, no LLM)
  │                   │     detect_stack (detect/cms.py, detect/waf.py, probe.py)
  │                   │     search_vuln × N components  (scrapers/registry.py)
  │                   │     fetch_cve_detail × top-20   (14 sources, cached)
  │                   ├── LLM review (ReAct loop, ≤15 steps)
  │                   ├── run_verify: EPSS + KEV enrichment, then parallel run_poc
  │                   │     run_poc: nuclei template → learned pattern → LLM loop
  │                   │              → save_poc → subprocess --check → verdict
  │                   │              (verdict validated: strong vs circumstantial proof)
  │                   └── run_report: deterministic, LLM-free render
  │
  ├── /poc         → run_poc for a specific CVE (nuclei → pattern → LLM)
  ├── /chat        → persistent per-scan Q&A (history persisted, per-user lock)
  ├── /model       → list/switch detect + report models from the router
  ├── /monitor     → vuln news listener (see below)
  ├── /library     → private fact library: search/CVE/related/evidence/target drift/notes/export
  └── /feedback /knowledge → self-improvement loop

Vuln monitor (agent/monitor.py)
  every 6h (and on /monitor check):
    Wordfence threat-intel (Playwright) + 35 product queries (cached)
    → filter published ≤14 days → dedupe vs sent_cves → top 5 by CVSS
    → fetch detail + advisories → AI summary + dorks → send → mark sent
    (re-entrancy guard: no concurrent cycles, no double-send)

LLM layer (llm.py)
  OpenAI-compatible router (9router), SSE streaming
  hard timeouts + retry (3×) on transient failures (5xx/524/ReadTimeout)
  runtime model overrides persisted in db settings

Scraper layer (scrapers/)
  registry.py: parallel fan-out, 30s per-source cap, aggregate cache
               (single-flight: concurrent same-key lookups share one scrape)
  each source: BaseScraper with pluggable SQLite cache (TTL 24h)
```

Private library (`library.py`, SQLite `lib_*` tables)
  scan + monitor + live source facts → normalize/deduplicate → canonical facts
  source claims → provenance + conflict ledger (first-seen canonical fact retained)
  verified findings → user-scoped evidence + target snapshots + drift
  FTS5/LIKE + local weighted concept retrieval → agent prior context
  refresh queue → re-query stale records without blocking scans

### Pipeline detail

| Phase | What runs | Bounded by |
|---|---|---|
| Detect | HTTP probe → CMS/plugin/service/WAF fingerprint | 15s client, 13 aux paths |
| Research | parallel `search_vuln` per component | 90s per search |
| Detail | top-20 CVEs × 14 sources (parallel, sem 10) | 90s each |
| AI review | ReAct loop emitting findings JSON | 15 steps × 600s |
| Verify | EPSS + KEV enrich, then `run_poc` per candidate (sem 10) | 600s per candidate |
| Report | deterministic render from `verified` field | LLM-free |

---

## Setup

```bash
git clone <repo-url> vuln-agent
cd vuln-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # then edit
```

### `.env`

```ini
# Telegram bot
TELEGRAM_BOT_TOKEN=123456:ABC-DEF        # from @BotFather
ALLOWED_USER_IDS=123456789,987654321     # who may use the bot

# LLM router (OpenAI-compatible). Any OpenAI-compatible endpoint works.
ROUTER_BASE=https://9router.kliksosmed.id/v1
ROUTER_KEY=sk-REPLACE_WITH_YOUR_KEY
MODEL_DETECT=al/qwen3.7-flash            # fast research model
MODEL_REPORT=al/deepseek-v4-flash        # report + PoC model

# misc
HTTP_TIMEOUT=20
USER_AGENT=vuln-agent/1.0 (+security-research)
LLM_TIMEOUT=180
LLM_MAX_STEPS=12
```

### Optional

- **NVD API key** (free): `NVD_API_KEY=...` — raises NVD rate limit from 5→50 req/30s.
- **nuclei binary**: `install -m 755 -d /usr/local/bin && curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_..._linux_amd64.zip | ...` — enables the fast template path. Without it, the YAML→Python fallback is used.
- **Playwright** (for Wordfence threat-intel + Cloudflare-challenged pages): `pip install playwright && playwright install chromium`.

### Run

```bash
python3 bot.py
```

---

## Telegram commands

| Command | Description |
|---|---|
| `/scan <url>` | Background scan: detect stack → research → verify → report |
| `/jobs` | List running / interrupted scans |
| `/poc <scan_id> <CVE>` | Generate + verify a PoC for a CVE (`force` to regenerate) |
| `/chat <scan_id> [question]` | Persistent Q&A about a scan (`/end` to exit) |
| `/model [detect\|report <id>] [list\|reset]` | Switch AI models at runtime (from provider list) |
| `/monitor on\|off\|list\|check` | Vuln news listener (6h interval, ≤14-day-old CVEs) |
| `/report <scan_id>` | Re-send a saved report |
| `/history` | List your scans |
| `/sources` | List vulnerability sources |
| `/feedback <scan_id> good\|bad\|wrong [note]` | Rate a scan (feeds self-improvement) |
| `/knowledge` | Show lessons learned from prior scans |

| `/library stats` | Personal library counts, source coverage, conflicts, and stale records |
| `/library search <query>` | Full-text search over canonical private facts |
| `/library cve <CVE>` | Canonical fact, affected ranges, provenance, and references |
| `/library related <CVE\|query>` | Deterministic locally related vulnerability search |
| `/library target <host>` | User-owned target snapshots and scan drift |
| `/library evidence <CVE>` | User-scoped scan evidence and observations |
| `/library note <entity> <text>` | Attach a private note to an entity |
| `/library refresh [CVE]` | Refresh one or a bounded batch of stale records |
| `/library export` | Export personal facts/evidence/notes as JSONL |
| `/library verify` | SQLite integrity and orphan-reference checks |

---

## Testing

```bash
python3 -m pytest tests/ -q
```

The suite covers: version-range matching, CVSS parsing, EPSS/KEV enrichment, JSON extraction, report rendering/ranking, research fallback, nuclei codegen, probe cookies, DB writers, LLM timeout handling.

The private-library suite additionally covers canonical/source idempotency, provenance conflicts, FTS fallback, conceptual related retrieval, evidence ownership, target drift, notes, JSONL round-trips, refresh failure/success behavior, backups, and integrity checks.

---

## Security notes

- `.env` is git-ignored — the API key never leaves your host.
- PoC execution is a direct subprocess (`python3 <poc> --target <url> --check`) — no sandbox. Only run against targets you own.
- `--check` mode is non-destructive (harmless payloads, math-echo proof). `--exploit` mode (via `/poc` LLM agent) performs active exploitation — use with permission.
- Auth: only `ALLOWED_USER_IDS` can use the bot. Leaving it empty opens the bot to everyone.

---

## Disclaimer

This project is for authorized security testing and research. The authors are not responsible for misuse. Scanning or exploiting systems without permission is illegal in most jurisdictions.

## License

MIT — free to use, modify, and contribute. Open source.

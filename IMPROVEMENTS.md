# Improvements — risk-aware prioritization + test coverage

This round hardens the accuracy-critical core with tests and adds a real
prioritization capability so reports lead with what actually matters.

## New capabilities

### CVSS v3.1 engine — `scrapers/cvss.py`
- Spec-exact base-score computation from a `CVSS:3.1/...` vector (official FIRST.org
  formula incl. the `roundup` rule), scope-changed and scope-unchanged cases.
- Severity-band mapping (NONE/LOW/MEDIUM/HIGH/CRITICAL) and a tolerant
  `normalize_severity()` that canonicalizes messy source labels ("Important" -> HIGH,
  "sev:high" -> HIGH).
- `enrich(cvss, severity, vector)` reconciles partial source data into one
  `(score, severity)` pair. Verified against canonical FIRST.org scores.

### EPSS enrichment — `scrapers/epss.py`
- New `BaseScraper` that pulls the Exploit Prediction Scoring System probability
  (0..1, "will it be exploited in the next 30 days") from FIRST.org, batched.
- Registered in `scrapers/registry.py` as a pure enrichment source (never invents
  affected ranges, so it can't change a VULNERABLE/NOT_AFFECTED verdict).
- Wired into `run_verify` via `_enrich_epss()` — one batched call annotates every
  candidate with its real EPSS score before scoring. Live API verified (Log4Shell -> 0.99999).

### Deterministic risk scoring — `agent/scoring.py`
- `score_finding()` fuses signals into a 0-100 priority + coarse band:
  verified-on-target verdict (dominant), CISA-KEV/in-the-wild, EPSS, CVSS, PoC availability.
- `rank_findings()` sorts findings high-risk first.
- `run_report` now ranks the `exploitable` list by risk and the Telegram report surfaces
  a `RISK <band> <score>` tag plus `EPSS %` per finding.
- Key invariant (tested): a bug *proven exploitable on the target* outranks a
  higher-CVSS but unverified bug.

## Bug fixes
- `bot.py`: PoC menu / keyboard callbacks read `report.get("vulns")`, which the report
  schema never produces (it stores `exploitable`/`checked`). Added `_report_cves()` so the
  buttons actually list CVEs. Button label now tolerates both findings (`label`) and report
  (`verified`) shapes.
- `agent/runner.run_report`: the UNREACHABLE recommendation was computed and then
  immediately overwritten by `recommendation = ""` (dead code). Now short-circuits and
  keeps its message.

## Tests — `tests/` (new; repo had none)
Offline, deterministic, network/LLM/Telegram all stubbed. Run: `python3 -m pytest`.
- `test_version_match.py` — the version-range matching engine (accuracy-critical).
- `test_cvss.py` — CVSS base scores vs canonical FIRST.org values + severity normalization.
- `test_epss.py` — EPSS parser + scraper (stubbed HTTP).
- `test_scoring.py` — risk-scoring ordering invariants.
- `test_report.py` / `test_report_ranking.py` — report bucketing, UNREACHABLE regression,
  end-to-end risk ordering + rendered RISK band.
- `test_enrich_epss.py` — EPSS enrichment wiring + best-effort failure behavior.

88 tests, all passing.

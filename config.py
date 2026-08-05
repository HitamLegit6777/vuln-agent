"""Config: load .env, expose constants, whitelist check."""
from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    # override=True: .env wins over stale shell env vars (e.g. ROUTER_BASE left
    # from an old setup) — the file is the source of truth for this deployment
    load_dotenv(Path(__file__).parent / ".env", override=True)
except Exception:
    pass

ROOT = Path(__file__).parent
DATA = ROOT / "data"
POC = ROOT / "poc"
DATA.mkdir(exist_ok=True)
POC.mkdir(exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ALLOWED_USER_IDS = [
    int(x) for x in os.getenv("ALLOWED_USER_IDS", "").replace(" ", "").split(",") if x
]

ROUTER_BASE = os.getenv("ROUTER_BASE", "http://localhost:3000/v1")
ROUTER_KEY = os.getenv("ROUTER_KEY", "free")
MODEL_DETECT = os.getenv("MODEL_DETECT", "al/glm-5.2")      # detection / research / matching
MODEL_REPORT = os.getenv("MODEL_REPORT", "al/deepseek-v4-pro")  # report synthesis + PoC

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))
USER_AGENT = os.getenv("USER_AGENT", "vuln-agent/1.0 (+security-research)")

# NVD API key (free, https://nvd.nist.gov/developers/request-an-api-key) — raises rate limit
# 5->50 req/30s. Only helps where services.nvd.nist.gov is network-reachable.
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
# optional HTTPS proxy to reach NVD if your host is IP-blocked by NIST
HTTPS_PROXY = os.getenv("HTTPS_PROXY", "")

LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "180"))
LLM_MAX_STEPS = int(os.getenv("LLM_MAX_STEPS", "12"))


def allowed(user_id: int) -> bool:
    if not ALLOWED_USER_IDS:
        return True
    return int(user_id) in ALLOWED_USER_IDS


def assert_configured():
    if not TELEGRAM_BOT_TOKEN:
        print("ERROR: TELEGRAM_BOT_TOKEN not set in .env", file=sys.stderr)
        sys.exit(1)

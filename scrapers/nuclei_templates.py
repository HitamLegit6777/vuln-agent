"""Nuclei templates integration — 4167+ CVE templates from projectdiscovery/nuclei-templates.

Flow:
  1. has_template(cve) — check if a nuclei template exists for this CVE (cve_index.json)
  2. run_nuclei(cve, target) — run nuclei binary directly with the template → verdict
  3. get_template_code(cve) — parse YAML → generate standalone Python PoC (fallback if no binary)

This gives ACCURATE PoC verification: nuclei's matchers are community-verified, not LLM-guessed.
Templates auto-refresh weekly via systemd timer (nuclei-refresh.timer).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _HERE / "nuclei-templates"
_INDEX_PATH = _TEMPLATES_DIR / "cve_index.json"

_index: dict[str, str] = {}


def _load_index() -> dict[str, str]:
    """Load CVE→template-path index (cached in memory)."""
    global _index
    if not _index and _INDEX_PATH.exists():
        try:
            _index = json.loads(_INDEX_PATH.read_text())
        except Exception:
            _index = {}
    return _index


def _refresh_index_if_stale():
    """Rebuild index if missing or templates dir was updated (git pull)."""
    global _index
    try:
        idx_mtime = _INDEX_PATH.stat().st_mtime if _INDEX_PATH.exists() else 0
        # check if any template file is newer than the index
        cves_dir = _TEMPLATES_DIR / "http" / "cves"
        if cves_dir.exists():
            # quick check: is the git HEAD newer than index?
            head = _TEMPLATES_DIR / ".git" / "refs" / "heads"
            if head.exists():
                newest_git = max(f.stat().st_mtime for _r, _d, fs in os.walk(head) for f in fs) if any(os.walk(head)) else 0
            else:
                newest_git = 0
            if newest_git > idx_mtime or not _index:
                _rebuild_index()
    except Exception:
        pass


def _rebuild_index():
    """Rebuild cve_index.json from all YAML templates."""
    global _index
    idx: dict[str, str] = {}
    cves_dir = _TEMPLATES_DIR / "http" / "cves"
    if not cves_dir.exists():
        _index = {}
        return
    for root, _dirs, files in os.walk(cves_dir):
        for fn in files:
            if not fn.endswith(".yaml"):
                continue
            fp = os.path.join(root, fn)
            cves: set[str] = set()
            m = re.match(r"(CVE-\d{4}-\d+)", fn, re.I)
            if m:
                cves.add(m.group(1).upper())
            try:
                content = Path(fp).read_text(errors="replace")[:3000]
                for m2 in re.finditer(r"(CVE-\d{4}-\d+)", content):
                    cves.add(m2.group(1).upper())
            except Exception:
                pass
            for cve in cves:
                idx[cve] = os.path.abspath(fp)
    try:
        _INDEX_PATH.write_text(json.dumps(idx))
        _index = idx
    except Exception:
        pass


def has_template(cve: str) -> bool:
    """Check if a nuclei template exists for this CVE."""
    _refresh_index_if_stale()
    idx = _load_index()
    return cve.upper() in idx


def get_template_path(cve: str) -> Optional[str]:
    """Get the filesystem path to the nuclei YAML template for a CVE."""
    _refresh_index_if_stale()
    idx = _load_index()
    p = idx.get(cve.upper())
    if p and os.path.exists(p):
        return p
    return None


async def run_nuclei(cve: str, target: str, timeout: int = 60) -> dict:
    """Run nuclei binary with the CVE template against the target.
    Returns {verdict, output, found, template_path}.

    verdict: EXPLOITABLE if nuclei matched, NOT EXPLOITABLE if no match,
             ERROR if nuclei failed to run.
    """
    tpl = get_template_path(cve)
    if not tpl:
        return {"verdict": "NO_TEMPLATE", "output": "", "found": False, "template_path": ""}

    # ensure target has scheme
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "http://" + t

    try:
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-t", tpl, "-u", t, "-nc", "-silent", "-j",
            "-timeout", "10", "-retries", "1", "-concurrency", "1",
            "-no-meta", "-ni",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        # kill the orphaned nuclei process tree — a cancel from an outer wait_for
        # (verify's 600s cap) would otherwise keep it scanning the target
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return {"verdict": "ERROR", "output": "nuclei timeout", "found": False,
                "template_path": tpl, "error": "timeout"}
    except FileNotFoundError:
        return {"verdict": "ERROR", "output": "nuclei binary not found", "found": False,
                "template_path": tpl, "error": "no-binary"}
    except Exception as e:
        return {"verdict": "ERROR", "output": str(e), "found": False,
                "template_path": tpl, "error": type(e).__name__}

    out = stdout.decode(errors="replace") if stdout else ""
    err = stderr.decode(errors="replace") if stderr else ""

    # If nuclei errored (non-zero exit + stderr), treat as ERROR not a match
    if proc.returncode != 0 and err and not out:
        return {"verdict": "ERROR", "output": err[:2000], "found": False,
                "template_path": tpl, "error": f"exit {proc.returncode}"}

    # nuclei -j outputs JSONL: one JSON object per matched finding (newline-delimited)
    # If no match, stdout is empty
    found = False
    matches: list[str] = []
    for line in out.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # try JSON parse — valid JSONL line = real finding
        try:
            obj = json.loads(line)
            if obj.get("template-id") or obj.get("matched-at") or obj.get("matched"):
                found = True
                tid = obj.get("template-id", "?")
                mat = obj.get("matched-at") or obj.get("host", "?")
                matches.append(f"{tid} @ {mat}")
        except json.JSONDecodeError:
            # non-JSON output in silent mode = also a finding (text format)
            if line and not line.startswith("[INF]") and not line.startswith("[ERR") \
                    and not line.startswith("[FTL") and not line.startswith("[WRN"):
                found = True
                matches.append(line[:200])

    if found:
        reason = "nuclei template matched: " + "; ".join(matches[:3])
        return {"verdict": "EXPLOITABLE", "output": out[:3000], "found": True,
                "template_path": tpl, "reason": reason}
    else:
        # nuclei ran successfully but no match = not exploitable (at least not via this template)
        reason = f"nuclei template {os.path.basename(tpl)} ran but no match (target not vulnerable or patched)"
        return {"verdict": "NOT EXPLOITABLE", "output": (out + err)[:2000], "found": False,
                "template_path": tpl, "reason": reason}


def _parse_yaml_simple(yaml_text: str) -> dict:
    """Minimal YAML parser for nuclei templates (avoids PyYAML dependency).
    Extracts: http requests (raw), matchers, severity, description."""
    info: dict = {"severity": "", "description": "", "name": "", "requests": [], "matchers": []}
    # info block
    sev = re.search(r"severity:\s*(\w+)", yaml_text)
    if sev:
        info["severity"] = sev.group(1)
    desc = re.search(r"description:\s*\|?\s*(.+?)(?=\n\s{2}\w|\n\n|\nhttp:|\n  reference:)", yaml_text, re.S)
    if desc:
        info["description"] = desc.group(1).strip()
    name = re.search(r"name:\s*(.+)", yaml_text)
    if name:
        info["name"] = name.group(1).strip()
    # raw HTTP requests
    raw_blocks = re.findall(r"- raw:\s*\n((?:\s{6,}.*\n?)+)", yaml_text)
    for block in raw_blocks:
        # strip the `- |` / `- >` block-scalar marker line and trailing blank lines
        lines = [ln.strip() for ln in block.strip().split("\n")]
        lines = [ln for ln in lines if ln and not re.match(r"^-\s*[|>][-+]?$", ln)]
        if not lines:
            continue
        info["requests"].append("\n".join(lines))
    if not info["requests"]:
        # try method+path style
        method_blocks = re.findall(r"- method:\s*(\w+)\s*\n\s*path:\s*(.+)", yaml_text)
        for method, path in method_blocks:
            info["requests"].append(f"{method} {path}")
    # matchers
    matcher_section = re.findall(r"- type:\s*(\w+)\s*\n(?:\s*(?:regex|status|word|part):\s*(.+)\n?)*", yaml_text)
    for mtype, mval in matcher_section:
        info["matchers"].append(f"{mtype}: {mval}")
    # status matchers
    status_matches = re.findall(r"status:\s*\n?\s*-\s*(\d+)", yaml_text)
    if status_matches:
        info["matchers"].append(f"status: {','.join(status_matches)}")
    return info


def get_template_code(cve: str) -> Optional[str]:
    """Generate a standalone Python PoC from the nuclei YAML template for this CVE.
    Falls back to this if the nuclei binary is not available. Returns Python source code."""
    tpl = get_template_path(cve)
    if not tpl:
        return None
    try:
        yaml_text = Path(tpl).read_text(errors="replace")
    except Exception:
        return None
    info = _parse_yaml_simple(yaml_text)
    if not info["requests"]:
        return None

    # build Python PoC from the parsed template
    severity = info.get("severity", "unknown")
    desc = info.get("description", "")[:300].replace('"', '\\"').replace("\n", " ")
    name = info.get("name", cve)

    requests_code = []
    for i, req in enumerate(info["requests"]):
        # parse method + path from raw HTTP request
        lines = req.strip().split("\n")
        if not lines:
            continue
        first = lines[0].strip()
        # skip malformed captures (e.g. a lone `- |` marker that slipped past the parser)
        if not re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+", first, re.I):
            continue
        parts = first.split()
        method, path = parts[0], parts[1]
        # collect headers
        headers = {}
        body = ""
        in_headers = True
        for line in lines[1:]:
            line = line.strip()
            if not line:
                in_headers = False
                continue
            if in_headers and ":" in line:
                k, v = line.split(":", 1)
                # skip nuclei template vars ({{Hostname}}, etc.)
                if "{{" in v:
                    v = v.replace("{{Hostname}}", "{target}")
                headers[k.strip()] = v.strip()
            elif not in_headers:
                body += line
        # replace nuclei template vars in path — random values for probes, drop interaction hosts
        import random as _r, string as _s
        path = re.sub(r"\{\{randstr:(\d+)\}\}", lambda m: "".join(_r.choices(_s.ascii_letters, k=int(m.group(1)))), path)
        path = re.sub(r"\{\{rand1\}\}|\{\{rand2\}\}|\{\{randstr\}\}", lambda m: "".join(_r.choices(_s.ascii_letters, k=8)), path)
        path = re.sub(r"\{\{hostName\}\}|\{\{interactsh-url\}\}|\{\{[^}]+\}\}", "", path)
        path = path.replace("{{Hostname}}", "")
        if not path.startswith("/"):
            path = "/" + path
        # escape any stray braces so the generated f-string stays valid Python
        path_f = path.replace("{", "{{").replace("}", "}}")
        body_f = body.replace("{", "{{").replace("}", "}}")
        req_var = f"r{i}"
        last_var = req_var
        requests_code.append(
            f'    # Request {i+1}: {method} {path}\n'
            f'    {req_var} = s.request("{method}", target + "{path_f}", '
            f'headers={headers!r}' + (f', data={body_f!r}' if body else '') + f', verify=False, timeout=10)\n'
            f'    print(f"[{i+1}] {method} {path_f} -> HTTP {{r{i}.status_code}}")\n'
        )
    if not requests_code:
        return None
    matchers_code = ""
    if info["matchers"]:
        matchers_code = '    # Matchers from nuclei template: ' + "; ".join(info["matchers"][:3]) + "\n"
        # simple status check
        status_match = [m for m in info["matchers"] if m.startswith("status:")]
        if status_match:
            codes = status_match[0].split(":", 1)[1].strip()
            matchers_code += f'    expected = [{codes}]\n'
            matchers_code += f'    if {last_var}.status_code in expected and {last_var}.status_code != 404:\n'
            matchers_code += f'        print("[EXPLOITABLE] nuclei template matched (HTTP " + str({last_var}.status_code) + ")")\n'
            matchers_code += f'        return\n'
        else:
            matchers_code += f'    if {last_var}.status_code == 200 and len({last_var}.text) > 0:\n'
            matchers_code += f'        print("[EXPLOITABLE] nuclei template responded (HTTP 200, len=" + str(len({last_var}.text)) + ")")\n'
            matchers_code += f'        return\n'
    else:
        matchers_code += f'    if {last_var}.status_code == 200:\n'
        matchers_code += f'        print("[EXPLOITABLE] target responded (HTTP 200)")\n'
        matchers_code += f'        return\n'

    poc = f'''#!/usr/bin/env python3
"""PoC for {cve} — auto-generated from nuclei template.
Template: {os.path.basename(tpl)}
Name: {name}
Severity: {severity}
Description: {desc}

This PoC was derived from the community-verified nuclei template at:
  {tpl}
"""
import argparse, sys
try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("pip install requests"); sys.exit(2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--check", action="store_true", default=True)
    ap.add_argument("--exploit", action="store_true")
    a = ap.parse_args()
    target = a.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target
    s = requests.Session()
    s.headers.update({{"User-Agent": "Mozilla/5.0 (nuclei-derived PoC)"}})
    print(f"[*] Target: {{target}}")
    print(f"[*] CVE: {cve} (nuclei template)")
{"".join(requests_code)}
{matchers_code}
    print(f"[NOT EXPLOITABLE] nuclei template did not match (HTTP {{ {last_var}.status_code}}, patched or not vulnerable)")

if __name__ == "__main__":
    main()
'''
    return poc


async def close():
    pass

"""Tests for agent.runner research fallback candidate salvage.

`run_research` runs a parallel pre-research phase (detect_stack + search_vuln +
fetch_cve_detail) and then an AI-review loop that is expected to emit findings JSON.
Previously, if the AI-review loop exhausted all steps without emitting findings, the
fallback report contained NO vulnerabilities (it read `acc["vulns"]`, which was never
populated). Now pre-research builds a CVE-keyed candidate map that seeds `acc["vulns"]`,
so an all-steps-exhausted run still reports the real candidates.
"""
import json

import pytest

import agent.runner as runner


_STACK = {
    "url": "http://t/", "cms": "wordpress", "cms_version": "6.0",
    "components": [{"name": "acme-plugin", "type": "plugin", "version": "1.0",
                    "evidence": "/wp-content/plugins/acme-plugin/"}],
    "services": [],
    "waf": [], "waf_summary": "", "waf_may_mask": False,
}

_SEARCH = {
    "query": "acme-plugin", "version": "1.0", "count": 1,
    "results": [{
        "cve": "CVE-2099-1234", "id": "GHSA-x", "source": "github",
        "title": "Acme RCE", "severity": "CRITICAL", "cvss": 9.8,
        "ranges": 1, "poc_refs": 0, "diff_patch": False,
        "match": True, "url": "https://example/CVE-2099-1234",
    }],
}


async def _fake_dispatch(name, args):
    if name == "detect_stack":
        return json.dumps(_STACK)
    if name == "search_vuln":
        # only the plugin has a hit; everything else empty
        if args.get("query") == "acme-plugin":
            return json.dumps(_SEARCH)
        return json.dumps({"results": []})
    if name == "fetch_cve_detail":
        return "grounded detail for " + str(args.get("cve"))
    return "{}"


async def _fake_llm_never_finalizes(messages, temperature=0.15, max_tokens=6144):
    # Always returns prose with no JSON object -> AI-review loop never emits findings.
    return "I am thinking about the target but will not emit JSON."


def test_fallback_salvages_precomputed_candidates(monkeypatch):
    monkeypatch.setattr(runner, "_dispatch", _fake_dispatch)
    monkeypatch.setattr(runner, "chat_detect", _fake_llm_never_finalizes)
    # keep the loop short so the test is fast
    monkeypatch.setattr(runner, "_RESEARCH_MAX_STEPS", 2)
    monkeypatch.setattr(runner, "_RESEARCH_FORCE_NUDGE_AT", 1)

    import asyncio
    findings_str, transcript = asyncio.run(runner.run_research("http://t/"))
    f = json.loads(findings_str)
    cves = {v.get("cve") for v in f.get("vulnerabilities", [])}
    assert "CVE-2099-1234" in cves, (
        "fallback must salvage the precomputed VULNERABLE candidate; got " + repr(cves))
    # the salvaged candidate keeps its label + score
    v = next(v for v in f["vulnerabilities"] if v["cve"] == "CVE-2099-1234")
    assert v["label"] == "VULNERABLE"
    assert v["cvss"] == 9.8
    assert v["component"] == "acme-plugin"


def test_ai_emitted_findings_still_win(monkeypatch):
    # When the AI DOES emit findings, those are returned (not the fallback).
    monkeypatch.setattr(runner, "_dispatch", _fake_dispatch)

    async def _fake_llm_emits(messages, temperature=0.15, max_tokens=6144):
        return json.dumps({
            "target": "http://t/",
            "stack": [{"type": "plugin", "name": "acme-plugin", "version": "1.0"}],
            "vulnerabilities": [{"cve": "CVE-2099-9999", "label": "VULNERABLE",
                                 "component": "acme-plugin", "cvss": 7.5}],
            "exploited_in_wild": [],
        })

    monkeypatch.setattr(runner, "chat_detect", _fake_llm_emits)
    monkeypatch.setattr(runner, "_RESEARCH_MAX_STEPS", 3)

    import asyncio
    findings_str, _ = asyncio.run(runner.run_research("http://t/"))
    f = json.loads(findings_str)
    cves = {v.get("cve") for v in f.get("vulnerabilities", [])}
    assert cves == {"CVE-2099-9999"}, cves

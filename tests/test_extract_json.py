"""Tests for LLM-response JSON extraction in agent/runner.py.

_extract_json is on the hot path of every ReAct turn: a tool call or the findings object
must be recovered from messy model output (fences, reasoning prose, trailing text, braces
inside strings). These lock in the shapes seen from real reasoning models.
"""
from __future__ import annotations

from agent import runner


def test_bare_object():
    assert runner._extract_json('{"tool": "detect_stack", "args": {"url": "x"}}') == {
        "tool": "detect_stack", "args": {"url": "x"}}


def test_fenced_json_block():
    text = '```json\n{"tool": "search_vuln", "args": {"query": "joomla"}}\n```'
    assert runner._extract_json(text) == {
        "tool": "search_vuln", "args": {"query": "joomla"}}


def test_fenced_without_lang():
    text = '```\n{"a": 1}\n```'
    assert runner._extract_json(text) == {"a": 1}


def test_object_followed_by_prose():
    # reasoning models often append explanation after the JSON
    text = '{"tool": "webfetch", "args": {"url": "y"}}\n\nI will fetch that page now.'
    assert runner._extract_json(text) == {"tool": "webfetch", "args": {"url": "y"}}


def test_prose_before_object():
    text = 'Here is the tool call you asked for:\n{"tool": "version_match", "args": {}}'
    assert runner._extract_json(text) == {"tool": "version_match", "args": {}}


def test_nested_objects_balanced():
    text = '{"stack": [{"name": "wp", "meta": {"a": {"b": 1}}}], "vulnerabilities": []}'
    obj = runner._extract_json(text)
    assert obj["stack"][0]["meta"]["a"]["b"] == 1


def test_braces_inside_string_value():
    # a regex/payload containing { } must not break brace balancing
    text = '{"reason": "matched pattern a{2,3} in body {not json}", "verdict": "ok"}'
    obj = runner._extract_json(text)
    assert obj["verdict"] == "ok"
    assert "a{2,3}" in obj["reason"]


def test_escaped_quotes_in_string():
    text = r'{"msg": "he said \"hi\" and left", "n": 2}'
    obj = runner._extract_json(text)
    assert obj["n"] == 2
    assert 'said' in obj["msg"]


def test_first_object_wins_for_tool_call():
    # ReAct = one tool call per turn; the first complete object is the actionable one
    text = '{"tool": "detect_stack", "args": {"url": "z"}}\nlater: {"final": {"verdict": "x"}}'
    assert runner._extract_json(text)["tool"] == "detect_stack"


def test_findings_object_with_newlines_in_strings():
    text = '{"summary": "line one\\nline two", "vulnerabilities": []}'
    obj = runner._extract_json(text)
    assert "\n" in obj["summary"]


def test_returns_none_for_no_json():
    assert runner._extract_json("just some prose, no braces here") is None
    assert runner._extract_json("") is None
    assert runner._extract_json(None) is None


def test_ignores_unbalanced_leading_brace():
    # a stray '{' then a valid object later should still recover the valid object
    text = 'oops { not valid ... then the real one: {"ok": true}'
    assert runner._extract_json(text) == {"ok": True}


def test_non_dict_json_is_rejected():
    # a top-level array is not a tool call / findings object
    assert runner._extract_json('[1, 2, 3]') is None

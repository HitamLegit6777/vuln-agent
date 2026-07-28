"""Regression tests for scrapers.nuclei_templates PoC code generation.

The generator builds a standalone Python PoC from a nuclei YAML template's raw
HTTP requests + matchers. A past bug emitted `f"[{i+1}] ..."` into the *generated*
source, where `i` (the generation-time loop var) does not exist at run time -> the
generated PoC crashed with NameError before issuing any request. These tests pin the
contract: generated code must (1) compile and (2) contain no runtime `{i...}` ref,
and the request index must be baked in as a literal.
"""
import re

from scrapers import nuclei_templates as nt


def _sample_yaml() -> str:
    # Minimal but realistic nuclei template with a raw HTTP request + status matcher.
    return (
        "id: CVE-2099-0001\n"
        "info:\n"
        "  name: Example RCE\n"
        "  severity: critical\n"
        "  description: Example vulnerability for codegen tests.\n"
        "http:\n"
        "  - raw:\n"
        "      - |\n"
        "        GET /admin/config.php HTTP/1.1\n"
        "        Host: {{Hostname}}\n"
        "        User-Agent: test\n"
        "    matchers:\n"
        "      - type: status\n"
        "        status:\n"
        "          - 200\n"
    )


def _gen_from_yaml(monkeypatch, yaml_text: str, cve: str = "CVE-2099-0001") -> str:
    # Point the generator at an in-memory template without touching the real index.
    monkeypatch.setattr(nt, "get_template_path", lambda c: "/tmp/fake.yaml")
    monkeypatch.setattr(nt.Path, "read_text", lambda self, *a, **k: yaml_text)
    return nt.get_template_code(cve)


def test_generated_poc_compiles(monkeypatch):
    code = _gen_from_yaml(monkeypatch, _sample_yaml())
    assert code, "generator returned no code for a template with a raw request"
    # Must be syntactically valid Python.
    compile(code, "<generated-poc>", "exec")


def test_generated_poc_has_no_runtime_loopvar(monkeypatch):
    code = _gen_from_yaml(monkeypatch, _sample_yaml())
    # The bug: literal `{i+1}` / `{i}` (not `{{...}}`) leaking into the emitted f-string.
    # After the fix the request number is baked in as a literal like `[1]`.
    assert "{i+1}" not in code, "generated PoC references undefined runtime var i (NameError)"
    # a bare {i} would also be a runtime NameError; ensure none survive
    assert not re.search(r"(?<!\{)\{i\}", code), "generated PoC has a runtime {i} reference"
    assert re.search(r"\[1\]", code), "request index should be baked in as a literal [1]"


def test_generated_poc_runs_without_nameerror(monkeypatch, tmp_path):
    """Execute the generated module body; a closed-port target must yield a network
    error, never a NameError from a leaked generation-time variable."""
    code = _gen_from_yaml(monkeypatch, _sample_yaml())
    ns: dict = {}
    exec(compile(code, "<generated-poc>", "exec"), ns)
    assert "main" in ns
    import sys
    argv = sys.argv
    sys.argv = ["poc", "--target", "http://127.0.0.1:9/"]
    try:
        ns["main"]()
    except NameError as e:  # the exact class of bug we are guarding against
        raise AssertionError(f"generated PoC raised NameError at runtime: {e}")
    except SystemExit:
        pass
    except Exception:
        # Any network/requests error is acceptable — we only forbid NameError.
        pass
    finally:
        sys.argv = argv

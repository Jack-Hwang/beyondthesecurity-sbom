"""Arch Intel pipeline units (arch_intel.py): entry points, license verdict + notice checklist + compatibility,
the metadata-only prompt invariant, the four validation layers, the deterministic fallback, deterministic Mermaid
generation, bounded snippets and the syntax highlighter. All fixtures are tiny trees built in tmp_path; no network."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom_app import arch
from bts_sbom_app import arch_intel

GPL3 = ("GNU GENERAL PUBLIC LICENSE\nVersion 3, 19 June 2007\n\n"
        "Everyone is permitted to copy and distribute verbatim copies of this license document.\n")
AGPL3 = ("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n\n"
         "Everyone is permitted to copy and distribute verbatim copies of this license document.\n")
BODY = "SECRET_BODY_MARKER_9137"
PKG_JSON = json.dumps({"name": "fixture", "version": "1.0.0", "main": "lib/entry.js", "bin": {"tool": "bin/tool.js"}})


def make_arch_repo(root, lic_text=GPL3):
    """A tiny tree with exactly 5 entry-point kinds and 2 import edges; no package.json scripts.start (that would
    add a 6th npm-start entry - AC BSA-AC-443 wants a 1:1 fixture)."""
    files = {
        "LICENSE": lic_text,
        "app/__init__.py": "",
        "app/__main__.py": "from app import main\n\nmain.run()\n",
        "app/main.py": "from app import service\n\n\ndef run():\n    return service.handle(%s)\n" % BODY,
        "app/service.py": "def handle(x):\n    data = %s\n    return data.upper()\n" % BODY,
        "scripts/cli.py": "from app import service\n\nif __name__ == '__main__':\n    print(service.handle('x'))\n",
        "package.json": PKG_JSON,
        "lib/entry.js": "const tool = require('../bin/tool.js');\nmodule.exports = tool;\n",
        "bin/tool.js": "module.exports = function tool(x) { return x; };\n",
        "cmd/server/main.go": "package main\n\nfunc main() {\n    println(\"server\")\n}\n",
    }
    for rel, txt in files.items():
        fp = os.path.join(root, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(txt)
    return root


@pytest.fixture
def repo(tmp_path):
    return make_arch_repo(str(tmp_path / "repo"))


# ------------------------------------------------------------------- AC: BSA-AC-443
def test_entry_points_detect_exactly_the_five_kinds(repo):
    """AC: BSA-AC-443"""
    files = arch.collect_files(repo, 4000)
    entries = arch_intel.entry_points(repo, files)
    got = {(e["path"], e["kind"]) for e in entries}
    assert len(entries) == 5
    assert ("app/__main__.py", "python-main") in got
    assert ("scripts/cli.py", "python-entry") in got
    assert ("lib/entry.js", "npm-main") in got
    assert ("bin/tool.js", "npm-bin") in got
    assert ("cmd/server/main.go", "go-main") in got
    assert all(k in {k for _, k in got} for k in ("python-main", "python-entry", "npm-main", "npm-bin", "go-main"))


# ------------------------------------------------------------------- AC: BSA-AC-444
def test_license_verdict_gpl3_is_strong_copyleft_with_a_checklist(repo):
    """AC: BSA-AC-444"""
    lic = arch_intel.license_verdict(repo)
    assert lic["project_license"] == "GPL-3.0-only"
    assert lic["category"] == "strong-copyleft"
    assert len(lic["notice"]["checklist"]) >= 3


# ------------------------------------------------------------------- AC: BSA-AC-445
def test_license_verdict_agpl3_flags_the_network_clause(tmp_path):
    """AC: BSA-AC-445"""
    lic = arch_intel.license_verdict(make_arch_repo(str(tmp_path / "agpl"), AGPL3))
    assert lic["category"] == "network-copyleft"
    assert lic["notice"]["network_clause"] is True
    assert any("13" in str(c.get("clause")) for c in lic["notice"]["checklist"])
    assert len(lic["notice"]["verdicts"]) == 3


# ------------------------------------------------------------------- AC: BSA-AC-446
def test_compat_matrix_returns_six_rows_with_closed_set_statuses(repo):
    """AC: BSA-AC-446"""
    lic = arch_intel.license_verdict(repo)
    rows = lic["compat"]["rows"]
    assert len(rows) == 6
    assert all(r["status"] in ("compatible", "conditional", "incompatible", "unknown") for r in rows)
    own = next(r for r in rows if r["your"] == "GPL-3.0-only")
    assert own["status"] == "compatible"


# ------------------------------------------------------------------- AC: BSA-AC-447
def test_prompt_evidence_carries_metadata_only(repo):
    """AC: BSA-AC-447"""
    lic = arch_intel.license_verdict(repo)
    st = arch_intel.structure(repo)
    ev = arch_intel.prompt_evidence("fixture", lic, st)
    blob = json.dumps(ev, ensure_ascii=False)
    assert blob.count(BODY) == 0
    assert blob.count("app/service.py") >= 1


# ------------------------------------------------------------------- AC: BSA-AC-448
def test_validate_arch_drops_a_component_with_an_invented_file():
    """AC: BSA-AC-448"""
    obj = {"overview": "ok", "components": [{"name": "Ghost", "role": "invented", "files": ["ghost/ghost.py"]},
                                            {"name": "Real", "role": "grounded", "files": ["app/service.py"]}],
           "scenarios": [], "activity": [], "license_note": ""}
    analysis, dropped = arch_intel.validate_arch(obj, {"app/service.py"}, set())
    assert dropped["semantic"] == 1
    assert [c["name"] for c in analysis["components"]] == ["Real"]


# ------------------------------------------------------------------- AC: BSA-AC-449
def test_validate_arch_drops_code_fences_into_the_rule_bucket():
    """AC: BSA-AC-449"""
    obj = {"overview": "ok", "components": [{"name": "Echo", "role": "```python\ndef x():\n    return 1\n```",
                                             "files": ["app/service.py"]}],
           "scenarios": [{"name": "Fenced", "description": "", "participants": ["Real"],
                          "steps": [{"actor": "User", "action": "```js\nfn()", "target": "app/service.py"}]}],
           "activity": [], "license_note": ""}
    analysis, dropped = arch_intel.validate_arch(obj, {"app/service.py"}, {"app/service.py"})
    assert dropped["rule"] == 1                                        # the fenced component role
    assert dropped["schema"] == 0
    assert [c["name"] for c in analysis["components"]] == []
    assert analysis["scenarios"] == []                                 # its only step carried a fence too


# ------------------------------------------------------------------- AC: BSA-AC-450
def test_propose_arch_without_a_client_returns_honest_deterministic(repo):
    """AC: BSA-AC-450"""
    lic = arch_intel.license_verdict(repo)
    st = arch_intel.structure(repo)
    ev = arch_intel.prompt_evidence("fixture", lic, st)
    res = arch_intel.propose_arch(ev, client=None, cache_dir=None, use_llm=True, lang="ko")
    assert res["source"] == "deterministic"
    assert "no LLM client configured" in res["llm_note"]
    a = res["analysis"]
    assert len(a["components"]) >= 1
    assert len(a["scenarios"]) == 1 and a["scenarios"][0]["inferred"] is True
    assert len(a["activity"]) == 0                                     # activity flows are never invented


# ------------------------------------------------------------------- AC: BSA-AC-451
def test_sequence_uses_a_return_arrow_for_user_and_labels_are_sanitized():
    """AC: BSA-AC-451"""
    scen = {"name": "t", "participants": ["User", "app/__main__.py"],
            "steps": [{"actor": "app/__main__.py", "action": "answer", "target": "User"}]}
    src = arch_intel.mermaid_sequence(scen)
    assert src.count("-->>") == 1
    assert arch_intel.mermaid_label('a"b\nc;d-->e') == "a'b c,d--)e"
    hostile = arch_intel.mermaid_label('x"y\nz;w-->v')
    assert '"' not in hostile and "\n" not in hostile and ";" not in hostile and "-->" not in hostile and ">" not in hostile


# ------------------------------------------------------------------- AC: BSA-AC-452
def test_code_snippets_are_bounded_and_anchor_centred(tmp_path):
    """AC: BSA-AC-452"""
    lines = ["line %d" % i for i in range(1, 201)]
    lines[99] = "ANCHOR_HERE = True"
    p = tmp_path / "big.py"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    key = [{"path": "big.py", "role": "hotspot (9 commits)", "anchors": [r"ANCHOR_HERE"]}]
    out = arch_intel.code_snippets(str(tmp_path), key)
    assert len(out) == 1
    item = out[0]
    assert item["end_line"] - item["start_line"] + 1 <= arch_intel.SNIPPET_MAX_LINES
    assert item["start_line"] <= 100 <= item["end_line"]
    assert item["truncated"] is True


# ------------------------------------------------------------------- AC: BSA-AC-453
def test_highlight_wraps_exactly_four_tokens_escapes_html_and_ignores_unknown_languages():
    """AC: BSA-AC-453"""
    code = 'def f():  # keep\nx = "str" + 42\n<script>alert(x)</script>\n'
    html = arch_intel.highlight(code, "py")
    assert html.count('<span class="tok-kw">') == 1                     # def
    assert html.count('<span class="tok-str">') == 1                    # "str"
    assert html.count('<span class="tok-com">') == 1                    # # keep
    assert html.count('<span class="tok-num">') == 1                    # 42
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "tok-" not in arch_intel.highlight(code, "brainfuck")

"""Portfolio export (BSA-AC-388..391) and proof evidence sidecar (BSA-AC-392..397).

``export`` collects the week-7 portfolio package (8 kinds) *from the project's own canonical files* into a
manifest of relative path + size + sha256 - it never writes new content for a kind, and a kind whose files do
not exist is reported ``missing`` rather than invented. Kinds 7 (demo video) and 8 (individual contribution
write-up) can only be produced by a person, so they are always reported ``human_required`` with a checklist.

``proof`` runs the project's own gates (pytest / speclint / doclint when present / evalrag) through an
injectable runner and classifies each PASS / FAIL / NOT RUN. A command that could not be run (missing module,
timeout, not found) is NOT RUN, never PASS - "an unrun check is not a passed check" is the whole point of the
product's honesty contract, and this is where that contract is tested on the tool itself.
"""
from __future__ import annotations

import glob as globmod
import hashlib
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import speclint, traceability
from .util import run as run_cmd
from .util import stamp, write_json

# Each pattern is matched with glob(..., recursive=True) relative to the project root; "**" patterns expand to
# every matching file, a plain path is a single expected file. Either way, a pattern with 0 matches is reported
# as one "missing" item for that pattern - nothing is fabricated.
PACKAGE_DEFS: List[Dict[str, Any]] = [
    {"n": 1, "name": "README", "globs": ["README.md"]},
    {"n": 2, "name": "SDD canonical (specs, ADRs, design docs)",
     "globs": ["specs/bts_sbom_app_features.md", "docs/adr/*.md", "docs/ARCHITECTURE.md", "docs/WORKFLOW.md"]},
    {"n": 3, "name": "Source, infra and harness",
     "globs": ["bts_sbom/**/*.py", "bts_sbom_app/**/*.py", "bts_sbom_app/web/**/*.js", "Dockerfile.bts-sbom-app",
               ".github/workflows/*.yml", "tools/**/*.py"]},
    {"n": 4, "name": "Evaluation reports",
     "globs": ["evals/*.json", "docs/LOOP_LOG.md", "evidence/loop/history.json", "evidence/loop/rag_history.json"]},
    {"n": 5, "name": "Operational evidence",
     "globs": ["docs/RUNBOOK.md", "tests/bts_sbom_app/test_server_cli.py"],
     "note": "this product is a localhost, no-auth tool: there is no deployed URL; operational evidence is local "
             "health/readiness checks and the tests that exercise them, not a hosted endpoint"},
    {"n": 6, "name": "Governance", "globs": ["docs/governance/*.md", "docs/ENFORCEMENT_MAP.md"]},
    {"n": 7, "name": "Demo video", "human_required": True,
     "checklist": ["record a short screen capture of a real run (scan, then a patch approval or a VEX decision)",
                   "upload it and link it from the submission (this tool does not host video)"]},
    {"n": 8, "name": "Individual contribution report and retrospective", "human_required": True,
     "checklist": ["write, in your own words, what you built, tested and decided",
                   "note what you would do differently with more time (a measurement, not a feeling)"]},
]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _inside_root(root: str, path: str) -> bool:
    """True only for a regular file (not a symlink) whose real path stays under ``root``: a manifest of the project's own files must
    not fingerprint a file elsewhere on the machine through a planted link or a ``..`` pattern."""
    if os.path.islink(path):
        return False
    base = os.path.realpath(root)
    real = os.path.realpath(path)
    return real.startswith(base + os.sep)


def _expand(root: str, pattern: str) -> List[str]:
    pat = os.path.join(root, *pattern.split("/"))
    matches = [m for m in globmod.glob(pat, recursive=True)
               if os.path.isfile(m) and "__pycache__" not in m.split(os.sep) and _inside_root(root, m)]
    return sorted(matches)


def _items(root: str, patterns: List[str]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for pat in patterns:
        matches = _expand(root, pat)
        if matches:
            for m in matches:
                rel = os.path.relpath(m, root).replace(os.sep, "/")
                items.append({"path": rel, "status": "found", "size": os.path.getsize(m), "sha256": _sha256_file(m)})
        else:
            items.append({"path": pat, "status": "missing", "size": None, "sha256": None})
    return items


def _build_package(root: str, pdef: Dict[str, Any]) -> Dict[str, Any]:
    if pdef.get("human_required"):
        return {"n": pdef["n"], "name": pdef["name"], "status": "human_required", "checklist": list(pdef["checklist"])}
    items = _items(root, pdef["globs"])
    found = sum(1 for it in items if it["status"] == "found")
    missing = len(items) - found
    status = "found" if missing == 0 and found > 0 else ("missing" if found == 0 else "partial")
    pkg: Dict[str, Any] = {"n": pdef["n"], "name": pdef["name"], "status": status, "found": found, "missing": missing, "items": items}
    if pdef.get("note"):
        pkg["note"] = pdef["note"]
    return pkg


def _self_assessment(root: str) -> Dict[str, Any]:
    """Measured evidence only - no rubric score is computed. Judgment-type rows are left ``human_review``."""
    try:
        tr = traceability.build(root)
        ac_count: Optional[int] = tr["summary"]["ac_count"]
        untested: Optional[int] = len(tr["summary"]["untested_acs"])
    except ValueError:
        ac_count = untested = None
    spec_path = os.path.join(root, traceability.SPEC_REL)
    lint_problems: Optional[int] = len(speclint.lint(spec_path)) if os.path.isfile(spec_path) else None
    tests_dir = os.path.join(root, traceability.TESTS_REL)
    test_files = len(globmod.glob(os.path.join(tests_dir, "test_*.py"))) if os.path.isdir(tests_dir) else None
    return {
        "measured": {
            "ac_count": ac_count,
            "untested_ac_count": untested,
            "test_file_count": test_files,
            "speclint_problem_count": lint_problems,
        },
        "judgment": {
            "design_rationale_quality": "human_review",
            "documentation_clarity": "human_review",
            "contribution_originality": "human_review",
        },
    }


def _render_readme(manifest: Dict[str, Any]) -> str:
    L: List[str] = ["# Portfolio package", "",
                     "Every path below is a pointer into this project's own files (path, size, sha256) - nothing is copied "
                     "or rewritten, and a missing original is reported `missing`, not invented.", "",
                     "| # | package | status | found | missing |", "|---|---|---|---|---|"]
    for p in manifest["packages"]:
        if p["status"] == "human_required":
            L.append("| %d | %s | human_required | - | - |" % (p["n"], p["name"]))
        else:
            L.append("| %d | %s | %s | %d | %d |" % (p["n"], p["name"], p["status"], p["found"], p["missing"]))
    L += ["", "## Self-assessment (measured rows only; judgment rows are `human_review`)", ""]
    sa = manifest["self_assessment"]
    for k, v in sa["measured"].items():
        L.append("- %s: %s" % (k, v))
    for k, v in sa["judgment"].items():
        L.append("- %s: %s" % (k, v))
    L += ["", "## Needs a human (packages 7 and 8)", ""]
    for p in manifest["packages"]:
        if p.get("checklist"):
            L.append("### %d. %s" % (p["n"], p["name"]))
            for item in p["checklist"]:
                L.append("- [ ] " + item)
            L.append("")
    return "\n".join(L) + "\n"


def export(root: str, out_dir: str) -> Dict[str, Any]:
    manifest = {
        "note": "paths, sizes and sha256 hashes only - file contents are not copied and originals are not modified",
        "packages": [_build_package(root, pdef) for pdef in PACKAGE_DEFS],
        "self_assessment": _self_assessment(root),
    }
    write_json(os.path.join(out_dir, "portfolio-manifest.json"), manifest)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_render_readme(manifest))
    return manifest


# --------------------------------------------------------------------------------------- proof (evidence sidecar)
Runner = Callable[[List[str], Optional[str], float], Tuple[int, str, str]]


def _commands() -> List[Dict[str, Any]]:
    py = sys.executable or "python"
    return [
        {"name": "pytest", "cmd": [py, "-X", "utf8", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/bts_sbom_app"]},
        {"name": "speclint", "cmd": [py, "-X", "utf8", "-m", "bts_sbom_app.speclint"]},
        {"name": "doclint", "cmd": [py, "-X", "utf8", "-m", "bts_sbom_app.doclint"]},
        {"name": "evalrag", "cmd": [py, "-X", "utf8", "-m", "bts_sbom_app.cli", "evalrag"]},
    ]


def _classify(rc: Optional[int]) -> Tuple[str, str]:
    if rc is None:
        return "NOT RUN", "module not found"
    if rc == 0:
        return "PASS", ""
    if rc == 124:
        return "NOT RUN", "timeout"
    if rc == 127:
        return "NOT RUN", "command not found"
    return "FAIL", "exit code %d" % rc


def _proof_run_path(out_dir: str) -> str:
    runs_dir = os.path.join(out_dir, "proof-runs")
    os.makedirs(runs_dir, exist_ok=True)
    ts = stamp()
    path = os.path.join(runs_dir, ts + ".json")
    n = 1
    while os.path.exists(path):                  # two runs in the same UTC second: do not clobber either
        path = os.path.join(runs_dir, "%s-%d.json" % (ts, n))
        n += 1
    return path


def proof(root: str, runner: Optional[Runner] = None, out_dir: Optional[str] = None, only: Optional[str] = None,
          timeout: float = 600.0) -> Dict[str, Any]:
    runner = runner or run_cmd
    out_dir = out_dir or os.path.join(root, "evidence", "proof")
    cmds = _commands()
    if only is not None:
        cmds = [c for c in cmds if c["name"] == only]
        if not cmds:
            raise ValueError("unknown proof command: %r" % only)
    results: List[Dict[str, Any]] = []
    for c in cmds:
        if c["name"] == "doclint" and not os.path.isfile(os.path.join(root, "bts_sbom_app", "doclint.py")):
            rc, out, err = None, "", ""          # the module does not exist (yet) in this tree - do not invent a run
        else:
            rc, out, err = runner(c["cmd"], root, timeout)
        status, reason = _classify(rc)
        results.append({"name": c["name"], "cmd": list(c["cmd"]), "exit_code": rc, "status": status, "reason": reason,
                        "summary_lines": len((out or "").splitlines()) + len((err or "").splitlines())})
    counts = {"PASS": sum(1 for r in results if r["status"] == "PASS"),
              "FAIL": sum(1 for r in results if r["status"] == "FAIL"),
              "NOT RUN": sum(1 for r in results if r["status"] == "NOT RUN")}
    if counts["FAIL"]:
        status = "fail"
    elif counts["NOT RUN"]:
        status = "incomplete"                    # NOT RUN is never counted toward "pass" (BSA-AC-392/393)
    elif counts["PASS"] >= 1:
        status = "pass"
    else:
        status = "incomplete"
    doc = {"root": root, "results": results, "counts": counts, "status": status}
    write_json(os.path.join(out_dir, "proof-results.json"), doc)     # overwritten every run
    write_json(_proof_run_path(out_dir), doc)                        # accumulated, one file per run
    return doc

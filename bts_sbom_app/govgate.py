"""Six-gate governance checklist (course: "ML pipeline operations governance", the 6-gate table) - exactly six
named rows, each a pass/fail read off a check this project already has. This module invents no new verdict logic
and writes no document; it only calls an existing function and reports what it said.

  Gate            existing check it reads
  --------------  --------------------------------------------------------------------------------------------
  Spec            speclint.lint(specs/bts_sbom_app_features.md) - every AC line well-formed (id, pattern, shall,
                  a measured number)
  AI-Review       doclint over the rest of the governance doc set (ADRs, MODEL_CARD, ORIGIN_LINEAGE,
                  DATA_CONTRACT) - every required section present
  Security        doclint.check_enforcement_table(docs/ENFORCEMENT_MAP.md) - no dangling file/function/test
                  reference in the enforcement map
  Compliance      the AI impact assessment: doclint's "impact" section check, plus its age since its last real
                  git commit (never file mtime - a checkout/clone resets every file's mtime to checkout time,
                  which would make every document look freshly written no matter how old its content is)
  Observability   docs/RUNBOOK.md: doclint's "runbook" section check, plus the same git-commit-age freshness
                  check as Compliance
  Agent Access    chat.catalog(writable=False) must not offer anything in chat.WRITE_TOOLS - a read-only session
                  (no ``--chat-actions``) must not even be offered a write-capable tool

Every check reads real files (and, for the two freshness rows, real git history via the project's own
``workspace.git`` helper - read-only, no mutation); a document that is not present is a FAIL, never a silent
skip (absent evidence is never a pass).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from . import chat, doclint, speclint, workspace
from .util import console_text

GATES: Tuple[str, ...] = ("Spec", "AI-Review", "Security", "Compliance", "Observability", "Agent Access")

#: a governance document older than this (days since its last git commit) is due for review - the same ~6 month
#: window conformance.py already uses for its own regime table (STALE_AFTER_MONTHS = 6)
STALE_AFTER_DAYS = 183

SPEC_REL = "specs/bts_sbom_app_features.md"
IMPACT_REL = "docs/governance/AI_IMPACT_ASSESSMENT.md"
RUNBOOK_REL = "docs/RUNBOOK.md"
ENFORCEMENT_REL = "docs/ENFORCEMENT_MAP.md"
#: AI-Review covers the governance docs NOT already covered by their own dedicated gate (impact -> Compliance,
#: runbook -> Observability, enforcement -> Security), so no document is linted under two different gate names
_AI_REVIEW_KINDS = ("adr", "modelcard", "lineage", "datacontract")


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def doc_age_days(root: str, rel_path: str) -> Optional[int]:
    """Days since ``rel_path``'s last git commit, or ``None`` when git has no answer (no ``.git`` here, git not on
    PATH, or the file was never committed) - staleness is then unknown, not assumed fresh or assumed stale."""
    rc, out, _ = workspace.git(root, "log", "-1", "--format=%ct", "--", rel_path)
    if rc != 0 or not out.strip():
        return None
    try:
        ts = int(out.strip().splitlines()[0])
    except ValueError:
        return None
    return max(0, int((time.time() - ts) // 86400))


def _gate_spec(root: str) -> Tuple[bool, str]:
    path = os.path.join(root, *SPEC_REL.split("/"))
    if not os.path.isfile(path):
        return False, "%s: not present" % SPEC_REL
    problems = speclint.lint(path)
    if problems:
        return False, "%d speclint problem(s): %s" % (len(problems), "; ".join(problems[:3]))
    return True, "ok (speclint: 0 problems)"


def _gate_ai_review(root: str) -> Tuple[bool, str]:
    found, _missing = doclint.discover(root)
    rows = [(p, k) for p, k in found if k in _AI_REVIEW_KINDS]
    if not rows:
        return False, "no governance document (ADR / model card / origin-lineage / data contract) was found"
    problems: List[str] = []
    for p, k in rows:
        probs = doclint.lint_file(p, kind=k, repo_root=root)
        if probs:
            problems.append("%s: %s" % (os.path.relpath(p, root).replace(os.sep, "/"), "; ".join(probs[:2])))
    if problems:
        return False, "%d of %d doc(s) have a problem: %s" % (len(problems), len(rows), "; ".join(problems[:3]))
    return True, "ok (doclint: %d doc(s), 0 problems)" % len(rows)


def _gate_security(root: str) -> Tuple[bool, str]:
    path = os.path.join(root, *ENFORCEMENT_REL.split("/"))
    text = _read(path)
    if text is None:
        return False, "%s: not present" % ENFORCEMENT_REL
    problems = doclint.check_enforcement_table(text, root)
    if problems:
        return False, "%d enforcement-map problem(s): %s" % (len(problems), "; ".join(problems[:3]))
    return True, "ok (enforcement-map check: 0 dangling references)"


def _gate_freshness(root: str, rel_path: str, kind: str) -> Tuple[bool, str]:
    path = os.path.join(root, *rel_path.split("/"))
    text = _read(path)
    if text is None:
        return False, "%s: not present" % rel_path
    problems = doclint.lint_text(text, kind, repo_root=root)
    age = doc_age_days(root, rel_path)
    stale = age is not None and age >= STALE_AFTER_DAYS
    bits: List[str] = []
    if problems:
        bits.append("%d doclint problem(s): %s" % (len(problems), "; ".join(problems[:2])))
    bits.append("%d day(s) since last commit" % age if age is not None else "age unknown (no git history for this file)")
    if stale:
        bits.append("STALE: review is due (>= %d days)" % STALE_AFTER_DAYS)
    ok = not problems and not stale
    return ok, ("ok, " if ok else "FAIL, ") + "; ".join(bits)


def _gate_agent_access(root: str) -> Tuple[bool, str]:
    offered = sorted(set(chat.catalog(False)) & set(chat.WRITE_TOOLS))
    if offered:
        return False, "write tool(s) offered to a read-only session (no --chat-actions): %s" % ", ".join(offered)
    return True, "ok (chat.catalog(writable=False) offers none of chat.WRITE_TOOLS)"


_CHECKS: Tuple[Tuple[str, Any], ...] = (
    ("Spec", _gate_spec),
    ("AI-Review", _gate_ai_review),
    ("Security", _gate_security),
    ("Compliance", lambda root: _gate_freshness(root, IMPACT_REL, "impact")),
    ("Observability", lambda root: _gate_freshness(root, RUNBOOK_REL, "runbook")),
    ("Agent Access", _gate_agent_access),
)


def evaluate(root: Optional[str] = None) -> Dict[str, Any]:
    """The 6 governance gates. Returns ``{"root", "rows": [{"gate", "status": "pass"|"fail", "detail"}, ...], "ok"}``
    with ``rows`` in exactly the order of ``GATES`` (always 6, never fewer - a check that cannot run is a FAIL
    row with the reason in ``detail``, not a missing row)."""
    root = root or _repo_root()
    rows: List[Dict[str, Any]] = []
    for name, fn in _CHECKS:
        try:
            ok, detail = fn(root)
        except Exception as exc:                                     # noqa: BLE001 - a gate must never crash the checklist
            ok, detail = False, "check raised %s: %s" % (type(exc).__name__, exc)
        rows.append({"gate": name, "status": "pass" if ok else "fail", "detail": detail})
    assert tuple(r["gate"] for r in rows) == GATES
    return {"root": root, "rows": rows, "ok": all(r["status"] == "pass" for r in rows)}


def render(result: Dict[str, Any]) -> str:
    lines = ["governance gates: %s" % ("ALL PASS" if result["ok"] else "FAIL")]
    for r in result["rows"]:
        lines.append("  %-14s %-4s %s" % (r["gate"], r["status"].upper(), r["detail"]))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="bts_sbom_app.govgate", description="6-gate governance checklist (read-only; exits 1 if any gate fails)")
    ap.add_argument("--root", default=None, help="repository root (default: this package's own repo root)")
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    result = evaluate(a.root)
    if a.json:
        print(json.dumps(result, indent=1))
    else:
        print(console_text(render(result)))
    return 0 if result["ok"] else 1


__all__ = ["GATES", "STALE_AFTER_DAYS", "doc_age_days", "evaluate", "render", "main"]

if __name__ == "__main__":
    sys.exit(main())

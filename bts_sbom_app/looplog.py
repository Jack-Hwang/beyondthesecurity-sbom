"""Render the loop history (evidence/loop/*.json) as Markdown: what changed in each pass and which metrics moved."""
from __future__ import annotations

import os
from typing import Any, Dict, List

from .util import read_json

E2E_KEYS = ("components", "vulns", "license_resolved_rate", "spdx_valid_rate", "plan_verified_rate", "fix_applied_rate", "arch_coverage",
            "exaone_rate", "ai_keep_rate", "stage_errors")
RAG_KEYS = ("golden_recall", "golden_found", "golden_ood", "dev_recall", "dev_found", "dev_ood", "test_recall", "test_found", "test_ood")


def _moves(prev: Dict[str, Any], cur: Dict[str, Any], keys) -> str:
    out = []
    for k in keys:
        a, b = prev.get(k), cur.get(k)
        if b is None or a == b:
            continue
        out.append("%s %s -> %s" % (k, "-" if a is None else a, b))
    return "; ".join(out) or "no gated/tracked metric moved"


def render(loop_root: str) -> str:
    L: List[str] = ["# Loop engineering log", "",
                    "One variable per pass. `accept` = no blocking metric regressed by more than 0.02 against the previous accepted pass.",
                    "Code fingerprints identify the exact tool version that produced each pass.", ""]
    hist = read_json(os.path.join(loop_root, "history.json"), []) or []
    L += ["## End-to-end passes (10 real GitHub sources)", "", "| # | tag | decision | variable changed | metrics that moved vs previous accepted pass | note |", "|---|---|---|---|---|---|"]
    prev: Dict[str, Any] = {}
    for h in hist:
        L.append("| %d | %s | %s | %s | %s | %s |" % (h["pass"], h["tag"], h["decision"], h["variable"].replace("|", "/"),
                                                 _moves(prev, h["metrics"], E2E_KEYS) if prev else "baseline", str(h.get("note", "")).replace("|", "/")))
        if h["decision"] in ("baseline", "accept"):
            prev = h["metrics"]
    L.append("")
    rag = read_json(os.path.join(loop_root, "rag_history.json"), []) or []
    if rag:
        L += ["## Retrieval passes (golden = regression set, dev = tuned on, test = written before tuning)", "",
              "| # | tag | decision | variable changed | metrics that moved |", "|---|---|---|---|---|"]
        prev = {}
        for h in rag:
            L.append("| %d | %s | %s | %s | %s |" % (h["pass"], h["tag"], h["decision"], h["variable"].replace("|", "/"), _moves(prev, h["metrics"], RAG_KEYS) if prev else "baseline"))
            if h["decision"] in ("baseline", "accept"):
                prev = h["metrics"]
        L.append("")
    return "\n".join(L) + "\n"

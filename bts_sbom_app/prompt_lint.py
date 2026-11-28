"""Instruction-conflict lint across the registered prompt blocks (backlog C83; course week 5 lesson 1, D4 §3
"Writing Instructions That Don't Conflict"): two rules that fire on the SAME input are where an LLM call site's
behaviour drifts, and the drift is silent until an eval catches it - so the conflict is linted before that.

Report-only, three rules over the live prompt constants (collected the same way promptreg collects them):

* ``duplicate_content``      - two prompt ids share one fingerprint: the same prompt under two names is a drift
                               trap (someone edits one copy, the other silently diverges);
* ``contract_mismatch``      - within one module, some prompts demand a machine contract ("ONLY valid JSON") while
                               others state free-prose output: two LLM call sites in one module with different
                               output contracts is exactly where a validator starts failing intermittently;
* ``numeric_bounds_conflict``- one prompt carries both an "at most N" and an "at least M" bound with M > N: the
                               instruction contradicts itself before any model sees it.

Every finding names the prompt ids so the fix is a one-file edit; nothing here changes any prompt.
"""
from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List

from .promptreg import _consts, _fp

_JSON_ONLY = re.compile(r"ONLY valid JSON", re.I)
_OUT_LANG = re.compile(r"words|문장|형식|답변은|in \w+ words|at most \d+ words", re.I)
_MOST = re.compile(r"at most (\d+)", re.I)
_LEAST = re.compile(r"at least (\d+)", re.I)


def lint(root: str) -> Dict[str, Any]:
    """(report) - the findings, each with the prompt ids that carry the conflict."""
    pkg = os.path.join(root, "bts_sbom_app")
    texts: Dict[str, str] = {}
    for fn in sorted(os.listdir(pkg)) if os.path.isdir(pkg) else []:
        if not fn.endswith(".py"):
            continue
        try:
            with open(os.path.join(pkg, fn), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (OSError, SyntaxError, ValueError):
            continue
        consts, _ = _consts(tree)
        for name, text in consts.items():
            texts["%s.%s" % (fn[:-3], name)] = text
    findings: List[Dict[str, Any]] = []
    by_fp: Dict[str, List[str]] = {}
    for pid, text in texts.items():
        by_fp.setdefault(_fp(text), []).append(pid)
    for fp, ids in sorted(by_fp.items()):
        if len(ids) > 1:
            findings.append({"rule": "duplicate_content", "ids": sorted(ids),
                             "detail": "the same prompt content is registered under %d names - one edit and they silently diverge" % len(ids)})
    by_mod: Dict[str, List[str]] = {}
    for pid in texts:
        by_mod.setdefault(pid.split(".", 1)[0], []).append(pid)
    for mod, ids in sorted(by_mod.items()):
        json_ids = sorted(i for i in ids if _JSON_ONLY.search(texts[i]))
        prose_ids = sorted(i for i in ids if i not in json_ids and _OUT_LANG.search(texts[i]))
        if json_ids and prose_ids:
            findings.append({"rule": "contract_mismatch", "ids": {"json_only": json_ids, "free_prose": prose_ids},
                             "detail": "module %s mixes machine contracts (%s) and free-prose output (%s) - validators will fail intermittently" % (mod, len(json_ids), len(prose_ids))})
    for pid, text in texts.items():
        most = _MOST.search(text)
        least = _LEAST.search(text)
        if most and least and int(least.group(1)) > int(most.group(1)):
            findings.append({"rule": "numeric_bounds_conflict", "ids": [pid],
                             "detail": "at most %s but at least %s in the same prompt" % (most.group(1), least.group(1))})
    return {"prompts_scanned": len(texts), "findings": findings, "clean": not findings,
            "report_only": "the lint names conflicts; changing a prompt is a pinned, evaluated step (promptreg)"}

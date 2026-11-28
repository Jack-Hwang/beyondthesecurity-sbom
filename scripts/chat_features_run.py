"""Chat-driven feature runner: replays evals/chat_features.json against the live BTS-SBOM service and verifies
each feature actually works through conversation - the expected tool fires, the answer is grounded.

Usage: python scripts/chat_features_run.py [--base http://127.0.0.1:8822] [--use-llm] [--suite evals/chat_features.json]

The suite is the contract: one question per chat-runnable feature (the 19 read tools + the knowledge lane);
write tools (analyze_project / apply_patch / confirm_decision) are deliberately absent - they change state and
are driven by the approval-gated flows instead. Results land in evidence/chat_features/report.json with one row
per question: expected tool, tools that actually fired, found flag, answer head. A feature "works" when its
expected tool fired AND the turn reported found=true.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _post(base: str, path: str, body: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
    req = urllib.request.Request(base + path, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


def run(base: str, suite: List[Dict[str, Any]], use_llm: bool = False, pause_s: float = 0.0) -> List[Dict[str, Any]]:
    """Replay the suite in order. A row whose ``tool`` is null/absent (the knowledge lane fires no tool) is
    verified by ``found=true`` alone."""
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(suite, 1):
        t0 = time.time()
        issues: List[str] = []
        try:
            res = _post(base, "/api/chat", {"question": row["q"], "project": row.get("project"),
                                            "use_llm": use_llm})
        except Exception as exc:
            issues.append("request failed: %s" % str(exc)[:160])
            res = {}
        tools = res.get("tools") or []
        expected = row.get("tool")
        fired = expected in tools
        if expected and not fired:
            issues.append("expected tool %r did not fire (got %s)" % (expected, tools or "none"))
        found = res.get("found")
        if not found:
            issues.append("turn reported found=false")
        answer = (res.get("answer") or "").replace("\n", " ")
        out.append({"feature": row.get("feature"), "tool": expected, "fired": fired, "found": found,
                    "tools": tools, "tool_args": res.get("tool_args") or {},   # C74: the fired call's argument values
                    "stage_ms": res.get("stage_ms") or {},                     # C75: where the turn spent its time
                    "answer_head": answer[:140], "routing": res.get("routing"),
                    "answer_source": res.get("answer_source"), "s": round(time.time() - t0, 1),
                    "issues": issues})
        mark = "ok " if not issues else "FAIL"
        print("[%2d/%d] %-14s %-4s %-3.1fs %s" % (i, len(suite), row.get("feature"), mark,
              time.time() - t0, ("; " + "; ".join(issues[:2])) if issues else ""), flush=True)
        if pause_s:
            time.sleep(pause_s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8822")
    ap.add_argument("--suite", default=os.path.join(ROOT, "evals", "chat_features.json"))
    ap.add_argument("--use-llm", action="store_true", help="turn the LLM lane on for every question")
    ap.add_argument("--pause", type=float, default=0.0, help="seconds between questions")
    a = ap.parse_args()
    suite = json.load(open(a.suite, encoding="utf-8"))
    out_dir = os.path.join(ROOT, "evidence", "chat_features")
    os.makedirs(out_dir, exist_ok=True)
    results = run(a.base, suite, use_llm=a.use_llm)
    passed = sum(1 for r in results if not r["issues"])
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump({"rounds": len(results), "passed": passed,
                   "wall_s": round(sum(r["s"] for r in results), 1), "use_llm": a.use_llm,
                   "results": results}, fh, ensure_ascii=False, indent=1)
    print("SUMMARY %d/%d passed (llm=%s) -> evidence/chat_features/report.json" % (passed, len(results), a.use_llm), flush=True)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())

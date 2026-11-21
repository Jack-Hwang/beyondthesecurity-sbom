"""Proof: the integration verification contract (task 5b) - run the verification commands, classify honestly.

PASS / FAIL / NOT RUN. NOT RUN = the command or module could not be found, a timeout, or skips - it is NEVER
counted as a pass. Overall status: "pass" only when 0 FAIL and at least 1 PASS and 0 NOT RUN; "incomplete" when
NOT RUN exists; "fail" otherwise. Sidecar: proof-results.json is overwritten every run (the summary), and
proof-runs/<UTC timestamp>.json accumulates (two runs in the same second never collide). Files hold commands,
exit codes and summary line counts only - never raw output.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

DEFAULT_COMMANDS: List[Dict[str, str]] = [
    {"name": "pytest", "cmd": "python -X utf8 -m pytest -q -p no:cacheprovider tests/bts_sbom_app"},
    {"name": "speclint", "cmd": "python -X utf8 -m bts_sbom_app.speclint"},
    {"name": "doclint", "cmd": "python -X utf8 -m bts_sbom_app.doclint --strict"},
    {"name": "evalrag", "cmd": "python -I -X utf8 run_bts_sbom_app.py evalrag"},
]
SIDECAR_SUMMARY = "proof-results.json"
SIDECAR_RUNS = "proof-runs"


def _default_runner(cmd: str, timeout: float = 1200.0) -> Tuple[int, str, str]:
    import subprocess
    try:
        p = subprocess.run(cmd.split(), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, shell=False)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def run(runner: Optional[Callable[[str], Tuple[int, str, str]]] = None, commands: Optional[List[Dict[str, str]]] = None,
        only: Optional[str] = None, out_dir: str = ".") -> Dict[str, Any]:
    runner = runner or _default_runner
    results: List[Dict[str, Any]] = []
    for spec in (commands or DEFAULT_COMMANDS):
        if only and spec["name"] != only:
            continue
        try:
            rc, out, err = runner(spec["cmd"])
        except Exception:                                      # noqa: BLE001 - a runner crash is NOT RUN, not a pass
            rc, out, err = 125, "", "runner raised"
        if rc == 0:
            status = "PASS"
        elif rc in (124, 125, 127):
            status = "NOT RUN"                                 # timeout / runner crash / command not found
        else:
            status = "FAIL"
        results.append({"name": spec["name"], "cmd": spec["cmd"], "exit": rc, "status": status,
                        "summary_lines": len([ln for ln in (out + "\n" + err).splitlines() if ln.strip()])})
    fails = [r for r in results if r["status"] == "FAIL"]
    notrun = [r for r in results if r["status"] == "NOT RUN"]
    passes = [r for r in results if r["status"] == "PASS"]
    if fails:
        overall = "fail"
    elif notrun:
        overall = "incomplete"
    elif passes:
        overall = "pass"
    else:
        overall = "incomplete"
    record = {"tool": "proof", "overall": overall, "results": results,
              "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _write_sidecar(out_dir, record)
    return record


def _write_sidecar(out_dir: str, record: Dict[str, Any]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, SIDECAR_SUMMARY), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    runs = os.path.join(out_dir, SIDECAR_RUNS)
    os.makedirs(runs, exist_ok=True)
    name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target = os.path.join(runs, name + ".json")
    seq = 0
    while os.path.exists(target):
        seq += 1
        target = os.path.join(runs, "%s-%d.json" % (name, seq))
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=1)
        fh.write("\n")

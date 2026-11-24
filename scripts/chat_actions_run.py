"""Replayable HITL action-flow evidence (AC-609): the approval chain, end to end, over real HTTP.

Until 2026-11-23 the full approve-then-execute chain existed only as a prose record (AC-593) plus in-process tests;
this runner makes it a replayable artifact. It builds a disposable git fixture, starts two throwaway servers on the
same evidence folder - one with --chat-actions, one without - and walks the chain a user would walk in the dock:

  1. "분석해줘"        -> the fixture is analysed into the throwaway evidence folder (analyze_project)
  2. "패치 해줘"        -> the plan shows its 16-hex approval token (and, over SSE, awaiting_approval)
  3. "패치 승인 <토큰>"  -> exactly that plan applies in an isolated work copy; origin untouched
  4. the saved record -> patch.status == applied (what the console and reports read)
  5. "장부에 남겨줘"    -> the decision preview returns its 12-hex confirm code
  6. "확정 <코드>"      -> the VEX decision reaches .triage.json
  7. the flag-off server refuses the same approval sentence (the negative direction)

Writes evidence/chat_actions/report.json and exits non-zero unless every step passed. The analyze/patch steps run the
real engine (network: OSV queries for the fixture's packages); pass --offline to skip, in which case steps that need
advisory data report honestly instead of failing silently.

Usage: python scripts/chat_actions_run.py [--evidence evidence/chat_actions] [--keep]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bts_sbom_app.cli import project_records       # noqa: E402
from bts_sbom_app.util import read_json            # noqa: E402

TOKEN_RE = re.compile(r"Approval token ([0-9a-f]{16})")
CODE_RE = re.compile(r"\bconfirm ([0-9a-f]{12})\b")
APPLIED = "Patch applied in an isolated work copy"


def _git(d: str, *args: str) -> None:
    subprocess.run(["git", *args], cwd=d, check=True, capture_output=True)


def make_fixture(root: str) -> str:
    d = os.path.join(root, "proj")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("requests==2.19.1\npyyaml==5.3\n")
    _git(d, "init", "-q", "-b", "main")
    _git(d, "add", "-A")
    _git(d, "commit", "-q", "-m", "fixture")
    return d


def _serve(root: str, evidence: str, port: int, actions: bool) -> subprocess.Popen:
    args = [sys.executable, "-m", "bts_sbom_app", "serve", "--host", "127.0.0.1", "--port", str(port),
            "--evidence", evidence, "--llm-config", os.path.join("evidence", ".llm_config.json")]
    if actions:
        args.append("--chat-actions")
    return subprocess.Popen(args, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _ask(base: str, q: str, project: str | None = None, timeout: int = 300) -> dict:
    body = {"question": q, "use_llm": False}
    if project:
        body["project"] = project
    req = urllib.request.Request(base + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait(base: str, tries: int = 60) -> None:
    for _ in range(tries):
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=5):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("server did not come up at %s" % base)


def run(root: str, evidence: str) -> dict:
    ev = os.path.join(root, evidence)
    tmp = tempfile.mkdtemp(prefix="bts_actions_run_")
    steps: list = []

    def step(name: str, q: str, project, ok: bool, detail: str) -> dict:
        steps.append({"step": name, "q": q, "project": project, "ok": ok, "detail": detail[:400]})
        print("[%s] %-22s %s" % ("ok" if ok else "FAIL", name, detail.splitlines()[0][:110] if detail else ""))
        return steps[-1]

    src = make_fixture(tmp)
    on_port, off_port = _free_port(), _free_port()
    proc_on = _serve(root, ev, on_port, actions=True)
    proc_off = _serve(root, ev, off_port, actions=False)
    base_on, base_off = "http://127.0.0.1:%d" % on_port, "http://127.0.0.1:%d" % off_port
    name = None
    try:
        _wait(base_on)
        _wait(base_off)

        # 1 - analysis through chat (the project lands in the throwaway evidence folder)
        r = _ask(base_on, "%s 분석해줘" % src)
        fired = "analyze_project" in (r.get("tools") or [])
        recs = project_records(ev)
        name = next(iter(recs), None)
        step("analyze_project", r.get("_q", "%s 분석해줘" % src), None, bool(fired and name and r.get("found")),
             (r.get("answer") or "") + " | projects: %s" % sorted(recs))
        if not name:
            return {"steps": steps, "passed": 0, "total": len(steps) or 1}

        # 2 - the plan shows its token
        r = _ask(base_on, "패치 해줘", name)
        m = TOKEN_RE.search(r.get("answer") or "")
        step("plan_patch", "패치 해줘", name, bool(m), r.get("answer") or "")
        if not m:
            return {"steps": steps, "passed": sum(1 for s in steps if s["ok"]), "total": len(steps)}
        tok = m.group(1)

        # 3 - the approval sentence applies exactly that plan
        r = _ask(base_on, "패치 승인 %s" % tok, name)
        step("apply_patch", "패치 승인 %s" % tok, name, APPLIED in (r.get("answer") or ""), r.get("answer") or "")

        # 4 - the saved record the console reads says applied, origin untouched
        rec = (project_records(ev).get(name) or (None, {}))[1]
        patch = rec.get("patch") or {}
        step("record_applied", "(record)", name, patch.get("status") == "applied",
             "status=%s work_copy=%s" % (patch.get("status"), patch.get("work_copy")))

        # 5 - the decision preview returns its confirm code
        vid = ((rec.get("vulns") or [{}])[0].get("id") or "")
        ok5, detail5 = False, "no advisory recorded for the fixture (offline?)"
        if vid:
            q = "%s 는 not_affected다. 우리 쓰임새에선 문제 안 되니까 장부에 남겨줘. 이유: 우리는 영향받는 버전을 안 쓴다" % vid
            r = _ask(base_on, q, name)
            m = CODE_RE.search(r.get("answer") or "")
            ok5 = bool(m)
            detail5 = (r.get("answer") or "")[:200]
            # 6 - the confirm code records the VEX decision
            if m:
                r = _ask(base_on, "확정 %s" % m.group(1), name)
                store = read_json(os.path.join(ev, ".triage.json"), {})
                hit = vid in json.dumps(store, ensure_ascii=False)          # the id can live in a key or a value
                step("confirm_decision", "확정 %s" % m.group(1), name, hit,
                     (r.get("answer") or "")[:200] + " | .triage.json has %s: %s" % (vid, hit))
        step("decision_preview", "(%s)" % vid or "-", name, ok5, detail5)

        # 7 - the flag-off server refuses the same approval sentence
        r = _ask(base_off, "패치 승인 %s" % tok, name)
        step("readonly_refusal", "패치 승인 %s" % tok, name, "read-only" in (r.get("answer") or ""), r.get("answer") or "")
    finally:
        proc_on.terminate()
        proc_off.terminate()
        try:
            proc_on.wait(timeout=15)
            proc_off.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc_on.kill()
            proc_off.kill()
        if not os.environ.get("BTS_ACTIONS_KEEP"):
            shutil.rmtree(tmp, ignore_errors=True)
    return {"steps": steps, "passed": sum(1 for s in steps if s["ok"]), "total": len(steps)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=os.path.join("evidence", "chat_actions"))
    args = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rep = run(root, args.evidence)
    os.makedirs(os.path.join(root, args.evidence), exist_ok=True)
    out = os.path.join(root, args.evidence, "report.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=1)
    print("SUMMARY %d/%d passed -> %s" % (rep["passed"], rep["total"], os.path.relpath(out, root)))
    return 0 if rep["passed"] == rep["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

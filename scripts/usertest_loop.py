"""User-test loop: replays the real user scenario against the live BTS-SBOM service and collects every defect
it can observe, so UI/feature improvements come from measurements, not guesses.

Usage: python scripts/usertest_loop.py [--base http://127.0.0.1:8822] [--rounds 100] [--source <local folder>]

Iteration classes (100 rounds -> 5 heavy / 15 medium / 80 light):
  heavy  (every 20th): the full 5-step user scenario over HTTP - scan the cloned legacy repo, verify the view
                       and report artifacts, verify a patch plan digest exists, verify the latest Arch Intel run
                       carries at least one sequence diagram (the step-5 deliverable).
  medium (every 5th):  the report surface - /api/view, SBOM + Markdown artifacts, decision coverage, SBOM
                       conformance, and a chat question routed to book_search.
  light  (rest):       the always-on surfaces - healthz/readyz/engine, the Book KB registry and search.

Every check failure is recorded as an issue string; the loop NEVER aborts on a defect (a defect found is a
result, not a crash). Output: evidence/usertest/findings.json + a one-line summary per class on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from typing import Any, Dict, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _req(base: str, method: str, path: str, body: Optional[Dict[str, Any]] = None, timeout: int = 30):
    """GET/POST with JSON in, JSON out where possible - but some artifacts (/api/doc) are Markdown text: a
    non-JSON body is returned as {'_text': <str>} so artifact endpoints can still be asserted on status."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8")
    try:
        return r.status, json.loads(raw or "{}")
    except ValueError:
        return r.status, {"_text": raw}


def wait_job(base: str, jid: str, timeout_s: float = 180.0) -> Dict:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        _, j = _req(base, "GET", "/api/jobs/" + jid, timeout=15)
        if (j or {}).get("state") != "running":
            return j
        time.sleep(1.0)
    return {"state": "timeout"}


def run_iteration(i: int, base: str, source: str) -> Dict:
    issues: list = []
    kind = "heavy" if i % 20 == 0 else ("medium" if i % 5 == 0 else "light")
    t0 = time.time()

    def check(name: str, ok: bool, detail: str = "") -> None:
        if not ok:
            issues.append("%s: %s" % (name, detail[:220]))

    # --- light: always-on surfaces (every round) ---
    st, d = _req(base, "GET", "/healthz")
    check("healthz", st == 200 and d.get("ok") is True)
    st, d = _req(base, "GET", "/readyz")
    check("readyz", st == 200 and d.get("ready") is True, json.dumps(d)[:180])
    st, d = _req(base, "GET", "/api/engine")
    check("engine", st == 200 and bool(d.get("name")))
    st, d = _req(base, "GET", "/api/books")
    check("books-builtin", st == 200 and d.get("built") is True)
    st, d = _req(base, "GET", "/api/books/search?q=fitness%20function&k=3")
    # the API contract (200 + boolean found + shaped rows) is what we test here; whether a topic hits depends
    # on which books the user currently has in the library, not on the service
    check("books-search", st == 200 and isinstance(d.get("found"), bool) and isinstance(d.get("results"), list),
          json.dumps(d)[:180])

    if kind in ("medium", "heavy"):
        # --- report surface: the selected project's view + artifacts + governance ---
        st, h = _req(base, "GET", "/api/history")
        names = [r["name"] for r in (h.get("history") or [])]
        check("history-nonempty", bool(names))
        proj = names[0] if names else ""
        if proj:
            import urllib.parse
            pn = urllib.parse.quote(proj)
            st, v = _req(base, "GET", "/api/view/" + pn)
            check("view-ok", st == 200 and bool(v.get("report")), json.dumps(v)[:180])
            rep = (v.get("report") or {}) if isinstance(v, dict) else {}
            check("view-severity", isinstance((rep.get("severity") or {}).get("total"), int))
            for fmt in ("cdx", "spdx", "vex"):
                st, _ = _req(base, "GET", "/api/sbom/%s?format=%s" % (pn, fmt))
                check("sbom-" + fmt, st == 200)
            st, _ = _req(base, "GET", "/api/doc/" + pn)
            check("doc-md", st == 200)
            st, c = _req(base, "GET", "/api/coverage/" + pn)
            check("coverage", st == 200 and c.get("schema") == "bts-sbom.coverage.v1", json.dumps(c)[:150])
            st, f = _req(base, "GET", "/api/conformance/" + pn)
            check("conformance", st == 200 and f.get("schema") == "bts-sbom.conformance.v1", json.dumps(f)[:150])
            st, ch = _req(base, "POST", "/api/chat", {"question": "책에서 fitness function 찾아줘"})
            check("chat-book", st == 200 and ch.get("found") is True and "book_search" in (ch.get("tools") or []),
                  json.dumps({"tools": (ch or {}).get("tools")})[:150])

    if kind == "heavy":
        # --- the full 5-step scenario over HTTP ---
        st, j = _req(base, "POST", "/api/scan", {"source": source, "use_llm": True, "patch": True, "approved": False})
        check("scan-submit", st == 202 and bool(j.get("job")), json.dumps(j)[:180])
        job: Optional[Dict[str, Any]] = None
        if j.get("job"):
            job = wait_job(base, j["job"], timeout_s=240.0)
            check("scan-done", job.get("state") == "done", json.dumps(job)[:200])
            m = job.get("metrics") or {}
            check("scan-findings", isinstance(m.get("vulns"), int))
            check("scan-name", bool(job.get("name")), json.dumps(job)[:120])
        st, d = _req(base, "GET", "/api/projects")
        check("projects-listed", st == 200 and bool(d.get("projects")))
        # step 5 deliverable: the latest Arch Intel run must carry at least one sequence diagram
        st, hh = _req(base, "GET", "/api/arch/history")
        runs = hh.get("history") or []
        check("arch-history", bool(runs), "no arch intel run recorded")
        if runs:
            rid = runs[0].get("id")
            st, doc = _req(base, "GET", "/api/arch/result/" + rid)
            seq = ((doc.get("diagrams") or {}).get("sequence")) or []
            check("arch-sequence", st == 200 and len(seq) >= 1,
                  "sequence diagrams: %d (ai_note: %s)" % (len(seq), (doc.get("ai_note") or "")[:120]))
        # step 4 deliverable: this heavy round itself ran with patch:true, so the reviewed plan digest must exist
        name = (job or {}).get("name") if isinstance(job, dict) else None
        if name:
            import urllib.parse
            st, v = _req(base, "GET", "/api/view/" + urllib.parse.quote(name))
            p = (v.get("patch") or {}) if isinstance(v, dict) else {}
            check("patch-digest", bool(p.get("digest")), "no plan digest in the view of %s (status %s)" % (name, p.get("status")))

    return {"i": i, "kind": kind, "ok": not issues, "issues": issues, "s": round(time.time() - t0, 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8822")
    ap.add_argument("--rounds", type=int, default=100)
    ap.add_argument("--source", default=r"C:\firebaseprojects\usertest\django-nV")
    a = ap.parse_args()
    out_dir = os.path.join(ROOT, "evidence", "usertest")
    os.makedirs(out_dir, exist_ok=True)
    results = []
    t0 = time.time()
    for i in range(1, a.rounds + 1):
        r = run_iteration(i, a.base, a.source)
        results.append(r)
        print("round %3d %-6s %s (%.1fs)%s" % (i, r["kind"], "ok" if r["ok"] else "ISSUES", r["s"],
              (" -> " + "; ".join(r["issues"][:3])) if r["issues"] else ""), flush=True)
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump({"rounds": a.rounds, "base": a.base, "wall_s": round(time.time() - t0, 1),
                   "passed": sum(1 for r in results if r["ok"]),
                   "results": results}, fh, ensure_ascii=False, indent=1)
    by_kind = {}
    for r in results:
        k = by_kind.setdefault(r["kind"], [0, 0])
        k[0 if r["ok"] else 1] += 1
    print("SUMMARY rounds=%d wall=%.0fs passed=%d" % (a.rounds, time.time() - t0, sum(1 for r in results if r["ok"])),
          " | ".join("%s ok=%d fail=%d" % (k, v[0], v[1]) for k, v in by_kind.items()), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

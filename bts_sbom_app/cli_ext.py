"""Command line for the SBOM-governance features: conformance | diff | vex | review | fleet.

Kept apart from ``cli.py`` (scan / patch / batch / loop / chat / serve) so the two can evolve independently; ``cli.main`` hands
these sub-commands over. Everything here reads existing evidence or SBOM files: nothing is scanned, pushed or sent.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from typing import Any, Dict, Optional, Tuple

from . import binscan, changes, conformance, coverage, fleet, portfolio, sbom, selfcheck, srcscan, traceability, triage
from .llm import ChatClient
from .util import console_text, read_json, write_json

COMMANDS = ("govgate", "secretscan", "audit", "access-token", "prompts", "evalsets", "ai-impact", "escalations", "conformance", "diff", "vex", "review", "fleet", "coverage", "srcscan", "binscan", "selfcheck",
            "trace", "portfolio", "proof")
PROOF_COMMAND_NAMES = ("pytest", "speclint", "doclint", "evalrag")


def add_commands(sub: Any) -> None:
    def ev(p: argparse.ArgumentParser) -> None:
        p.add_argument("--evidence", default=None, help="evidence folder of analysed projects (default: <repo>/evidence/runs)")
        p.add_argument("--json", action="store_true")

    c = sub.add_parser("conformance", help="check an SBOM against NTIA 2021, CISA 2025 draft, EU CRA, BSI TR-03183-2 and vulnerability readiness")
    c.add_argument("source", help="SBOM file (CycloneDX / SPDX JSON), project record file, or a project name in the evidence folder")
    c.add_argument("--regime", action="append", default=None, choices=sorted(conformance.REGIMES), help="limit to one regime (repeatable)")
    c.add_argument("--require", default=None, choices=sorted(conformance.REGIMES), help="exit 1 unless this regime is conformant")
    ev(c)
    d = sub.add_parser("diff", help="what changed between two analyses / SBOMs, with threshold alerts")
    d.add_argument("before", help="record / SBOM file, or a project name (then AFTER is its previous analysis vs the latest)")
    d.add_argument("after", nargs="?", default=None)
    d.add_argument("--threshold", type=float, default=changes.DEFAULT_THRESHOLD, help="score threshold for alerts (default 7.0)")
    d.add_argument("--brief", action="store_true", help="print the short change brief")
    d.add_argument("--llm", action="store_true", help="let EXAONE write the brief (every figure is verified against the facts)")
    d.add_argument("--llm-config", default=None)
    d.add_argument("--fail-on-alert", action="store_true", help="exit 1 when a critical or high alert exists")
    ev(d)
    v = sub.add_parser("vex", help="OpenVEX of a project with the triage decisions applied (fail-closed)")
    v.add_argument("project")
    v.add_argument("--triage", default=None, help="decision store (default: <evidence>/.triage.json)")
    v.add_argument("--today", default=None, help="date used for expiry checks, YYYY-MM-DD (default: today)")
    v.add_argument("--out", default=None, help="write the OpenVEX document here")
    ev(v)
    r = sub.add_parser("review", help="findings whose match is weaker than the rest - a worklist for a human decision")
    r.add_argument("project")
    r.add_argument("--triage", default=None)
    ev(r)
    f = sub.add_parser("fleet", help="which analysed projects use a component / are hit by an advisory; portfolio roll-up")
    f.add_argument("--cve", default=None, help="advisory id or alias")
    f.add_argument("--component", default=None)
    f.add_argument("--version", default=None, help="constraint, e.g. '<2.0,>=1.0' or '2.19.1'")
    ev(f)
    gg = sub.add_parser("govgate", help="6-gate governance checklist (Spec, AI-Review, Security, Compliance, Observability, Agent Access) from the existing checks; exit 1 when a gate fails")
    gg.add_argument("--json", action="store_true")
    gg.add_argument("--root", default=argparse.SUPPRESS, help="repository root (default: --root of the command)")
    sx = sub.add_parser("secretscan", help="secret scan of a LOCAL source folder: file + line + rule only, never the value; a partial scan (skipped binary/oversized files) exits 1 like a finding")
    sx.add_argument("folder", help="LOCAL source folder to scan")
    sx.add_argument("--max", type=int, default=50, help="findings to print (the JSON has all)")
    sx.add_argument("--json", action="store_true")
    au = sub.add_parser("audit", help="stratified audit sample: licence resolutions by resolution source, or closed triage/VEX decisions by severity lane (deterministic with --seed)")
    au.add_argument("project", help="project record file, or a project name in the evidence folder")
    au.add_argument("--kind", default="licenses", choices=("licenses", "triage"))
    au.add_argument("--seed", type=int, default=0)
    au.add_argument("--frac", type=float, default=0.1, help="licenses: share of each source's resolved components to sample (minimum 1 per source)")
    au.add_argument("--margin", type=float, default=0.1, help="triage: margin of error of the lane sample size")
    au.add_argument("--confidence", type=float, default=0.9, help="triage: confidence of the lane sample size")
    au.add_argument("--triage", default=None, help="decision store (default: <evidence>/.triage.json)")
    ev(au)
    at = sub.add_parser("access-token", help="print a fresh 256-bit access token for BTS_SBOM_ACCESS_TOKEN (the shared-secret gate of a deployed instance)")
    at.add_argument("--json", action="store_true")
    pm = sub.add_parser("prompts", help="prompt registry and drift gate: every prompt fingerprinted and pinned; --update re-pins after a deliberate change (needs --reason)")
    pm.add_argument("--update", action="store_true", help="re-pin the prompts as they are now (refused while a changed prompt kept its PROMPT_VERSION)")
    pm.add_argument("--reason", default=None, help="what changed in the prompt and why (recorded in the registry history)")
    pm.add_argument("--require-loop-evidence", action="store_true", help="with --update: refuse the re-pin unless a fresh evidence/loop pass (or --loop-fingerprint) measured these exact prompts")
    pm.add_argument("--loop-fingerprint", default=None, help="with --update: a loop pass's recorded prompt digest that vouches for freshness directly")
    pm.add_argument("--json", action="store_true")
    pm.add_argument("--root", default=argparse.SUPPRESS, help="repository root that holds bts_sbom_app/ and evals/ (default: --root of the command)")
    esv = sub.add_parser("evalsets", help="integrity of the retrieval eval sets: composition per set and segment, fingerprints (the pin), leak / duplicate / dangling-expectation findings")
    esv.add_argument("--json", action="store_true")
    esv.add_argument("--root", default=argparse.SUPPRESS, help="repository root that holds evals/ and knowledge/ (default: --root of the command)")
    aim = sub.add_parser("ai-impact", help="the AI impact assessment (export of existing artifacts): print it, --write it to docs/, or --check the committed copy for staleness (exit 1)")
    aim.add_argument("--check", action="store_true", help="gate the committed docs/AI_IMPACT_ASSESSMENT.md: sections, cited paths, cited AC ids, version stamp")
    aim.add_argument("--write", default=None, metavar="PATH", help="write the freshly resolved assessment here (default path is docs/AI_IMPACT_ASSESSMENT.md)")
    aim.add_argument("--json", action="store_true")
    es = sub.add_parser("escalations", help="the chat handoff log: list open / resolved escalations, or resolve one with the reviewer's note")
    es.add_argument("--status", default="all", choices=("all", "open", "resolved"))
    es.add_argument("--resolve", default=None, metavar="ID", help="close the escalation E-xxxxxxxx (needs --note and --by)")
    es.add_argument("--note", default=None, help="the reviewer's note: what was decided and why")
    es.add_argument("--by", default=None, help="who resolved it")
    ev(es)
    cv = sub.add_parser("coverage", help="decision coverage: which advisories a standing decision or a verified plan already handles, and the worklist")
    cv.add_argument("project", help="project record file, or a project name in the evidence folder")
    cv.add_argument("--triage", default=None, help="decision store (default: <evidence>/.triage.json)")
    ev(cv)
    ss = sub.add_parser("srcscan", help="FOSSLight-style source scan: SPDX tags, copyright lines and license files, per file (read-only, bounded)")
    ss.add_argument("folder", help="LOCAL source folder to scan")
    ss.add_argument("--json", action="store_true")
    bs = sub.add_parser("binscan", help="FOSSLight-style binary scan: binary list + embedded license/copyright string evidence (no binary DB - evidence, not identification)")
    bs.add_argument("folder", help="LOCAL source folder to scan")
    bs.add_argument("--json", action="store_true")
    sc = sub.add_parser("selfcheck", help="FOSSLight-style self-check sheet (CSV) of an analysed project: OSS name/version/license per component, unresolved left empty")
    sc.add_argument("project", help="project record file, or a project name in the evidence folder")
    sc.add_argument("--out", default=None, help="write the CSV here (default: print)")
    ev(sc)
    tr = sub.add_parser("trace", help="AC | EARS pattern | spec section (module) | test traceability matrix")
    tr.add_argument("--format", default="md", choices=("md", "json"))
    tr.add_argument("--out", default=None, help="write the rendered matrix here (default: print)")
    tr.add_argument("--root", default=argparse.SUPPRESS, help="repository root to read specs/ and tests/ from (default: --root of the command)")
    pf = sub.add_parser("portfolio", help="week-7 portfolio package: export paths/sizes/hashes of the project's own files (writes nothing new)")
    pf_sub = pf.add_subparsers(dest="portfolio_cmd", required=True)
    pfe = pf_sub.add_parser("export", help="write portfolio-manifest.json + README.md under --out")
    pfe.add_argument("--out", required=True, help="folder to write portfolio-manifest.json and README.md into")
    pfe.add_argument("--root", default=argparse.SUPPRESS, help="repository root to collect the portfolio from (default: --root of the command)")
    pfe.add_argument("--json", action="store_true")
    pr = sub.add_parser("proof", help="run pytest / speclint / doclint (if present) / evalrag and record PASS/FAIL/NOT RUN evidence "
                                      "(NOT RUN is never counted as PASS)")
    pr.add_argument("--out", default=None, help="evidence sidecar folder (default: <repo>/evidence/proof)")
    pr.add_argument("--only", default=None, choices=PROOF_COMMAND_NAMES, help="run just this one command")
    pr.add_argument("--json", action="store_true")


def _evidence(a: argparse.Namespace) -> str:
    return a.evidence or os.path.join(a.root, "evidence", "runs")


def _say(obj: Any, as_json: bool, text: str) -> None:
    print(json.dumps(obj, ensure_ascii=True, indent=1, default=str) if as_json else console_text(text))


def _record(ref: str, evidence: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """(path-or-folder, record) for a record file or a project name; (None, None) when neither resolves."""
    from .cli import project_records
    if os.path.isfile(ref):
        obj = read_json(ref, None)
        return ref, obj if isinstance(obj, dict) else None
    hit = project_records(evidence).get(ref)
    return (hit[0], hit[1]) if hit else (None, None)


def _store(a: argparse.Namespace) -> Dict[str, Any]:
    path = a.triage or os.path.join(_evidence(a), ".triage.json")
    d = read_json(path, {})
    return d if isinstance(d, dict) else {}


def run(a: argparse.Namespace) -> int:
    if a.cmd == "conformance":
        evidence = _evidence(a)
        path = a.source
        if not os.path.isfile(path):
            folder, rec = _record(a.source, evidence)
            if folder is None:
                print("ERROR: %r is neither a file nor a project in %s" % (a.source, evidence), file=sys.stderr)
                return 2
            path = os.path.join(folder, os.path.basename(folder) + ".json")
        doc, note = conformance.load_document(path)
        if doc is None:
            print("ERROR: " + note, file=sys.stderr)
            return 2
        res = conformance.evaluate(doc, a.regime)
        _say(res, a.json, conformance.render_md(res))
        if a.require and res.get("regimes", {}).get(a.require, {}).get("verdict") != "conformant":
            return 1
        return 0
    if a.cmd == "diff":
        evidence = _evidence(a)
        try:
            if a.after is None:
                folder, rec = _record(a.before, evidence)
                if folder is None:
                    print("ERROR: %r is not a project in %s (give two files, or a project name)" % (a.before, evidence), file=sys.stderr)
                    return 2
                base = os.path.basename(folder)
                prev = read_json(os.path.join(folder, base + ".prev.json"), None)
                if not isinstance(prev, dict):
                    print("ERROR: %s has no previous analysis to compare with (it is analysed once so far)" % a.before, file=sys.stderr)
                    return 2
                d = changes.diff(prev, rec, threshold=a.threshold)
            else:
                d = changes.diff(changes.load(a.before), changes.load(a.after), threshold=a.threshold)
        except ValueError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
        text = changes.render_md(d)
        if a.brief or a.llm:
            if a.llm_config:
                os.environ["BTS_SBOM_LLM_CONFIG"] = a.llm_config
            client = ChatClient.from_env(ledger=os.path.join(a.root, "evidence", ".llm_ledger.json")) if a.llm else None
            b = changes.brief(d, client=client if client is not None and client.available else None, use_llm=a.llm)
            d["brief"] = b
            text = b["text"] + (("\n\nnote: " + b["llm_note"]) if b["llm_note"] else "")
        _say(d, a.json, text)
        return 1 if a.fail_on_alert and any(x["severity"] in ("critical", "high") for x in d["alerts"]) else 0
    if a.cmd in ("vex", "review"):
        folder, rec = _record(a.project, _evidence(a))
        if rec is None:
            print("ERROR: %r is not a project in %s" % (a.project, _evidence(a)), file=sys.stderr)
            return 2
        store = _store(a)
        if a.cmd == "review":
            rows = triage.review_candidates(rec, store)
            _say({"project": rec.get("name"), "candidates": rows}, a.json,
                 "\n".join(["%d finding(s) with a weaker match in %s (a worklist, not a verdict):" % (len(rows), rec.get("name"))] +
                           ["- %s %s %s: %s" % (x["id"], x["package"], x["version"], "; ".join(x["reasons"])) for x in rows]))
            return 0
        today: Optional[datetime.date] = None
        if a.today:
            today = triage.parse_date(a.today)
            if today is None:
                print("ERROR: --today must be YYYY-MM-DD", file=sys.stderr)
                return 2
        doc = sbom.openvex(rec["name"], rec.get("vulns") or [], triage=store, today=today)
        ev = triage.evaluate(rec.get("vulns") or [], store, today=today)
        if a.out:
            write_json(a.out, doc)
        print(console_text("triage: %s; stale decisions: %d" % (", ".join("%s %d" % kv for kv in ev["counts"].items() if kv[1]) or "no findings", len(ev["stale"]))),
              file=sys.stderr)
        for x in ev["rejected"] + ev["expired"]:
            print(console_text("  not applied: %s %s - %s" % (x["id"], x["package"], x.get("issue") or "expired " + x.get("expires", ""))), file=sys.stderr)
        if not a.out:
            print(json.dumps(doc, ensure_ascii=a.json, indent=1))
        return 0
    if a.cmd == "govgate":
        from . import govgate
        res = govgate.evaluate(a.root)
        _say(res, a.json, govgate.render(res))
        return 0 if res["ok"] else 1
    if a.cmd == "secretscan":
        from . import secretscan
        if not os.path.isdir(a.folder):
            print("ERROR: %r is not a folder" % a.folder, file=sys.stderr)
            return 2
        findings, summary = secretscan.scan_tree(a.folder)
        text = ["secretscan %s: %d finding(s) in %d file(s) scanned; skipped %d (binary %d, oversized %d, unreadable %d)%s" % (
            summary["root"], len(findings), summary["files_scanned"], summary["files_skipped_total"], summary["files_skipped_binary"],
            summary["files_skipped_oversized"], summary["files_skipped_unreadable"], " - COVERAGE LIMITED: 0 findings is not a clean result" if summary["coverage_limited"] else "")]
        text += ["  %s:%d [%s]" % (f["file"], f["line"], f["rule"]) for f in findings[:max(0, a.max)]]
        if len(findings) > a.max:
            text.append("  ... %d more (use --json)" % (len(findings) - a.max))
        _say({"findings": findings, "summary": summary}, a.json, "\n".join(text))
        return 1 if findings or summary["coverage_limited"] else 0
    if a.cmd == "audit":
        folder, rec = _record(a.project, _evidence(a))
        if rec is None:
            print("ERROR: %r is neither a record file nor a project in %s" % (a.project, _evidence(a)), file=sys.stderr)
            return 2
        if a.kind == "licenses":
            from . import licenses as licmod
            res = licmod.audit_sample(rec.get("components") or [], frac=a.frac, seed=a.seed)
            text = ["licence audit queue of %s: %d component(s) sampled from %d resolution source(s) (seed %d)" % (rec.get("name"), len(res["queue"]), len(res["by_source"]), a.seed)]
            text += ["  %s: %d sampled of %d resolved" % (s, res["sampled"].get(s, 0), n) for s, n in sorted(res["by_source"].items())]
            text += ["    review: %s@%s license=%s source=%s" % (c.get("name"), c.get("version"), c.get("license"), c.get("license_source")) for c in res["queue"][:40]]
        else:
            res = triage.stratified_audit(rec.get("vulns") or [], _store(a), seed=a.seed, margin=a.margin, confidence=a.confidence)
            text = ["triage audit queue of %s: %d of %d closed decision(s) sampled across %d severity lane(s) (seed %d, margin %s, confidence %s)" % (
                rec.get("name"), len(res["queue"]), res["closed_total"], len(res["lanes"]), a.seed, a.margin, a.confidence)]
            text += ["  %s: %d sampled of %d closed" % (lane, res["sampled"].get(lane, 0), n) for lane, n in sorted(res["by_lane"].items())]
            text += ["    re-review: %s %s (%s)" % (f.get("id"), f.get("package"), (f.get("triage") or {}).get("state")) for f in res["queue"][:40]]
        _say(res, a.json, "\n".join(text))
        return 0
    if a.cmd == "access-token":
        from . import access
        tok = access.generate()
        _say({"token": tok, "env": access.ENV, "min_length": access.MIN_LENGTH}, a.json, tok)
        return 0
    if a.cmd == "prompts":
        from . import evalguard, evals, promptreg
        if a.update:
            try:
                done = promptreg.update(a.root, a.reason, eval_pins={n: evalguard.fingerprint(g) for n, g in evals.rag_set_items(a.root).items()},
                                        require_loop_evidence=a.require_loop_evidence, loop_fingerprint=a.loop_fingerprint)
            except ValueError as exc:
                print("ERROR: %s" % exc, file=sys.stderr)
                return 2
            _say(done, a.json, "pinned %d prompt(s); changed: %s; digest %s" % (done["pinned"], ", ".join(done["changed"]) or "none", done["digest"]))
            return 0
        st = promptreg.check(a.root)
        lines = ["%d prompt(s) in the code, %d pinned, digest %s: %s" % (st["prompts"], st["pinned"], st["digest"], "ok" if st["ok"] else "DRIFT")]
        lines += ["  changed  %s (pinned %s, now %s)" % (d["id"], d["pinned"], d["now"]) for d in st["drift"]]
        lines += ["  unpinned %s" % p for p in st["unpinned"]] + ["  missing  %s (pinned, no longer in the code)" % p for p in st["missing"]]
        lines += ["  version  %s changed but %s kept its PROMPT_VERSION: bump it before re-pinning" % (v["id"], v["version"]) for v in st["version_not_bumped"]]
        if not st["ok"]:
            lines.append('review the change, run the evals, then: bts-sbom-app prompts --update --reason "<what changed and why>"')
        _say(st, a.json, "\n".join(lines))
        return 0 if st["ok"] else 1
    if a.cmd == "ai-impact":
        from . import ai_impact
        if a.check:
            r = ai_impact.gate(a.root)
            _say(r, a.json, "\n".join(["ai-impact gate: %s (%s)" % ("ok" if r["ok"] else "FAIL", ai_impact.DOC_PATH)] +
                                      ["  stale: %s" % f for f in r["findings"]]))
            return 0 if r["ok"] else 1
        payload = ai_impact.assess(a.root)
        md = ai_impact.render(payload)
        if a.write:
            path = a.write if os.path.isabs(a.write) else os.path.join(a.root, a.write)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(md)
            print("wrote %s" % path)
            return 0
        _say(payload, a.json, md)
        return 0
    if a.cmd == "evalsets":
        from . import evalguard, evals
        rep = evals.eval_integrity(a.root)
        lines = ["eval sets in %s" % a.root]
        for name, c in rep["sets"].items():
            lines.append("- %s: %d item(s) (%d in-domain, %d out-of-domain), fingerprint %s%s" % (
                name, c["n"], c["in_domain"], c["ood"], c["fingerprint"], ("; no in-domain query in " + ", ".join(c["missing"])) if c["missing"] else ""))
            lines.append("    thin segments (n < %d, reported but not gated): %s" % (evalguard.MIN_SEGMENT_N, ", ".join(c["thin"]) or "none"))
        lk = rep["leak"]
        lines.append("leak check: %d blocking, %d warning" % (lk["blocking"], lk["warnings"]))
        lines += ["  [%s] %s" % (f["severity"], evalguard.describe(f)) for f in lk["findings"]]
        inv = evals.eval_inventory(a.root)                          # the course's holdout 구성표: 전형/경계/적대 over EVERY declared corpus
        rep["inventory"] = inv
        lines.append("composition (전형/경계/적대):")
        for name, c in inv["sets"].items():
            k = c["kinds"]
            lines.append("  - %s: typical %d, boundary %d, adversarial %d (rules: %s)" % (
                name, k.get("typical", 0), k.get("boundary", 0), k.get("adversarial", 0),
                ", ".join("%s=%d" % (r, n) for r, n in sorted(c["kind_rules"].items()) if n)))
            lines += ["    NOTE: %s" % t for t in inv["coverage_gate"]["notes"] if t.startswith(name + ":")]
        lines += ["  FAIL: %s" % f for f in inv["coverage_gate"]["failed"]]
        cg_pass = inv["coverage_gate"]["pass"]
        lines.append("coverage gate: %s" % ("pass" if cg_pass else "FAIL (%d)" % len(inv["coverage_gate"]["failed"])))
        dev = evals.injection_guard_eval(a.root)
        hold_items = []
        try:
            with open(os.path.join(a.root, "evals", "injection_holdout.jsonl"), encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    try:
                        rec_ = json.loads(ln)
                    except ValueError:
                        continue
                    if isinstance(rec_, dict):
                        hold_items.append(rec_)
        except OSError:
            pass
        hold = evalguard.injection_eval(hold_items) if hold_items else None
        inj_ok = None if hold is None else bool(hold["recall"] is not None and hold["recall"] >= 0.90 and (hold["benign_false_positive_rate"] or 0.0) <= 0.05)   # None: not measured here, not a pass and not a failure of THIS folder
        rep["injection"] = {"dev": dev, "holdout": hold, "gate": {"min_recall": 0.90, "max_false_positive_rate": 0.05, "pass": inj_ok}}
        lines.append("injection guard: dev recall %s precision %s fp-rate %s | holdout %s (gate: recall >= 0.90 and false-positive rate <= 0.05 on the HOLDOUT -> %s)" % (
            dev["recall"], dev["precision"], dev["benign_false_positive_rate"],
            ("recall %s precision %s fp-rate %s" % (hold["recall"], hold["precision"], hold["benign_false_positive_rate"])) if hold else "NOT MEASURED (evals/injection_holdout.jsonl missing)",
            "pass" if inj_ok else ("not measured" if inj_ok is None else "FAIL")))
        en = evals.rag_en_eval(a.root)
        rep["english"] = en
        lines.append("English retrieval (probe, not loop-gated): recall@5 %s MRR %s found %s OOD rejection %s (n=%s in-domain + %s out-of-domain)" % (
            en["recall_at_k"], en["mrr"], en["found_rate"], en["ood_rate"], en["queries"], en["ood_queries"]))
        _say(rep, a.json, "\n".join(lines))
        return 1 if lk["blocking"] or inj_ok is False or not cg_pass else 0
    if a.cmd == "escalations":
        from . import escalation as escmod
        evidence = _evidence(a)
        if a.resolve:
            try:
                done = escmod.resolve(evidence, a.resolve, a.note, a.by)
            except KeyError:
                print("ERROR: unknown escalation %s" % a.resolve, file=sys.stderr)
                return 2
            except ValueError as exc:
                print("ERROR: %s" % exc, file=sys.stderr)
                return 2
            _say({"id": a.resolve, **done}, a.json, "resolved %s by %s: %s" % (a.resolve, done["resolution"]["by"], done["resolution"]["note"]))
            return 0
        rows = [(i, s) for i, s in sorted(escmod.load(evidence).items()) if a.status == "all" or s["status"] == a.status]
        text = "\n".join(["%d escalation(s) (%s) in %s" % (len(rows), a.status, evidence)] + [
            "- %s [%s] %s -> %s (project %s): %s" % (i, s["status"], s["payload"].get("trigger"), s["payload"].get("destination"), s["payload"].get("project") or "-",
                                                  (s["payload"].get("triggering_question") or "")[:70]) for i, s in rows])
        _say({"escalations": [dict(s, id=i) for i, s in rows]}, a.json, text)
        return 0
    if a.cmd == "fleet":
        from .cli import load_projects
        projs = load_projects(_evidence(a))
        if not projs:
            print("ERROR: no analysed project in %s" % _evidence(a), file=sys.stderr)
            return 2
        if a.cve or a.component:
            try:
                res = fleet.affected(projs, vuln_id=a.cve, component=a.component, version=a.version)
            except ValueError as exc:
                print("ERROR: %s" % exc, file=sys.stderr)
                return 2
            _say(res, a.json, fleet.render_affected_md(res))
            return 0
        res = fleet.rollup(projs)
        _say(res, a.json, fleet.render_rollup_md(res))
        return 0
    if a.cmd == "coverage":
        folder, rec = _record(a.project, _evidence(a))
        if rec is None:
            print("ERROR: %r is neither a record file nor a project in %s" % (a.project, _evidence(a)), file=sys.stderr)
            return 2
        c = coverage.build(rec, _store(a))
        _say(coverage.compact(c), a.json, coverage.to_md(c))
        return 0
    if a.cmd in ("srcscan", "binscan"):
        try:
            c = srcscan.build(a.folder) if a.cmd == "srcscan" else binscan.build(a.folder)
        except ValueError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
        mod = srcscan if a.cmd == "srcscan" else binscan
        _say(c, a.json, mod.to_md(c))
        return 0
    if a.cmd == "selfcheck":
        folder, rec = _record(a.project, _evidence(a))
        if rec is None:
            print("ERROR: %r is neither a record file nor a project in %s" % (a.project, _evidence(a)), file=sys.stderr)
            return 2
        csv_text = selfcheck.to_csv(rec)
        if a.out:
            with open(a.out, "w", encoding="utf-8", newline="") as fh:      # a CSV is text, not JSON: written directly
                fh.write(csv_text)
            print(console_text("self-check sheet written to %s (%d rows)" % (a.out, selfcheck.build(rec)["components"])))
        else:
            _say(selfcheck.build(rec), a.json, csv_text)
        return 0
    if a.cmd == "trace":
        try:
            result = traceability.build(a.root)
        except ValueError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
        text = traceability.render_md(result) if a.format == "md" else traceability.render_json(result)
        if a.out:
            with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print(console_text("traceability matrix (%s) written to %s (%d AC)" % (a.format, a.out, result["summary"]["ac_count"])))
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return 0
    if a.cmd == "portfolio":
        if a.portfolio_cmd == "export":
            manifest = portfolio.export(a.root, a.out)
            kinds = {p["n"]: p["status"] for p in manifest["packages"]}
            _say(manifest, a.json, "portfolio exported to %s: %s" % (
                a.out, ", ".join("#%d=%s" % (n, kinds[n]) for n in sorted(kinds))))
            return 0
        return 2
    if a.cmd == "proof":
        try:
            doc = portfolio.proof(a.root, out_dir=a.out, only=a.only)
        except ValueError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
        _say(doc, a.json, "proof %s: PASS=%d FAIL=%d NOT RUN=%d" % (
            doc["status"], doc["counts"]["PASS"], doc["counts"]["FAIL"], doc["counts"]["NOT RUN"]))
        return 0 if doc["status"] == "pass" else 1
    return 2


# ------------------------------------------------------------------ chat (read-only by default; --actions opens the gated actions)
def add_chat_flags(c: argparse.ArgumentParser) -> None:
    c.add_argument("--actions", action="store_true", help="let the chat analyse sources, apply an APPROVED patch (token typed by you) and record VEX decisions "
                                                          "(confirm code typed by you); nothing is pushed and the origin is never written")
    c.add_argument("--work", default=None, help="folder for work copies (default: a temp folder per action)")
    c.add_argument("--offline", action="store_true", help="analyses started from the chat do not query the network")
    c.add_argument("-i", "--interactive", action="store_true", help="keep asking: one question per line until an empty line or EOF")


def chat_main(a: argparse.Namespace) -> int:
    from . import actions as actionsmod, chat as chatmod, evals
    from .cli import _client, _print, evidence_chunks, load_projects
    evidence = a.evidence or (os.path.join(a.root, "evidence", "runs") if a.actions else None)
    if not a.question and not a.interactive:
        print("ERROR: give a question, or --interactive", file=sys.stderr)
        return 2
    projs = load_projects(evidence) if evidence else {}
    client = _client(a.root, not a.llm, getattr(a, "llm_config", None))
    acts = actionsmod.ChatActions(a.root, evidence, client=client, work_root=a.work, offline=a.offline, use_llm=bool(a.llm)) if a.actions else None
    store = read_json(os.path.join(evidence, ".triage.json"), {}) if evidence else {}
    bot = chatmod.Chatbot(evals.build_index(a.root, evidence_chunks(projs)), projs, client, acts, store if isinstance(store, dict) else {})

    def one(q: str) -> None:
        r = bot.ask(q, project=a.project, use_llm=bool(a.llm))
        note = (" note=" + r["llm_note"]) if r.get("llm_note") else ""
        partial = (" status=partial (failed tool(s): %s)" % ", ".join(str(t.get("tool")) for t in r.get("tool_errors") or [])) if r.get("status") == "partial" else ""
        _print(r, a.json, "found=%s source=%s citation_accuracy=%s%s%s\n%s" % (r["found"], r["answer_source"], r["citation_accuracy"], note, partial, r["answer"]))

    if a.question:
        one(a.question)
    if a.interactive:
        print(console_text("actions %s - type a question, empty line to stop" % ("ON (each gated)" if acts else "off (read-only)")))
        for line in sys.stdin:
            if not line.strip():
                break
            one(line.strip())
    return 0

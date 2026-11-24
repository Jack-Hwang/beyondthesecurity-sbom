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

COMMANDS = ("conformance", "diff", "vex", "review", "fleet", "coverage", "srcscan", "binscan", "selfcheck",
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
        _print(r, a.json, "found=%s source=%s citation_accuracy=%s%s\n%s" % (r["found"], r["answer_source"], r["citation_accuracy"], note, r["answer"]))

    if a.question:
        one(a.question)
    if a.interactive:
        print(console_text("actions %s - type a question, empty line to stop" % ("ON (each gated)" if acts else "off (read-only)")))
        for line in sys.stdin:
            if not line.strip():
                break
            one(line.strip())
    return 0

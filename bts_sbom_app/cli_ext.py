"""Command line for the SBOM-governance features: conformance | diff | vex | review | fleet.

Kept apart from ``cli.py`` (scan / patch / batch / loop / chat / serve) so the two can evolve independently; ``cli.main`` hands
these sub-commands over. Everything here reads existing evidence or SBOM files: nothing is scanned, pushed or sent.
"""
from __future__ import annotations

import argparse
import datetime
import json
import tempfile
import os
import sys
from typing import Any, Dict, Optional, Tuple

from . import binscan, changes, conformance, coverage, fleet, sbom, selfcheck, srcscan, triage
from .llm import ChatClient
from .util import console_text, read_json, write_json

COMMANDS = ("conformance", "diff", "vex", "review", "fleet", "coverage", "srcscan", "binscan", "selfcheck", "trace", "portfolio", "proof", "verify-dev", "obligations", "legacy", "alternatives", "migration", "codeprop", "vnv", "evidence", "reconcile", "handover")


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


def _obligations_md(res: dict, only: Optional[str]) -> str:
    from .obligations import DISCLAIMER
    L = ["# Obligations", "", "_%s_" % DISCLAIMER, ""]
    scen = ("--distribution", ) if False else ([only] if only else ["internal", "binary", "saas"])
    for s in scen:
        sc = (res.get("scenarios") or {}).get(s) or {}
        L += ["## %s — %s" % (s, sc.get("status")), "", "offer=%(source_offer)s review=%(review)s unknown=%(unknown)s none=%(none)s" % (sc.get("counts") or {}), ""]
        for row in sc.get("components") or []:
            L.append("- %s %s (%s): **%s** scope=%s — %s" % (row.get("name"), row.get("version"), row.get("license"), row.get("verdict"), row.get("scope"), row.get("why")))
        L.append("")
    if only and (res.get("scenarios") or {}).get(only):
        res = dict(res, scenarios={only: res["scenarios"][only]})
    return chr(10).join(L) + chr(10)


def _legacy_text(res: dict) -> str:
    from .legacy import DISCLAIMER
    s = res.get("summary") or {}
    L = ["# Legacy assessment", "", "_%s_" % DISCLAIMER,
         "high=%(high)s medium=%(medium)s low=%(low)s unknown=%(unknown)s | eol=%(eol)s no_upstream_fix=%(no_upstream_fix)s" % s, ""]
    for row in res.get("rows") or []:
        eol = (row.get("eol") or {}) or {}
        L.append("- %s %s: risk **%s** (eol=%s/%s, no_upstream_fix=%s, advisories=%s) %s" % (
            row.get("component"), row.get("version"), row.get("risk"), eol.get("status"), eol.get("source"),
            row.get("no_upstream_fix"), row.get("advisories"), "; ".join(row.get("reasons") or [])))
    return chr(10).join(L) + chr(10)


def run(a: argparse.Namespace) -> int:
    if a.cmd == "trace":
        from . import traceability
        root = a.root or os.getcwd()
        matrix = traceability.build(root)
        if a.out:
            text = traceability.render_json(matrix) if a.format == "json" else traceability.render_md(matrix)
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print("traceability matrix written: %s" % a.out)
            return 0
        print(traceability.render_md(matrix))
        return 0
    if a.cmd == "portfolio":
        from . import portfolio
        manifest = portfolio.export(a.root or os.getcwd(), a.out)
        print("portfolio manifest: %s (%d packages)" % (os.path.join(a.out, "manifest.json"), len(manifest["packages"])))
        return 0
    if a.cmd == "proof":
        from . import proof
        record = proof.run(only=a.only, out_dir=a.out)
        print("proof: %s (%s)" % (record["overall"].upper(), ", ".join("%s=%s" % (r["name"], r["status"]) for r in record["results"])))
        return 0 if record["overall"] == "pass" else (1 if record["overall"] == "fail" else 2)
    if a.cmd == "verify-dev":
        from . import verifydev
        return verifydev.run(base_url=a.base_url or "", token=a.token or "", out_dir=a.out)
    if a.cmd == "obligations":
        from . import obligations
        evidence = _evidence(a)
        _folder, rec = _record(a.project, evidence)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence), file=sys.stderr)
            return 2
        res = rec.get("obligations") or obligations.assess(rec.get("components") or [],
                                                           project_license=(rec.get("license") or {}).get("project_license", ""), computed_on_read=True)
        md = _obligations_md(res, a.distribution)
        _say(res, a.json, md)
        return 0
    if a.cmd == "handover":
        from . import handover
        evidence_dir = _evidence(a)
        _folder, rec = _record(a.project, evidence_dir)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence_dir), file=sys.stderr)
            return 2
        base_dir = os.path.join(_folder or ".", "handover")
        if a.post:
            frozen = handover.load(base_dir)
            if frozen is None:
                print("ERROR: no frozen baseline in %s - run handover --freeze first" % base_dir, file=sys.stderr)
                return 2
            res = handover.post_handover(rec, frozen)
        else:
            res = handover.freeze(rec, base_dir)
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "reconcile":
        from . import reconcile
        evidence_dir = _evidence(a)
        _folder, rec = _record(a.project, evidence_dir)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence_dir), file=sys.stderr)
            return 2
        if not a.sbom or not os.path.isfile(a.sbom):
            print("ERROR: give --sbom <path to the provider SBOM json>", file=sys.stderr)
            return 2
        doc = json.load(open(a.sbom, encoding="utf-8"))
        res = reconcile.reconcile(doc, rec)
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "evidence":
        from . import evidence
        evidence_dir = _evidence(a)
        _folder, rec = _record(a.project, evidence_dir)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence_dir), file=sys.stderr)
            return 2
        manifest = evidence.bundle(rec, os.path.join(_folder or ".", "bundle"))
        print(json.dumps(manifest, ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "vnv":
        from . import vnv
        evidence = _evidence(a)
        _folder, rec = _record(a.project, evidence)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence), file=sys.stderr)
            return 2
        res = rec.get("vnv") or vnv.report(rec, plan_ref=a.plan_ref, req_ref=a.req_ref)
        if a.out:
            with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(vnv.render_md(res))
            print("vnv report written: %s" % a.out)
        else:
            print(vnv.render_md(res))
        return 0
    if a.cmd == "codeprop":
        from . import codeprop
        if a.apply:
            if not a.source or not a.token:
                print("ERROR: --apply needs --source DIR and --token <digest of the diff>", file=sys.stderr)
                return 2
            proposal = json.load(open(a.proposal_file, encoding="utf-8")) if getattr(a, "proposal_file", None) else None
            if proposal is None:
                print("ERROR: --apply needs --proposal-file <saved proposal json>", file=sys.stderr)
                return 2
            res = codeprop.apply(a.source, proposal, a.token, a.work or tempfile.mkdtemp(prefix="bts_sbom_codeprop_"))
            print(json.dumps(res, ensure_ascii=False, indent=1))
            return 0 if res.get("applied") else 1
        source = a.source
        if not source and a.project:
            _folder, rec = _record(a.project, _evidence(a))
            if rec is None:
                print("ERROR: unknown project %r" % a.project, file=sys.stderr)
                return 2
            proposals = codeprop.list_proposals(os.path.join(_folder or "", "codeprop"))
            print(json.dumps({"proposals": proposals, "note": "read-only; propose from a local source with --source DIR"}, ensure_ascii=False, indent=1))
            return 0
        if not source:
            print("ERROR: give --source DIR (a local folder) to propose edits", file=sys.stderr)
            return 2
        client = None
        if a.llm_config:
            from .cli import _client
            client = _client(os.getcwd(), False, a.llm_config)
        res = codeprop.propose(source, a.component, to_version=a.to or "", client=client)
        if res.get("status") == "proposed" and a.project:
            _folder, _rec = _record(a.project, _evidence(a))
            if _folder:
                res["diff_path"] = codeprop.save_diff(os.path.join(_folder, "codeprop"), res["id"], res["diff"])
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0 if res.get("status") == "proposed" else 1
    if a.cmd == "migration":
        from . import migration
        evidence = _evidence(a)
        _folder, rec = _record(a.project, evidence)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence), file=sys.stderr)
            return 2
        res = rec.get("migration") or migration.plan(rec, root=a.source)
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "alternatives":
        from . import alternatives
        evidence = _evidence(a)
        _folder, rec = _record(a.project, evidence)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence), file=sys.stderr)
            return 2
        if rec.get("alternatives") and not a.online:
            res = rec["alternatives"]
        else:
            client = None
            if a.llm_config:
                from .cli import _client
                client = _client(os.getcwd(), False, a.llm_config)
            res = alternatives.suggest([], table=alternatives.load_table(), client=client, online=bool(a.online))
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0
    if a.cmd == "legacy":
        from . import legacy
        evidence = _evidence(a)
        _folder, rec = _record(a.project, evidence)
        if rec is None:
            print("ERROR: unknown project %r in %s" % (a.project, evidence), file=sys.stderr)
            return 2
        res = rec.get("legacy") or legacy.assess(rec.get("components") or [], rec.get("plans") or [], online=bool(a.online))
        blob = json.dumps(res, ensure_ascii=False, indent=1)
        print(blob if a.json else _legacy_text(res))
        return 0
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
    return 2


# ------------------------------------------------------------------ chat (read-only by default; --actions opens the gated actions)
def add_commands_ext(sub: Any) -> None:
    """The traceability/portfolio/proof/verify-dev sub-commands (task 5b/22); earlier commands are untouched."""

    def ev(p: argparse.ArgumentParser) -> None:
        p.add_argument("--evidence", default=None, help="evidence folder of analysed projects (default: <repo>/evidence/runs)")
        p.add_argument("--json", action="store_true")

    tr = sub.add_parser("trace", help="traceability matrix (AC <-> pattern <-> section <-> tests)")
    tr.add_argument("--format", default="md", choices=["md", "json"])
    tr.add_argument("--out", default=None)
    tr.add_argument("--root", default=None)
    po = sub.add_parser("portfolio", help="export the 8 portfolio packages as a manifest (paths + hashes)")
    po.add_argument("--out", required=True)
    po.add_argument("--root", default=None)
    pf = sub.add_parser("proof", help="run the verification commands and classify PASS/FAIL/NOT RUN")
    pf.add_argument("--out", default=".")
    pf.add_argument("--only", default=None)
    vd = sub.add_parser("verify-dev", help="verify a deployment (DEV_BASE_URL); missing deployment = NOT RUN, exit 2")
    vd.add_argument("--base-url", default=None)
    vd.add_argument("--token", default=None)
    vd.add_argument("--out", default=".")
    ob = sub.add_parser("obligations", help="per-component source-disclosure duties by use scenario (reference rules, not legal advice)")
    ob.add_argument("project")
    ob.add_argument("--distribution", default=None, choices=["internal", "binary", "saas"])
    ev(ob)
    lg = sub.add_parser("legacy", help="legacy / EOL component assessment (offline by default)")
    lg.add_argument("project")
    lg.add_argument("--online", action="store_true")
    ev(lg)
    al = sub.add_parser("alternatives", help="replacement candidates (evidence table + verified AI candidates)")
    al.add_argument("project")
    al.add_argument("--llm-config", default=None)
    al.add_argument("--online", action="store_true")
    ev(al)
    mg = sub.add_parser("migration", help="migration / upgrade impact plan with waves")
    mg.add_argument("project")
    mg.add_argument("--source", default=None)
    ev(mg)
    cp = sub.add_parser("codeprop", help="code-edit proposals (propose only; apply needs the diff digest token)")
    cp.add_argument("project", nargs="?", default=None)
    cp.add_argument("--source", default=None)
    cp.add_argument("--component", required=True)
    cp.add_argument("--to", default=None)
    cp.add_argument("--llm-config", default=None)
    vn = sub.add_parser("vnv", help="V&V evidence report in the TR 8477 8.1 shape (pass / pass with restrictions / fail)")
    vn.add_argument("project")
    vn.add_argument("--plan-ref", default="")
    vn.add_argument("--req-ref", default="")
    vn.add_argument("--out", default=None)
    ev(vn)
    eb = sub.add_parser("evidence", help="evidence bundle: SHA-256 manifest of the SBOM/VEX/record/report artifacts")
    eb.add_argument("project")
    ev(eb)
    rc = sub.add_parser("reconcile", help="cross-check a provider SBOM against the scanned artifacts (TR 5.2)")
    rc.add_argument("project")
    rc.add_argument("--sbom", required=True, help="provider SBOM json (CycloneDX/SPDX)")
    ev(rc)
    ho = sub.add_parser("handover", help="freeze a handover baseline and flag post-handover findings (TR 4.7)")
    ho.add_argument("project")
    ho.add_argument("--freeze", action="store_true", default=True)
    ho.add_argument("--post", action="store_true", help="compare the current analysis against the frozen baseline")
    ev(ho)
    cp.add_argument("--apply", action="store_true")
    cp.add_argument("--token", default=None)
    cp.add_argument("--proposal-file", default=None)
    cp.add_argument("--work", default=None)


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

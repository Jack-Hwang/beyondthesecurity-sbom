"""Command line: scan | patch | arch | batch | loop | evalrag | evalchat | contextpack | chat | books | serve."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

from . import __version__, arch as archmod, batch, chat as chatmod, evals, loop, pipeline, rag, report, workspace
from . import cli_ext
from .llm import ChatClient
from .util import console_text, kv, read_json, write_json


def _client(root: str, no_llm: bool, cfg: Optional[str]) -> Optional[ChatClient]:
    if cfg:
        os.environ["BTS_SBOM_LLM_CONFIG"] = cfg
    if no_llm:
        return None
    c = ChatClient.from_env(ledger=os.path.join(root, "evidence", ".llm_ledger.json"))
    return c if c.available else None


def _settings(a: argparse.Namespace) -> Dict[str, Any]:
    s: Dict[str, Any] = {"offline": a.offline, "online_license": not a.no_license_online, "license_extra_registries": not a.no_license_extra, "use_llm": not a.no_llm, "lang": a.lang,
                         "arch_online": a.arch_online}
    s["engine_opts"] = {"dedupe": not a.no_dedupe, "merge_ruby_platforms": not a.no_ruby_merge, "go_mvs": not a.no_go_mvs}
    if getattr(a, "industries", None):
        s["industries"] = [x.strip() for x in a.industries.split(",") if x.strip()]
    if getattr(a, "policy", None):
        s["policy"] = read_json(a.policy, {})
    if getattr(a, "patch", False) or a.cmd == "patch":
        s.update(patch=True, approved=bool(getattr(a, "approve", False)), approval_token=getattr(a, "token", None), rounds=a.rounds,
                 deliver_target=getattr(a, "deliver", "branch"))
        kw = {k: v for k, v in (("dest", getattr(a, "dest", None)), ("remote_url", getattr(a, "remote", None)),
                                ("allow_origin_write", getattr(a, "allow_origin_write", False)), ("allow_push", getattr(a, "allow_push", False)),
                                ("open_pr", getattr(a, "open_pr", False))) if v}
        s["deliver_kw"] = kw
    return s


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", default=None, help="evidence output folder (default: <repo>/evidence/runs)")
    p.add_argument("--work", default=None, help="work-copy folder (default: a temp folder)")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--no-license-online", action="store_true")
    p.add_argument("--no-license-extra", action="store_true", help="disable the wider registry fallbacks (npm legacy licenses, Maven POM)")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--no-dedupe", action="store_true", help="keep one finding per manifest instead of merging duplicates")
    p.add_argument("--no-ruby-merge", action="store_true", help="keep RubyGems platform variants as separate components")
    p.add_argument("--no-go-mvs", action="store_true", help="treat go.sum-only module versions as installed")
    p.add_argument("--llm-config", default=None)
    p.add_argument("--lang", default="ko", choices=("ko", "en"))
    p.add_argument("--arch-online", action="store_true", help="use endoflife.date for runtime EOL")
    p.add_argument("--industries", default=None)
    p.add_argument("--policy", default=None)
    p.add_argument("--json", action="store_true")


def _patch_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--approve", action="store_true", help="apply the patch (without it only the plan is shown)")
    p.add_argument("--token", default=None, help="approval digest of the reviewed plan")
    p.add_argument("--rounds", type=int, default=2)
    p.add_argument("--deliver", default="branch", choices=("branch", "folder", "inplace", "github"))
    p.add_argument("--dest", default=None)
    p.add_argument("--allow-origin-write", action="store_true")
    p.add_argument("--remote", default=None)
    p.add_argument("--allow-push", action="store_true")
    p.add_argument("--open-pr", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="bts-sbom-app", description="BTS-SBOM license / vulnerability / architecture analysis")
    ap.add_argument("--version", action="version", version="bts_sbom_app " + __version__)
    ap.add_argument("--root", default=evals.repo_root())
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="analyse one source (git URL, owner/repo or folder)")
    s.add_argument("source"); s.add_argument("--name"); s.add_argument("--ref"); s.add_argument("--depth", type=int, default=200)
    _common(s)
    s.add_argument("--patch", action="store_true"); _patch_args(s)
    p = sub.add_parser("patch", help="plan or apply dependency fixes")
    p.add_argument("source"); p.add_argument("--name"); p.add_argument("--ref"); p.add_argument("--depth", type=int, default=200)
    _common(p); _patch_args(p)
    a = sub.add_parser("arch", help="legacy architecture analysis")
    a.add_argument("source"); a.add_argument("--ref"); a.add_argument("--depth", type=int, default=200)
    _common(a)
    b = sub.add_parser("batch", help="analyse many sources")
    b.add_argument("sources_json"); b.add_argument("--tag", default="batch"); b.add_argument("--jobs", type=int, default=1)
    b.add_argument("--patch", action="store_true"); _common(b); _patch_args(b)
    l = sub.add_parser("loop", help="run one loop-engineering pass (golden batch + RAG eval + gate)")
    l.add_argument("sources_json"); l.add_argument("--variable", required=True); l.add_argument("--hypothesis", default="")
    l.add_argument("--tag", default="pass"); l.add_argument("--jobs", type=int, default=1); l.add_argument("--patch", action="store_true")
    _common(l); _patch_args(l)
    e = sub.add_parser("evalrag", help="retrieval + chatbot grounding evaluation")
    e.add_argument("--golden", default=None); e.add_argument("--json", action="store_true")
    ec = sub.add_parser("evalchat", help="tool-routing evaluation of the governance and action tools (BSA-AC-209): regex baseline, LLM planner with --llm-config")
    ec.add_argument("--llm-config", default=None); ec.add_argument("--json", action="store_true")
    cp = sub.add_parser("contextpack", help="bounded read-only view of a LOCAL source folder: license files + import sites of one package")
    cp.add_argument("folder"); cp.add_argument("--package", default=None); cp.add_argument("--max-chars", type=int, default=60000)
    cp.add_argument("--cxml", action="store_true", help="print the rendergit-style text for an LLM chat"); cp.add_argument("--json", action="store_true")
    el = sub.add_parser("evallicense", help="license identification gold set: deterministic baseline, and the council when configured")
    el.add_argument("--council-config", default=None); el.add_argument("--max-cases", type=int, default=None); el.add_argument("--json", action="store_true")
    co = sub.add_parser("council", help="license council over the unresolved license evidence of one analysed project (suggestions only)")
    co.add_argument("--evidence", required=True); co.add_argument("--project", required=True); co.add_argument("--council-config", default=None)
    co.add_argument("--max-items", type=int, default=8); co.add_argument("--json", action="store_true")
    lg = sub.add_parser("looplog", help="render evidence/loop history as Markdown")
    lg.add_argument("--out", default=None)
    rl = sub.add_parser("ragloop", help="retrieval-only loop pass over the golden/dev/test sets")
    rl.add_argument("--variable", required=True); rl.add_argument("--hypothesis", default=""); rl.add_argument("--tag", default="rag")
    rl.add_argument("--json", action="store_true")
    bk = sub.add_parser("books", help="build the book knowledge base from a local folder of PDF/EPUB books")
    bk.add_argument("src"); bk.add_argument("--out", default=None, help="output folder (default: <root>/evidence/books)")
    bk.add_argument("--json", action="store_true")
    mc = sub.add_parser("mcp", help="serve the Model Context Protocol over stdio (JSON-RPC 2.0: tools/list, tools/call)")
    mc.add_argument("--evidence", default=None)
    c = sub.add_parser("chat", help="ask a grounded question (with --actions: analyse, patch with an approval token, record VEX decisions)")
    c.add_argument("question", nargs="?", default=None); c.add_argument("--evidence", default=None); c.add_argument("--project", default=None)
    c.add_argument("--llm", action="store_true"); c.add_argument("--llm-config", default=None); c.add_argument("--json", action="store_true")
    cli_ext.add_chat_flags(c)
    sv = sub.add_parser("serve", help="JSON API + small web UI")
    sv.add_argument("--port", type=int, default=8800); sv.add_argument("--host", default="127.0.0.1"); sv.add_argument("--evidence", default=None)
    sv.add_argument("--llm-config", default=None)
    sv.add_argument("--chat-actions", action="store_true", help="let /api/chat analyse sources, apply approved patches and record VEX decisions (each behind its confirmation)")
    cli_ext.add_commands(sub)
    return ap


def _out(a: argparse.Namespace, default_sub: str) -> str:
    return a.out or os.path.join(a.root, "evidence", default_sub)


def _print(obj: Any, as_json: bool, text: str = "") -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=True, indent=1, default=str))
    else:
        print(console_text(text))          # stream-aware: real characters when the console can show them


def project_records(evidence: str) -> Dict[str, Any]:
    """name -> (folder of the record, record). When a name occurs in several runs the last one visited wins."""
    found: Dict[str, Any] = {}
    if not evidence or not os.path.isdir(evidence):
        return found
    for dp, _, fns in os.walk(evidence):
        for fn in fns:
            if fn.endswith(".json") and not fn.endswith((".cdx.json", ".spdx.json", ".vex.json")) and os.path.basename(dp) == fn[:-5]:
                rec = read_json(os.path.join(dp, fn), None)
                if isinstance(rec, dict) and rec.get("schema") in pipeline.PROJECT_SCHEMAS_ACCEPTED and not rec.get("error"):
                    found[rec["name"]] = (dp, rec)
    return found


def load_projects(evidence: str) -> Dict[str, Dict[str, Any]]:
    return {name: rec for name, (_, rec) in project_records(evidence).items()}


def evidence_chunks(projs: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for nm, rec in projs.items():
        out.extend(rag.chunk_markdown(report.project_md(rec), "evidence/" + nm + ".md", meta={"kind": "evidence", "project": nm}))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    for st in (sys.stdout, sys.stderr):
        try:                                   # never crash on an un-encodable character; BTS_SBOM_UNICODE=1 forces UTF-8 output
            if os.environ.get("BTS_SBOM_UNICODE") == "1":
                st.reconfigure(encoding="utf-8", errors="replace")
            else:
                st.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    a = build_parser().parse_args(argv)
    if a.cmd in cli_ext.COMMANDS:
        return cli_ext.run(a)
    if a.cmd in ("scan", "patch"):
        if getattr(a, "approve", False) and not getattr(a, "token", None):
            print("note: --approve without --token applies the plan as computed now; pass --token <digest of the reviewed plan> to pin it",
                  file=sys.stderr)
        client = _client(a.root, a.no_llm, a.llm_config)
        work = a.work or tempfile.mkdtemp(prefix="bts_sbom_work_")
        rec = pipeline.run_project(a.source, work_root=work, out_dir=_out(a, "runs"), name=a.name, ref=a.ref, depth=a.depth, client=client,
                                   cache_dir=os.path.join(a.root, "evidence", "cache"), **_settings(a))
        if rec.get("error"):
            _print(rec, a.json, "ERROR: %s" % rec["error"])
            return 2
        pa = rec["patch"]
        if a.cmd == "patch" and pa.get("status") == "not_approved":
            md = report.project_md(rec) + "\n\nplan digest (use --approve --token %s): not applied" % pa.get("digest")
        else:
            md = report.project_md(rec)
        _print({k: v for k, v in rec.items() if k not in ("components", "vulns", "_docs")}, a.json, md + "\n\nwork copy: %s\nevidence: %s" % (rec.get("path"), (rec.get("artifacts") or {}).get("record")))
        if pa.get("status") in ("digest_mismatch", "regression_reverted", "blocked", "error"):
            return 1                           # a rejected / reverted patch must be visible to automation
        return 0
    if a.cmd == "arch":
        work = a.work or tempfile.mkdtemp(prefix="bts_sbom_work_")
        ws = workspace.prepare(a.source, work, ref=a.ref, depth=a.depth)
        if not ws["ok"]:
            _print(ws, a.json, "ERROR: " + ws["error"])
            return 2
        res = archmod.analyze(ws["path"], online=a.arch_online)
        txt = ["Architecture of %s" % a.source, "files %s, LOC %s" % (res["stack"]["files"], res["stack"]["loc"]), "graph: %s" % kv({k: v for k, v in res["graph"].items() if k in ("import_edges", "cycle_count", "tangle_ratio", "max_depth")})]
        txt += ["hotspot %s score %s" % (h["file"], h["score"]) for h in res["hotspots"][:5]] + ["%s %s: %s" % (m["kind"], m["target"], m["why"]) for m in res["modernization"]]
        _print(res, a.json, "\n".join(txt))
        return 0
    if a.cmd in ("batch", "loop"):
        srcs = read_json(a.sources_json, [])
        client = _client(a.root, a.no_llm, a.llm_config)
        out = _out(a, "batch")
        st = _settings(a)
        st["cache_dir"] = os.path.join(a.root, "evidence", "cache")
        if a.cmd == "batch":
            res = batch.run_batch(srcs, out, tag=a.tag, jobs=a.jobs, client=client, settings=st, work_root=a.work)
            _print(res["summary"], a.json, report.batch_md(res["summary"], res["records"]))
            return 0
        rag_e = evals.rag_eval(a.root)
        chat_e = evals.chat_eval(a.root)
        entry = loop.run_pass(a.tag, srcs, out, os.path.join(a.root, "evidence", "loop"), variable=a.variable, hypothesis=a.hypothesis, settings=st,
                              client=client, rag_eval=rag_e, chat_eval=chat_e, jobs=a.jobs, hyp_client=client, work_root=a.work)
        _print(entry, a.json, "pass %s [%s] decision=%s gate=%s\nfailed=%s undecidable=%s\nnext=%s" % (entry["pass"], a.variable, entry["decision"], entry["gate"]["pass"], entry["gate"]["failed"], entry["gate"].get("undecidable", []), [h["variable"] for h in entry["next"]["items"]]))
        return 0 if entry["decision"] != "rollback" else 1
    if a.cmd == "books":
        from . import books as booksmod
        out = a.out or os.path.join(a.root, "evidence", "books")
        t0 = time.time()
        reg = booksmod.build(a.src, out)
        t = reg.get("totals") or {}
        took = round(time.time() - t0, 1)
        txt = ["books: %s -> %s (%ss)" % (a.src, out, took),
               "files %s: ok %s, skipped %s, duplicates %s | sections %s, chars %s | pdftotext: %s" % (
                   t.get("files"), t.get("ok"), t.get("skipped"), t.get("duplicates"), t.get("sections"), t.get("chars"),
                   reg.get("pdftotext") or "NOT FOUND (pdfs skipped)")]
        for b in reg.get("books", []):
            if b.get("status") != "ok":
                why = b.get("reason") or ("duplicate of %s" % b.get("duplicate_of") or "?") if (b.get("reason") or b.get("duplicate_of")) else b.get("status")
                txt.append("  %s: %s (%s)" % (b.get("file"), b.get("status"), why))
        _print(reg, a.json, "\n".join(txt))
        return 0
    if a.cmd == "mcp":
        from . import mcp_server
        # stdout carries ONLY protocol messages (a stray line corrupts the MCP session); the banner goes to stderr
        print("bts-sbom MCP server: protocol %s, tools: %s" % (mcp_server.PROTOCOL_VERSION,
                                                               ", ".join(t["name"] for t in mcp_server.TOOL_DEFS)), file=sys.stderr)
        return mcp_server.serve_stdio(mcp_server.Session(a.root, a.evidence), sys.stdin, sys.stdout)
    if a.cmd == "evalrag":
        r = evals.rag_eval(a.root, a.golden)
        c = evals.chat_eval(a.root)
        _print({"rag": r, "chat": c}, a.json, "RAG recall@5=%s mrr=%s ndcg@5=%s ood=%s | chat found=%s routing=%s citation=%s" % (r["recall_at_k"], r["mrr"], r["ndcg_at_k"], r["ood_rate"], c["found_rate"], c["tool_routing_rate"], c["citation_accuracy"]))
        return 0 if not r["misses"] and not c["misses"] else 1
    if a.cmd == "evalchat":
        from . import evals_chat
        client = _client(a.root, False, a.llm_config) if a.llm_config else None
        r = evals_chat.governance_routing_eval(a.root, client)
        miss = "".join(" | %s -> expected %s, got %s" % (m["q"], m["expected"], ",".join(m.get("tools") or [])) for m in r["misses"][:4])
        _print(r, a.json, "%s router: %d of %d paraphrased governance/action questions reached the expected tool%s" % (
            r["router"], r["cases"] - len(r["misses"]), r["cases"], miss))
        return 0                                                  # the numbers are a measurement, not a target: the regex baseline misses on purpose
    if a.cmd == "contextpack":
        from . import contextpack
        try:
            pack = contextpack.build(a.folder, a.package, max_chars=a.max_chars)
        except ValueError as exc:
            _print({"error": str(exc)}, a.json, str(exc))
            return 2
        _print(pack, a.json, contextpack.to_cxml(pack) if a.cxml else "contextpack %s: %d items, %d import sites listed of %d, %d excluded, %d over budget, %d chars" % (
            pack["root"], len(pack["items"]), pack["import_sites_listed"], pack["import_sites_found"], len(pack["excluded"]), len(pack["dropped_over_budget"]), pack["chars"]))
        return 0
    if a.cmd == "evallicense":
        from . import council
        members, chair, note = council.members_from_config(a.council_config, os.path.join(a.root, "evidence", "llm"))
        r = evals.license_eval(a.root, members if len(members) >= 2 else None, chair, limit=a.max_cases)
        b = r["baseline"]
        line = "baseline: correct=%s confident_wrong=%s missed=%s abstained_ok=%s" % (b["correct"], b["confident_wrong"], b["missed"], b["abstained_correctly"])
        if "council" in r:
            c = r["council"]
            line += "\ncouncil: correct=%s confident_wrong=%s missed=%s abstained_ok=%s statuses=%s calls=%s conflicts=%d" % (
                c["correct"], c["confident_wrong"], c["missed"], c["abstained_correctly"], c["statuses"], c["calls"], len(c["conflicts"]))
        else:
            line += "\ncouncil: not run (%s)" % (note or "fewer than 2 members")
        _print(r, a.json, line)
        return 0
    if a.cmd == "council":
        from . import council
        found = project_records(a.evidence).get(a.project)
        if not found:
            _print({"error": "unknown project"}, a.json, "unknown project %r in %s" % (a.project, a.evidence))
            return 2
        members, chair, note = council.members_from_config(a.council_config, os.path.join(a.root, "evidence", "llm"))
        res = council.run_record(found[1], members, chair, cache_dir=os.path.join(a.root, "evidence", "llm", "council_cache"), max_items=a.max_items)
        write_json(os.path.join(found[0], "council.json"), res)
        _print(res, a.json, "council %s: %s items, statuses %s, calls %s, skipped %d%s" % (
            a.project, len(res["items"]), res["summary"], res["calls"], len(res["skipped"]), (" | " + note) if note else ""))
        return 0
    if a.cmd == "looplog":
        from . import looplog
        md = looplog.render(os.path.join(a.root, "evidence", "loop"))
        if a.out:
            with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(md)
        _print({}, False, md)
        return 0
    if a.cmd == "ragloop":
        e = loop.run_rag_pass(a.tag, os.path.join(a.root, "evidence", "loop"), a.root, variable=a.variable, hypothesis=a.hypothesis)
        _print(e, a.json, "rag pass %s [%s] decision=%s failed=%s undecidable=%s\n%s" % (e["pass"], a.variable, e["decision"], e["gate"]["failed"], e["gate"].get("undecidable", []), json.dumps(e["metrics"], sort_keys=True)))
        return 0 if e["decision"] != "rollback" else 1
    if a.cmd == "chat":
        return cli_ext.chat_main(a)
    if a.cmd == "serve":
        from . import server
        return server.serve(a.root, a.host, a.port, a.evidence or os.path.join(a.root, "evidence", "runs"), getattr(a, "llm_config", None),
                            chat_actions=bool(getattr(a, "chat_actions", False)))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

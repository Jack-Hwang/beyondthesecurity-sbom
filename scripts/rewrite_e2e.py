"""Measured end-to-end run of the SBOM -> rewrite path on REAL data (evidence/rewrite_rea/).

Inputs (all local, read-only): a real scan record (the u-boot run), the real legacy component's sdist folder
(concurrencytest 0.1.12, GPL) and the analysed project's source tree (for usage sites). The run is written to
``evidence/rewrite_rea/`` - the dossier, spec, generated code, the result record and ``E2E_RAW.json``.

    python scripts/rewrite_e2e.py --record <evidence/runs> --project u-boot --source <sdist folder> --component concurrencytest.py \
        --project-root <u-boot tree> [--llm-config <json>] [--books-root <repo checkout holding evidence/books>]

Run A: SBOM licence trigger, rea requested (absent here -> recorded absent), LLM generation when a config is given.
Run B: MECHANISM DEMO of the EOL path: an operator declaration (a demo input, NOT a measured fact about the component)
       re-runs the same lane offline (scaffold) to show the trigger kinds, the compatibility-target spec section and the
       policy-vs-legal clean-room record.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bts_sbom_app import books, rag, rea_adapter, reimpl, rewrite  # noqa: E402
from bts_sbom_app.cli import project_records  # noqa: E402
from bts_sbom_app.llm import ChatClient  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "evidence", "rewrite_rea")


def _write(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--component", required=True)
    ap.add_argument("--project-root", default=None)
    ap.add_argument("--llm-config", default=None)
    ap.add_argument("--books-root", default=None)
    a = ap.parse_args()

    rec = project_records(a.record)[a.project][1]
    name = os.path.splitext(os.path.basename(a.component))[0]
    cands = rewrite.candidates(rec)
    _write(os.path.join(OUT, "candidates.json"), cands)
    row = rewrite.find(cands, name)
    assert row is not None, "%s is not a rewrite candidate of %s" % (name, a.project)
    det = rea_adapter.detect()
    _write(os.path.join(OUT, "rea_detect.json"), {k: det.get(k) for k in ("state", "version", "runtime", "reason", "upstream")})

    client = None
    if a.llm_config:
        os.environ["BTS_SBOM_LLM_CONFIG"] = a.llm_config
        os.environ.setdefault("BTS_SBOM_LLM_DAILY_BUDGET", "600")
        c = ChatClient.from_env(ledger=os.path.join(OUT, ".llm_ledger.json"))
        client = c if c.available else None
    idx = None
    if a.books_root:
        chunks = books.load_chunks(os.path.join(a.books_root, "evidence", "books")) + books.load_notes(a.books_root)
        idx = rag.Index(chunks) if chunks else None

    def provider(iface):
        return reimpl.infer_patterns(iface, book_index=idx, client=client)

    events = []
    resA = reimpl.reimpl(a.source, a.component, os.path.join(OUT, "run_A_license"), client=client, trigger=rewrite.trigger_record(row),
                         patterns_provider=provider, rea_provider=lambda root, comp: rea_adapter.collect(root),
                         project_root=a.project_root, project_rec=rec, progress=events.append)
    _write(os.path.join(OUT, "run_A_license", "record.json"), resA)
    _write(os.path.join(OUT, "run_A_license", "events.json"), [e["event"] for e in events])

    demo = rewrite.candidates(rec, declared=[{"component": name, "kind": "eol",
                                              "note": "DEMO declaration for the mechanism run - not a measured fact about this component"}])
    rowB = rewrite.find(demo, name)
    eventsB = []
    resB = reimpl.reimpl(a.source, a.component, os.path.join(OUT, "run_B_eol_declared_demo"), client=None, trigger=rewrite.trigger_record(rowB),
                         rea_provider=lambda root, comp: rea_adapter.collect(root), project_root=a.project_root, project_rec=rec,
                         progress=eventsB.append)
    _write(os.path.join(OUT, "run_B_eol_declared_demo", "record.json"), resB)

    raw = {"candidates": cands["counts"], "components": cands["components"], "rea": det.get("state"),
           "A": {k: resA.get(k) for k in ("verdict", "generated_by", "attempts", "copy_gate", "tests", "rea", "trigger", "patterns", "runtime", "adopted_tests")},
           "B": {k: resB.get(k) for k in ("verdict", "generated_by", "trigger", "rea", "runtime")}, "events_A": [e["event"] for e in events]}
    _write(os.path.join(OUT, "E2E_RAW.json"), raw)
    print(json.dumps(raw, ensure_ascii=False, indent=1, default=str))
    return 0 if resA.get("verdict") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

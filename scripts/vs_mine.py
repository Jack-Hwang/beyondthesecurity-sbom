"""Strings miner for the REA lane: run binscan._strings over the extracted VS assemblies and report the
validation/DGML vocabulary. Reusable: python scripts/vs_mine.py [terms CSV] (default terms = the layer
validation vocabulary). Evidence output: downloads/vs2026/rea_findings.json (regenerated each run)."""
from __future__ import annotations

import glob
import io
import json
import sys

sys.path.insert(0, ".")
from bts_sbom_app.binscan import _strings  # noqa: E402

DEFAULT_TERMS = ("forbiddennamespace", "validate", "violation", "bypass", "illegal", "must not",
                 "does not connect", "dgml", "graphschema", "contains")


def main() -> int:
    terms = (sys.argv[1].split(",") if len(sys.argv) > 1 else DEFAULT_TERMS)
    files = sorted(glob.glob("downloads/vs2026/extracted/**/*.dll", recursive=True))
    findings: dict = {}
    for f in files:
        name = f.replace(chr(92), "/").split("/")[-1].replace(".dll", "")
        strs = _strings(open(f, "rb").read())
        hits = sorted(set(x for x in strs
                          if any(t in x.lower() for t in terms) and 8 <= len(x) < 220))
        if hits:
            findings[name] = hits
            print("-- %s (%d strings total, %d hits)" % (name, len(strs), len(hits)))
            for h in hits[:6]:
                print("   ", h[:170])
    out = "downloads/vs2026/rea_findings.json"
    io.open(out, "w", encoding="utf-8", newline="\n").write(
        json.dumps({"terms": terms, "findings": findings}, ensure_ascii=False, indent=1))
    print("evidence:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

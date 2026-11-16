"""bts-sbom command-line interface.

Subcommands
-----------
    sbom       build an SPDX 2.3 SBOM from a manifest/lockfile
    sector     6-sector regulatory report (cra | fda | r155 | dod | finance | robot)
    scan       OSV-Scanner-style vulnerability scan of manifests/lockfiles/SBOMs
    vex        emit or inspect an OpenVEX document
    selfsbom   generate an SBOM of the bts-sbom package itself (also the default
               when the CLI is invoked with no arguments)

Exit codes: 0 = ok, 2 = usage/input error (unknown sector, unreadable file,
invalid documents). Errors are HONEST: an unsupported input fails with a reason,
never with a fabricated document.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from bts_sbom import __version__
from bts_sbom._internal.timeutil import utc_now_iso
from bts_sbom.sbom import sbom_from_manifest, validate_spdx
from bts_sbom.sectors import SECTORS, sector_report, write_evidence


def _load_json(path: str, what: str) -> Any:
    p = Path(path)
    if not p.is_file():
        raise SystemExitError(2, "%s file not found: %s" % (what, path))
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExitError(2, "cannot read %s %s: %s" % (what, path, exc))


class SystemExitError(SystemExit):
    """Exit with a code and a one-line reason on stderr."""

    def __init__(self, code: int, message: str):
        super().__init__(code)
        self.message = message


# ── self-SBOM demo ────────────────────────────────────────────────────────────

def build_self_sbom(timestamp: Optional[str] = None) -> Dict[str, Any]:
    """CycloneDX document describing the bts-sbom package itself.

    Honest by construction: ONE component (this distribution, stdlib-only),
    an EMPTY dependency graph asserted with CycloneDX ``aggregate: complete``
    (zero third-party runtime dependencies is a checkable fact), and per-module
    ``bts-sbom:vendored-from`` provenance properties.
    """
    import bts_sbom
    ts = timestamp or utc_now_iso()
    modules: List[str] = sorted(
        p.relative_to(Path(bts_sbom.__file__).parent).as_posix()
        for p in Path(bts_sbom.__file__).parent.rglob("*.py")
        if "__pycache__" not in p.parts
    )
    props = [{"name": "bts-sbom:python-requires", "value": ">=3.10"},
             {"name": "bts-sbom:runtime-dependencies", "value": "none (stdlib only)"}]
    vendored = [m for m in modules if m.startswith("_internal/") or m in
                ("sbom.py", "vex.py", "reachability.py", "osvscanner.py",
                 "sca_report.py", "supply_chain.py", "sectors.py")]
    for m in vendored:
        props.append({"name": "bts-sbom:vendored-module", "value": m})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:bts-sbom-self-%s" % __version__,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{"vendor": "BTS", "name": "bts-sbom", "version": __version__}],
            "component": {
                "type": "application",
                "bom-ref": "pkg:pypi/bts-sbom@%s" % __version__,
                "name": "bts-sbom",
                "version": __version__,
                "purl": "pkg:pypi/bts-sbom@%s" % __version__,
                "supplier": {"name": "BTS authors"},
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "description": "regulatory-sector SBOM/SCA toolkit "
                               "(CRA/FDA 524B/R155/EO 14028/finance/robot)",
                "properties": props,
            },
        },
        "components": [],
        "dependencies": [{"ref": "pkg:pypi/bts-sbom@%s" % __version__, "dependsOn": []}],
        "compositions": [{"aggregate": "complete",
                          "dependencies": ["pkg:pypi/bts-sbom@%s" % __version__]}],
    }


# ── command handlers ──────────────────────────────────────────────────────────

def cmd_sbom(args) -> int:
    from bts_sbom._internal import manifests
    if manifests.parser_for(args.path) is None:
        raise SystemExitError(2, "no parser for %r — supported: %s"
                              % (args.path, ", ".join(sorted(manifests.supported_names()))))
    doc = sbom_from_manifest(args.path, doc_name=args.name, created=args.created)
    if not doc.get("packages"):
        raise SystemExitError(2, "manifest %r parsed but contains no components "
                                 "(no pinned dependency lines?) — an empty SBOM "
                                 "would be misleading" % args.path)
    errors = validate_spdx(doc)
    if errors:
        raise SystemExitError(2, "generated SPDX document failed validation: "
                                 + "; ".join(errors[:5]))
    return _emit(doc, args.out)


def cmd_sector(args) -> int:
    if args.sector not in SECTORS:
        raise SystemExitError(2, "unknown sector %r; valid sectors: %s"
                              % (args.sector, ", ".join(SECTORS)))
    sbom = _load_json(args.sbom, "SBOM")
    vex = _load_json(args.vex, "VEX") if args.vex else None
    eol = _load_json(args.eol, "EOL") if args.eol else None
    try:
        report = sector_report(args.sector, sbom, vex=vex, eol=eol)
    except ValueError as exc:
        raise SystemExitError(2, str(exc))
    if args.evidence:
        paths = write_evidence(report, out_dir=args.evidence)
        print("# evidence: %s (history: %s)"
              % (paths["latest"], paths["history"]), file=sys.stderr)
    return _emit(report, args.out)


def cmd_scan(args) -> int:
    from bts_sbom.osvscanner import OsvScanner, gate_exit_code
    scanner = OsvScanner(offline=args.offline)
    result = scanner.scan(args.target, dry_run=args.dry_run,
                          with_licenses=args.licenses)
    rendered = scanner.render(result, args.fmt)
    print(rendered)
    if args.gate and not args.dry_run:
        return gate_exit_code(result)
    return 0


def cmd_vex(args) -> int:
    from bts_sbom import vex as vex_mod
    if args.check:
        statements = vex_mod.load_vex_file(args.check)
        summary = {"file": args.check, "statements": len(statements),
                   "statuses": {}}
        for st in statements:
            summary["statuses"][st.status] = summary["statuses"].get(st.status, 0) + 1
        return _emit(summary, args.out)
    if args.from_scan:
        result = _load_json(args.from_scan, "scan result")
        doc = vex_mod.from_scan_result(result, timestamp=args.timestamp or utc_now_iso())
        return _emit(doc, args.out)
    raise SystemExitError(2, "vex: provide --from-scan FILE (emit OpenVEX from a "
                             "scan result JSON) or --check FILE (validate a VEX file)")


def cmd_selfsbom(args) -> int:
    return _emit(build_self_sbom(timestamp=args.created), args.out)


def _emit(doc: Any, out: Optional[str]) -> int:
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    if out:
        Path(out).write_text(text + "\n", encoding="utf-8")
        print("wrote %s" % out, file=sys.stderr)
    else:
        print(text)
    return 0


# ── argparse ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    epilog = ("honour code: every verdict is computed from the documents you "
              "supply; absent evidence is reported as such (not_evidence), never "
              "as a pass or an invented failure.")
    p = argparse.ArgumentParser(
        prog="bts-sbom",
        description="regulatory-sector SBOM/SCA toolkit — "
                    "CRA · FDA 524B · UNECE R155/R156 · EO 14028 · "
                    "금융 OSS 가이드 · 로봇/ISO 10218",
        epilog=epilog)
    p.add_argument("--version", action="version", version="bts-sbom " + __version__)
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sb = sub.add_parser("sbom", help="build an SPDX 2.3 SBOM from a manifest/lockfile")
    sb.add_argument("path", help="manifest or lockfile (requirements.txt, "
                                 "package-lock.json, Cargo.lock, pom.xml, ...)")
    sb.add_argument("--name", default=None, help="document name (default: file stem)")
    sb.add_argument("--created", default=None, help="creation timestamp (RFC-3339)")
    sb.add_argument("--out", default=None, help="write JSON to FILE (default: stdout)")
    sb.set_defaults(func=cmd_sbom)

    sc = sub.add_parser("sector", help="6-sector regulatory report "
                                       "(cra | fda | r155 | dod | finance | robot)")
    sc.add_argument("--sector", required=True, choices=SECTORS,
                    help="regulatory sector to report against")
    sc.add_argument("--sbom", required=True, help="SPDX 2.3 or CycloneDX 1.5 SBOM JSON")
    sc.add_argument("--vex", default=None, help="optional VEX document JSON")
    sc.add_argument("--eol", default=None,
                    help="optional {component: {\"eol\": date, \"status\": ...}} JSON")
    sc.add_argument("--out", default=None, help="write the report JSON to FILE")
    sc.add_argument("--evidence", default=None,
                    help="also persist the report as evidence (latest + history) under DIR")
    sc.set_defaults(func=cmd_sector)

    sn = sub.add_parser(
        "scan",
        help="OSV-style vulnerability scan (online queries OSV.dev; --offline "
             "uses only the local cache DB and honestly reports packages with "
             "no cached answer as NOT verified clean)")
    sn.add_argument("target", help="file or directory to scan")
    sn.add_argument("--offline", action="store_true",
                    help="no network I/O: local DB only (zero network)")
    sn.add_argument("--dry-run", action="store_true",
                    help="discovery only — no OSV query at all")
    sn.add_argument("--licenses", action="store_true",
                    help="also run the license analysis")
    sn.add_argument("--fmt", default="table",
                    choices=["table", "json", "markdown", "vertical", "sarif"])
    sn.add_argument("--gate", action="store_true",
                    help="exit 1 when vulnerabilities found, 2 when data is "
                         "inconclusive (CI gate mode)")
    sn.set_defaults(func=cmd_scan)

    vx = sub.add_parser("vex", help="emit OpenVEX from a scan result, or validate a VEX file")
    vx.add_argument("--from-scan", default=None,
                    help="scan-result JSON (bts-sbom scan --fmt json) → OpenVEX document")
    vx.add_argument("--check", default=None, help="validate a VEX file and summarize it")
    vx.add_argument("--timestamp", default=None, help="RFC-3339 timestamp (default: now)")
    vx.add_argument("--out", default=None, help="write JSON to FILE (default: stdout)")
    vx.set_defaults(func=cmd_vex)

    ss = sub.add_parser("selfsbom",
                        help="emit a CycloneDX SBOM of the bts-sbom package itself")
    ss.add_argument("--created", default=None, help="creation timestamp (RFC-3339)")
    ss.add_argument("--out", default=None, help="write JSON to FILE")
    ss.set_defaults(func=cmd_selfsbom)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # bare `python -m bts_sbom` / `bts-sbom` runs the self-SBOM demo —
        # the package can produce a real SBOM of itself out of the box.
        return cmd_selfsbom(argparse.Namespace(created=None, out=None))
    try:
        return args.func(args)
    except SystemExitError as exc:
        print("bts-sbom: %s" % exc.message, file=sys.stderr)
        return exc.code
    except ValueError as exc:
        print("bts-sbom: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

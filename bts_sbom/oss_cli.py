"""Command-line surface of the OSS suite:  ``bts-sbom oss ...``  and  ``bts-sbom notice ...``.

    bts-sbom oss scan TARGET     source / dependency / binary scan of a folder, archive or URL -> report(s) [+ notice]
    bts-sbom oss yocto ROOT      OSS report from the artifacts of an existing Yocto build (no bitbake is run)
    bts-sbom oss android ROOT    OSS report from the output of an existing Android build
    bts-sbom oss precheck ...    lint | add | convert | download   (REUSE-style copyright / license declarations)
    bts-sbom oss compare A B     change log between two reports
    bts-sbom notice REPORT       OSS notice (html | text | simple-html | simple-text) from a report

All text printed by --help is ASCII on purpose (it must survive a cp949 / cp1252 console).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, List, Optional

from bts_sbom import notice as notice_mod
from bts_sbom import ossreport, ossscan
from bts_sbom.ossreport import OssReport


class CliError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _split(values: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        out.extend(x.strip() for x in str(v).split(",") if x.strip())
    return out


def _write_outputs(report: OssReport, formats: List[str], out: Optional[str], stem: str) -> List[str]:
    written = []
    formats = formats or ["xlsx"]
    for fmt in formats:
        if fmt not in ossreport.FORMATS:
            raise CliError(2, "unknown format %r (choose from %s)" % (fmt, ", ".join(ossreport.FORMATS)))
    if out and len(formats) > 1 and os.path.splitext(out)[1] and not os.path.isdir(out):
        raise CliError(2, "-o names a single file but %d formats were requested; give a directory" % len(formats))
    for fmt in formats:
        dest = ossreport.default_path(out, fmt, stem)
        written.append(ossreport.write_report(report, fmt, dest))
    return written


def _print_overview(report: OssReport, files: List[str]) -> None:
    ov = ossscan.overview(report)
    c = ov["counts"]
    print("OSS scan: %d source, %d dependency, %d binary item(s); %d excluded; %d without a license" % (
        c["src"], c["dep"], c["bin"], ov["excluded"], ov["without_license"]), file=sys.stderr)
    for tier, rows in ov["license_tiers"].items():
        if rows:
            print("  %-12s %s" % (tier, ", ".join("%s (%d)" % (r["license"], r["components"]) for r in rows[:8])), file=sys.stderr)
    for w in report.warnings[:12]:
        print("  warning: %s" % w, file=sys.stderr)
    if len(report.warnings) > 12:
        print("  ... %d more warning(s) in the report" % (len(report.warnings) - 12), file=sys.stderr)
    for f in files:
        print("wrote %s" % f, file=sys.stderr)


def _notice_options(args: Any) -> notice_mod.NoticeOptions:
    return notice_mod.NoticeOptions(
        fmt=getattr(args, "notice_format", None) or getattr(args, "format", "html"), title=getattr(args, "title", "") or "",
        product=getattr(args, "product", "") or "", lang=getattr(args, "lang", "en"),
        show_version=not getattr(args, "hide_version", False), license_dirs=list(getattr(args, "license_dir", None) or []),
        fetch_license_texts=bool(getattr(args, "fetch_license_texts", False)),
        cache_dir=getattr(args, "license_cache", "") or "", contact=getattr(args, "contact", "") or "",
        strict=bool(getattr(args, "strict", False)), include_excluded=False)


def _emit_notice(report: OssReport, opts: notice_mod.NoticeOptions, out: Optional[str], audit_path: Optional[str]) -> int:
    res = notice_mod.build_notice(report, opts)
    ext = ".html" if opts.fmt.endswith("html") else ".txt"
    dest = out if out and os.path.splitext(out)[1] and not os.path.isdir(out) else os.path.join(
        out or ".", "bts_notice_%s%s" % (opts.fmt.replace("-", "_"), ext))
    notice_mod.write_notice(res, dest)
    print("wrote %s" % dest, file=sys.stderr)
    a = res.audit
    print("notice: %d component(s), %d license(s); %s" % (a["components"], len(a["licenses"]),
                                                          "complete" if a["complete"] else "INCOMPLETE: " + "; ".join(a["problems"])),
          file=sys.stderr)
    if audit_path:
        with open(audit_path, "w", encoding="utf-8") as fh:
            json.dump(a, fh, indent=2, ensure_ascii=False)
        print("wrote %s" % audit_path, file=sys.stderr)
    return 0 if res.ok else 1


# ------------------------------------------------------------------------------------------------------ handlers
def cmd_oss_scan(args: Any) -> int:
    modes = _split(args.mode) or ["all"]
    try:
        with ossscan.prepare_target(args.target, branch=args.branch or "") as pt:
            correction: Any = False if args.no_correction else (args.correct_file or None)
            report = ossscan.run_scan(pt.root, modes, excludes=_split(args.exclude), correction=correction,
                                      online=bool(args.online), kb_files=list(args.kb or []), engine=args.engine,
                                      max_files=args.max_files, recursive_dependencies=not args.no_recursive,
                                      meta={"spec": args.target, "kind": pt.kind, **pt.meta})
            report.warnings = list(pt.warnings) + report.warnings
            files = _write_outputs(report, _split(args.format), args.out, "bts_report")
            code = 0
            if args.notice:
                nargs = args
                nargs.notice_format = args.notice
                code = _emit_notice(report, _notice_options(nargs), args.out if args.out and os.path.isdir(args.out) else None,
                                    args.notice_audit)
    except ossscan.TargetError as exc:
        raise CliError(2, str(exc))
    except ValueError as exc:
        raise CliError(2, str(exc))
    _print_overview(report, files)
    return code


def _write_report_cmd(report: OssReport, args: Any, stem: str) -> int:
    files = _write_outputs(report, _split(args.format), args.out, stem)
    _print_overview(report, files)
    return 0


def cmd_oss_yocto(args: Any) -> int:
    from bts_sbom._internal import oss_yocto
    try:
        report = oss_yocto.scan(args.root, buildhistory=args.buildhistory, bom_json=args.bom_json,
                                installed_names=args.installed_names, installed_packages=args.installed_packages,
                                license_manifest=args.license_manifest, sbom_info=_split(args.sbom_info),
                                binary_root=args.binary_root, excludes=_split(args.exclude))
    except (OSError, ValueError) as exc:
        raise CliError(2, "yocto scan failed: %s" % exc)
    return _write_report_cmd(report, args, "bts_yocto_report")


def cmd_oss_android(args: Any) -> int:
    from bts_sbom._internal import oss_android
    try:
        report = oss_android.scan(args.root, build_log=args.build_log, out_dir=args.out_dir, excludes=_split(args.exclude),
                                  dedupe_against=args.dedupe_against, packaging_config=args.packaging_config)
    except (OSError, ValueError) as exc:
        raise CliError(2, "android scan failed: %s" % exc)
    return _write_report_cmd(report, args, "bts_android_report")


def cmd_oss_compare(args: Any) -> int:
    try:
        a, b = ossreport.read_report(args.before), ossreport.read_report(args.after)
    except (OSError, ValueError) as exc:
        raise CliError(2, "cannot read report: %s" % exc)
    cmp = ossreport.compare_reports(a, b)
    fmt = args.format
    if fmt == "json":
        text = json.dumps(cmp, indent=2, ensure_ascii=False) + "\n"
    elif fmt == "yaml":
        from bts_sbom._internal import miniyaml
        text = miniyaml.dumps(cmp)
    else:
        text = ossreport.compare_to_text(cmp)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("wrote %s" % args.out, file=sys.stderr)
    else:
        print(text, end="")
    s = cmp["summary"]
    print("compare: +%d -%d ~%d" % (s["added"], s["deleted"], s["changed"]), file=sys.stderr)
    return 0


def cmd_notice(args: Any) -> int:
    try:
        report = ossreport.read_report(args.report)
    except (OSError, ValueError) as exc:
        raise CliError(2, "cannot read report %s: %s" % (args.report, exc))
    return _emit_notice(report, _notice_options(args), args.out, args.audit)


def cmd_oss_precheck(args: Any) -> int:
    from bts_sbom._internal import oss_precheck
    act = args.pc_cmd
    try:
        if act == "lint":
            res = oss_precheck.lint(args.path, excludes=_split(args.exclude), include_hidden=args.include_hidden)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("REUSE-style check: %s (%d files checked)" % ("COMPLIANT" if res["compliant"] else "NOT COMPLIANT", res["files_checked"]))
                for key, title in (("missing_both", "missing copyright and license"), ("missing_copyright", "missing copyright"),
                                   ("missing_license", "missing license"), ("license_texts_missing", "license text missing in LICENSES/")):
                    items = res.get(key) or []
                    if items:
                        print("%s (%d):" % (title, len(items)))
                        for x in items[:50]:
                            print("  %s" % x)
            return 0 if res["compliant"] else 1
        if act == "add":
            edits = oss_precheck.add_headers(args.path, args.files or [args.path], license=args.license, copyright=args.copyright,
                                             download_location=args.download_location or "", dry_run=not args.apply)
            for e in edits:
                print("%s %s" % ("WROTE" if args.apply else "WOULD WRITE", e.get("file", e)))
            if not args.apply:
                print("dry run: nothing was written (use --apply)", file=sys.stderr)
            return 0
        if act == "convert":
            report = oss_precheck.convert(args.path)
            return _write_report_cmd(report, args, "bts_precheck_report")
        if act == "download":
            res = oss_precheck.download_licenses(args.path, list(args.license_id or []), online=args.online)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0
    except (OSError, ValueError) as exc:
        raise CliError(2, "precheck %s failed: %s" % (act, exc))
    raise CliError(2, "precheck: choose lint, add, convert or download")


def dispatch(args: Any) -> int:
    try:
        return args.oss_func(args)
    except CliError as exc:
        print("bts-sbom: %s" % exc, file=sys.stderr)
        return exc.code


# --------------------------------------------------------------------------------------------------------- parser
def _fmt_args(p: Any, default_fmt: str = "xlsx") -> None:
    p.add_argument("--format", "-f", action="append", default=None,
                   help="report format (repeat or comma-separate): %s (default %s)" % (", ".join(ossreport.FORMATS), default_fmt))
    p.add_argument("--out", "-o", default=None, help="output directory (or a single file name when one format is chosen)")


def _notice_args(p: Any) -> None:
    p.add_argument("--license-dir", action="append", default=None,
                   help="directory with license texts named <SPDX-ID>.txt (repeatable); used for the notice")
    p.add_argument("--fetch-license-texts", action="store_true",
                   help="OPT-IN network: fetch missing SPDX license texts from the SPDX license list")
    p.add_argument("--license-cache", default="", help="directory that caches fetched license texts")
    p.add_argument("--contact", default="", help="contact for the written source-code offer (required to emit one)")
    p.add_argument("--lang", default="en", choices=["en", "ko"], help="notice language")
    p.add_argument("--product", default="", help="product name shown in the notice")
    p.add_argument("--title", default="", help="notice title")
    p.add_argument("--hide-version", action="store_true", help="do not print OSS versions in the notice")
    p.add_argument("--strict", action="store_true", help="exit 1 when the notice is incomplete (missing license text etc.)")


def register(sub: Any) -> None:
    oss = sub.add_parser("oss", help="OSS compliance scanners (source, dependency, binary, yocto, android, precheck), "
                                      "reports, compare")
    osub = oss.add_subparsers(dest="oss_cmd", metavar="ACTION")
    osub.required = True

    sc = osub.add_parser("scan", help="scan a folder, archive (zip tar tgz bz2 jar whl rpm src.rpm) or URL (git or archive)")
    sc.add_argument("target", help="folder, archive file, git URL (https/ssh) or http(s) archive URL")
    sc.add_argument("--mode", "-m", action="append", default=None, help="source, dependency, binary or all (default all); comma-separated")
    sc.add_argument("--exclude", "-e", action="append", default=None, help="path or glob to exclude (repeatable)")
    sc.add_argument("--branch", default="", help="git branch or tag for a git URL")
    sc.add_argument("--no-correction", action="store_true", help="do not apply sbom-info.yaml")
    sc.add_argument("--correct-file", default=None, help="sbom-info.yaml at another location")
    sc.add_argument("--kb", action="append", default=None, help="local binary knowledge file (JSON/CSV of hash -> OSS), repeatable")
    sc.add_argument("--engine", default="builtin", choices=["builtin", "scancode"],
                    help="source engine: builtin (default) or scancode (OPT-IN: runs the scancode tool if installed)")
    sc.add_argument("--max-files", type=int, default=200000, help="file count limit (default 200000)")
    sc.add_argument("--no-recursive", action="store_true", help="dependency scan stops below a directory that has a manifest")
    sc.add_argument("--online", action="store_true",
                    help="OPT-IN network: look up licenses missing from the manifests in public registries (npm, PyPI, "
                         "crates.io, Maven Central); only package names and versions are sent")
    sc.add_argument("--notice", default=None, choices=list(notice_mod.FORMATS), help="also write an OSS notice in this format")
    sc.add_argument("--notice-audit", default=None, help="write the notice audit (missing texts etc.) as JSON")
    _fmt_args(sc)
    _notice_args(sc)
    sc.set_defaults(func=dispatch, oss_func=cmd_oss_scan)

    yo = osub.add_parser("yocto", help="OSS report from an existing Yocto build's artifacts (bitbake is NOT run)")
    yo.add_argument("root", help="directory containing the build artifacts (searched for buildhistory, bom.json, ...)")
    yo.add_argument("--buildhistory", default=None, help="buildhistory/packages directory")
    yo.add_argument("--bom-json", default=None, help="bom.json from bom.bbclass")
    yo.add_argument("--installed-names", default=None, help="installed-package-names.txt")
    yo.add_argument("--installed-packages", default=None, help="installed-packages.txt")
    yo.add_argument("--license-manifest", default=None, help="tmp/deploy/licenses/<image>/license.manifest")
    yo.add_argument("--sbom-info", action="append", default=None, help="sbom-info.yaml / oss-pkg-info.yaml (repeatable)")
    yo.add_argument("--binary-root", default=None, help="decompressed rootfs directory for the binary scanner")
    yo.add_argument("--exclude", "-e", action="append", default=None, help="path or glob to exclude")
    _fmt_args(yo)
    yo.set_defaults(func=dispatch, oss_func=cmd_oss_yocto)

    an = osub.add_parser("android", help="OSS report from an existing Android build output (the build is NOT run)")
    an.add_argument("root", help="Android source root (contains the out/ directory)")
    an.add_argument("--build-log", default=None, help="build log file name or path")
    an.add_argument("--out-dir", default=None, help="build output directory (default root/out)")
    an.add_argument("--dedupe-against", default=None, help="previous scan result to remove duplicate binaries against")
    an.add_argument("--packaging-config", default=None, help="pkgConfig.json listing prohibited files")
    an.add_argument("--exclude", "-e", action="append", default=None, help="path or glob to exclude")
    _fmt_args(an)
    an.set_defaults(func=dispatch, oss_func=cmd_oss_android)

    pc = osub.add_parser("precheck", help="REUSE-style copyright and license declaration check (lint), header insertion (add), "
                                           "sbom-info.yaml conversion (convert), license text download (download)")
    psub = pc.add_subparsers(dest="pc_cmd", metavar="MODE")
    psub.required = True
    pl = psub.add_parser("lint", help="check that files declare copyright and license")
    pl.add_argument("path", nargs="?", default=".")
    pl.add_argument("--exclude", "-e", action="append", default=None)
    pl.add_argument("--include-hidden", action="store_true")
    pl.add_argument("--json", action="store_true")
    pa = psub.add_parser("add", help="insert SPDX headers into files that lack them (dry run unless --apply)")
    pa.add_argument("path", help="project root (writes stay inside it)")
    pa.add_argument("files", nargs="*", help="files to edit (default: the path itself)")
    pa.add_argument("--license", required=True, help="SPDX license expression")
    pa.add_argument("--copyright", required=True, help="copyright text")
    pa.add_argument("--download-location", default="")
    pa.add_argument("--apply", action="store_true", help="actually write the files")
    pv = psub.add_parser("convert", help="convert sbom-info.yaml files below a path into an OSS report")
    pv.add_argument("path", nargs="?", default=".")
    _fmt_args(pv)
    pd = psub.add_parser("download", help="download license texts into LICENSES/ (needs --online)")
    pd.add_argument("path", nargs="?", default=".")
    pd.add_argument("--license-id", action="append", default=None, help="SPDX id (repeatable)")
    pd.add_argument("--online", action="store_true", help="allow network access to the SPDX license list")
    for p in (pl, pa, pv, pd):
        p.set_defaults(func=dispatch, oss_func=cmd_oss_precheck)

    cp = osub.add_parser("compare", help="compare two reports (xlsx, json, yaml): added / deleted / changed")
    cp.add_argument("before")
    cp.add_argument("after")
    cp.add_argument("--format", "-f", default="text", choices=["text", "json", "yaml"])
    cp.add_argument("--out", "-o", default=None)
    cp.set_defaults(func=dispatch, oss_func=cmd_oss_compare)

    nt = sub.add_parser("notice", help="generate an OSS notice (html, text, simple-html, simple-text) from a report")
    nt.add_argument("report", help="report file written by 'oss scan' (xlsx, json or yaml)")
    nt.add_argument("--format", "-f", default="html", choices=list(notice_mod.FORMATS))
    nt.add_argument("--out", "-o", default=None, help="output file or directory")
    nt.add_argument("--audit", default=None, help="write the audit (missing texts, missing copyright, ...) as JSON")
    _notice_args(nt)
    nt.set_defaults(func=dispatch, oss_func=cmd_notice)

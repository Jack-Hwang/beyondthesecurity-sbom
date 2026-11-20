"""OSS report: one model for what the source / dependency / binary / Yocto / Android scanners find.

The column names follow the FOSSLight Report as its public guide documents them (OSS Name, OSS Version, License,
Download Location, Homepage, Copyright Text, Exclude, Comment; sheets SRC / BIN / DEP), so a report written here can be
read by people and tools used to that layout.  This is a re-implementation from the documented format - no FOSSLight
code is used - and round-tripping through FOSSLight Hub has not been verified.

Honesty rules (same as the rest of bts-sbom): a field the scanner could not establish stays EMPTY - it is never filled
with a guess; "-" is only written for OSS Name where the FOSSLight convention defines it (in-house / unidentified code);
every item records how it was found (``evidence``); corrections from sbom-info.yaml are visible in ``comment``.

Formats written: xlsx, csv, json, yaml, spdx-json, spdx-tag, cyclonedx-json, cyclonedx-xml.   Read: xlsx, json, yaml.
"""
from __future__ import annotations

import csv
import fnmatch
import io
import json
import os
import re
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bts_sbom import __version__
from bts_sbom._internal import miniyaml, xlsx_min

SCHEMA = "bts-sbom.oss-report/1"
KINDS = ("src", "bin", "dep")
SHEET_NAMES = {"src": "SRC_FL_Source", "bin": "BIN_FL_Binary", "dep": "DEP_FL_Dependency"}
INFO_SHEET = "Scanner Info"

# header names as documented by the FOSSLight Report guide; "Source Path"/"Binary Path"/"Depends On" per scanner guides
_COMMON = ["ID", "OSS Name", "OSS Version", "License", "Download Location", "Homepage", "Copyright Text", "Exclude",
           "Comment"]
# Two trailing columns beyond the FOSSLight set carry what a report must not lose: "Needs Check" marks a finding whose
# license/identity is a guess (binary banner match, missing manifest license ...) and "Notice Status" is the Android
# scanner's NOTICE state.  Both are empty for an ordinary finding.
_EXTRA = ["Needs Check", "Notice Status"]
COLUMNS = {
    "src": ["ID", "Source Path"] + _COMMON[1:] + _EXTRA,
    "bin": ["ID", "Binary Path"] + _COMMON[1:] + ["Checksum"] + _EXTRA,
    "dep": ["ID", "Package URL", "OSS Name", "OSS Version", "License", "Download Location", "Homepage",
            "Copyright Text", "Exclude", "Comment", "Depends On", "Direct"] + _EXTRA,
}


@dataclass
class OssItem:
    kind: str = "src"                       # src | bin | dep
    oss_name: str = ""                      # "" = unknown; "-" = in-house / unidentified (FOSSLight convention)
    version: str = ""
    licenses: List[str] = field(default_factory=list)   # SPDX ids/expressions or raw names, as found
    download_location: str = ""
    homepage: str = ""
    copyright: str = ""
    license_text: str = ""                  # only when the license text is not otherwise resolvable
    source_path: str = ""                   # src: file/dir; bin: binary path; dep: manifest that declared it
    comment: str = ""
    exclude: bool = False
    purl: str = ""
    checksum: str = ""
    depends_on: List[str] = field(default_factory=list)
    direct: Optional[bool] = None
    needs_check: bool = False
    notice_status: str = ""                 # Android scanner: ok | ok(NA) | nok | nok(NA)
    evidence: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def license_field(self) -> str:
        return ", ".join(lic for lic in self.licenses if lic)

    def key(self) -> Tuple[str, str, str, str]:
        return (self.kind, (self.oss_name or "").lower(), self.version, self.purl or self.source_path)


@dataclass
class OssReport:
    items: List[OssItem] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def of_kind(self, kind: str) -> List[OssItem]:
        return [i for i in self.items if i.kind == kind]

    def active(self) -> List[OssItem]:
        return [i for i in self.items if not i.exclude]

    def merge(self, other: "OssReport") -> "OssReport":
        self.items.extend(other.items)
        self.warnings.extend(other.warnings)
        for k, v in (other.info.get("scanners") or {}).items():
            self.info.setdefault("scanners", {})[k] = v
        return self


def new_info(analyzed_path: str = "", excluded: Sequence[str] = (), **extra: Any) -> Dict[str, Any]:
    info: Dict[str, Any] = {"tool": "bts-sbom oss", "tool_version": __version__,
                            "python": sys.version.split()[0],
                            "started": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "analyzed_path": analyzed_path, "excluded": list(excluded), "scanners": {}}
    info.update(extra)
    return info


# ============================================================================================ (de)serialisation
def item_to_dict(i: OssItem) -> Dict[str, Any]:
    return asdict(i)


def item_from_dict(d: Dict[str, Any]) -> OssItem:
    known = {f for f in OssItem.__dataclass_fields__}
    kw = {k: v for k, v in d.items() if k in known}
    kw["extra"] = dict(kw.get("extra") or {})
    for k, v in d.items():
        if k not in known:
            kw["extra"][k] = v
    lic = kw.get("licenses")
    if isinstance(lic, str):
        kw["licenses"] = split_licenses(lic)
    for k in ("oss_name", "version", "download_location", "homepage", "copyright", "license_text", "source_path",
              "comment", "purl", "checksum", "notice_status"):
        if kw.get(k) is None:
            kw[k] = ""
        kw[k] = str(kw[k])
    kw["exclude"] = _truthy(kw.get("exclude"))
    if kw.get("kind") not in KINDS:
        kw["kind"] = "src"
    return OssItem(**kw)


def split_licenses(text: str) -> List[str]:
    """FOSSLight writes several licenses of one OSS comma-separated; SPDX expressions contain no commas."""
    return [p.strip() for p in re.split(r"\s*,\s*", text or "") if p.strip()]


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v or "").strip().lower() in ("1", "true", "yes", "y", "x", "v", "o")


def report_to_dict(r: OssReport) -> Dict[str, Any]:
    return {"schema": SCHEMA, "info": r.info, "warnings": r.warnings, "items": [item_to_dict(i) for i in r.items]}


def report_from_dict(d: Dict[str, Any]) -> OssReport:
    if not isinstance(d, dict) or not isinstance(d.get("items"), list):
        raise ValueError("not an OSS report (no 'items' list)")
    return OssReport(items=[item_from_dict(x) for x in d["items"] if isinstance(x, dict)],
                     info=dict(d.get("info") or {}), warnings=list(d.get("warnings") or []))


def _csv_safe(v: Any) -> str:
    """Neutralise spreadsheet formula injection (values come from untrusted repositories)."""
    s = "" if v is None else str(v)
    if s and (s[0] in "=+@\t\r" or (s[0] == "-" and len(s) > 1 and any(c in s for c in "=|(@"))):
        return "'" + s
    return s


# FOSSLight writes a dependency's OSS Name as "<manager>:<name>" (npm:lodash, pypi:requests, ...); Maven/Gradle/Android use
# "<group>:<artifact>" without a manager prefix.  The model keeps the plain name and the manager in extra["manager"].
_PREFIXED_MANAGERS = ("npm", "pnpm", "yarn", "pypi", "cocoapods", "swift", "carthage", "go", "nuget", "helm", "cargo",
                      "pub", "unity")


def _dep_display_name(i: OssItem) -> str:
    mgr = str((i.extra or {}).get("manager") or "")
    if mgr in _PREFIXED_MANAGERS and i.oss_name and not i.oss_name.startswith(mgr + ":"):
        return "%s:%s" % (mgr, i.oss_name)
    return i.oss_name


def _row(i: OssItem, idx: int) -> List[str]:
    lic = i.license_field
    tail = ["Check" if i.needs_check else "", i.notice_status]
    if i.kind == "src":
        return [str(idx), i.source_path, i.oss_name, i.version, lic, i.download_location, i.homepage, i.copyright,
                "Exclude" if i.exclude else "", i.comment] + tail
    if i.kind == "bin":
        return [str(idx), i.source_path, i.oss_name, i.version, lic, i.download_location, i.homepage, i.copyright,
                "Exclude" if i.exclude else "", i.comment, i.checksum] + tail
    return [str(idx), i.purl, _dep_display_name(i), i.version, lic, i.download_location, i.homepage, i.copyright,
            "Exclude" if i.exclude else "", i.comment, ", ".join(i.depends_on),
            "" if i.direct is None else ("Direct" if i.direct else "Transitive")] + tail


def _info_rows(r: OssReport) -> List[List[str]]:
    rows = [[k.replace("_", " ").title(), v if isinstance(v, str) else ("; ".join(map(str, v)) if isinstance(v, list) else str(v))]
            for k, v in r.info.items() if k != "scanners"]
    for name, sc in (r.info.get("scanners") or {}).items():
        rows.append(["Comment (%s)" % name, sc if isinstance(sc, str) else json.dumps(sc, ensure_ascii=False)])
    for w in r.warnings:
        rows.append(["Warning", w])
    return rows


def to_xlsx(r: OssReport, dest: Any) -> None:
    sheets = [xlsx_min.Sheet(INFO_SHEET, ["Key", "Value"], _info_rows(r), widths={0: 28, 1: 90})]
    for kind in KINDS:
        items = r.of_kind(kind)
        if not items and kind != "src":
            continue
        hidden = {COLUMNS[kind].index("Checksum")} if kind == "bin" else set()   # checksum hidden by default, as documented
        sheets.append(xlsx_min.Sheet(SHEET_NAMES[kind], COLUMNS[kind], [_row(i, n + 1) for n, i in enumerate(items)],
                                     hidden=hidden))
    xlsx_min.write_xlsx(dest, sheets)


def to_csv(r: OssReport) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Kind", "ID", "Path/Purl", "OSS Name", "OSS Version", "License", "Download Location", "Homepage",
                "Copyright Text", "Exclude", "Comment"] + _EXTRA)
    for n, i in enumerate(r.items, 1):
        w.writerow([_csv_safe(x) for x in [i.kind.upper(), n, i.purl if i.kind == "dep" else i.source_path, i.oss_name,
                                           i.version, i.license_field, i.download_location, i.homepage, i.copyright,
                                           "Exclude" if i.exclude else "", i.comment,
                                           "Check" if i.needs_check else "", i.notice_status]])
    return buf.getvalue()


def to_json(r: OssReport) -> str:
    return json.dumps(report_to_dict(r), indent=2, ensure_ascii=False) + "\n"


def to_yaml(r: OssReport) -> str:
    doc: Dict[str, Any] = {"schema": SCHEMA, "scanner info": {k: v for k, v in r.info.items()}}
    for kind in KINDS:
        items = r.of_kind(kind)
        if items:
            doc[SHEET_NAMES[kind]] = [{h: v for h, v in zip(COLUMNS[kind], _row(i, n + 1)) if v != ""}
                                       for n, i in enumerate(items)]
    if r.warnings:
        doc["warnings"] = r.warnings
    return miniyaml.dumps(doc)


# ------------------------------------------------------------------------------------------------------ readers
def _item_from_row(kind: str, header: List[str], row: List[str]) -> Optional[OssItem]:
    cells = {h.strip(): (row[n].strip() if n < len(row) else "") for n, h in enumerate(header)}
    if not any(v for k, v in cells.items() if k != "ID"):
        return None
    lic = split_licenses(cells.get("License", ""))
    depends = split_licenses(cells.get("Depends On", ""))
    it = OssItem(kind=kind, oss_name=cells.get("OSS Name", ""), version=cells.get("OSS Version", ""), licenses=lic,
                 download_location=cells.get("Download Location", ""), homepage=cells.get("Homepage", ""),
                 copyright=cells.get("Copyright Text", ""), comment=cells.get("Comment", ""),
                 exclude=_truthy(cells.get("Exclude", "")), depends_on=depends, checksum=cells.get("Checksum", ""),
                 needs_check=_truthy(cells.get("Needs Check", "")) or cells.get("Needs Check", "").lower() == "check",
                 notice_status=cells.get("Notice Status", ""))
    if kind == "dep":
        it.purl = cells.get("Package URL", "")
        head, sep, rest = it.oss_name.partition(":")
        if sep and head in _PREFIXED_MANAGERS and rest:
            it.extra["manager"], it.oss_name = head, rest
        d = cells.get("Direct", "")
        it.direct = True if d.lower() == "direct" else (False if d.lower() == "transitive" else None)
    else:
        it.source_path = cells.get("Source Path", "") or cells.get("Binary Path", "")
    return it


def read_report(path: str) -> OssReport:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".json",):
        with open(path, "r", encoding="utf-8-sig") as fh:
            return report_from_dict(json.load(fh))
    if ext in (".yaml", ".yml"):
        doc = miniyaml.load_file(path)
        if not isinstance(doc, dict):
            raise ValueError("not an OSS report YAML")
        r = OssReport(info=dict(doc.get("scanner info") or {}), warnings=list(doc.get("warnings") or []))
        for kind, sheet in SHEET_NAMES.items():
            for rec in doc.get(sheet) or []:
                if isinstance(rec, dict):
                    row = [str(rec.get(h, "") or "") for h in COLUMNS[kind]]
                    it = _item_from_row(kind, COLUMNS[kind], row)
                    if it:
                        r.items.append(it)
        return r
    if ext in (".xlsx", ".xlsm"):
        book = xlsx_min.read_xlsx(path)
        r = OssReport()
        for kind, sheet in SHEET_NAMES.items():
            rows = book.get(sheet) or next((v for k, v in book.items() if k.upper().startswith(kind.upper())), None)
            if not rows:
                continue
            header = rows[0]
            for row in rows[1:]:
                it = _item_from_row(kind, header, row)
                if it:
                    r.items.append(it)
        for row in book.get(INFO_SHEET, [])[1:]:
            if len(row) >= 2 and row[0] and not row[0].startswith(("Comment", "Warning")):
                r.info[row[0].lower().replace(" ", "_")] = row[1]
        return r
    raise ValueError("unsupported report type %r (use .xlsx, .json or .yaml)" % ext)


# ============================================================================================= SBOM exports
_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9.+-]+$")


def _spdx_license(raw: str, extracted: Dict[str, Dict[str, str]]) -> str:
    """SPDX expression for ``raw``: valid expressions pass through; anything else becomes a LicenseRef (never guessed)."""
    from bts_sbom._internal import license_spdx
    raw = (raw or "").strip()
    if not raw or raw.upper() in ("NOASSERTION", "NONE"):
        return "NOASSERTION"
    try:
        license_spdx.parse_expression(raw)
        return raw
    except Exception:
        ref = "LicenseRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", raw).strip("-")[:60]
        extracted.setdefault(ref, {"licenseId": ref, "name": raw,
                                   "extractedText": "License name as found by the scanner: %s (no text collected)" % raw})
        return ref


def _purl_for(i: OssItem) -> str:
    return i.purl or ""


def to_spdx_json(r: OssReport, name: str = "bts-sbom-oss-report") -> Dict[str, Any]:
    extracted: Dict[str, Dict[str, str]] = {}
    pkgs: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for n, i in enumerate(r.active(), 1):
        base = re.sub(r"[^A-Za-z0-9.-]+", "-", i.oss_name or "unknown").strip("-") or "unknown"
        seen[base] = seen.get(base, 0) + 1
        spdxid = "SPDXRef-Package-%s-%d" % (base, n)
        exprs = [_spdx_license(lic, extracted) for lic in i.licenses]
        lic = " AND ".join(exprs) if len(exprs) > 1 else (exprs[0] if exprs else "NOASSERTION")
        p: Dict[str, Any] = {"name": i.oss_name if i.oss_name and i.oss_name != "-" else (i.source_path or "unknown"),
                             "SPDXID": spdxid, "downloadLocation": i.download_location or "NOASSERTION",
                             "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": lic,
                             "copyrightText": i.copyright or "NOASSERTION"}
        if i.version:
            p["versionInfo"] = i.version
        if i.homepage:
            p["homepage"] = i.homepage
        if i.checksum and re.fullmatch(r"[0-9a-fA-F]{64}", i.checksum):
            p["checksums"] = [{"algorithm": "SHA256", "checksumValue": i.checksum.lower()}]
        if i.purl:
            p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                  "referenceLocator": i.purl}]
        if i.comment:
            p["comment"] = i.comment
        pkgs.append(p)
    doc: Dict[str, Any] = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
        "documentNamespace": "https://bts-sbom.local/spdx/oss/%s" % uuid.uuid5(
            uuid.NAMESPACE_URL, json.dumps([p["SPDXID"] + p["name"] for p in pkgs])),
        "creationInfo": {"created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": ["Tool: bts-sbom-%s" % __version__]},
        "packages": pkgs,
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": p["SPDXID"]} for p in pkgs],
        "documentDescribes": [p["SPDXID"] for p in pkgs],
    }
    if extracted:
        doc["hasExtractedLicensingInfos"] = list(extracted.values())
    return doc


_TV_CTRL = re.compile("[\x00-\x08\x0e-\x1f\x7f]")
_TV_BREAKS = re.compile("[\r\n\x0b\x0c\x85\u2028\u2029]+")
_TV_CLOSE = re.compile(r"<\s*/\s*text\s*>", re.IGNORECASE)
_TV_OPEN = re.compile(r"<\s*text\s*>", re.IGNORECASE)


def _tv_line(v: Any) -> str:
    """A single-line tag value.  Everything in a report comes from an untrusted tree: a name or version holding a line
    break would otherwise start a new, forged tag (``PackageName: ...``, ``SPDXID: ...``, ``FilesAnalyzed: true``)."""
    return _TV_BREAKS.sub(" ", _TV_CTRL.sub("", "" if v is None else str(v))).strip()


def _tv_text(v: Any) -> str:
    """A multi-line ``<text>`` value: it can neither close the block early (``</text>`` followed by forged tags) nor
    open a nested one; the delimiters inside the text are defused by a space, the text is otherwise kept."""
    s = _TV_CTRL.sub("", "" if v is None else str(v)).replace("\r\n", "\n").replace("\r", "\n")
    s = _TV_CLOSE.sub("< /text>", s)
    return _TV_OPEN.sub("< text>", s)


def to_spdx_tag(r: OssReport) -> str:
    doc = to_spdx_json(r)
    out = ["SPDXVersion: SPDX-2.3", "DataLicense: CC0-1.0", "SPDXID: SPDXRef-DOCUMENT",
           "DocumentName: " + _tv_line(doc["name"]), "DocumentNamespace: " + _tv_line(doc["documentNamespace"]),
           "Creator: Tool: bts-sbom-%s" % __version__, "Created: " + _tv_line(doc["creationInfo"]["created"]), ""]
    for p in doc["packages"]:
        out += ["PackageName: " + _tv_line(p["name"]), "SPDXID: " + _tv_line(p["SPDXID"])]
        if p.get("versionInfo"):
            out.append("PackageVersion: " + _tv_line(p["versionInfo"]))
        out += ["PackageDownloadLocation: " + _tv_line(p["downloadLocation"]), "FilesAnalyzed: false",
                "PackageLicenseConcluded: " + _tv_line(p["licenseConcluded"]),
                "PackageLicenseDeclared: " + _tv_line(p["licenseDeclared"])]
        cr = _tv_text(p["copyrightText"])
        out.append("PackageCopyrightText: " + ("<text>%s</text>" % cr if "\n" in cr or "<" in cr else _tv_line(cr)))
        if p.get("homepage"):
            out.append("PackageHomePage: " + _tv_line(p["homepage"]))
        for c in p.get("checksums", []):
            out.append("PackageChecksum: SHA256: " + _tv_line(c["checksumValue"]))
        for ref in p.get("externalRefs", []):
            out.append("ExternalRef: PACKAGE-MANAGER purl " + _tv_line(ref["referenceLocator"]))
        out.append("")
    for e in doc.get("hasExtractedLicensingInfos", []):
        out += ["LicenseID: " + _tv_line(e["licenseId"]), "LicenseName: " + _tv_line(e["name"]),
                "ExtractedText: <text>%s</text>" % _tv_text(e["extractedText"]), ""]
    return "\n".join(out) + "\n"


def to_cyclonedx_json(r: OssReport, name: str = "bts-sbom-oss-report") -> Dict[str, Any]:
    from bts_sbom._internal import license_spdx
    comps: List[Dict[str, Any]] = []
    used_refs = {"root"}                         # bom-ref must be unique in the document (the metadata component owns "root")
    for n, i in enumerate(r.active(), 1):
        ref = base = i.purl or "oss:%d:%s@%s" % (n, i.oss_name or "unknown", i.version)
        dup = 1
        while ref in used_refs:                  # the same package seen in two manifests carries one purl twice
            dup += 1
            ref = "%s#%d" % (base, dup)
        used_refs.add(ref)
        c: Dict[str, Any] = {"type": "library" if i.kind != "bin" else "file", "bom-ref": ref,
                             "name": i.oss_name if i.oss_name and i.oss_name != "-" else (i.source_path or "unknown")}
        if i.version:
            c["version"] = i.version
        if i.purl:
            c["purl"] = i.purl
        lics: List[Dict[str, Any]] = []
        for lic in i.licenses:
            try:
                license_spdx.parse_expression(lic)
                if re.search(r"\b(AND|OR|WITH)\b", lic):
                    lics.append({"expression": lic})
                else:
                    lics.append({"license": {"id": lic}})
            except Exception:
                lics.append({"license": {"name": lic}})
        if lics:
            c["licenses"] = lics
        if i.copyright:
            c["copyright"] = i.copyright
        refs = []
        if i.download_location:
            refs.append({"type": "distribution", "url": i.download_location})
        if i.homepage:
            refs.append({"type": "website", "url": i.homepage})
        if refs:
            c["externalReferences"] = refs
        if i.checksum and re.fullmatch(r"[0-9a-fA-F]{64}", i.checksum):
            c["hashes"] = [{"alg": "SHA-256", "content": i.checksum.lower()}]
        comps.append(c)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "serialNumber": "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([c["bom-ref"] for c in comps])),
            "metadata": {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "tools": [{"vendor": "BTS", "name": "bts-sbom", "version": __version__}],
                         "component": {"type": "application", "name": name, "bom-ref": "root"}},
            "components": comps}


_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff\ud800-\udfff]")


def to_cyclonedx_xml(r: OssReport) -> str:
    from xml.sax.saxutils import escape as _escape

    def escape(s: str, entities: Optional[Dict[str, str]] = None) -> str:
        return _escape(_XML_BAD.sub("", s), entities or {})

    d = to_cyclonedx_json(r)
    ns = "http://cyclonedx.org/schema/bom/1.5"
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<bom xmlns="%s" version="1" serialNumber="%s">' % (ns, escape(d["serialNumber"])),
           "<metadata><timestamp>%s</timestamp></metadata>" % d["metadata"]["timestamp"], "<components>"]
    for c in d["components"]:
        out.append('<component type="%s" bom-ref="%s"><name>%s</name>' % (c["type"], escape(c["bom-ref"], {'"': "&quot;"}), escape(c["name"])))
        if c.get("version"):
            out.append("<version>%s</version>" % escape(c["version"]))
        if c.get("licenses"):
            out.append("<licenses>")
            for lic in c["licenses"]:
                if "expression" in lic:
                    out.append("<expression>%s</expression>" % escape(lic["expression"]))
                elif "id" in lic["license"]:
                    out.append("<license><id>%s</id></license>" % escape(lic["license"]["id"]))
                else:
                    out.append("<license><name>%s</name></license>" % escape(lic["license"]["name"]))
            out.append("</licenses>")
        if c.get("copyright"):
            out.append("<copyright>%s</copyright>" % escape(c["copyright"]))
        if c.get("purl"):
            out.append("<purl>%s</purl>" % escape(c["purl"]))
        out.append("</component>")
    out.append("</components></bom>")
    return "".join(out) + "\n"


FORMATS = ("xlsx", "csv", "json", "yaml", "spdx-json", "spdx-tag", "cyclonedx-json", "cyclonedx-xml")
_EXT = {"xlsx": ".xlsx", "csv": ".csv", "json": ".json", "yaml": ".yaml", "spdx-json": ".spdx.json",
        "spdx-tag": ".spdx", "cyclonedx-json": ".cdx.json", "cyclonedx-xml": ".cdx.xml"}


def write_report(r: OssReport, fmt: str, dest: str) -> str:
    """Write ``r`` in ``fmt`` to ``dest`` (a file path).  Returns the path written."""
    fmt = fmt.lower()
    if fmt not in FORMATS:
        raise ValueError("unknown format %r (choose from %s)" % (fmt, ", ".join(FORMATS)))
    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    if fmt == "xlsx":
        to_xlsx(r, dest)
        return dest
    text = {"csv": lambda: to_csv(r), "json": lambda: to_json(r), "yaml": lambda: to_yaml(r),
            "spdx-json": lambda: json.dumps(to_spdx_json(r), indent=2, ensure_ascii=False) + "\n",
            "spdx-tag": lambda: to_spdx_tag(r),
            "cyclonedx-json": lambda: json.dumps(to_cyclonedx_json(r), indent=2, ensure_ascii=False) + "\n",
            "cyclonedx-xml": lambda: to_cyclonedx_xml(r)}[fmt]()
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return dest


def default_path(out: Optional[str], fmt: str, stem: str = "bts_report") -> str:
    ext = _EXT[fmt]
    if out and not os.path.isdir(out) and os.path.splitext(out)[1]:
        return out
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(out or ".", "%s_%s%s" % (stem, stamp, ext))


# ============================================================================== sbom-info.yaml corrections
def _norm_path(p: str) -> str:
    p = (p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def path_matches(pattern: str, path: str) -> bool:
    """sbom-info.yaml path rule: glob with '*' crossing '/', or a directory prefix ('dir/' / 'dir/*')."""
    pat, p = _norm_path(pattern), _norm_path(path)
    if not pat:
        return False
    if fnmatch.fnmatchcase(p, pat) or p == pat:
        return True
    if pat.endswith("/") and p.startswith(pat):
        return True
    return False


class CorrectionError(ValueError):
    pass


def load_corrections(path: str) -> List[Dict[str, Any]]:
    """Flatten sbom-info.yaml into blocks: {package, version, paths, licenses, download, homepage, copyright, exclude,
    comment}.  Structure per the public guide: ``package: [ {version, 'source name or path', license, ...}, ... ]``;
    package ``'-'`` marks in-house code or an exclusion-only block."""
    try:
        doc = miniyaml.load_file(path)
    except (miniyaml.YamlError, OSError) as exc:
        raise CorrectionError("cannot read correction file %s: %s" % (path, exc))
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise CorrectionError("%s: top level must be a mapping of package name -> list of version blocks" % path)

    def as_list(v: Any) -> List[str]:
        if v is None:
            return []
        return [str(x) for x in v] if isinstance(v, list) else [str(v)]

    blocks: List[Dict[str, Any]] = []
    for pkg, vers in doc.items():
        if not isinstance(vers, list):
            raise CorrectionError("%s: %r must hold a list of version blocks" % (path, pkg))
        for b in vers:
            if not isinstance(b, dict):
                raise CorrectionError("%s: a version block of %r is not a mapping" % (path, pkg))
            if "version" not in b:
                raise CorrectionError("%s: a version block of %r has no 'version' (use '' when none applies)" % (path, pkg))
            blocks.append({"package": str(pkg), "version": "" if b.get("version") is None else str(b["version"]),
                           "paths": as_list(b.get("source name or path")), "licenses": as_list(b.get("license")),
                           "download": "" if b.get("download location") is None else str(b["download location"]),
                           "homepage": "" if b.get("homepage") is None else str(b["homepage"]),
                           "copyright": "" if b.get("copyright text") is None else str(b["copyright text"]).rstrip("\n"),
                           "exclude": _truthy(b.get("exclude")), "comment": "" if b.get("comment") is None else str(b["comment"])})
    return blocks


def apply_corrections(r: OssReport, blocks: Sequence[Dict[str, Any]], source: str = "sbom-info.yaml") -> Dict[str, int]:
    """Apply correction blocks to src/bin items (dependency items are never corrected, as the guide states).
    A matched item is OVERRIDDEN in place and annotated; a block path that matched nothing is appended as a loaded entry."""
    stats = {"corrected": 0, "excluded": 0, "loaded": 0}
    for b in blocks:
        matched_paths = set()
        for it in r.items:
            if it.kind == "dep":
                continue
            hit = next((p for p in b["paths"] if path_matches(p, it.source_path)), None)
            if hit is None:
                continue
            matched_paths.add(hit)
            if b["exclude"]:
                it.exclude = True
                it.comment = _join(it.comment, "Excluded by %s" % source)
                stats["excluded"] += 1
                continue
            if b["package"] != "-":
                it.oss_name = b["package"]
            else:
                it.oss_name = "-"
            if b["package"] != "-" or b["version"]:
                it.version = b["version"]
            if b["licenses"]:
                it.licenses = list(b["licenses"])
            for src_f, dst_f in (("download", "download_location"), ("homepage", "homepage"), ("copyright", "copyright")):
                if b[src_f]:
                    setattr(it, dst_f, b[src_f])
            it.comment = _join(it.comment, b["comment"] or "Corrected by %s" % source)
            it.evidence.append("corrected by %s" % source)
            stats["corrected"] += 1
        for p in b["paths"]:
            if p in matched_paths or b["exclude"]:
                continue
            r.items.append(OssItem(kind="src", oss_name=b["package"], version=b["version"], licenses=list(b["licenses"]),
                                   download_location=b["download"], homepage=b["homepage"], copyright=b["copyright"],
                                   source_path=p, comment=_join(b["comment"], "Loaded by %s" % source),
                                   evidence=["loaded from %s" % source]))
            stats["loaded"] += 1
    return stats


def _join(a: str, b: str) -> str:
    return "; ".join(x for x in (a, b) if x)


# ================================================================================================ compare
_CMP_FIELDS = ("oss_name", "version", "license_field", "download_location", "homepage", "copyright", "exclude")


def _cmp_key(i: OssItem) -> Tuple[str, str]:
    if i.kind == "dep":
        return (i.kind, (i.purl or ("%s@%s" % (i.oss_name, i.version))).lower())
    return (i.kind, "%s|%s" % (i.source_path.lower(), (i.oss_name or "").lower()))


def compare_reports(a: OssReport, b: OssReport) -> Dict[str, Any]:
    """Change log between two reports (``a`` = before, ``b`` = after): added / deleted / changed, per item key."""
    ia = {_cmp_key(i): i for i in a.items}
    ib = {_cmp_key(i): i for i in b.items}
    added = [item_to_dict(ib[k]) for k in sorted(set(ib) - set(ia))]
    deleted = [item_to_dict(ia[k]) for k in sorted(set(ia) - set(ib))]
    changed = []
    for k in sorted(set(ia) & set(ib)):
        diffs = {}
        for f in _CMP_FIELDS:
            va, vb = getattr(ia[k], f), getattr(ib[k], f)
            if va != vb:
                diffs[f] = {"before": va, "after": vb}
        if diffs:
            changed.append({"key": list(k), "oss_name": ib[k].oss_name, "changes": diffs})
    return {"summary": {"added": len(added), "deleted": len(deleted), "changed": len(changed)},
            "added": added, "deleted": deleted, "changed": changed}


def compare_to_text(c: Dict[str, Any]) -> str:
    s = c["summary"]
    lines = ["OSS report comparison: +%d added, -%d deleted, ~%d changed" % (s["added"], s["deleted"], s["changed"]), ""]
    for it in c["added"]:
        lines.append("+ %s %s %s  [%s]" % (it["oss_name"] or it["source_path"], it["version"], ", ".join(it["licenses"]), it["kind"]))
    for it in c["deleted"]:
        lines.append("- %s %s %s  [%s]" % (it["oss_name"] or it["source_path"], it["version"], ", ".join(it["licenses"]), it["kind"]))
    for ch in c["changed"]:
        lines.append("~ %s" % ch["oss_name"])
        for f, d in ch["changes"].items():
            lines.append("    %s: %r -> %r" % (f, d["before"], d["after"]))
    return "\n".join(lines) + "\n"

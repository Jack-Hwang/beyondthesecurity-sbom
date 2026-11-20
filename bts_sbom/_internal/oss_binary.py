"""Binary scanner: a native, offline re-implementation of what the FOSSLight Binary Scanner's public user guide
documents it does, emitting ``bts_sbom.ossreport.OssReport`` items (``kind="bin"``). No FOSSLight code is read or
used - detection logic below is written from the public ELF/PE/Mach-O/ZIP/JAR/Java-properties/cargo-auditable/
systemd-ELF_PACKAGE_METADATA format specifications and from the behaviour the guide describes.

What this module does, natively and offline:
  1. Detects binary files by MAGIC BYTES (never by extension alone, except for the zip-based archive family where
     the magic ``PK\\x03\\x04``/``PK\\x05\\x06`` is shared with plain .zip/.docx/etc., so the extension additionally
     gates jar/war/ear/apk/aar classification): ELF, PE/MZ, Mach-O (thin + fat/universal), ``ar`` archives (static
     libs), zip-based jar/war/ear/apk/aar, dex, wasm.  ``.class`` files are explicitly excluded from detection: a
     Java class file's magic (``0xCAFEBABE``) collides with the Mach-O *fat* magic and the two cannot be told apart
     from the first 4 bytes alone - rather than guess, this scanner skips ``.class`` files entirely (a documented
     limitation, not a silent wrong guess).
  2. Computes sha256 (``item.checksum``) and sha1 (``item.extra["sha1"]``) of every detected binary.
  3. Looks binaries up in a LOCAL knowledge base (``kb_files``): JSON or CSV files mapping a sha256 or sha1 hex
     digest (case-insensitive) to {oss_name, version, licenses, download_location, homepage, copyright[, purl]}.
     JSON accepts either ``{"<hash>": {...fields...}, ...}`` or ``[{"sha256": "<hash>", ...fields...}, ...]``
     (a record needs a ``sha256`` or ``sha1``/``hash`` key in list form).  CSV needs a header row with any of
     ``sha256, sha1, oss_name, version, licenses, download_location, homepage, copyright, purl``; multiple license
     ids in one CSV cell are separated by ``;`` or ``|`` (not ``,``, which is the CSV delimiter).  An exact hash
     match is the strongest signal available and short-circuits any further analysis of that file; its evidence
     reads ``"hash match in <kb file>"``.
  4. Without a KB match: for zip-based jar/war/ear/apk/aar, reads (never extracts to disk) ``META-INF/MANIFEST.MF``,
     every ``META-INF/maven/*/*/pom.properties`` (+ the matching ``pom.xml`` for declared licenses) and builds a
     Maven purl ``pkg:maven/<groupId>/<artifactId>@<version>``.  A jar with MULTIPLE ``pom.properties`` (a shaded /
     uber jar) gets one base item for the outer jar (identified from its manifest when possible) plus one item per
     embedded artifact, each carrying evidence ``"embedded in <jar path>"``.
  5. Without a jar/KB match: extracts printable ASCII strings (>=6 chars, the file is read up to ``strings_limit``
     bytes) from ELF/PE/Mach-O/ar/dex/wasm files and matches a conservative, anchored set of well-known open-source
     version banners (OpenSSL, zlib, libcurl, SQLite, libpng, expat, BusyBox, glibc, GCC, libxml2, libjpeg-turbo,
     FreeType, LZ4, zstd, XZ Utils, Go).  Each match becomes its own item with ``needs_check=True`` and a comment
     stating plainly that it is a string-based lead, not a verified match.  Such an item gets a ``licenses`` value
     ONLY when the binary also contains an explicit, syntactically-valid ``SPDX-License-Identifier:`` tag AND there
     is exactly one banner match in the file (so the tag is not misattributed across several different embedded
     libraries); free-text license prose found in the strings (e.g. an MIT/Apache/GPL header) is recorded as
     EVIDENCE ONLY on whichever item represents the file, per the honesty contract - never as a confirmed license.
  6. Embedded build/SBOM metadata, read directly from the file (best-effort, degrades to "not decoded" rather than
     guessing):
       * ELF ``.note.package`` section (systemd's documented ELF_PACKAGE_METADATA note, type 0xcafe1a7e): parsed as
         one or more length-prefixed ELF notes, each JSON-decoded.
       * ELF ``.dep-v0`` section (cargo-auditable): zlib-inflated (output bounded) and JSON-decoded per the
         documented ``{"packages": [...]}`` shape; any failure is skipped, not guessed at.
       * Go build info: the binary is searched for the linker's ``\\xff Go buildinf:`` marker; when present, this
         module does a best-effort scan for the plain-text ``dep\\t<module>\\t<version>\\t`` lines modern (1.18+)
         toolchains leave readable in the data section.  This does NOT reproduce ``go version -m``'s pointer-chasing
         decoder (that needs a real ELF/PE loader) - a Go binary whose build info is only reachable through pointers
         yields no dependency items, and the limitation is recorded, never papered over with a guess.
       * ``.NET``: a ``*.deps.json`` file found next to a PE is parsed for its documented ``libraries`` map
         (``"type": "package"`` entries only) - no CLR bytecode is read.
  7. Free-text license material embedded in a binary (e.g. license prose, bare SPDX ids without the explicit tag
     form) is NEVER promoted to a confirmed license - see point 5.
  8. A detected binary that none of the above identifies still gets exactly ONE item, ``oss_name=""``,
     comment ``"no open source identified"`` (FOSSLight's report lists unmatched binaries too), UNLESS the file
     falls under the project's documented default exclusions (test/doc/hidden/build-script paths - see
     ``oss_common.default_exclude_reason``), in which case it is still reported (never silently dropped, per
     ``oss_common``'s own transparency contract) but marked ``exclude=True`` with the exclusion reason as its
     comment, and is not deep-analysed (an exact KB hash match is still honoured, since that is free information).

NOT implemented (see also the ``report.info["scanners"]["binary"]["not_supported"]`` list on every report this
module produces, and the per-run ``report.warnings``):
  * TLSH similarity matching against FOSSLight's Binary DB: there is no such database available offline, and a
    TLSH digest is only meaningfully comparable against one produced by the exact reference TLSH implementation -
    reimplementing it here would not let any digest it produces be compared against FOSSLight's own data anyway.
  * CVE / vulnerability scanning for JAR files: this module does not carry a CVE database.  It exposes every purl
    it derived through :func:`purls_for` instead, so a caller can feed them to ``bts_sbom.osvscanner``.
  * Go's pointer-based (pre-1.18-style) build-info layout, and any build-info format whose module list is only
    reachable by resolving a runtime pointer into a loaded, relocated image - see point 6 above.
  * Mach-O / dex / wasm / ar files get magic-byte detection, hashing, KB lookup and string-banner scanning, but no
    format-specific embedded-metadata extraction (that is only implemented for ELF/PE/zip-jar in this version).

Safety, honoured throughout: the analysed tree is UNTRUSTED DATA (read only, nothing is executed, imported or
``eval``-ed); ``oss_common.walk`` is used for traversal (symlinks never followed); every read is bounded
(``MAX_HASH_BYTES`` whole-file hashing, ``strings_limit`` string extraction, per-entry and per-archive JAR bounds
that never trust a zip's own declared sizes, bounded ELF section/note counts); XML (pom.xml) is rejected outright
if it contains a ``<!DOCTYPE`` or ``<!ENTITY`` declaration, before it is ever handed to ``xml.etree``.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import struct
import urllib.parse
import zipfile
import zlib
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bts_sbom import ossreport
from bts_sbom.ossreport import OssItem, OssReport
from bts_sbom._internal import oss_common

SCANNER_NAME = "binary"

# ---------------------------------------------------------------------------------------------------- bounds
MAX_FILES = 200_000
HEADER_READ = 8192                      # enough for ELF/PE/Mach-O/ar/dex/wasm headers
MAX_HASH_BYTES = 300_000_000            # whole-file hashing bound; bigger files are reported, not hashed
DEFAULT_STRINGS_LIMIT = 4_000_000
MIN_STRING_LEN = 6
MAX_KB_BYTES = 50_000_000
MAX_ZIP_ENTRIES = 100_000
MAX_ZIP_UNCOMPRESSED = 2 * 1024 ** 3     # total declared uncompressed size across a jar's entries
MAX_MANIFEST_READ = 2_000_000            # per-entry bound for MANIFEST.MF / pom.properties / pom.xml
MAX_ELF_SECTIONS = 10_000
MAX_NOTE_SECTION = 1_000_000
MAX_DEPV0_SECTION = 50_000_000
MAX_DEPV0_DECOMPRESSED = 50_000_000

_JAR_EXTS = {".jar", ".war", ".ear", ".apk", ".aar"}
_MACHO_THIN = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
_MACHO_FAT = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _join_c(a: str, b: str) -> str:
    return "; ".join(x for x in (a, b) if x)


# ============================================================================================ format detection
def _detect_format(head: bytes, ext: str) -> Optional[str]:
    """Magic-byte classification; ``None`` = not a binary format this scanner recognises."""
    if not head or ext == ".class":
        return None
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in _MACHO_THIN:
        return "macho"
    if head[:4] in _MACHO_FAT:
        return "macho-fat"
    if head[:8] == b"!<arch>\n":
        return "ar"
    if head[:4] == b"dex\n":
        return "dex"
    if head[:4] == b"\x00asm":
        return "wasm"
    if head[:4] in _ZIP_MAGICS and ext in _JAR_EXTS:
        return "jar-zip"
    return None


# ================================================================================================= hashing
def _hashes(path: str, cap: int) -> Tuple[Optional[str], Optional[str], bool]:
    """(sha256, sha1, oversized).  ``oversized`` True means the file is bigger than ``cap``: both digests are
    ``None`` and nothing else reads the file's content either."""
    h256, h1 = hashlib.sha256(), hashlib.sha1()
    n = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                n += len(chunk)
                if n > cap:
                    return None, None, True
                h256.update(chunk)
                h1.update(chunk)
    except OSError:
        return None, None, False
    return h256.hexdigest(), h1.hexdigest(), False


# ============================================================================================ knowledge base
def _kb_records_from_json(doc: Any) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(v, dict):
                out.append((str(k), v))
    elif isinstance(doc, list):
        for rec in doc:
            if not isinstance(rec, dict):
                continue
            h = rec.get("sha256") or rec.get("sha1") or rec.get("hash")
            if h:
                out.append((str(h), rec))
    else:
        raise ValueError("top level must be a JSON object or a list of objects")
    return out


def _kb_records_from_csv(text: str) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV knowledge base has no header row")
    for row in reader:
        rec = {(k or "").strip().lower(): v for k, v in row.items() if k}
        h = rec.get("sha256") or rec.get("sha1") or rec.get("hash")
        if h:
            out.append((str(h), rec))
    return out


def _load_kb(paths: Sequence[str]) -> Tuple[Dict[str, Tuple[Dict[str, Any], str]], List[str]]:
    merged: Dict[str, Tuple[Dict[str, Any], str]] = {}
    warnings: List[str] = []
    for p in paths or ():
        try:
            size = os.path.getsize(p)
        except OSError as exc:
            warnings.append("knowledge base %s: cannot stat (%s)" % (p, exc))
            continue
        if size > MAX_KB_BYTES:
            warnings.append("knowledge base %s: larger than %d bytes, skipped" % (p, MAX_KB_BYTES))
            continue
        text = oss_common.read_text(p, limit=MAX_KB_BYTES + 1)
        if not text:
            warnings.append("knowledge base %s: empty or unreadable, skipped" % p)
            continue
        if len(text.encode("utf-8", "replace")) > MAX_KB_BYTES:
            warnings.append("knowledge base %s: larger than %d bytes, skipped" % (p, MAX_KB_BYTES))
            continue
        ext = os.path.splitext(p)[1].lower()
        try:
            records = _kb_records_from_json(json.loads(text)) if ext == ".json" else _kb_records_from_csv(text)
        except (ValueError, csv.Error, UnicodeDecodeError) as exc:
            warnings.append("knowledge base %s: could not be parsed (%s)" % (p, exc))
            continue
        for h, rec in records:
            h = (h or "").strip().lower()
            if _HEX_RE.match(h) and h not in merged:
                merged[h] = (rec, p)
    return merged, warnings


def _apply_kb_record(item: OssItem, rec: Dict[str, Any]) -> None:
    item.oss_name = str(rec.get("oss_name") or rec.get("name") or "")
    item.version = str(rec.get("version") or "")
    lic = rec.get("licenses") or rec.get("license")
    if isinstance(lic, list):
        item.licenses = [str(x).strip() for x in lic if str(x).strip()]
    elif lic:
        item.licenses = ossreport.split_licenses(re.sub(r"[;|]", ",", str(lic)))
    item.download_location = str(rec.get("download_location") or rec.get("download") or "")
    item.homepage = str(rec.get("homepage") or "")
    item.copyright = str(rec.get("copyright") or "")
    if rec.get("purl"):
        item.purl = str(rec["purl"])


# ================================================================================================ strings
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)


def _extract_strings(data: bytes) -> str:
    return "\n".join(m.group().decode("ascii") for m in _PRINTABLE_RE.finditer(data))


_BANNERS: List[Tuple[str, "re.Pattern"]] = [
    ("OpenSSL", re.compile(r"\bOpenSSL\s+(\d+\.\d+\.\d+[a-z]?)\b")),
    ("zlib", re.compile(r"\bzlib\s+(\d+\.\d+(?:\.\d+)?)\b")),
    ("zlib", re.compile(r"\bdeflate\s+(\d+\.\d+(?:\.\d+)?)\s+Copyright\b")),
    ("libcurl", re.compile(r"\blibcurl/(\d+\.\d+\.\d+)\b")),
    ("SQLite", re.compile(r"\bSQLite version\s+(\d+\.\d+\.\d+)\b")),
    ("libpng", re.compile(r"\blibpng version\s+(\d+\.\d+\.\d+)\b")),
    ("expat", re.compile(r"\bexpat_(\d+\.\d+\.\d+)\b")),
    ("BusyBox", re.compile(r"\bBusyBox v(\d+\.\d+\.\d+)\b")),
    ("glibc", re.compile(r"\bGNU C Library\b.{0,120}?version\s+(\d+\.\d+)\b", re.S)),
    ("GCC", re.compile(r"\bGCC:\s*\([^)]*\)\s*(\d+\.\d+\.\d+)\b")),
    ("libxml2", re.compile(r"\blibxml2[ /](\d+\.\d+\.\d+)\b")),
    ("libjpeg-turbo", re.compile(r"\blibjpeg-turbo version\s+(\d+\.\d+\.\d+)\b")),
    ("FreeType", re.compile(r"\bFreeType\s+(\d+\.\d+\.\d+)\b")),
    ("LZ4", re.compile(r"\bLZ4 version\s+(\d+\.\d+\.\d+)\b")),
    ("zstd", re.compile(r"\bzstd\s+(\d+\.\d+\.\d+)\b")),
    ("XZ Utils", re.compile(r"\bXZ Utils\s+(\d+\.\d+\.\d+)\b")),
    ("Go", re.compile(r"\bgo(1\.\d{1,2}(?:\.\d{1,2})?)\b")),
]


def _match_version_banners(text: str) -> List[Tuple[str, str, str]]:
    """[(name, version, snippet), ...] - at most one hit per distinct library name."""
    hits: List[Tuple[str, str, str]] = []
    seen = set()
    for name, rx in _BANNERS:
        if name in seen:
            continue
        m = rx.search(text)
        if not m:
            continue
        seen.add(name)
        snippet = re.sub(r"\s+", " ", m.group(0)).strip()[:160]
        hits.append((name, m.group(1), snippet))
    return hits


def _find_spdx_tag(text: str) -> Optional[str]:
    """An explicit, syntactically-valid ``SPDX-License-Identifier:`` tag - the one string form in binary strings
    honest enough to resolve to a license (reusing the same tag scanner the source-file scanner uses)."""
    from bts_sbom._internal import license_scan, license_spdx
    m = license_scan._SPDX_TAG_RE.search(text)
    if not m:
        return None
    expr = license_scan._clean_spdx_expr(m.group(1))
    if not expr:
        return None
    try:
        license_spdx.parse_expression(expr)
    except Exception:
        return None
    return expr


def _find_license_phrase(text: str) -> Optional[Tuple[str, str]]:
    """(spdx_id, snippet) for free-text license prose found in the strings - evidence only, see module docstring."""
    from bts_sbom._internal import license_scan
    hit = license_scan._detect_notice(text)
    if not hit:
        return None
    spdx_id, _line, snippet = hit
    return spdx_id, snippet


# ================================================================================================= Go buildinfo
_GO_BUILDINF_MAGIC = b"\xff Go buildinf:"
_GO_DEP_RE = re.compile(rb"(?:^|\n)dep\t(\S+)\t(\S+)\t")


def _parse_go_buildinfo(data: bytes) -> List[OssItem]:
    if _GO_BUILDINF_MAGIC not in data:
        return []
    items: List[OssItem] = []
    seen = set()
    for m in _GO_DEP_RE.finditer(data):
        mod = m.group(1).decode("ascii", "replace")
        ver = m.group(2).decode("ascii", "replace")
        if not mod or mod in seen or mod == "=>":
            continue
        seen.add(mod)
        purl = "pkg:golang/%s@%s" % (urllib.parse.quote(mod, safe="/"), urllib.parse.quote(ver, safe=""))
        items.append(OssItem(kind="bin", oss_name=mod, version=ver, purl=purl, needs_check=True,
                             comment="Go module dependency read by best-effort string scanning of the build-info "
                                     "blob (the linker's pointer-based layout is not decoded; see module docstring)",
                             evidence=["Go buildinfo dependency line"]))
        if len(items) >= 500:
            break
    return items


# =================================================================================================== ELF sections
def _elf_header(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"
    bits = 32 if ei_class == 1 else 64
    try:
        if bits == 32:
            fields = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        else:
            fields = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    except struct.error:
        return {"bits": bits, "endian": endian, "machine": None, "e_shoff": 0, "e_shentsize": 0,
                "e_shnum": 0, "e_shstrndx": 0}
    (_type, machine, _ver, _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum,
     shentsize, shnum, shstrndx) = fields
    return {"bits": bits, "endian": endian, "machine": machine, "e_shoff": shoff, "e_shentsize": shentsize,
            "e_shnum": min(shnum, MAX_ELF_SECTIONS), "e_shstrndx": shstrndx}


def _elf_sections(path: str, hdr: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not hdr or not hdr.get("e_shoff") or not hdr.get("e_shnum"):
        return []
    endian, bits = hdr["endian"], hdr["bits"]
    entsize, count = hdr["e_shentsize"], hdr["e_shnum"]
    fmt = (endian + "IIIIIIIIII") if bits == 32 else (endian + "IIQQQQIIQQ")
    want = struct.calcsize(fmt)
    if entsize < want:
        return []
    try:
        with open(path, "rb") as fh:
            fh.seek(hdr["e_shoff"])
            raw = fh.read(entsize * count)
            entries: List[Dict[str, Any]] = []
            for i in range(count):
                chunk = raw[i * entsize: i * entsize + want]
                if len(chunk) < want:
                    break
                name_off, typ, _flags, _addr, offset, size, _link, _info, align, _es = struct.unpack(fmt, chunk)
                entries.append({"name_off": name_off, "type": typ, "offset": offset, "size": size, "align": align})
            shstrndx = hdr["e_shstrndx"]
            strtab_data = b""
            if 0 <= shstrndx < len(entries):
                strtab = entries[shstrndx]
                cap = MAX_NOTE_SECTION * 5
                if 0 < strtab["size"] <= cap:
                    fh.seek(strtab["offset"])
                    strtab_data = fh.read(strtab["size"])
    except (OSError, struct.error):
        return []
    for e in entries:
        off = e["name_off"]
        if 0 <= off < len(strtab_data):
            end = strtab_data.find(b"\x00", off)
            e["name"] = strtab_data[off: end if end != -1 else len(strtab_data)].decode("utf-8", "replace")
        else:
            e["name"] = ""
    return entries


def _read_section(path: str, sec: Dict[str, Any], cap: int) -> Optional[bytes]:
    if sec["size"] <= 0 or sec["size"] > cap:
        return None
    try:
        with open(path, "rb") as fh:
            fh.seek(sec["offset"])
            return fh.read(sec["size"])
    except OSError:
        return None


_NT_FDO_PACKAGING_METADATA = 0xCAFE1A7E


def _parse_note_package(data: bytes, endian: str) -> List[OssItem]:
    """ELF .note.package notes, per systemd's documented ELF_PACKAGE_METADATA format (public spec)."""
    items: List[OssItem] = []
    pos, n, count = 0, len(data), 0
    while pos + 12 <= n and count < 64:
        try:
            namesz, descsz, ntype = struct.unpack_from(endian + "III", data, pos)
        except struct.error:
            break
        pos += 12
        if namesz > n or descsz > n:
            break
        pos += namesz
        pos = (pos + 3) & ~3
        desc_end = pos + descsz
        if desc_end > n:
            break
        desc = data[pos:desc_end]
        pos = (desc_end + 3) & ~3
        count += 1
        if ntype != _NT_FDO_PACKAGING_METADATA:
            continue
        try:
            meta = json.loads(desc.decode("utf-8", "replace"))
        except ValueError:
            continue
        if not isinstance(meta, dict):
            continue
        name, version, ptype = str(meta.get("name") or ""), str(meta.get("version") or ""), str(meta.get("type") or "")
        purl = ("pkg:%s/%s%s" % (ptype, name, ("@%s" % version) if version else "")) if (ptype and name) else ""
        items.append(OssItem(kind="bin", oss_name=name, version=version, purl=purl,
                             comment="packaging metadata recorded by the build system "
                                     "(ELF .note.package, see https://systemd.io/ELF_PACKAGE_METADATA/)",
                             evidence=[".note.package ELF note (type=%s)" % (ptype or "?")]))
    return items


def _parse_cargo_auditable(data: bytes) -> Optional[List[OssItem]]:
    """Best-effort cargo-auditable ``.dep-v0`` decode: zlib-inflate (bounded) then JSON per the documented shape.
    Any failure returns ``None`` (skip, never guess) - matches the assignment's "skip if zlib payload invalid"."""
    try:
        dobj = zlib.decompressobj()
        raw = dobj.decompress(data, MAX_DEPV0_DECOMPRESSED)
    except zlib.error:
        return None
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, list):
        return None
    items: List[OssItem] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name, version = str(pkg.get("name") or ""), str(pkg.get("version") or "")
        if not name:
            continue
        purl = "pkg:cargo/%s" % urllib.parse.quote(name, safe="")
        if version:
            purl += "@%s" % urllib.parse.quote(version, safe="")
        items.append(OssItem(kind="bin", oss_name=name, version=version, purl=purl,
                             comment="dependency recorded by cargo-auditable at build time (best-effort decode "
                                     "of the .dep-v0 ELF section)",
                             evidence=["cargo-auditable dependency metadata (.dep-v0 ELF section)"]))
    return items


def _elf_embedded_sbom(path: str, head: bytes) -> Tuple[List[OssItem], List[str]]:
    items: List[OssItem] = []
    warns: List[str] = []
    hdr = _elf_header(head)
    if not hdr:
        return items, warns
    try:
        sections = _elf_sections(path, hdr)
    except Exception:
        sections = []
    by_name = {s["name"]: s for s in sections if s.get("name")}

    note = by_name.get(".note.package")
    if note:
        data = _read_section(path, note, MAX_NOTE_SECTION)
        if data is None:
            warns.append(".note.package section missing, too large or unreadable, skipped")
        else:
            items.extend(_parse_note_package(data, hdr["endian"]))

    depv0 = by_name.get(".dep-v0")
    if depv0:
        data = _read_section(path, depv0, MAX_DEPV0_SECTION)
        if data is None:
            warns.append(".dep-v0 section missing, too large or unreadable, skipped")
        else:
            parsed = _parse_cargo_auditable(data)
            if parsed is None:
                warns.append(".dep-v0 section present but could not be decoded (best-effort cargo-auditable parser)")
            else:
                items.extend(parsed)
    return items, warns


# =================================================================================================== .NET deps.json
def _dotnet_deps_json(path: str) -> List[OssItem]:
    directory = os.path.dirname(path)
    stem = os.path.splitext(os.path.basename(path))[0]
    preferred = stem + ".deps.json"
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return []
    candidates = [n for n in names if n == preferred] + [n for n in names if n != preferred and n.lower().endswith(".deps.json")]
    items: List[OssItem] = []
    for name in candidates:
        full = os.path.join(directory, name)
        if not os.path.isfile(full) or os.path.islink(full):
            continue
        text = oss_common.read_text(full, limit=MAX_MANIFEST_READ)
        if not text:
            continue
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        libs = doc.get("libraries") if isinstance(doc, dict) else None
        if not isinstance(libs, dict):
            continue
        for key, meta in libs.items():
            if not isinstance(meta, dict) or meta.get("type") != "package":
                continue
            pkg_name, _sep, version = str(key).rpartition("/")
            if not pkg_name:
                continue
            purl = "pkg:nuget/%s@%s" % (urllib.parse.quote(pkg_name, safe=""), urllib.parse.quote(version, safe=""))
            items.append(OssItem(kind="bin", oss_name=pkg_name, version=version, purl=purl,
                                 comment="dependency recorded in %s next to this assembly" % name,
                                 evidence=["%s (.NET dependency manifest)" % name]))
        break       # one deps.json is authoritative; do not merge several sibling manifests
    return items


def _pe_is_dotnet(data: bytes) -> Optional[bool]:
    """Best-effort: is the COM-descriptor (CLI header) data directory present and non-empty?  ``None`` = could not
    tell (header too short / not actually a PE)."""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff_off = e_lfanew + 4
        _machine, _nsec, _ts, _symtab, _nsyms, opt_size, _ch = struct.unpack_from("<HHIIIHH", data, coff_off)
        opt_off = coff_off + 20
        if opt_size < 2 or opt_off + 2 > len(data):
            return None
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x10B:
            dirs_off = opt_off + 96
        elif magic == 0x20B:
            dirs_off = opt_off + 112
        else:
            return None
        com_off = dirs_off + 14 * 8
        if com_off + 8 > len(data) or com_off + 8 > opt_off + opt_size:
            return None
        rva, size = struct.unpack_from("<II", data, com_off)
        return bool(rva and size)
    except struct.error:
        return None


# ====================================================================================================== JAR / zip
def _parse_manifest(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    key: Optional[str] = None
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if raw.startswith(" ") and key:
            out[key] += raw[1:]
            continue
        if not raw.strip():
            key = None
            continue
        if ":" in raw:
            k, _sep, v = raw.partition(":")
            key = k.strip()
            out[key] = v.strip()
        else:
            key = None
    return out


def _unescape_props(v: str) -> str:
    return v.replace("\\:", ":").replace("\\=", "=").replace("\\\\", "\\")


def _parse_properties(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        i += 1
        s = line.lstrip(" \t")
        if not s or s[0] in "#!":
            continue
        guard = 0
        while line.endswith("\\") and not line.endswith("\\\\") and i < n and guard < 10000:
            line = line[:-1] + lines[i].lstrip(" \t")
            i += 1
            guard += 1
        m = re.match(r"\s*([^=:\s]+)\s*[:=]\s*(.*)$", line) or re.match(r"\s*(\S+)\s+(.*)$", line)
        if m:
            out[m.group(1)] = _unescape_props(m.group(2))
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(elem: ET.Element, name: str) -> str:
    for c in elem:
        if _local(c.tag) == name:
            return (c.text or "").strip()
    return ""


def _safe_parse_xml(data: bytes, max_bytes: int) -> Optional[ET.Element]:
    if not data or len(data) > max_bytes:
        return None
    from bts_sbom._internal import safe_xml
    try:
        return safe_xml.fromstring(data)
    except (ET.ParseError, safe_xml.DtdNotAllowed):
        return None


def _pom_fields(root: ET.Element) -> Dict[str, Any]:
    group, artifact, version = _child_text(root, "groupId"), _child_text(root, "artifactId"), _child_text(root, "version")
    for c in root:
        if _local(c.tag) == "parent":
            group = group or _child_text(c, "groupId")
            version = version or _child_text(c, "version")
    licenses: List[str] = []
    for c in root:
        if _local(c.tag) == "licenses":
            for lic in c:
                if _local(lic.tag) == "license":
                    name = _child_text(lic, "name")
                    if name:
                        licenses.append(name)
    return {"group": group, "artifact": artifact, "version": version, "licenses": licenses}


def _maven_purl(group: str, artifact: str, version: str) -> str:
    if not (group and artifact):
        return ""
    g, a = urllib.parse.quote(group, safe=""), urllib.parse.quote(artifact, safe="")
    return ("pkg:maven/%s/%s@%s" % (g, a, urllib.parse.quote(version, safe=""))) if version else ("pkg:maven/%s/%s" % (g, a))


def _apply_manifest_fallback(it: OssItem, manifest: Dict[str, str]) -> bool:
    filled = False
    name = manifest.get("Implementation-Title") or manifest.get("Bundle-SymbolicName") or manifest.get("Automatic-Module-Name")
    version = manifest.get("Implementation-Version") or manifest.get("Bundle-Version")
    if name and not it.oss_name:
        it.oss_name, filled = name, True
    if version and not it.version:
        it.version, filled = version, True
    lic = manifest.get("Bundle-License")
    if lic and not it.licenses:
        it.licenses, filled = ossreport.split_licenses(lic), True
    vendor = manifest.get("Implementation-Vendor")
    if vendor:
        it.comment = _join_c(it.comment, "Vendor (from MANIFEST.MF): %s" % vendor)
    return filled


def _analyze_jar(path: str, rel: str, warnings: List[str]) -> Tuple[List[OssItem], bool]:
    items: List[OssItem] = []
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError) as exc:
        warnings.append("%s: not a valid zip/jar archive (%s)" % (rel, exc))
        return items, False
    try:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            warnings.append("%s: zip has more than %d entries, jar analysis skipped" % (rel, MAX_ZIP_ENTRIES))
            return items, False
        # never trust a zip's own declared sizes - but a sum this large is reason enough to stop before reading
        if sum(max(0, i.file_size) for i in infos) > MAX_ZIP_UNCOMPRESSED:
            warnings.append("%s: zip declares more than %d bytes uncompressed; jar analysis skipped "
                            "(possible zip bomb)" % (rel, MAX_ZIP_UNCOMPRESSED))
            return items, False

        by_name = {i.filename: i for i in infos}

        def _safe_read(info: zipfile.ZipInfo) -> Optional[bytes]:
            if info.file_size > MAX_MANIFEST_READ:
                warnings.append("%s: entry %s declares oversized content, skipped" % (rel, info.filename))
                return None
            try:
                with zf.open(info) as fh:
                    data = fh.read(MAX_MANIFEST_READ + 1)
            except (zipfile.BadZipFile, OSError, zlib.error, RuntimeError) as exc:
                warnings.append("%s: entry %s could not be read (%s)" % (rel, info.filename, exc))
                return None
            if len(data) > MAX_MANIFEST_READ:
                warnings.append("%s: entry %s exceeds the read bound, skipped" % (rel, info.filename))
                return None
            return data

        manifest: Dict[str, str] = {}
        mf_info = by_name.get("META-INF/MANIFEST.MF")
        if mf_info:
            data = _safe_read(mf_info)
            if data is not None:
                manifest = _parse_manifest(data.decode("utf-8", "replace"))

        pom_props_names = sorted(n for n in by_name if n.startswith("META-INF/maven/") and n.endswith("pom.properties"))
        pom_records: List[Dict[str, Any]] = []
        for n in pom_props_names:
            data = _safe_read(by_name[n])
            if data is None:
                continue
            props = _parse_properties(data.decode("utf-8", "replace"))
            group, artifact, version = props.get("groupId", ""), props.get("artifactId", ""), props.get("version", "")
            if not (group and artifact):
                continue
            pom_xml_name = n[: -len("pom.properties")] + "pom.xml"
            licenses: List[str] = []
            if pom_xml_name in by_name:
                xdata = _safe_read(by_name[pom_xml_name])
                if xdata is not None:
                    root = _safe_parse_xml(xdata, MAX_MANIFEST_READ)
                    if root is not None:
                        pf = _pom_fields(root)
                        licenses = pf["licenses"]
                        version = version or pf["version"]
            pom_records.append({"group": group, "artifact": artifact, "version": version, "licenses": licenses, "path": n})

        if len(pom_records) == 1:
            r0 = pom_records[0]
            it = OssItem(kind="bin", source_path=rel, oss_name=r0["artifact"], version=r0["version"],
                        licenses=list(dict.fromkeys(r0["licenses"])), purl=_maven_purl(r0["group"], r0["artifact"], r0["version"]),
                        evidence=["pom.properties in jar (%s)" % r0["path"]])
            _apply_manifest_fallback(it, manifest)
            items.append(it)
        elif len(pom_records) > 1:
            base_name = manifest.get("Implementation-Title") or manifest.get("Bundle-SymbolicName") or ""
            base_version = manifest.get("Implementation-Version") or manifest.get("Bundle-Version") or ""
            base = OssItem(kind="bin", source_path=rel, oss_name=base_name, version=base_version,
                          comment="shaded/uber jar containing %d embedded artifacts (see the items below)" % len(pom_records),
                          evidence=(["META-INF/MANIFEST.MF"] if manifest else []))
            items.append(base)
            for r0 in pom_records:
                it = OssItem(kind="bin", source_path=rel, oss_name=r0["artifact"], version=r0["version"],
                            licenses=list(dict.fromkeys(r0["licenses"])),
                            purl=_maven_purl(r0["group"], r0["artifact"], r0["version"]),
                            comment="embedded in %s" % rel,
                            evidence=["embedded in %s" % rel, "pom.properties in jar (%s)" % r0["path"]])
                items.append(it)
        elif manifest:
            it = OssItem(kind="bin", source_path=rel)
            if _apply_manifest_fallback(it, manifest):
                it.evidence.append("META-INF/MANIFEST.MF")
                items.append(it)
    finally:
        zf.close()
    return items, bool(items)


# ======================================================================================================= per-file
def _scan_one(abspath: str, rel: str, fmt: str, head: bytes, kb: Dict[str, Tuple[Dict[str, Any], str]],
             strings_limit: int, warnings: List[str], counts: Dict[str, int]) -> List[OssItem]:
    excl_reason = oss_common.default_exclude_reason(rel)
    sha256, sha1, oversized = _hashes(abspath, MAX_HASH_BYTES)
    if oversized:
        warnings.append("%s: larger than %d bytes, hashing and content analysis skipped" % (rel, MAX_HASH_BYTES))

    kb_hit = None
    if sha256 and sha256.lower() in kb:
        kb_hit = kb[sha256.lower()]
    elif sha1 and sha1.lower() in kb:
        kb_hit = kb[sha1.lower()]

    def _finish(items: List[OssItem]) -> List[OssItem]:
        for it in items:
            it.extra.setdefault("binary_format", fmt)
            if not it.checksum:
                it.checksum = sha256 or ""
            if sha1:
                it.extra.setdefault("sha1", sha1)
            it.source_path = it.source_path or rel
        return items

    base = OssItem(kind="bin", source_path=rel)
    if excl_reason:
        base.exclude = True
        base.comment = excl_reason
        counts["excluded"] += 1

    if kb_hit is not None:
        rec, src = kb_hit
        _apply_kb_record(base, rec)
        base.evidence.append("hash match in %s" % src)
        counts["matched_hash"] += 1
        return _finish([base])

    if excl_reason:
        return _finish([base])          # default-excluded: identified only by an exact hash match, not deep-analysed

    if oversized:
        base.comment = _join_c(base.comment, "no open source identified")
        counts["unmatched"] += 1
        return _finish([base])

    if fmt == "jar-zip":
        items, matched = _analyze_jar(abspath, rel, warnings)
        if matched:
            counts["matched_jar_metadata"] += len(items)
            return _finish(items)
        base.comment = _join_c(base.comment, "no open source identified")
        counts["unmatched"] += 1
        return _finish([base])

    data = oss_common.read_bytes(abspath, limit=strings_limit)
    if len(data) >= strings_limit:
        note = "%s: string scan bounded to the first %d bytes" % (rel, strings_limit)
        if note not in warnings:
            warnings.append(note)
    strings_text = _extract_strings(data)

    extra_items: List[OssItem] = []
    hits = _match_version_banners(strings_text)
    for name, version, snippet in hits:
        extra_items.append(OssItem(
            kind="bin", source_path=rel, oss_name=name, version=version, needs_check=True,
            evidence=["version banner: %s" % snippet],
            comment="string-based identification from an embedded version banner; not verified against the "
                     "binary's actual code - treat this as a lead to confirm by hand, not an exact match"))
    if len(hits) == 1:
        spdx_tag = _find_spdx_tag(strings_text)
        if spdx_tag:
            extra_items[0].licenses = [spdx_tag]
            extra_items[0].evidence.append("SPDX-License-Identifier tag found in binary strings")
    counts["matched_string_banner"] += len(hits)

    phrase = _find_license_phrase(strings_text)
    if phrase:
        spdx_id, snippet = phrase
        note = ("license text signature found in binary strings (reads like %s); recorded as evidence only, "
                "never as a confirmed license" % spdx_id)
        target = extra_items[0] if extra_items else base
        target.comment = _join_c(target.comment, note)
        target.evidence.append("license phrase in strings: %s" % snippet)

    go_items = _parse_go_buildinfo(data)
    extra_items.extend(go_items)
    counts["embedded_sbom_items"] += len(go_items)

    if fmt == "elf":
        sbom_items, sb_warnings = _elf_embedded_sbom(abspath, head)
        for w in sb_warnings:
            full = "%s: %s" % (rel, w)
            if full not in warnings:
                warnings.append(full)
        extra_items.extend(sbom_items)
        counts["embedded_sbom_items"] += len(sbom_items)
    elif fmt == "pe":
        dn_items = _dotnet_deps_json(abspath)
        extra_items.extend(dn_items)
        counts["embedded_sbom_items"] += len(dn_items)
        dotnet = _pe_is_dotnet(head)
        if dotnet is not None:
            for it in extra_items:
                it.extra.setdefault("dotnet_clr_header", dotnet)
            base.extra.setdefault("dotnet_clr_header", dotnet)

    if not extra_items:
        base.comment = _join_c(base.comment, "no open source identified")
        counts["unmatched"] += 1
        return _finish([base])
    return _finish(extra_items)


# ========================================================================================================= public
def scan(root: str, *, excludes: Sequence[str] = (), kb_files: Sequence[str] = (), max_files: int = MAX_FILES,
        strings_limit: int = DEFAULT_STRINGS_LIMIT) -> OssReport:
    """Scan ``root`` for binary files and return an :class:`bts_sbom.ossreport.OssReport` of ``kind="bin"`` items.
    See the module docstring for what is and is not detected, and ``report.info["scanners"]["binary"]`` /
    ``report.warnings`` on the result for this run's own limits and skipped work."""
    report = OssReport(info=ossreport.new_info(analyzed_path=root, excluded=list(excludes)))
    warnings: List[str] = []
    kb, kb_warnings = _load_kb(kb_files)
    warnings.extend(kb_warnings)

    counts = {"binaries_found": 0, "matched_hash": 0, "matched_jar_metadata": 0, "matched_string_banner": 0,
             "embedded_sbom_items": 0, "unmatched": 0, "excluded": 0}

    stats = oss_common.WalkStats()
    for abspath, rel in oss_common.walk(root, excludes=excludes, max_files=max_files, stats=stats):
        ext = os.path.splitext(rel)[1].lower()
        head = oss_common.read_bytes(abspath, limit=HEADER_READ)
        fmt = _detect_format(head, ext)
        if fmt is None:
            continue
        counts["binaries_found"] += 1
        report.items.extend(_scan_one(abspath, rel, fmt, head, kb, strings_limit, warnings, counts))

    if stats.truncated:
        warnings.append("file walk stopped at max_files=%d; some binaries may not have been scanned" % max_files)
    if stats.skipped_symlinks:
        warnings.append("%d symlink(s) skipped (never followed)" % len(stats.skipped_symlinks))
    if stats.unreadable_dirs:
        warnings.append("%d director(y/ies) could not be read" % len(stats.unreadable_dirs))

    report.warnings = warnings
    report.info.setdefault("scanners", {})[SCANNER_NAME] = {
        "counts": counts,
        "files_walked": stats.files,
        "kb_files": list(kb_files),
        "not_supported": [
            "TLSH similarity matching against FOSSLight's Binary DB (no such database exists offline, and a TLSH "
            "digest is only comparable against one produced by the exact reference TLSH implementation)",
            "CVE/vulnerability lookup for JAR files (no CVE database here - use purls_for(report) with "
            "bts_sbom.osvscanner instead)",
            "Go build-info module lists that are only reachable through the linker's pointer-based layout "
            "(pre-1.18-style); only the plain-text dependency lines modern toolchains leave readable are read",
            "format-specific embedded-metadata extraction for Mach-O / dex / wasm / ar (detection, hashing, KB "
            "lookup and string-banner scanning still apply to them)",
        ],
    }
    return report


def purls_for(report: OssReport) -> List[str]:
    """Every distinct, non-empty purl this scanner derived, in first-seen order - feed these to
    ``bts_sbom.osvscanner`` for vulnerability lookup (this module carries no CVE database of its own)."""
    seen: List[str] = []
    seen_set = set()
    for it in report.of_kind("bin"):
        if it.purl and it.purl not in seen_set:
            seen_set.add(it.purl)
            seen.append(it.purl)
    return seen

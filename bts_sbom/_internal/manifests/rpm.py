# vendored from common/manifests/rpm.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
RPM package-database parser - the native-DB inventory layer for RPM-based
rootfs images (RHEL/CentOS/Rocky/AlmaLinux/Fedora, and Yocto/OE builds
configured with the rpm backend), parsing the on-disk database directly.

Closes an OS-package-manager SCA gap exactly like ``common/manifests/dpkg.py``
does for Debian: before this module, ``sca_guard.agent.nodes.package_extractor``'s
"Layer 1: Package Manager DBs" step covered dpkg/opkg/apk but had NO rpm
reader at all, so any RPM-based rootfs pulled out of firmware (see
``common/firmware_tools.py``) was invisible to the installed-package inventory
feeding CVE matching. ``sca_guard/agent/state.py``'s ``DetectedPackage.source``
docstring already lists ``"rpm-db"`` as an expected value, and
``common/osv_client.py``'s ``map_ecosystem`` already maps ``"rpm" -> "Red Hat"``
and ``common/version_cmp.py`` already knows the RPM ``epoch:version-release``
comparison rules - this module is the missing piece that actually populates
that path.

Why a real pure-Python parser (NOT the ``rpm``/``python-rpm`` bindings):
librpm is a native library that is not installed (and not reliably
installable) on a non-RPM host such as this project's Windows/CI dev
environment, so a binding-based approach would make the whole feature
SETUP_REQUIRED everywhere except on an RPM distro itself. The on-disk header
record format, however, is a small, stable, public binary layout (the same
"lead + signature + header" tag/type/offset/count structure used both inside
every standalone ``.rpm`` file and as the blob payload of every row in a
modern rpmdb) and is fully decodable with nothing but ``struct`` + ``sqlite3``
from the standard library - no native dependency, nothing mocked.

Database backends and what this module actually supports:

  * **sqlite** (RPM >= 4.16; the default on Fedora 33+/RHEL9+/openSUSE since
    ~2021) - ``usr/lib/sysimage/rpm/rpmdb.sqlite`` or
    ``var/lib/rpm/rpmdb.sqlite``, a plain SQLite3 file with one row per
    package in a ``Packages(hnum, blob)`` table. FULLY PARSED: opened with
    the stdlib ``sqlite3`` module, each ``blob`` is the same header structure
    documented above.
  * **Berkeley DB (bdb)** (RHEL/CentOS <= 7 and most pre-2021 rpm builds) -
    ``var/lib/rpm/Packages``, a BerkeleyDB hash file. NOT parsed - BerkeleyDB
    is itself a native on-disk format with no stdlib reader, and this
    module does not ship a from-scratch bdb implementation. Detected by
    magic-byte sniffing only, so the caller can report an honest
    "found but unsupported format" note instead of silently returning an
    empty (indistinguishable-from-"no rpm here") package list.
  * **ndb** (openSUSE/SLE, rpm's newer "ndb" backend) -
    ``var/lib/rpm/Packages.db``. Same treatment: detected, not parsed.

Strict honesty (CLAUDE.md Section 2.1): ``parse_rpm_status`` returns real
packages for the sqlite backend and an empty list for every other case - it
never fabricates a package list for a format it cannot read.
``unsupported_rpmdb_note`` is how a caller surfaces *why* the list is empty
when an rpmdb file genuinely exists but could not be parsed, exactly the
"write skip details, don't fake a result" pattern CLAUDE.md requires for a
missing tool/dependency.

NOTE: this module is intentionally NOT registered in this package's
``_BY_RELPATH_SUFFIX`` / ``parse_file()`` text-manifest registry. That
registry's ``parse_file`` always opens candidates in ``"r", encoding="utf-8"``
text mode (correct for dpkg's plain-text status file) - handing it a binary
SQLite file would raise ``UnicodeDecodeError`` on first read, which the
generic ``except Exception: return []`` in ``parse_file`` would silently
swallow into an always-empty result. That would be a parser that looks wired
but can never fire - worse than no parser at all. Use the functions below
directly against an extracted rootfs path instead (see
``sca_guard/agent/nodes/package_extractor.py``'s Layer 1).
"""
from __future__ import annotations

import os
import sqlite3
import struct
from typing import Any, Dict, List, Optional, Tuple

from bts_sbom._internal.models import DetectedPackage

# common.osv_client.OsvClient.map_ecosystem("rpm") -> "Red Hat" already exists;
# this is the matching source-side ecosystem tag (lowercase, like every other
# manifest parser's convention - see common/manifests/dpkg.py's ECOSYSTEM note).
ECOSYSTEM = "rpm"
SOURCE = "rpm-db"

# ─────────────────────────── on-disk format constants ───────────────────────
# RPM "header" structure magic (stable since RPM 3.x): 8e ad e8 01 00 00 00 00.
# Identical whether the header sits inside a standalone .rpm file or is the
# blob payload of one row of a sqlite-backed rpmdb.
_HEADER_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
_HEADER_PREAMBLE = struct.Struct(">II")      # il (index count), dl (data length)
_INDEX_ENTRY = struct.Struct(">iiii")        # tag, type, offset, count

# RPM tag ids (lib/rpmtag.h) - the handful this module actually needs.
RPMTAG_NAME = 1000
RPMTAG_VERSION = 1001
RPMTAG_RELEASE = 1002
RPMTAG_EPOCH = 1003
RPMTAG_ARCH = 1022

# RPM header value types (lib/rpmtypes.h) this module knows how to decode.
_T_CHAR = 1
_T_INT8 = 2
_T_INT16 = 3
_T_INT32 = 4
_T_INT64 = 5
_T_STRING = 6
_T_BIN = 7
_T_STRING_ARRAY = 8
_T_I18NSTRING = 9

_SQLITE_MAGIC = b"SQLite format 3\x00"
_NDB_MAGIC = b"RpmP"
# Classic BerkeleyDB hash-file magic (0x00061561), byte order depends on the
# endianness the db was created with - check both.
_BDB_HASH_MAGIC_LE = bytes([0x61, 0x15, 0x06, 0x00])
_BDB_HASH_MAGIC_BE = bytes([0x00, 0x06, 0x15, 0x61])

# Candidate rpmdb locations inside an extracted rootfs, newest layout first.
_RPMDB_CANDIDATES: Tuple[str, ...] = (
    "usr/lib/sysimage/rpm/rpmdb.sqlite",   # RHEL9/Fedora 36+ (moved out of /var)
    "var/lib/rpm/rpmdb.sqlite",            # RHEL8/Fedora 33-35, openSUSE (sqlite)
    "var/lib/rpm/Packages.db",             # SUSE/SLE "ndb" backend
    "var/lib/rpm/Packages",                # legacy BerkeleyDB hash backend
)


def _decode_value(blob: bytes, data_start: int, offset: int, typ: int, count: int) -> Any:
    pos = data_start + offset
    if typ in (_T_STRING, _T_STRING_ARRAY, _T_I18NSTRING):
        values: List[str] = []
        p = pos
        n = max(count, 1)
        for _ in range(n):
            end = blob.index(b"\x00", p)
            values.append(blob[p:end].decode("utf-8", errors="replace"))
            p = end + 1
        return values[0] if typ == _T_STRING else values
    if typ == _T_INT32:
        return struct.unpack_from(">i", blob, pos)[0]
    if typ == _T_INT16:
        return struct.unpack_from(">h", blob, pos)[0]
    if typ in (_T_INT8, _T_CHAR):
        return blob[pos]
    if typ == _T_INT64:
        return struct.unpack_from(">q", blob, pos)[0]
    if typ == _T_BIN:
        return blob[pos:pos + count]
    return None                           # unknown/unhandled type - ignore, don't guess


def decode_header(blob: bytes) -> Dict[int, Any]:
    """Decode one RPM header blob -> {tag_id: value}.

    Returns {} for anything that is not a well-formed header (wrong magic,
    truncated index/data, an index entry pointing past the end of the data
    section, ...) - a malformed record is honestly "nothing to report", never
    a best-effort guess. One corrupt row never raises out of a caller's loop
    over many rows (callers should still only see a clean dict or an empty
    one; this function itself does not raise).
    """
    try:
        blob = bytes(blob)
        if len(blob) < 16 or blob[:8] != _HEADER_MAGIC:
            return {}
        count, dl = _HEADER_PREAMBLE.unpack_from(blob, 8)
        index_start = 16
        data_start = index_start + 16 * count
        data_end = data_start + dl
        if count < 0 or dl < 0 or data_end > len(blob):
            return {}                     # truncated/corrupt - nothing honest to report
        tags: Dict[int, Any] = {}
        for i in range(count):
            tag, typ, off, cnt = _INDEX_ENTRY.unpack_from(blob, index_start + i * 16)
            if off < 0 or off >= dl:
                continue                  # one bad entry doesn't invalidate the rest
            try:
                value = _decode_value(blob, data_start, off, typ, cnt)
            except Exception:
                continue
            if value is not None:
                tags[tag] = value
        return tags
    except Exception:
        return {}


def nevra_from_tags(tags: Dict[int, Any]) -> Optional[Dict[str, str]]:
    """{tag_id: value} -> {"name", "version", "release", "epoch", "arch"} or
    None when the record lacks the minimum needed to identify a package."""
    name = tags.get(RPMTAG_NAME)
    version = tags.get(RPMTAG_VERSION)
    if not name or not version:
        return None
    release = tags.get(RPMTAG_RELEASE) or ""
    epoch = tags.get(RPMTAG_EPOCH)
    arch = tags.get(RPMTAG_ARCH) or ""
    return {
        "name": str(name),
        "version": str(version),
        "release": str(release),
        "epoch": "" if epoch is None else str(epoch),
        "arch": str(arch),
    }


def _full_version(nevra: Dict[str, str]) -> str:
    # common/version_cmp.py's RPM comparator expects exactly this
    # "[epoch:]version-release" shape (_RPM_EPOCH_FULL_RE / _RPM_EPOCH_NREL_RE).
    v = f"{nevra['version']}-{nevra['release']}" if nevra["release"] else nevra["version"]
    return f"{nevra['epoch']}:{v}" if nevra["epoch"] else v


def header_to_package(blob: bytes, file_path: str = "") -> Optional[DetectedPackage]:
    """One rpmdb header blob -> DetectedPackage, or None for an unparseable /
    incomplete record (never raises)."""
    nevra = nevra_from_tags(decode_header(blob))
    if nevra is None:
        return None
    version = _full_version(nevra)
    purl = f"pkg:rpm/{nevra['name']}@{version}"
    if nevra["arch"]:
        purl += f"?arch={nevra['arch']}"
    try:
        return DetectedPackage(
            name=nevra["name"], version=version, ecosystem=ECOSYSTEM, purl=purl,
            source=SOURCE, provenance=[SOURCE],
            # A header record alone can't prove direct-vs-transitive (that
            # needs the separate "weak"/"recommends" dependency tags, not
            # read here) - "unknown" matches dpkg.py's identical honesty call.
            relationship="unknown", depth=0, confidence="high",
            file_path=file_path,
        )
    except Exception:
        return None


def parse_rpmdb_sqlite(path: str) -> List[DetectedPackage]:
    """Parse a modern sqlite-backed rpmdb (``Packages(hnum, blob)``) -> list of
    DetectedPackage. Never raises - any sqlite/format error yields []."""
    packages: List[DetectedPackage] = []
    try:
        conn = sqlite3.connect(path)
        try:
            cur = conn.execute("SELECT blob FROM Packages")
            for (blob,) in cur:
                pkg = header_to_package(blob, file_path=path)
                if pkg is not None:
                    packages.append(pkg)
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return packages


def _sniff_format(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except Exception:
        return "unknown"
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if head[:4] == _NDB_MAGIC:
        return "ndb"
    if len(head) >= 16 and head[12:16] in (_BDB_HASH_MAGIC_LE, _BDB_HASH_MAGIC_BE):
        return "bdb"
    return "unknown"


def find_rpmdb(rootfs: str) -> Optional[Tuple[str, str]]:
    """First rpmdb file found under ``rootfs`` (newest layout first) -> its
    absolute path and sniffed format ("sqlite" | "bdb" | "ndb" | "unknown"),
    or None when no candidate path exists at all."""
    for rel in _RPMDB_CANDIDATES:
        path = os.path.join(rootfs, *rel.split("/"))
        if os.path.isfile(path):
            return path, _sniff_format(path)
    return None


def parse_rpm_status(rootfs: str) -> List[DetectedPackage]:
    """Parse the installed-package inventory out of an extracted rootfs's
    rpm database. Only the sqlite backend is actually readable (see module
    docstring); every other case - no rpmdb present, or a bdb/ndb/unknown
    format - returns [] (call ``unsupported_rpmdb_note`` to tell those two
    apart for an honest engine_notes entry)."""
    found = find_rpmdb(rootfs)
    if not found:
        return []
    path, fmt = found
    if fmt == "sqlite":
        return parse_rpmdb_sqlite(path)
    return []


_UNSUPPORTED_LABELS = {
    "bdb": "a legacy BerkeleyDB rpmdb",
    "ndb": "a SUSE/SLE 'ndb' rpmdb",
    "unknown": "an rpmdb file in an unrecognized format",
}


def unsupported_rpmdb_note(rootfs: str) -> Optional[str]:
    """None when there is nothing to report (no rpmdb found, or the sqlite
    backend was found and parsed normally); otherwise an ASCII, human-readable
    note for ``state['engine_notes']`` explaining that a real rpmdb exists but
    could not be parsed - so the caller reports an honest incomplete
    inventory instead of a silent, indistinguishable-from-empty []."""
    found = find_rpmdb(rootfs)
    if not found:
        return None
    path, fmt = found
    if fmt == "sqlite":
        return None
    label = _UNSUPPORTED_LABELS.get(fmt, _UNSUPPORTED_LABELS["unknown"])
    return (f"rpm-db: found {path} but it is {label}; only the modern sqlite "
            f"rpmdb backend is parsed (no native librpm/BerkeleyDB dependency "
            f"available) - this rootfs's RPM package inventory is INCOMPLETE, "
            f"not confirmed empty.")


__all__ = [
    "ECOSYSTEM", "SOURCE",
    "decode_header", "nevra_from_tags", "header_to_package",
    "parse_rpmdb_sqlite", "find_rpmdb", "parse_rpm_status",
    "unsupported_rpmdb_note",
]

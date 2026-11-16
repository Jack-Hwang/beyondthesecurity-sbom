# vendored from common/manifests/dpkg.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Debian package database parser - dpkg's ``var/lib/dpkg/status``.

Closes the OS-package-manager SCA gap: a full embedded Linux rootfs pulled out
of firmware (see common/firmware_tools.py) carries dpkg's status file, which
lists every package the on-device OS actually has installed. Before this
module nothing in the manifest-discovery -> CVE-matching -> reachability ->
EPSS/KEV pipeline (sca_guard/agent/nodes/manifest_parser.py ->
sca_guard/agent/nodes/cve_scanner.py) could see those packages at all - only
app-level ecosystems (npm/pip/maven/cargo/go/...) were covered.

Format (``man 5 deb-status`` is the closest formal reference): RFC822-ish
stanzas separated by one blank line. Each stanza is a sequence of
"Field: value" lines; a line that starts with whitespace is a CONTINUATION of
the previous field (long multi-line ``Description`` fields are the common
case) and does not start a new field.

The ``Status`` field is three space-separated words - want/eflag/status, e.g.
"install ok installed" vs "deinstall ok config-files" vs "purge ok
not-installed".  ONLY the exact third word "installed" means the package is
actually present on disk; a package dpkg still has metadata for (removed,
held-but-removed, half-installed, config-files-only, ...) must NOT be
reported as an installed component.

NOTE on a pre-existing bug elsewhere in this codebase: the ad-hoc dpkg-status
reader in server/api.py's ``/api/firmware/rootfs-sbom`` auto-extractor tests
``"installed" in line.lower()``. That is a plain substring test, and
"installed" IS a substring of both "not-installed" and "half-installed" - so
a removed-but-not-purged or half-installed package is misreported as
currently present by that endpoint. This parser checks the exact trailing
status word instead and does not repeat that bug. (That endpoint is a
separate, disconnected code path - it is not wired to OSV/CVE matching at
all - and is out of scope for this change; noted here only so the bug is not
silently reintroduced via copy-paste.)

Honesty: no single malformed stanza can wipe out the rest of the file -
stanzas are parsed and emitted independently, so a truncated file (cut off
mid-record, with no closing blank line) still yields every well-formed
package that appeared before the cut; only the incomplete dangling record is
silently dropped (there is nothing honest to assert about a stanza missing a
Package/Version/parseable Status - "drop it" there means "nothing to
report", not "give up on the whole file", which is what an all-or-nothing
``json.loads``-style parser would do on the same input).
"""
from __future__ import annotations

from typing import Any, Dict, List

from bts_sbom._internal.models import DetectedPackage

# common.osv_client.OsvClient.map_ecosystem("debian") -> "Debian", OSV.dev's
# own ecosystem string for Debian packages (keep this literal lowercase - it
# matches every other manifest parser's convention: "pypi", "npm", "cargo",
# "go", "rubygems", "composer", "maven", "nuget", ... all lowercase source
# tags that OsvClient.map_ecosystem() canonicalises up to the real OSV name).
ECOSYSTEM = "debian"
_INSTALLED_STATUS_WORD = "installed"


def _flush(stanza: Dict[str, str], out: List[Any]) -> None:
    name = stanza.get("Package", "").strip()
    version = stanza.get("Version", "").strip()
    if not name or not version:
        return                        # incomplete stanza - nothing honest to report
    status_words = stanza.get("Status", "").split()
    if len(status_words) != 3 or status_words[2] != _INSTALLED_STATUS_WORD:
        return                        # removed / half-installed / unknown: not present
    arch = stanza.get("Architecture", "").strip()
    purl = "pkg:deb/%s/%s@%s" % (ECOSYSTEM, name, version)
    if arch:
        purl += "?arch=%s" % arch
    try:
        out.append(DetectedPackage(
            name=name, version=version, ecosystem=ECOSYSTEM, purl=purl,
            source="manifest:debian", provenance=["manifest:debian"],
            # dpkg's status file alone cannot prove direct-vs-transitive (that
            # needs apt's separate /var/lib/apt/extended_states "Auto-Installed"
            # records, which are not read here) - "unknown" is the honest tag,
            # matching how binary-signature-sourced components are tagged.
            relationship="unknown",
            depth=0, confidence="high",
        ))
    except Exception:
        return                        # one malformed stanza never nukes the rest


def parse_dpkg_status(text: str, path: str = "") -> List[Any]:
    """Parse a dpkg ``var/lib/dpkg/status`` file -> ``DetectedPackage`` list.

    Only ``Status: ... installed`` entries are emitted. Never raises - the
    worst case for genuinely unparseable input is an empty list, exactly like
    every other parser in this package (see common/manifests/extra.py).
    """
    out: List[Any] = []
    stanza: Dict[str, str] = {}
    for raw_line in (text or "").splitlines():
        if raw_line.strip() == "":
            if stanza:
                _flush(stanza, out)
            stanza = {}
            continue
        if raw_line[:1] in (" ", "\t"):
            continue                  # continuation line - belongs to the prior field
        field, sep, value = raw_line.partition(":")
        if not sep:
            continue                  # malformed line inside a stanza - skip it
        stanza[field.strip()] = value.strip()
    if stanza:                        # EOF with no trailing blank line
        _flush(stanza, out)
    return out


__all__ = ["parse_dpkg_status", "ECOSYSTEM"]

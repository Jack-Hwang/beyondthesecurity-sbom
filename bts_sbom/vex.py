# vendored from sca_guard/vex.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
OpenVEX document generation — the portable, standalone VEX interchange format
(https://openvex.dev, used by vexctl / Grype / Trivy). AutoGuard already embeds
CycloneDX-native VEX inside the CDX BOM (sbom_generator.py); this module emits the
*separate* OpenVEX JSON that downstream scanners consume to suppress or confirm
findings, and derives honest default statements straight from an OSV scan result.

Spec conformance (OpenVEX v0.2.0):
  * status ∈ {not_affected, affected, fixed, under_investigation}
  * a `not_affected` statement MUST carry a `justification` from the fixed vocab
    (or an `impact_statement`); OpenVEX rejects a bare not_affected.
  * an `affected` statement SHOULD carry an `action_statement`.
  * each statement pins the vulnerability, the product(s), and (optionally) the
    exact subcomponents, so the assertion is unambiguous.

HONESTY DISCIPLINE:
  * A package the OSV scan could NOT authoritatively query (`offline_no_data` /
    `unqueried`) is emitted as `under_investigation`, never as `not_affected` —
    absence of a queried result is not a clean bill of health.
  * A package with active advisories is `affected` with the advisory ids listed.
  * We never invent a `not_affected` justification; callers must supply it from a
    real triage decision. `withdrawn_statements()` is the one place we assert
    `not_affected`, and only because the advisory itself was withdrawn upstream.
"""
import json
import logging
import re as _re
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from bts_sbom._internal import timeutil

logger = logging.getLogger("OpenVEX")

_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# OpenVEX status vocabulary (exact spec tokens).
VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

# OpenVEX justification vocabulary — REQUIRED for a not_affected statement.
VEX_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
    "protected_by_compiler_hardening",
}

# Named constants — use these in code rather than raw strings.
VEX_JUSTIFICATION_COMPONENT_NOT_PRESENT      = "component_not_present"
VEX_JUSTIFICATION_CODE_NOT_PRESENT           = "vulnerable_code_not_present"
VEX_JUSTIFICATION_CODE_NOT_CONTROLLED        = "vulnerable_code_cannot_be_controlled_by_adversary"
VEX_JUSTIFICATION_CODE_NOT_IN_PATH           = "vulnerable_code_not_in_execute_path"
VEX_JUSTIFICATION_INLINE_MITIGATIONS         = "inline_mitigations_already_exist"
VEX_JUSTIFICATION_PROTECTED_BY_COMPILER      = "protected_by_compiler_hardening"

# Vulnerability ID format validation patterns.
# CVE-YYYY-NNNNN: 4-digit year, 4+ digit sequence (case-insensitive per practice).
# GHSA-XXXX-XXXX-XXXX: GitHub Security Advisory alphanumeric-triplet.
# _INTERNAL_ID_RE covers synthetic IDs AutoGuard emits (UNQUERIED:*, OSV-*, etc.).
_CVE_RE = _re.compile(r'^CVE-\d{4}-\d{4,}$', _re.IGNORECASE)
_GHSA_RE = _re.compile(r'^GHSA-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}$', _re.IGNORECASE)
_INTERNAL_ID_RE = _re.compile(r'^(UNQUERIED:|OSV-|RUSTSEC-|PYSEC-|GO-)', _re.IGNORECASE)


def _is_valid_vuln_id(vid: str) -> bool:
    """Return True when *vid* matches an accepted vulnerability identifier format.

    Accepted formats:
    * ``CVE-YYYY-NNNNN``           (4-digit year, 4+ digit sequence, case-insensitive)
    * ``GHSA-XXXX-XXXX-XXXX``     (GitHub Security Advisory alphanumeric triplet)
    * Internal AutoGuard sentinels: ``UNQUERIED:*``, ``OSV-*``, ``RUSTSEC-*``, etc.
    """
    return bool(_CVE_RE.match(vid) or _GHSA_RE.match(vid) or _INTERNAL_ID_RE.match(vid))


# CycloneDX → OpenVEX justification mapping.
# Three CycloneDX variant families are encountered in practice:
#
#   1. CDX 1.4 snake_case: code_not_present, code_not_reachable, protected_by_compiler …
#      These do NOT appear in VEX_JUSTIFICATIONS (OpenVEX vocab), so they must be
#      explicitly mapped here; the fallback `just_raw in VEX_JUSTIFICATIONS` misses them.
#
#   2. CDX 1.6 snake_case (matches OpenVEX directly): vulnerable_code_not_present …
#      These ARE in VEX_JUSTIFICATIONS, so the fallback handles them.
#      Listing them here as well avoids the map-miss-then-fallback path.
#
#   3. PascalCase from non-conformant tools (e.g. some SBOM generators):
#      ComponentNotPresent, VulnerableCodeNotPresent …
#
# CDX 1.4 values without a clean OpenVEX equivalent
# (requires_configuration, requires_dependency, requires_environment) are intentionally
# absent — they map to None via the fallback, and the caller should surface them via
# an impact_statement instead.
_CDX_JUSTIFICATION_MAP: Dict[str, str] = {
    # CDX 1.4 snake_case
    "code_not_present":                                 VEX_JUSTIFICATION_CODE_NOT_PRESENT,
    "code_not_reachable":                               VEX_JUSTIFICATION_CODE_NOT_IN_PATH,
    "protected_by_compiler":                            VEX_JUSTIFICATION_PROTECTED_BY_COMPILER,
    "protected_at_runtime":                             VEX_JUSTIFICATION_INLINE_MITIGATIONS,
    "protected_at_perimeter":                           VEX_JUSTIFICATION_INLINE_MITIGATIONS,
    "protected_by_mitigations":                         VEX_JUSTIFICATION_INLINE_MITIGATIONS,
    # CDX 1.6 / OpenVEX snake_case (direct match — also in VEX_JUSTIFICATIONS)
    "component_not_present":                            VEX_JUSTIFICATION_COMPONENT_NOT_PRESENT,
    "vulnerable_code_not_present":                      VEX_JUSTIFICATION_CODE_NOT_PRESENT,
    "vulnerable_code_not_in_execute_path":              VEX_JUSTIFICATION_CODE_NOT_IN_PATH,
    "vulnerable_code_cannot_be_controlled_by_adversary": VEX_JUSTIFICATION_CODE_NOT_CONTROLLED,
    "inline_mitigations_already_exist":                 VEX_JUSTIFICATION_INLINE_MITIGATIONS,
    "protected_by_compiler_hardening":                  VEX_JUSTIFICATION_PROTECTED_BY_COMPILER,
    # PascalCase (non-conformant tools)
    "ComponentNotPresent":                              VEX_JUSTIFICATION_COMPONENT_NOT_PRESENT,
    "VulnerableCodeNotPresent":                         VEX_JUSTIFICATION_CODE_NOT_PRESENT,
    "VulnerableCodeCannotBeControlledByAdversary":      VEX_JUSTIFICATION_CODE_NOT_CONTROLLED,
    "VulnerableCodeNotInExecutePath":                   VEX_JUSTIFICATION_CODE_NOT_IN_PATH,
    "InlineMitigationsAlreadyExist":                    VEX_JUSTIFICATION_INLINE_MITIGATIONS,
    "ProtectedByCompilerHardening":                     VEX_JUSTIFICATION_PROTECTED_BY_COMPILER,
}

# our internal triage_status -> OpenVEX status
_STATUS_MAP = {
    "resolved": "fixed",
    "fixed": "fixed",
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "in_triage": "under_investigation",
    "open": "under_investigation",
    "accepted": "affected",
    "exploitable": "affected",
    "affected": "affected",
}


class VexError(ValueError):
    """Raised when a statement would violate the OpenVEX spec (fail closed)."""


def _validate_statement(st: Dict[str, Any]) -> None:
    status = st.get("status")
    if status not in VEX_STATUSES:
        raise VexError(f"invalid VEX status {status!r}; must be one of {sorted(VEX_STATUSES)}")
    if status == "not_affected":
        just = st.get("justification")
        if not just and not st.get("impact_statement"):
            raise VexError(
                "a 'not_affected' VEX statement requires either a 'justification' "
                f"(one of {sorted(VEX_JUSTIFICATIONS)}) or an 'impact_statement'; "
                "asserting not_affected without evidence violates the OpenVEX spec and "
                "could silently suppress real vulnerabilities"
            )
        if just and just not in VEX_JUSTIFICATIONS:
            raise VexError(f"invalid justification {just!r}; must be one of {sorted(VEX_JUSTIFICATIONS)}")
    vuln_name = st.get("vulnerability", {}).get("name") or ""
    if not vuln_name:
        raise VexError("statement is missing a vulnerability name")
    if not _is_valid_vuln_id(vuln_name):
        raise VexError(
            f"vulnerability id {vuln_name!r} does not match an accepted format "
            "(expected CVE-YYYY-NNNNN or GHSA-XXXX-XXXX-XXXX)"
        )
    if not st.get("products"):
        raise VexError("statement is missing products")


def statement(vuln_id: str, products: List[str], status: str,
              justification: Optional[str] = None,
              action_statement: Optional[str] = None,
              impact_statement: Optional[str] = None,
              aliases: Optional[List[str]] = None,
              subcomponents: Optional[List[str]] = None) -> Dict[str, Any]:
    """Build (and validate) a single OpenVEX statement."""
    st: Dict[str, Any] = {
        "vulnerability": {"name": vuln_id},
        "products": [{"@id": p} for p in products],
        "status": status,
    }
    if aliases:
        st["vulnerability"]["aliases"] = sorted(set(aliases))
    if subcomponents:
        for p in st["products"]:
            p["subcomponents"] = [{"@id": s} for s in subcomponents]
    if justification:
        st["justification"] = justification
    if action_statement:
        st["action_statement"] = action_statement
    if impact_statement:
        st["impact_statement"] = impact_statement
    _validate_statement(st)
    return st


def build_document(statements: List[Dict[str, Any]], *, author: str = "bts-sbom",
                   timestamp: str, doc_id: str = "https://bts-sbom.local/vex/generated",
                   version: int = 1, tooling: str = "bts-sbom") -> Dict[str, Any]:
    """Assemble a complete OpenVEX document. `timestamp` (RFC-3339) is passed in so
    the output is reproducible/deterministic for CI and tests."""
    for st in statements:
        _validate_statement(st)
        st.setdefault("timestamp", timestamp)
    return {
        "@context": _CONTEXT,
        "@id": doc_id,
        "author": author,
        "timestamp": timestamp,
        "version": version,
        "tooling": tooling,
        "statements": statements,
    }


def _purl_or_name(pkg: Dict[str, Any]) -> str:
    """Prefer a purl product id; fall back to ecosystem/name@version."""
    if pkg.get("purl"):
        return pkg["purl"]
    eco = pkg.get("ecosystem", "")
    name, ver = pkg.get("name", ""), pkg.get("version", "")
    base = f"pkg:{eco.lower()}/{name}" if eco else name
    return f"{base}@{ver}" if ver else base


def from_scan_result(result: Dict[str, Any], *, timestamp: str,
                     author: str = "bts-sbom") -> Dict[str, Any]:
    """Derive an honest OpenVEX document from an OsvScanner result:
       * package with active advisories        -> affected (ids + action)
       * package flagged offline_no_data/unqueried -> under_investigation
       * everything else queried with no vulns  -> (no statement; silence = no claim)
    We deliberately do NOT emit not_affected for silent-clean packages — OpenVEX
    not_affected is an explicit human triage assertion, not the absence of a hit."""
    statements: List[Dict[str, Any]] = []
    for src in result.get("results", []):
        for pe in src.get("packages", []):
            pk = pe.get("package", {})
            product = _purl_or_name(pk)
            vulns = pe.get("vulnerabilities", []) or []
            if vulns:
                for v in vulns:
                    vid = v.get("id", "")
                    if not vid:
                        continue
                    statements.append(statement(
                        vid, [product], "affected",
                        action_statement=(f"Upgrade {pk.get('name','')} to a fixed "
                                          f"version; see the advisory."),
                        aliases=v.get("aliases") or None))
            elif pe.get("scan_status") in ("offline_no_data", "unqueried"):
                statements.append(statement(
                    f"UNQUERIED:{pk.get('name','')}", [product], "under_investigation",
                    impact_statement=("package could not be authoritatively queried "
                                      "(offline/no data) — NOT verified clean")))
    return build_document(statements, author=author, timestamp=timestamp)


def withdrawn_statements(withdrawn: List[Dict[str, Any]], *, timestamp: str,
                         author: str = "bts-sbom") -> Dict[str, Any]:
    """Emit not_affected statements for advisories that were WITHDRAWN upstream —
    the one legitimate machine-decidable not_affected (component_not_present is the
    closest OpenVEX justification: the advisory no longer asserts a real vuln)."""
    statements = []
    for w in withdrawn:
        vid, product = w.get("id", ""), w.get("product", "")
        if not vid or not product:
            continue
        statements.append(statement(
            vid, [product], "not_affected",
            justification="vulnerable_code_not_present",
            impact_statement=(f"advisory {vid} was withdrawn upstream "
                              f"({w.get('withdrawn','')}) and no longer asserts a vulnerability")))
    return build_document(statements, author=author, timestamp=timestamp)


def from_triaged(cve_objs: List[Any], *, timestamp: str,
                 author: str = "bts-sbom") -> Dict[str, Any]:
    """Map a list of triaged CveVulnerability objects to OpenVEX statements using
    their triage_status / triage_justification (fields already OpenVEX-style)."""
    statements = []
    for c in cve_objs:
        # A statement must have a valid vulnerability ID; skip silently-invalid entries
        # rather than propagating a VexError for every malformed object in the list.
        vid = (getattr(c, "cve_id", "") or "") or (getattr(c, "osv_id", "") or "")
        if not vid:
            logger.warning(
                "Skipping VEX statement: no vulnerability ID for %s@%s",
                getattr(c, "package_name", "?"),
                getattr(c, "package_version", "?"),
            )
            continue
        status = _STATUS_MAP.get(getattr(c, "triage_status", "") or "open",
                                 "under_investigation")
        product = f"pkg:{getattr(c, 'ecosystem', '').lower()}/{c.package_name}@{c.package_version}"
        just = getattr(c, "triage_justification", None)
        kwargs: Dict[str, Any] = {}
        if status == "not_affected":
            if just in VEX_JUSTIFICATIONS:
                kwargs["justification"] = just
            else:
                # cannot assert not_affected without a valid justification -> demote
                status = "under_investigation"
        elif status == "affected":
            kwargs["action_statement"] = (f"Upgrade to {c.fixed_version}" if getattr(c, "fixed_version", None)
                                          else "No fixed version published; apply mitigations.")
        osv_id = getattr(c, "osv_id", None)
        statements.append(statement(vid, [product], status,
                                    aliases=[osv_id] if osv_id and osv_id != vid else None,
                                    **kwargs))
    return build_document(statements, author=author, timestamp=timestamp)


# ── reachability-aware VEX (the Snyk/Endor Labs "reachability" differentiator) ──
# Map AutoGuard's function-level symbol reachability to an OpenVEX (status, just).
# Only SYMBOL-level evidence licenses a not_affected — a package merely being
# "present_only" is not sufficient to assert the vulnerable code is unreachable.
def _reachability_to_vex(symbol_reachability: str, pkg_reachability: str):
    """Return (status, justification, note) or (None, None, note) when the signal
    is too weak to assert anything (caller then falls back to affected/under_inv)."""
    sr = (symbol_reachability or "unknown").lower()
    if sr == "symbol_absent":
        return ("not_affected", "vulnerable_code_not_present",
                "the vulnerable function is absent from the linked binary")
    if sr == "defined_not_referenced":
        return ("not_affected", "vulnerable_code_not_in_execute_path",
                "the vulnerable function is present but never called (not reachable)")
    if sr == "reachable":
        return ("affected", None, "the vulnerable function is reachable from an entry point")
    # symbol reachability unknown → do NOT downgrade to not_affected on package-level
    # 'present_only' alone; that is an under-investigation, not a clean assertion.
    return (None, None, f"symbol reachability {sr!r} / package {pkg_reachability!r} — insufficient to assert")


def from_cve_reachability(cve_objs: List[Any], *, timestamp: str,
                          author: str = "bts-sbom") -> Dict[str, Any]:
    """Build an OpenVEX document whose statements are driven by FUNCTION-LEVEL
    reachability analysis — automatically emitting `not_affected` with the correct
    justification when the vulnerable symbol is absent or defined-but-uncalled, and
    `affected` when it is reachable. This is the reachability-triage that commercial
    tools charge for, produced honestly: an unknown reachability never becomes a
    clean not_affected, it stays under_investigation."""
    statements = []
    for c in cve_objs:
        # Guard: both cve_id and osv_id may be None/empty — apply the same
        # vid-guard as from_triaged() to avoid passing None to statement().
        vid = (getattr(c, "cve_id", "") or "") or (getattr(c, "osv_id", "") or "")
        if not vid:
            logger.warning(
                "Skipping reachability VEX statement: no vulnerability ID for %s@%s",
                getattr(c, "package_name", "?"),
                getattr(c, "package_version", "?"),
            )
            continue
        product = f"pkg:{getattr(c, 'ecosystem', '').lower()}/{c.package_name}@{c.package_version}"
        status, just, note = _reachability_to_vex(
            getattr(c, "symbol_reachability", "unknown"),
            getattr(c, "reachability", "unknown"))
        kwargs: Dict[str, Any] = {"impact_statement": note}
        if status == "not_affected":
            kwargs["justification"] = just
        elif status == "affected":
            kwargs.pop("impact_statement", None)
            kwargs["action_statement"] = (f"Upgrade to {c.fixed_version}"
                                          if getattr(c, "fixed_version", None)
                                          else "No fixed version; apply mitigations.")
        else:
            status = "under_investigation"
        osv_id = getattr(c, "osv_id", None)
        statements.append(statement(
            vid, [product], status,
            aliases=[osv_id] if osv_id and osv_id != vid else None, **kwargs))
    return build_document(statements, author=author, timestamp=timestamp)


# ── VEX ingestion / round-trip (consume a VEX, not just produce one) ────────────
class VexIndex:
    """A parsed OpenVEX document indexed for suppression lookups. Downstream scans
    query `status_for(vuln_ids, product)` to honour an upstream triage decision —
    only `not_affected` and `fixed` statements suppress a finding; `affected` and
    `under_investigation` never do."""

    _SUPPRESSING = {"not_affected", "fixed"}

    def __init__(self, document: Dict[str, Any]):
        self.document = document
        # (vuln_token_upper, product) -> statement.
        # Vulnerability tokens are stored upper-cased so CVE IDs match regardless of
        # the case used in the VEX document vs. the case used in a scan finding.
        self._by_key: Dict[tuple, Dict[str, Any]] = {}
        for st in (document.get("statements") or []):
            _validate_statement(st)
            name = st["vulnerability"]["name"]
            tokens = {name} | set(st["vulnerability"].get("aliases", []) or [])
            for p in st.get("products", []):
                pid = p.get("@id", "")
                for t in tokens:
                    upper_t = t.upper()
                    # Index only under the statement's own literal product id.
                    # A versioned product (e.g. pkg:pypi/requests@9.9.9) is pinned
                    # to EXACTLY that version — it must never be reachable via the
                    # version-stripped key, or it would widen to every version of
                    # the package. A version-less product id (no "@version") has
                    # nothing to strip, so this single store already makes it
                    # reachable by its bare id — which is exactly "applies to
                    # every version" (see status_for's stripped-query fallback).
                    self._by_key[(upper_t, pid)] = st

    def status_for(self, vuln_ids, product: str):
        """Return (status, justification) for the first matching statement, or
        (None, None). `vuln_ids` may be a single id or an iterable of id+aliases.
        CVE ID matching is case-insensitive: both index keys and query ids are
        upper-cased before comparison so ``CVE-2021-1234`` matches ``cve-2021-1234``.

        Product matching: an exact (vuln, product) match is tried first — this is
        what lets a version-pinned statement (e.g. requests@9.9.9) match only that
        exact version. Only when there is no exact match do we fall back to the
        version-stripped product key — and because a versioned statement is never
        indexed under its stripped form (see __init__), that fallback can only
        ever hit a statement whose product carried NO version to begin with, i.e.
        one that is meant to apply to every version of the package. A version-
        pinned statement can therefore never widen to suppress a different
        version."""
        if isinstance(vuln_ids, str):
            vuln_ids = [vuln_ids]
        for vid in vuln_ids:
            upper_vid = vid.upper()
            st = self._by_key.get((upper_vid, product))
            if st:
                return st["status"], st.get("justification")
            stripped_product = _strip_version(product)
            if stripped_product != product:
                st = self._by_key.get((upper_vid, stripped_product))
                if st:
                    return st["status"], st.get("justification")
        return None, None

    def is_suppressed(self, vuln_ids, product: str) -> bool:
        status, _ = self.status_for(vuln_ids, product)
        return status in self._SUPPRESSING


def parse_document(document: Dict[str, Any]) -> VexIndex:
    """Validate and index an OpenVEX document for suppression queries. Raises
    VexError on a spec violation (fail-closed — a malformed VEX suppresses nothing)."""
    if document.get("@context", "").split("/ns/")[0] != "https://openvex.dev":
        raise VexError("not an OpenVEX document (@context mismatch)")
    return VexIndex(document)


def apply_to_findings(findings: List[Dict[str, Any]], index: VexIndex) -> Dict[str, Any]:
    """Apply a VEX index to a list of findings (each a dict with `vuln_ids` or
    `cve_id`/`osv_id` and `product`). Returns {active, suppressed} partitions with
    each suppressed finding annotated with the VEX status/justification that
    silenced it — so suppression is always auditable, never silent."""
    active, suppressed = [], []
    for f in findings:
        ids = f.get("vuln_ids")
        if not ids:
            ids = [i for i in (f.get("cve_id"), f.get("osv_id")) if i]
        product = f.get("product", "")
        status, just = index.status_for(ids, product)
        if status in VexIndex._SUPPRESSING:
            g = dict(f)
            g["vex_status"], g["vex_justification"] = status, just
            suppressed.append(g)
        else:
            active.append(f)
    return {"active": active, "suppressed": suppressed,
            "suppressed_count": len(suppressed), "active_count": len(active)}


@dataclass
class VexStatement:
    """Lightweight, format-agnostic representation of a single VEX statement.
    Used as the common return type for load_vex_file() regardless of source format."""
    cve_id: str
    purl: str
    status: str
    justification: Optional[str] = None
    action_statement: Optional[str] = None
    impact_statement: Optional[str] = None
    aliases: List[str] = field(default_factory=list)


def generate_openvex(statements: List[VexStatement],
                     author: str = "bts-sbom") -> Dict[str, Any]:
    """Return a complete OpenVEX v0.2.0 JSON-LD dict from a list of VexStatement
    objects.  Each call gets a fresh UUID document id so documents are unique even
    when the same statements are exported multiple times.

    Each built statement is validated against the OpenVEX spec before assembly —
    a ``not_affected`` entry without a ``justification`` or ``impact_statement``
    raises ``VexError`` rather than silently producing an invalid document.
    """
    built = []
    for stmt in statements:
        st: Dict[str, Any] = {
            "vulnerability": {"name": stmt.cve_id},
            "products": [{"@id": stmt.purl}],
            "status": stmt.status,
            **({"justification": stmt.justification} if stmt.justification else {}),
            **({"action_statement": stmt.action_statement} if stmt.action_statement else {}),
            **({"impact_statement": stmt.impact_statement} if stmt.impact_statement else {}),
        }
        # Fail-closed: a malformed statement (e.g. bare not_affected) must not
        # silently produce an invalid document that suppresses real findings.
        _validate_statement(st)
        built.append(st)
    return {
        "@context": _CONTEXT,
        "@id": "https://bts-sbom.local/vex/" + str(uuid.uuid4()),
        "author": author,
        "timestamp": timeutil.utcnow().isoformat() + "Z",
        "version": 1,
        "statements": built,
    }


def _parse_openvex_document(doc: Dict[str, Any]) -> List[VexStatement]:
    """Convert an OpenVEX document dict into a list of VexStatement objects."""
    out: List[VexStatement] = []
    for st in (doc.get("statements") or []):
        vuln = st.get("vulnerability", {})
        cve_id = vuln.get("name", "")
        aliases = list(vuln.get("aliases", []) or [])
        for prod in st.get("products", []):
            out.append(VexStatement(
                cve_id=cve_id,
                purl=prod.get("@id", ""),
                status=st.get("status", "under_investigation"),
                justification=st.get("justification"),
                action_statement=st.get("action_statement"),
                impact_statement=st.get("impact_statement"),
                aliases=aliases,
            ))
    return out


def _parse_cyclonedx_vex(doc: Dict[str, Any]) -> List[VexStatement]:
    """Convert a CycloneDX VEX document dict into a list of VexStatement objects.
    Handles both standalone CDX VEX files and CDX BOM dicts that embed
    vulnerabilities.  Status tokens are mapped to the OpenVEX vocabulary."""
    _cdx_status: Dict[str, str] = {
        "not_affected": "not_affected",
        "false_positive": "not_affected",
        "exploitable": "affected",
        "in_triage": "under_investigation",
        "resolved": "fixed",
        "resolved_with_pedigree": "fixed",
    }
    out: List[VexStatement] = []
    for vuln in (doc.get("vulnerabilities") or []):
        cve_id = vuln.get("id", "")
        analysis = vuln.get("analysis", {})
        just_raw = analysis.get("justification", "")
        # Map CDX justification to OpenVEX vocab using the module-level table.
        # The table covers CDX 1.4 snake_case, CDX 1.6/OpenVEX snake_case, and
        # PascalCase from non-conformant tools.  A CDX value absent from the table
        # (e.g. requires_configuration) maps to None so the caller can fall back to
        # an impact_statement rather than emitting an invalid justification.
        justification = _CDX_JUSTIFICATION_MAP.get(just_raw) or None
        for affect in (vuln.get("affects") or []):
            purl = affect.get("ref", "")
            for v in (affect.get("versions") or [{"status": analysis.get("state", "")}]):
                raw_status = v.get("status", "")
                status = _cdx_status.get(raw_status, "under_investigation")
                impact_statement = analysis.get("detail")
                # Fail-closed: enforce the SAME statement validation the OpenVEX
                # producers use (_validate_statement) — a bare CycloneDX
                # not_affected (no justification/impact_statement) must raise
                # VexError here too, not silently pass through load_vex_file()/
                # `bts-sbom vex --check` as valid evidence.
                _validate_statement({
                    "status": status,
                    "justification": justification,
                    "impact_statement": impact_statement,
                    "vulnerability": {"name": cve_id},
                    "products": [{"@id": purl}] if purl else [],
                })
                out.append(VexStatement(
                    cve_id=cve_id,
                    purl=purl,
                    status=status,
                    justification=justification,
                    impact_statement=impact_statement,
                ))
    return out


def load_vex_file(path: str) -> List[VexStatement]:
    """Read a VEX JSON file and return a list of VexStatement objects.

    Auto-detects the source format by inspecting ``@context``:
    * if ``@context`` contains ``"openvex"``  -> parsed as OpenVEX v0.2.0
    * otherwise                               -> parsed as CycloneDX VEX / BOM

    Raises ``VexError`` on JSON decode failures or unrecognisable structure so
    callers can fail-closed rather than silently ignoring a corrupt VEX file.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise VexError(f"cannot load VEX file {path!r}: {exc}") from exc

    if not isinstance(doc, dict):
        raise VexError(f"VEX file {path!r} must contain a JSON object at the top level")

    context = doc.get("@context", "")
    if "openvex" in context:
        logger.debug("load_vex_file: detected OpenVEX format (%s)", path)
        return _parse_openvex_document(doc)

    logger.debug("load_vex_file: detected CycloneDX VEX format (%s)", path)
    return _parse_cyclonedx_vex(doc)


def _strip_version(pid: str) -> str:
    """`pkg:pypi/foo@1.0` -> `pkg:pypi/foo` (product identity without the version)."""
    return pid.rsplit("@", 1)[0] if "@" in pid else pid


def render(document: Dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False)

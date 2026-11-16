"""Stdlib data models replacing the platform's pydantic state models.

The platform keeps these in ``sca_guard/agent/state.py`` as pydantic
BaseModels. bts-sbom is stdlib-only, so the SAME field surface is provided
here as plain dataclasses. Field-for-field these carry what the vendored
SCA pipeline (manifest parsers, OsvScanner._to_cve, fix_planner, vex)
reads or writes:

  * DetectedPackage  -- one dependency found in a manifest / lockfile /
    package database (name, version, ecosystem, purl, provenance, and the
    direct/transitive graph evidence).
  * CveVulnerability -- one advisory matched against a component, with the
    triage / VEX / reachability fields the report layer consumes.

Honesty note: this is a REPLACEMENT, not a re-implementation of pydantic.
No validation/coercion happens here (values are used as given); the fields
below are exactly the attributes the vendored modules access.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectedPackage:
    """One dependency discovered in a manifest/lockfile/package-DB."""
    name: str
    version: str
    ecosystem: str                    # Debian, RPM, PyPI, npm, OSS-Fuzz, etc.
    purl: str = ""                    # Package URL (pkg:deb/debian/busybox@1.35.0)
    source: str = "manifest"          # "dpkg-db" | "rpm-db" | manifest:<ecosystem> | ...
    license: Optional[str] = None
    file_path: Optional[str] = None   # Path where detected inside rootfs

    # --- Binary-signature evidence (commercial binary-SCA style) ---
    cpe: Optional[str] = None
    confidence: str = "high"          # high (pkg-db/signature) | medium | low
    evidence: Optional[str] = None    # matched banner string that justified the match
    sha256: Optional[str] = None
    provenance: List[str] = field(default_factory=list)

    # --- Dependency graph (direct vs transitive) ---
    relationship: str = "unknown"     # direct | transitive | unknown
    depth: int = 0                    # 0 = direct/root, >0 = transitive depth
    dependency_parents: List[str] = field(default_factory=list)

    # --- Reachability ---
    reachability: str = "unknown"     # reachable | present_only | unknown
    reachable_note: Optional[str] = None

    # --- Package Health Score ---
    health_score: float = 0.0
    health_details: Optional[Dict[str, Any]] = None


@dataclass
class CveVulnerability:
    """One advisory matched against one component (platform state contract)."""
    package_name: str
    package_version: str
    cve_id: str                       # CVE-2024-xxxxx or GHSA-xxxx
    osv_id: Optional[str] = None
    severity: str = "UNKNOWN"         # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str = ""
    fixed_version: Optional[str] = None
    fix_available: bool = False
    references: List[str] = field(default_factory=list)
    ecosystem: str = "generic"

    # --- Prioritization (EPSS + CISA KEV + maturity) ---
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    kev: bool = False
    is_kev: bool = False
    exploit_maturity: Optional[str] = None
    priority_score: float = 0.0
    priority_label: Optional[str] = None      # P0..P4
    exploit_evidence: List[str] = field(default_factory=list)
    epss_source: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    published: Optional[str] = None
    last_modified: Optional[str] = None

    # --- Triage / VEX state ---
    triage_status: str = "open"       # open | not_affected | false_positive | in_triage | resolved | accepted
    triage_justification: Optional[str] = None
    is_malicious: bool = False
    auto_triaged: bool = False
    triage_suggestion: Optional[str] = None

    # --- Dependency / reachability context ---
    relationship: str = "unknown"     # direct | transitive | unknown
    reachability: str = "unknown"     # reachable | present_only | unknown
    symbol_reachability: str = "unknown"      # reachable | defined_not_referenced | symbol_absent | unknown
    symbol_reachability_confidence: str = "curated"
    symbol_evidence: Optional[str] = None
    upgrade_path: Optional[str] = None
    suggested_action: Optional[str] = None    # upgrade | patch | workaround | accept
    target_version: Optional[str] = None


__all__ = ["DetectedPackage", "CveVulnerability"]

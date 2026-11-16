"""bts-sbom — regulatory-sector SBOM/SCA toolkit (stdlib-only, pip-installable).

CRA · FDA 524B · UNECE R155/R156 · EO 14028 · 금융 OSS 가이드 · 로봇/ISO 10218

Public API (behavior-preserving vendor of the platform sca_guard/common SCA
stack; see bts_sbom/_internal/ for the vendored supporting modules):

    from bts_sbom import sector_report, build_spdx_document, OsvScanner, VexIndex
"""
from bts_sbom.sbom import (  # noqa: F401
    TOOL_NAME,
    build_spdx_document,
    sbom_from_manifest,
    sbom_from_resolver_graph,
    validate_spdx,
)
from bts_sbom.vex import (  # noqa: F401
    VexError,
    VexIndex,
    VexStatement,
    apply_to_findings,
    build_document,
    from_cve_reachability,
    from_scan_result,
    from_triaged,
    generate_openvex,
    load_vex_file,
    parse_document,
    render,
    statement,
    withdrawn_statements,
)
from bts_sbom.osvscanner import (  # noqa: F401
    DATA_STATUSES,
    OsvScanner,
    component_identity,
    gate_exit_code,
    is_exact_version,
    normalize_ecosystem,
    sca_gate_check,
    scan,
)
from bts_sbom.sca_report import build_report  # noqa: F401
from bts_sbom.supply_chain import SupplyChainAnalyzer  # noqa: F401
from bts_sbom.reachability import (  # noqa: F401
    ReachabilityEngine,
    ReachabilityResult,
    enrich_sca_vulns,
)
from bts_sbom.sectors import (  # noqa: F401
    SCHEMA,
    SECTORS,
    SECTOR_PROFILES,
    SECTOR_TITLES,
    sector_report,
    write_evidence,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # sbom
    "TOOL_NAME", "build_spdx_document", "sbom_from_manifest",
    "sbom_from_resolver_graph", "validate_spdx",
    # vex
    "VexError", "VexIndex", "VexStatement", "apply_to_findings",
    "build_document", "from_cve_reachability", "from_scan_result",
    "from_triaged", "generate_openvex", "load_vex_file", "parse_document",
    "render", "statement", "withdrawn_statements",
    # osvscanner
    "DATA_STATUSES", "OsvScanner", "component_identity", "gate_exit_code",
    "is_exact_version", "normalize_ecosystem", "sca_gate_check", "scan",
    # report / analysis
    "build_report", "SupplyChainAnalyzer",
    # reachability
    "ReachabilityEngine", "ReachabilityResult", "enrich_sca_vulns",
    # sectors
    "SCHEMA", "SECTORS", "SECTOR_PROFILES", "SECTOR_TITLES",
    "sector_report", "write_evidence",
]

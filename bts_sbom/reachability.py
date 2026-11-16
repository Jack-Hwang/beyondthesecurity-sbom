# vendored from sca_guard/reachability.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
SCA Reachability Analysis — Snyk / Black Duck commercial gap-closer

Connects CVE/vulnerability findings from the SCA scanner to the call graph built
by `misra_guard/dataflow/callgraph.py`.

HONEST VERDICT CONTRACT (audit SCA-P0-A / 2026-10-11)
-----------------------------------------------------
A non-path in an incomplete call graph proves nothing.  The only thing this
analysis can assert without completeness evidence is "no path was found from
the confirmed roots of the graph AS BUILT".  Therefore:

  REACHABLE            — a direct-call path from an effective entry point to the
                         vulnerable function was found; the path is reported.
                         (A found path is real code regardless of graph
                         completeness, so it is never downgraded.)
  UNREACHABLE          — no path exists AND the graph is complete enough to make
                         that absence meaningful: every completeness assumption
                         the verdict rests on is listed in `assumptions`.
  REACHABILITY_UNKNOWN — the verdict cannot be proven: no effective entry point,
                         unresolved callback / indirect-call registrations,
                         same-name function collisions, or an incomplete build
                         model.  UNKNOWN is NEVER relaxed to UNREACHABLE, never
                         risk-downgraded, and never treated as safe.

Every result also carries graph completeness, root completeness, the build
model, unsupported constructs and provenance, so a reviewer can see exactly
what the verdict does and does not cover.

Entry points
------------
  ReachabilityEngine.analyze(source_files, vulns) → List[ReachabilityResult]
  enrich_sca_vulns(vulns, source_files)            → vulns with reachability field
"""
from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("SCAReachability")

VERDICT_REACHABLE = "REACHABLE"
VERDICT_UNREACHABLE = "UNREACHABLE"
VERDICT_UNKNOWN = "REACHABILITY_UNKNOWN"

# Functions that are typical entry points in ECU/embedded code
_DEFAULT_ENTRY_POINTS = {
    "main", "app_main", "os_main",
    # AUTOSAR OS tasks
    "TASK", "ISR", "SchM_Enter", "SchM_Exit",
    # FreeRTOS tasks
    "vTaskCreate", "xTaskCreate", "vTaskStartScheduler",
    # CAN callbacks
    "CanIf_RxIndication", "CanIf_TxConfirmation", "Can_MainFunction_Read",
    # UDS
    "UdsApp_HandleRequest", "Dcm_MainFunction",
    # OTA
    "Fota_MainFunction", "FotaClient_Process",
    # LIN
    "LinIf_MainFunction", "Lin_Wakeup",
    # Test harnesses
    "test_main", "setUp", "tearDown",
}

# Known vulnerable function names by CVE family (used when library version match
# gives us the affected function name).  This is a simplified table — a full
# production system queries an NVD/OSV function-level API.
_CVE_FUNCTION_MAP: Dict[str, List[str]] = {
    # OpenSSL
    "CVE-2014-0160": ["ssl3_read_bytes", "dtls1_process_heartbeat"],  # Heartbleed
    "CVE-2022-0778": ["BN_mod_sqrt"],
    "CVE-2023-0286": ["X509_get1_email", "GENERAL_NAME_cmp"],
    # libcurl
    "CVE-2023-38545": ["socks5_resolve_remote"],
    "CVE-2022-27781": ["tftp_receive_packet"],
    # expat
    "CVE-2022-25236": ["PREFIX_from_NsName"],
    "CVE-2022-40674": ["doContent"],
    # zlib
    "CVE-2022-37434": ["inflateGetHeader"],
    # glibc
    "CVE-2015-7547": ["_nss_dns_gethostbyname4_r"],
    # busybox
    "CVE-2022-28391": ["receive_file"],
    # mbedTLS
    "CVE-2021-44732": ["mbedtls_ssl_read"],
}

# Callback / indirect-call evidence in raw source text.  False positives only
# make the analysis MORE conservative (they record incompleteness), which is the
# safe direction; false negatives are impossible for the shapes below because
# both address-of and bare-name registration argument positions are covered.
_ADDR_TAKEN_RE = re.compile(r"&\s*([A-Za-z_]\w*)\b")
_BARE_ARG_RE = re.compile(r"[(,]\s*([A-Za-z_]\w*)\s*[,)]")


@dataclass
class ReachabilityResult:
    cve_id: str
    package: str
    version: str
    verdict: str                  # REACHABLE | UNREACHABLE | REACHABILITY_UNKNOWN
    vuln_functions: List[str]
    reachable_via: List[str] = field(default_factory=list)  # call path (REACHABLE)
    detail: str = ""
    # ---- completeness evidence (audit SCA-P0-A) ----
    graph_completeness: Dict[str, Any] = field(default_factory=dict)
    root_completeness: Dict[str, Any] = field(default_factory=dict)
    build_model: Dict[str, Any] = field(default_factory=dict)
    unsupported_constructs: List[str] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    # completeness assumptions an UNREACHABLE verdict depends on
    assumptions: List[str] = field(default_factory=list)
    # reasons a verdict could not be proven (UNKNOWN only)
    unknown_reasons: List[str] = field(default_factory=list)
    # WHERE the vulnerability-existence claim comes from. Existence (the CVE
    # matches this package version) is asserted UPSTREAM of this engine by the
    # SCA data layer; reachability is a separate dimension and NEVER overrides
    # it. In particular REACHABILITY_UNKNOWN does not mean exploitable=false —
    # no field derived here may be read as an exploitability denial.
    existence_basis: str = ("advisory-match (asserted by the SCA data layer "
                            "before this engine runs)")

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class _Graph:
    """Call graph as built, with the completeness evidence needed to say what
    the graph does and does not cover."""
    adjacency: Dict[str, Set[str]]
    defs: Dict[str, List[str]]           # name -> [file, ...] (per-TU identity)
    collisions: Dict[str, List[str]]     # name -> files defining it more than once
    callback_candidates: Set[str]        # defined names registered/address-taken
    unresolved_callees: Set[str]         # called but never defined (binary-only)
    functions: int
    files_parsed: int
    files_failed: List[str]

    @property
    def all_funcs(self) -> Set[str]:
        return set(self.adjacency)


def _completeness(graph: Optional[_Graph]) -> Dict[str, Any]:
    if graph is None:
        return {"complete": False, "reasons": ["no call graph could be built"],
                "functions": 0, "files_parsed": 0, "files_failed": [],
                "same_name_collisions": {}, "unresolved_callees": []}
    collisions = {k: v for k, v in graph.collisions.items()}
    complete = (graph.functions > 0 and not graph.files_failed
                and not graph.callback_candidates and not collisions
                and not graph.unresolved_callees)
    return {
        "complete": complete,
        "reasons": ([] if complete else [
            *(["source files failed to parse: %s" % graph.files_failed]
              if graph.files_failed else []),
            *(["callback / address-taken registrations unresolved: %s"
               % sorted(graph.callback_candidates)]
              if graph.callback_candidates else []),
            *(["same-name functions in multiple translation units: %s" % collisions]
              if collisions else []),
            *(["calls leave the analyzed graph: %s"
               % sorted(graph.unresolved_callees)]
              if graph.unresolved_callees else []),
        ]),
        "functions": graph.functions,
        "files_parsed": graph.files_parsed,
        "files_failed": list(graph.files_failed),
        "same_name_collisions": collisions,
        "unresolved_callees": sorted(graph.unresolved_callees),
    }


# ---------------------------------------------------------------------------
# Call graph construction with per-TU provenance
# ---------------------------------------------------------------------------

def _build_graph_from_sources(source_files: List[str]) -> _Graph:
    """Parse every source file, keep file/translation-unit identity per function,
    then populate call edges via the real callgraph engine (CallGraph).

    Same-name functions across files are recorded as collisions: the bare-name
    adjacency unions their edges (a conservative over-approximation for path
    FINDING) but any verdict that depends on WHICH definition is bound is
    refused (see _unknown_reasons).
    """
    from bts_sbom._internal.callgraph import parse_functions, CallGraph

    per_file: List[tuple] = []          # (file, [ParsedFunction, ...])
    files_failed: List[str] = []
    for sf in source_files:
        if not os.path.isfile(sf):
            files_failed.append(sf)
            continue
        ext = os.path.splitext(sf)[1].lower()
        if ext not in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"):
            continue
        try:
            with open(sf, encoding="utf-8", errors="replace") as fh:
                code = fh.read()
            fns = parse_functions(code)
            if fns:
                per_file.append((sf, fns))
        except Exception as e:
            logger.debug("callgraph parse error in %s: %s", sf, e)
            files_failed.append(sf)

    all_fns = [fn for _f, fns in per_file for fn in fns]
    if not all_fns:
        return _Graph(adjacency={}, defs={}, collisions={},
                      callback_candidates=set(), unresolved_callees=set(),
                      functions=0, files_parsed=0, files_failed=files_failed)

    # The CallGraph constructor populates fn.calls (direct + indirect) against
    # the GLOBAL defined set, so cross-file direct calls resolve correctly.
    cg = CallGraph(all_fns)

    defs: Dict[str, List[str]] = {}
    for sf, fns in per_file:
        for fn in fns:
            defs.setdefault(fn.name, []).append(sf)
    collisions = {name: files for name, files in defs.items() if len(files) > 1}

    adjacency: Dict[str, Set[str]] = {}
    for fn in all_fns:
        # UNION across same-named defs (never overwrite): dropping one def's
        # edges hid real call edges and manufactured false UNREACHABLEs.
        adjacency.setdefault(fn.name, set()).update(
            {cs.callee for cs in fn.calls if cs.callee})

    unresolved: Set[str] = set()
    for callees in adjacency.values():
        unresolved.update(c for c in callees if c not in defs)

    # Callback / indirect-call evidence: defined functions whose address is
    # taken or that appear as a bare registration argument.  A framework can
    # invoke any of them without a graph edge we can see.
    defined = set(defs)
    callback_candidates: Set[str] = set(cg.address_taken) & defined
    for sf, fns in per_file:
        with open(sf, encoding="utf-8", errors="replace") as fh:
            code = fh.read()
        for m in _BARE_ARG_RE.finditer(code):
            name = m.group(1)
            if name in defined:
                callback_candidates.add(name)

    return _Graph(adjacency=adjacency, defs=defs, collisions=collisions,
                  callback_candidates=callback_candidates,
                  unresolved_callees=unresolved,
                  functions=len(defs), files_parsed=len(per_file),
                  files_failed=files_failed)


def _reachable_from(entry_points: Set[str], target: str,
                    adj: Dict[str, Set[str]]) -> Optional[List[str]]:
    """BFS from any entry point to target. Returns path or None."""
    if target in entry_points:
        return [target]
    visited: Set[str] = set()
    # Queue: (current_node, path_so_far)
    queue: list = [(ep, [ep]) for ep in entry_points if ep in adj]
    while queue:
        node, path = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        for callee in adj.get(node, []):
            new_path = path + [callee]
            if callee == target:
                return new_path
            if callee not in visited:
                queue.append((callee, new_path))
    return None


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class ReachabilityEngine:
    """Links SCA CVE findings to call-graph reachability — without ever
    converting an unproven verdict into a downgrade.

    ``build_model`` records what the analyzed file list represents.  The default
    (``None``) is an ad-hoc file list with NO attested translation-unit
    completeness, which blocks UNREACHABLE (an absent path proves nothing when
    translation units may be missing).  A caller that derived the list from a
    real build (e.g. compile_commands.json) attests:
        {"mode": "declared", "translation_units": [...], "declared_complete": True}
    """

    def __init__(self, entry_points: Optional[Set[str]] = None,
                 build_model: Optional[Dict[str, Any]] = None):
        self._custom_entries = entry_points is not None
        self.entry_points = entry_points or _DEFAULT_ENTRY_POINTS.copy()
        self.build_model = dict(build_model) if build_model else {
            "mode": "ad-hoc-files",
            "declared_complete": False,
            "note": "file list was not attested against a real build "
                    "(compile_commands.json / full TU set) - absence of a "
                    "path cannot prove unreachability",
        }

    # -- blocker / metadata helpers ------------------------------------------
    def _root_completeness(self, graph: _Graph,
                           effective_entries: Set[str]) -> Dict[str, Any]:
        return {
            "declared_entry_points": sorted(self.entry_points),
            "effective_entries": sorted(effective_entries),
            "roots_resolved": bool(effective_entries),
            "callback_roots": sorted(graph.callback_candidates),
            "note": ("callbacks registered through function pointers are "
                     "potential roots the graph cannot enumerate" if
                     graph.callback_candidates else ""),
        }

    def _unknown_reasons(self, graph: _Graph,
                         effective_entries: Set[str],
                         vuln_fns: List[str],
                         source_files: List[str]) -> List[str]:
        """Every reason the verdict cannot be proven for these functions."""
        reasons: List[str] = []
        if not effective_entries:
            reasons.append(
                "no effective entry point: none of the declared entry points "
                "(%d) are defined in the parsed graph - a framework callback "
                "may call anything" % len(self.entry_points))
        if graph.callback_candidates:
            reasons.append(
                "unresolved callback / indirect-call registration: %s - the "
                "graph cannot enumerate their runtime targets"
                % sorted(graph.callback_candidates))
        if graph.files_failed:
            reasons.append(
                "source files were missing or failed to parse: %s - the "
                "analyzed graph is incomplete" % sorted(graph.files_failed))
        if graph.collisions:
            reasons.append(
                "same-name collision(s) exist in the analyzed translation "
                "units: %s - bare-name binding and paths are not complete"
                % {name: graph.collisions[name]
                   for name in sorted(graph.collisions)})
        if graph.unresolved_callees:
            reasons.append(
                "calls leave the analyzed graph: %s - without external-call "
                "models those callees may invoke callbacks into the program"
                % sorted(graph.unresolved_callees))
        if not self.build_model.get("declared_complete"):
            reasons.append(
                "incomplete build model: %s" % self.build_model.get("mode"))
        else:
            declared = self.build_model.get("translation_units")
            if not isinstance(declared, (list, tuple, set)) or not declared:
                reasons.append(
                    "declared-complete build model has no translation_units "
                    "inventory to verify")
            else:
                def _canon(path: Any) -> str:
                    return os.path.normcase(os.path.realpath(os.fspath(path)))

                declared_units = {_canon(path) for path in declared}
                analyzed_units = {
                    _canon(path) for path in source_files
                    if os.path.splitext(os.fspath(path))[1].lower()
                    in (".c", ".cpp", ".cc", ".cxx")
                }
                missing = sorted(declared_units - analyzed_units)
                undeclared = sorted(analyzed_units - declared_units)
                if missing:
                    reasons.append(
                        "declared translation units were not supplied to the "
                        "analysis: %s" % missing)
                if undeclared:
                    reasons.append(
                        "analyzed translation units were absent from the "
                        "declared build inventory: %s" % undeclared)
        return reasons

    def analyze(
        self,
        source_files: List[str],
        vulns: List[Dict[str, Any]],
    ) -> List[ReachabilityResult]:
        """
        Parameters
        ----------
        source_files : list of C/C++ source file paths
        vulns        : list of SCA vuln dicts with keys:
                       cve_id, package, version, (optional) affected_functions

        Returns
        -------
        List[ReachabilityResult]
        """
        graph = _build_graph_from_sources(source_files)
        all_funcs = graph.all_funcs
        effective_entries = self.entry_points & all_funcs
        graph_meta = _completeness(graph)
        root_meta = self._root_completeness(graph, effective_entries)
        provenance = {
            "engine": "bts_sbom.reachability.ReachabilityEngine",
            "parser": "bts_sbom._internal.callgraph.parse_functions+CallGraph",
            "source_files": list(source_files),
            "entry_point_source": "caller" if self._custom_entries
                                  else "default-embedded",
            "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        def _meta() -> Dict[str, Any]:
            return {"graph_completeness": dict(graph_meta),
                    "root_completeness": dict(root_meta),
                    "build_model": dict(self.build_model),
                    "unsupported_constructs": sorted(graph.callback_candidates)
                                              + sorted(graph.collisions),
                    "provenance": dict(provenance)}

        if not all_funcs:
            # No graph — everything is UNKNOWN (honest; never a downgrade)
            results = []
            for v in vulns:
                r = ReachabilityResult(
                    cve_id=v.get("cve_id", ""),
                    package=v.get("package", v.get("name", "")),
                    version=v.get("version", ""),
                    verdict=VERDICT_UNKNOWN,
                    vuln_functions=[],
                    detail="Source files unavailable or unparseable — reachability undetermined",
                    unknown_reasons=["call graph is empty: nothing parsed"])
                r.__dict__.update(_meta())
                results.append(r)
            return results

        results: List[ReachabilityResult] = []
        for vuln in vulns:
            cve_id = vuln.get("cve_id", "")
            pkg = vuln.get("package", vuln.get("name", ""))
            ver = vuln.get("version", "")

            # Determine which functions to probe
            vuln_fns: List[str] = list(vuln.get("affected_functions", []))
            if not vuln_fns and cve_id in _CVE_FUNCTION_MAP:
                vuln_fns = _CVE_FUNCTION_MAP[cve_id]

            if not vuln_fns:
                r = ReachabilityResult(
                    cve_id=cve_id, package=pkg, version=ver,
                    verdict=VERDICT_UNKNOWN,
                    vuln_functions=[],
                    detail="No function-level CVE mapping available — manual review required",
                    unknown_reasons=["no function-level CVE mapping available"])
                r.__dict__.update(_meta())
                results.append(r)
                continue

            # BFS for each candidate function
            found_path: Optional[List[str]] = None
            reachable_fn = ""
            for fn in vuln_fns:
                path = _reachable_from(effective_entries, fn, graph.adjacency)
                if path:
                    found_path = path
                    reachable_fn = fn
                    break

            if found_path:
                # A proven path is real code — REACHABLE is never relaxed.  But
                # a same-name collision ON the path (or on the target) makes the
                # binding ambiguous: the path may traverse the wrong definition.
                on_path = sorted(set(found_path) & set(graph.collisions))
                if on_path or reachable_fn in graph.collisions:
                    r = ReachabilityResult(
                        cve_id=cve_id, package=pkg, version=ver,
                        verdict=VERDICT_UNKNOWN,
                        vuln_functions=vuln_fns,
                        detail=f"A call path to '{reachable_fn}' exists "
                               f"({' -> '.join(found_path)}) but same-name "
                               f"collisions {on_path or [reachable_fn]} make the "
                               "bound definition ambiguous — not asserted "
                               "REACHABLE, not downgraded",
                        unknown_reasons=[
                            "same-name collision on the proven path: %s" % on_path])
                    r.__dict__.update(_meta())
                    results.append(r)
                    continue
                r = ReachabilityResult(
                    cve_id=cve_id, package=pkg, version=ver,
                    verdict=VERDICT_REACHABLE,
                    vuln_functions=vuln_fns,
                    reachable_via=found_path,
                    detail=f"Vulnerable function '{reachable_fn}' reachable via: "
                           + " -> ".join(found_path),
                )
                r.__dict__.update(_meta())
                results.append(r)
                continue

            # No path found.  Provable UNREACHABLE requires EVERY completeness
            # assumption to hold; any blocker keeps the verdict UNKNOWN.
            reasons = self._unknown_reasons(
                graph, effective_entries, vuln_fns, source_files)
            any_present = any(fn in all_funcs for fn in vuln_fns)
            if reasons:
                if any_present:
                    detail = (f"Vulnerable functions {vuln_fns} exist in the graph "
                              "but no path was found from the confirmed roots — "
                              "the absence is NOT provable as UNREACHABLE "
                              "(completeness blockers below)")
                else:
                    detail = (f"Functions {vuln_fns} not found in parsed sources "
                              "(may be in a binary-only library) — reachability "
                              "undetermined")
                    reasons = ["vulnerable functions absent from the parsed graph "
                               "(binary-only library or parse gap)"] + reasons
                r = ReachabilityResult(
                    cve_id=cve_id, package=pkg, version=ver,
                    verdict=VERDICT_UNKNOWN,
                    vuln_functions=vuln_fns,
                    detail=detail,
                    unknown_reasons=reasons)
                r.__dict__.update(_meta())
                results.append(r)
                continue

            # Every assumption holds: the absence of a path is meaningful.
            assumptions = [
                "entry points confirmed in-graph: %s" % sorted(effective_entries),
                "no unresolved callback / indirect-call registrations detected",
                "no same-name collisions on the vulnerable functions",
                "build model: %s (declared complete by the caller)"
                % self.build_model.get("mode"),
                "parser approximation: regex-based C/C++ call extraction "
                "(bts_sbom._internal.callgraph) — macro-generated or "
                "preprocessed-away calls are not visible",
            ]
            r = ReachabilityResult(
                cve_id=cve_id, package=pkg, version=ver,
                verdict=VERDICT_UNREACHABLE,
                vuln_functions=vuln_fns,
                detail=f"Vulnerable functions {vuln_fns} exist in code and are "
                       "not reachable from any effective entry point UNDER THE "
                       "COMPLETENESS ASSUMPTIONS LISTED — not a safety claim",
            )
            r.assumptions = assumptions
            r.__dict__.update(_meta())
            results.append(r)

        return results


def enrich_sca_vulns(
    vulns: List[Dict[str, Any]],
    source_files: List[str],
    entry_points: Optional[Set[str]] = None,
    build_model: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Enrich a list of SCA vuln dicts with reachability information in-place.
    Returns the same list (mutated) for pipeline chaining.

    Adds to each vuln:
      reachability             : "REACHABLE" | "UNREACHABLE" | "REACHABILITY_UNKNOWN"
      reachability_path        : list of function names (only when REACHABLE)
      reachability_detail      : human-readable explanation
      reachability_completeness: graph/root completeness, build model,
                                 unsupported constructs, provenance
      reachability_assumptions : UNREACHABLE only — assumptions the verdict rests on
      reachability_unknown_reasons : UNKNOWN only — why the verdict is unproven
      vulnerability_present    : constant "asserted_by_advisory_match" — the
                                 vulnerability EXISTS because an advisory matched;
                                 this is independent of `reachability` and is
                                 never weakened by it (UNKNOWN is not absence)
      reachability_exploitable : always None — an explicit NOT-ASSERTED marker.
                                 No engine in this path derives exploitability:
                                 even REACHABLE proves a code path, not attacker
                                 exploitability, and REACHABILITY_UNKNOWN must
                                 never surface as exploitable=false.

    An UNKNOWN verdict is never converted into a safe/downgraded state here.
    """
    engine = ReachabilityEngine(entry_points=entry_points, build_model=build_model)
    results = engine.analyze(source_files, vulns)
    by_cve = {r.cve_id: r for r in results}
    for v in vulns:
        r = by_cve.get(v.get("cve_id", ""))
        if r:
            v["reachability"] = r.verdict
            v["reachability_path"] = r.reachable_via
            v["reachability_detail"] = r.detail
            v["reachability_completeness"] = {
                "graph": r.graph_completeness,
                "roots": r.root_completeness,
                "build_model": r.build_model,
                "unsupported_constructs": r.unsupported_constructs,
                "provenance": r.provenance,
            }
            v["reachability_assumptions"] = r.assumptions
            v["reachability_unknown_reasons"] = r.unknown_reasons
            # existence / reachability stay SEPARATE fields (Batch C1): the
            # advisory match asserts existence; reachability never retracts it.
            v["vulnerability_present"] = "asserted_by_advisory_match"
            v["reachability_exploitable"] = None   # not derived here — ever
    return vulns

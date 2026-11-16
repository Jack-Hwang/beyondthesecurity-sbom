# vendored from sca_guard/supply_chain.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Supply-chain risk analysis — the dependency-substitution attacks that a CVE-only
SCA never sees, but that Snyk / Socket.dev / JFrog make a headline feature:

  * TYPOSQUATTING          a dependency name one edit away from a popular package
                           (`reqeusts`→`requests`, `loadash`→`lodash`) — an attacker
                           publishes malware under the misspelling.
  * HOMOGLYPH / CONFUSABLE  visually-identical substitution (`l`↔`1`, `rn`↔`m`,
                           `0`↔`o`) that reads as a trusted name.
  * DEPENDENCY CONFUSION    an internal/private package name that also resolves from a
                           PUBLIC registry — the resolver may pull the attacker's
                           public copy (the 2021 Birsan attack).

Deterministic and offline. HONESTY / PRECISION discipline:
  * the exact popular name itself is NEVER flagged (only near-misses are),
  * a match must be a genuine near-miss (bounded edit distance / confusable-equal),
    with a minimum name length so short names don't create noise,
  * dependency-confusion is only asserted for names the caller declares INTERNAL
    (policy-driven) — we never guess that a public package is "supposed to be private",
  * the popular-name seed list is small and explicit; callers extend it with their
    own registry-popularity data (the method does not pretend to know every package).
"""
import re
import logging
from typing import List, Dict, Any, Optional, Iterable, Set

logger = logging.getLogger("SupplyChain")

# Authoritative crates.io popular-crate seed set.  Used by _analyze_crates for
# both edit-distance typosquat detection and case-only impersonation checks
# (crates.io is case-sensitive: "Serde" and "serde" are different crate names).
# Extend via the ``popular=`` constructor argument; this frozenset is never
# modified at runtime.
_POPULAR_CRATES: frozenset = frozenset({
    "serde", "tokio", "reqwest", "axum", "anyhow", "thiserror", "clap", "rand",
    "rayon", "hyper", "tonic", "actix-web", "warp", "diesel", "sqlx", "sea-orm",
    "nom", "regex", "log", "env-logger", "tracing", "futures", "async-std",
    "crossbeam", "parking-lot", "openssl", "rustls", "ring", "ed25519-dalek",
    "sha2", "aes", "base64",
    # aliases already normalised (underscores → hyphens via _norm_name)
    "env_logger", "parking_lot", "ed25519_dalek", "actix_web", "sea_orm",
})

# Popular Maven 'groupId:artifactId' coordinates.  _analyze_maven compares
# incoming coordinates against this set using per-component edit-distance so
# that groupId and artifactId confusion are each caught independently.
_POPULAR_MAVEN: frozenset = frozenset({
    "com.google.guava:guava",
    "com.fasterxml.jackson.core:jackson-databind",
    "org.apache.logging.log4j:log4j-core",
    "org.springframework:spring-core",
    "org.apache.commons:commons-lang3",
    "io.netty:netty-all",
    "org.slf4j:slf4j-api",
    "junit:junit",
    "org.mockito:mockito-core",
})

# A modest, explicit per-ecosystem popular-name seed set. Extend via `popular=`.
_POPULAR = {
    "npm": {"lodash", "react", "express", "axios", "chalk", "request", "commander",
            "moment", "debug", "webpack", "babel", "jquery", "vue", "next", "eslint",
            "typescript", "dotenv", "colors", "yargs", "uuid", "bluebird", "async"},
    "pypi": {"requests", "numpy", "pandas", "flask", "django", "urllib3", "pyyaml",
             "boto3", "setuptools", "pillow", "scipy", "click", "jinja2", "pytest",
             "cryptography", "sqlalchemy", "beautifulsoup4", "colorama", "certifi",
             "python-dateutil", "six", "wheel", "attrs", "tornado", "tensorflow"},
    # crates.io uses the expanded _POPULAR_CRATES set; see _analyze_crates for
    # the ecosystem-specific detection logic (medium severity, CWE-1357).
    "crates.io": set(_POPULAR_CRATES),
    "rubygems": {"rails", "rake", "bundler", "rspec", "nokogiri", "puma", "sinatra"},
}

# Confusable → canonical character folding (a conservative, high-signal subset).
_CONFUSABLE = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b",
               "|": "l", "!": "i"}
_BIGRAM_CONFUSABLE = [("rn", "m"), ("vv", "w"), ("cl", "d")]

# Words that are suspicious when appended/prepended to a popular package name.
# Examples: requests-official, secure-lodash, react-patched.
# Kept intentionally small to minimise false positives.
_SQUATTING_AFFIXES: frozenset = frozenset({
    "official",   # no legitimate package appends 'official' to a popular name
    "backup",     # attacker variant / shadow copy
    "patched",    # signals a modified fork used to hide malicious changes
    "fixed",      # same attack vector as 'patched'
    "secure",     # "secure-requests" / "requests-secure" is a common lure name
})


def _canon_ecosystem(eco: str) -> str:
    e = (eco or "").strip().lower()
    return {"pip": "pypi", "python": "pypi", "node": "npm", "npmjs": "npm",
            "cargo": "crates.io", "crates": "crates.io", "rust": "crates.io",
            "gem": "rubygems", "ruby": "rubygems"}.get(e, e)


def _norm_name(name: str) -> str:
    """Registry-normalized name: lowercase, and for PyPI '_'/'.' fold to '-'."""
    n = (name or "").strip().lower()
    n = re.sub(r"[._]+", "-", n)
    return n


def _confusable_fold(name: str) -> str:
    s = name
    for a, b in _BIGRAM_CONFUSABLE:
        s = s.replace(a, b)
    return "".join(_CONFUSABLE.get(c, c) for c in s)


def _edit_distance_le(a: str, b: str, maxd: int = 1) -> int:
    """Bounded Levenshtein: returns the distance if <= maxd, else maxd+1."""
    la, lb = len(a), len(b)
    if abs(la - lb) > maxd:
        return maxd + 1
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        best = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            best = min(best, cur[j])
        if best > maxd:
            return maxd + 1
        prev = cur
    return prev[lb] if prev[lb] <= maxd else maxd + 1


class SupplyChainAnalyzer:
    MIN_LEN = 4                       # ignore very short names (noise)

    def __init__(self, popular: Optional[Dict[str, Iterable[str]]] = None,
                 internal_names: Optional[Iterable[str]] = None):
        self.popular = {k: set(map(_norm_name, v)) for k, v in _POPULAR.items()}
        for eco, names in (popular or {}).items():
            self.popular.setdefault(_canon_ecosystem(eco), set()).update(map(_norm_name, names))
        self.internal = set(map(_norm_name, internal_names or ()))

    def _pop_for(self, eco: str) -> Set[str]:
        return self.popular.get(_canon_ecosystem(eco), set())

    def analyze_one(self, name: str, ecosystem: str) -> Optional[Dict[str, Any]]:
        norm = _norm_name(name)
        eco = _canon_ecosystem(ecosystem)
        pop = self._pop_for(ecosystem)
        # dependency confusion: an internal name resolving from a public registry.
        if norm in self.internal:
            return self._mk(name, ecosystem, "dependency-confusion", norm,
                            f"'{name}' is a declared INTERNAL package name but is being "
                            f"resolved from the public {eco} registry — "
                            f"a resolver may pull an attacker's public copy (namespace confusion).",
                            "high")

        # ---- scoped npm package handling (@scope/inner) -------------------------
        # A scoped package's inner name is never directly compared against the
        # popular-name list (lengths differ wildly), so attacks like @evil/lodash
        # were silently missed.  Handle two cases explicitly:
        #   (a) inner name EXACTLY matches a popular unscoped package → namespace shadow
        #   (b) inner name is within edit-distance 1 of a popular package → typosquat
        # @types/* is the DefinitelyTyped scope for TypeScript type stubs — skip it.
        if eco == "npm" and norm.startswith("@") and "/" in norm:
            scope, inner = norm.split("/", 1)
            if scope != "@types" and len(inner) >= self.MIN_LEN:
                if inner in pop:
                    return self._mk(
                        name, ecosystem, "namespace-confusion", inner,
                        f"'{name}' is a scoped npm package whose inner name '{inner}' exactly "
                        f"matches the popular unscoped package '{inner}'. A scoped package can "
                        f"shadow or impersonate an unscoped package when a registry resolver "
                        f"prefers scoped results — verify the scope is authorised.",
                        "high",
                    )
                # typosquat of the inner name inside a scope
                for p in pop:
                    if abs(len(p) - len(inner)) <= 1 and _edit_distance_le(inner, p, 1) == 1:
                        return self._mk(
                            name, ecosystem, "typosquat", p,
                            f"'{name}' scoped package inner name '{inner}' is one edit away "
                            f"from the popular package '{p}' — typosquatting inside a scope "
                            f"namespace.", "high",
                        )
            # Scoped packages are not further compared against unscoped popular names.
            return None

        # crates.io and maven receive ecosystem-specific detection that uses
        # module-level authoritative sets (_POPULAR_CRATES / _POPULAR_MAVEN),
        # medium severity, and CWE-1357 throughout — delegate before the
        # generic path so severity and CWE are always correct for these ecosystems.
        if eco == "crates.io":
            return self._analyze_crates(name, norm)
        if eco == "maven":
            return self._analyze_maven(name)

        if len(norm) < self.MIN_LEN or norm in pop:
            return None               # exact popular / too short → never flagged
        # homoglyph / confusable: folds to a popular name.
        folded = _confusable_fold(norm)
        if folded != norm and folded in pop:
            return self._mk(name, ecosystem, "homoglyph", folded,
                            f"'{name}' uses confusable characters that read as the popular "
                            f"package '{folded}' — likely a homoglyph impersonation.", "high")
        # typosquat: within edit distance 1 of a popular name.
        for p in pop:
            if abs(len(p) - len(norm)) <= 1 and _edit_distance_le(norm, p, 1) == 1:
                return self._mk(name, ecosystem, "typosquat", p,
                                f"'{name}' is one edit away from the popular package '{p}' "
                                f"(typosquatting) — verify the intended dependency.", "high")
        # transposition (adjacent swap) — edit distance 2 but a classic typo.
        for p in pop:
            if len(p) == len(norm) and self._is_transposition(norm, p):
                return self._mk(name, ecosystem, "typosquat", p,
                                f"'{name}' is an adjacent-character transposition of the popular "
                                f"package '{p}' (typosquatting).", "medium")
        # prefix/suffix injection: {popular}-{affix} or {affix}-{popular}.
        # Attackers register names like "requests-official" or "secure-lodash" to
        # lure developers; edit distance misses these because the added word can be
        # many characters long.  Only a targeted list of suspicious affixes is used
        # to keep the false-positive rate low.
        for p in pop:
            if norm.startswith(p + "-"):
                affix = norm[len(p) + 1:]
                if affix in _SQUATTING_AFFIXES:
                    return self._mk(name, ecosystem, "typosquat", p,
                                    f"'{name}' appends '-{affix}' to the popular package '{p}' "
                                    f"— suffix-injection typosquatting pattern.", "medium")
            elif norm.endswith("-" + p):
                affix = norm[:-(len(p) + 1)]
                if affix in _SQUATTING_AFFIXES:
                    return self._mk(name, ecosystem, "typosquat", p,
                                    f"'{name}' prepends '{affix}-' to the popular package '{p}' "
                                    f"— prefix-injection typosquatting pattern.", "medium")
        return None

    # ------------------------------------------------------------------
    # Ecosystem-specific namespace confusion: crates.io
    # ------------------------------------------------------------------

    def _analyze_crates(self, name: str, norm: str) -> Optional[Dict[str, Any]]:
        """crates.io-specific namespace-confusion and typosquat detection.

        Two attack patterns are detected:

        Case-only impersonation
            crates.io is case-sensitive: ``Serde`` and ``serde`` are *different*
            crate names.  If the incoming name's lowercase form matches a popular
            crate but the name itself has uppercase letters, an attacker may have
            registered the capitalised variant as a separate malicious crate.

        Edit-distance typosquat
            A crate whose normalised name is exactly one edit (insert / delete /
            substitute) away from a popular crate.

        Severity is **medium** (not high) for both patterns because crates.io
        enforces unique names within the registry's own normalisation rules,
        which limits some classic typosquat vectors.  CWE-1357 (Reliance on
        Insufficiently Trustworthy Component) is used throughout rather than
        CWE-506 because the risk is resolver-level misdirection, not embedded
        malicious code per se.

        Exact popular-crate matches (after normalisation) are never flagged.
        Names shorter than MIN_LEN are skipped to suppress noise.
        """
        if len(norm) < self.MIN_LEN:
            return None

        pop = self._pop_for("crates.io")  # _POPULAR_CRATES + any user extensions

        # -- Case-only impersonation ------------------------------------------
        # name has uppercase letters but its normalised form matches a popular
        # crate → the raw name is a differently-cased variant of that crate.
        if name != name.lower() and norm in pop:
            canonical = name.lower()
            return {
                "package": name,
                "ecosystem": "crates.io",
                "kind": "namespace-confusion",
                "resembles": canonical,
                "confidence": "medium",
                "description": (
                    f"'{name}' differs from the popular crate '{canonical}' only in "
                    f"letter case. crates.io is case-sensitive — an attacker can "
                    f"publish a separate '{name}' crate to impersonate '{canonical}'."
                ),
                "cwe": "CWE-1357",
                "category": "supply-chain",
                "recommendation": (
                    f"if you intended '{canonical}', update the dependency to the "
                    f"exact lowercase name; confirm no attacker-published '{name}' "
                    f"variant exists on crates.io."
                ),
            }

        # -- Exact match (correct casing, all-lowercase) ----------------------
        if norm in pop:
            return None   # legitimate popular crate — never flagged

        # -- Edit-distance 1 typosquat ----------------------------------------
        for p in pop:
            if abs(len(norm) - len(p)) > 1:
                continue
            if _edit_distance_le(norm, p, 1) == 1:
                return {
                    "package": name,
                    "ecosystem": "crates.io",
                    "kind": "typosquat",
                    "resembles": p,
                    "confidence": "medium",
                    "description": (
                        f"'{name}' is one edit away from the popular crate '{p}' "
                        f"(typosquatting via crates.io namespace) — verify the "
                        f"intended dependency."
                    ),
                    "cwe": "CWE-1357",
                    "category": "supply-chain",
                    "recommendation": (
                        f"did you mean '{p}'? check the crates.io publisher and "
                        f"download count before adding this crate."
                    ),
                }
        return None

    # ------------------------------------------------------------------
    # Ecosystem-specific namespace confusion: Maven
    # ------------------------------------------------------------------

    def _analyze_maven(self, name: str) -> Optional[Dict[str, Any]]:
        """Maven ``groupId:artifactId`` namespace-confusion detection.

        Splits the incoming coordinate on ``:`` and independently compares
        each component against entries in ``_POPULAR_MAVEN``:

        * **groupId confusion** — groupId is within edit-distance 1 of a
          popular package's groupId while the artifactId matches exactly.
          Attackers register ``com.google.guavaa:guava`` to intercept
          resolvers that mistype the group.
        * **artifactId typosquat** — artifactId is within edit-distance 1
          while the groupId matches exactly.  ``com.google.guava:guavaa``
          is a classic example.
        * **Both parts close** — both groupId and artifactId are each within
          edit-distance 1 (but the full coordinate is not an exact match).

        Exact matches of both parts are never flagged — the caller has the
        real package.  Severity is **medium** and CWE-1357 is used
        throughout, consistent with the crates.io handler.
        """
        if ":" not in name:
            return None
        g, a = name.split(":", 1)
        if not g or not a:
            return None
        g_lc, a_lc = g.lower(), a.lower()

        for coord in _POPULAR_MAVEN:
            if ":" not in coord:
                continue
            pg, pa = coord.split(":", 1)
            pg_lc, pa_lc = pg.lower(), pa.lower()

            # Exact match of both components → legitimate package, never flag.
            if g_lc == pg_lc and a_lc == pa_lc:
                return None

            g_dist = _edit_distance_le(g_lc, pg_lc, 1)
            a_dist = _edit_distance_le(a_lc, pa_lc, 1)

            # Both components must be within edit-distance 1 to avoid noisy
            # cross-group false positives (e.g. any artifact named "core").
            if g_dist <= 1 and a_dist <= 1:
                if g_lc != pg_lc and a_lc == pa_lc:
                    desc = (
                        f"'{name}' has groupId '{g}' one edit away from the popular "
                        f"package '{coord}' groupId '{pg}' (same artifactId '{pa}') "
                        f"— groupId namespace confusion attack."
                    )
                elif g_lc == pg_lc and a_lc != pa_lc:
                    desc = (
                        f"'{name}' has artifactId '{a}' one edit away from the popular "
                        f"package '{coord}' artifactId '{pa}' (same groupId '{pg}') "
                        f"— artifactId typosquat."
                    )
                else:
                    desc = (
                        f"'{name}' has both groupId '{g}' and artifactId '{a}' within "
                        f"edit-distance 1 of the popular Maven coordinate '{coord}' "
                        f"— possible namespace confusion attack."
                    )
                return {
                    "package": name,
                    "ecosystem": "maven",
                    "kind": "namespace-confusion",
                    "resembles": coord,
                    "confidence": "medium",
                    "description": desc,
                    "cwe": "CWE-1357",
                    "category": "supply-chain",
                    "recommendation": (
                        f"verify '{name}' is the intended Maven dependency; "
                        f"it closely resembles '{coord}' — confirm the publisher "
                        f"and source repository before use."
                    ),
                }
        return None

    @staticmethod
    def _is_transposition(a: str, b: str) -> bool:
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 2 and diff[1] == diff[0] + 1 and \
            a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]

    def analyze(self, dependencies: Iterable[Any], ecosystem: str = "") -> List[Dict[str, Any]]:
        """Analyze a list of dependency names (strings) or objects with .name/.ecosystem."""
        out: List[Dict[str, Any]] = []
        for dep in dependencies:
            if isinstance(dep, str):
                name, eco = dep, ecosystem
            else:
                name = getattr(dep, "name", "") or (dep.get("name", "") if isinstance(dep, dict) else "")
                eco = (getattr(dep, "ecosystem", "") or
                       (dep.get("ecosystem", "") if isinstance(dep, dict) else "") or ecosystem)
            if not name:
                continue
            f = self.analyze_one(name, eco)
            if f:
                out.append(f)
        if out:
            logger.info("supply-chain: %d substitution-risk finding(s).", len(out))
        return out

    @staticmethod
    def _mk(name, eco, kind, target, desc, confidence):
        if kind == "dependency-confusion":
            cwe = "CWE-1357"
            rec = (f"confirm '{name}' is the intended package; if it should be private, "
                   f"pin the internal registry / scope and block public resolution.")
        elif kind == "namespace-confusion":
            # Scoped package whose inner name matches a popular unscoped package.
            # CWE-1357 (Reliance on Insufficiently Trustworthy Component) also applies;
            # CWE-506 (Embedded Malicious Code) is less precise here.
            cwe = "CWE-1357"
            rec = (f"ensure '{name}' is the authorised scoped variant of '{target}'; "
                   f"lock the registry scope so the resolver cannot fall back to the "
                   f"unscoped public package or an attacker-controlled scope.")
        else:
            cwe = "CWE-506"
            rec = f"did you mean '{target}'? verify the publisher/downloads before installing."
        return {"package": name, "ecosystem": _canon_ecosystem(eco), "kind": kind,
                "resembles": target, "confidence": confidence, "description": desc,
                "cwe": cwe, "category": "supply-chain", "recommendation": rec}

    # ------------------------------------------------------------------
    # Safe arithmetic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
        """Division with zero-denominator guard — prevents ZeroDivisionError in score normalization.

        Returns *default* (0.0) whenever denominator is zero instead of raising.
        """
        if denominator == 0:
            return default
        return numerator / denominator

    # ------------------------------------------------------------------
    # Transitive dependency traversal with depth + cycle guards
    # ------------------------------------------------------------------

    def get_transitive_deps(
        self,
        pkg_name: str,
        dep_graph: Dict[str, List[str]],
        depth: int = 0,
        visited: Optional[Set[str]] = None,
    ) -> Set[str]:
        """Recursively collect all transitive dependencies from *dep_graph*.

        Safety guards (both bugs prevented by this implementation):
          * **Depth limit** — recursion stops when depth > 10 to prevent runaway
            traversal of very deep or artificially inflated dependency trees.
          * **Circular dependency protection** — a *visited* set is threaded through
            every recursive call; a node already in the set is skipped immediately,
            breaking any dependency cycle without infinite recursion.

        Args:
            pkg_name:  Root package whose transitive deps are being collected.
            dep_graph: Adjacency map {package_name: [direct_dep, …]}.
            depth:     Current recursion depth (callers omit; starts at 0).
            visited:   Already-seen package names (callers omit; allocated here).

        Returns:
            Flat ``set`` of all reachable transitive dependency names (excluding the
            root *pkg_name* itself).
        """
        if visited is None:
            visited = set()
        # Depth guard: stop before the call stack grows without bound.
        if depth > 10:
            logger.debug(
                "get_transitive_deps: depth limit (>10) reached at %r — stopping traversal",
                pkg_name,
            )
            return set()
        # Cycle guard: skip nodes we have already expanded.
        if pkg_name in visited:
            logger.debug(
                "get_transitive_deps: cycle detected at %r — skipping to prevent infinite recursion",
                pkg_name,
            )
            return set()
        visited.add(pkg_name)
        result: Set[str] = set()
        for dep in dep_graph.get(pkg_name, []):
            result.add(dep)
            result.update(
                self.get_transitive_deps(dep, dep_graph, depth + 1, visited)
            )
        return result

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def compute_risk_score(
        self, findings: List[Dict[str, Any]], total_packages: int
    ) -> float:
        """Return a 0.0–1.0 supply-chain risk score.

        Score = clamp(weighted_findings / total_packages, 0, 1).
        Uses *_safe_divide* so an empty/zero package list returns 0.0 instead of
        raising ZeroDivisionError.
        """
        _WEIGHT: Dict[str, float] = {"high": 1.0, "medium": 0.5, "low": 0.2}
        weighted = sum(_WEIGHT.get(f.get("confidence", "low"), 0.2) for f in findings)
        return min(1.0, self._safe_divide(weighted, float(total_packages)))

# vendored from common/supplier_resolve.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""Supplier / originator resolution for SBOM components - with the BASIS recorded.

NTIA "Supplier Name" is the weakest element of every SBOM this product makes:
the CycloneDX builder knew 13 hard-coded purl prefixes and the SPDX builder
none at all, so most components said nothing about who provides them.

What we can honestly say offline, strongest first:

  declared         the manifest / ingested SBOM named a supplier (kept verbatim)
  curated-table    a reviewed (ecosystem, namespace) -> organisation mapping
  <ns>-namespace   the package coordinate itself names an owner: an npm scope,
                   a Maven groupId, a Go module host/org, a Composer vendor.
                   This is an IDENTIFIER of the party that publishes under that
                   namespace, not a verified legal-entity name; the basis string
                   says so and NTIA scoring reports how many components rest on it.

Anything else (an unscoped PyPI / npm / crates.io package, a bare gem...) stays
UNRESOLVED here - the optional online registry lookup (common.registry_meta)
may add an *author* for it, and if that is unavailable the component honestly
has no supplier.  Nothing is guessed from a package's name.

Pure functions, no I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote

# --- curated (ecosystem, namespace) -> organisation -------------------------------
# npm scope (without '@')
_NPM_SCOPES = {
    "angular": "Google LLC", "angular-devkit": "Google LLC", "google-cloud": "Google LLC",
    "tensorflow": "Google LLC", "grpc": "The gRPC Authors", "firebase": "Google LLC",
    "babel": "Babel", "types": "DefinitelyTyped", "aws-sdk": "Amazon Web Services",
    "aws-cdk": "Amazon Web Services", "azure": "Microsoft Corporation",
    "microsoft": "Microsoft Corporation", "nestjs": "NestJS", "mui": "MUI",
    "emotion": "Emotion", "sentry": "Sentry", "vue": "Vue.js", "jest": "OpenJS Foundation",
    "eslint": "OpenJS Foundation", "webpack": "OpenJS Foundation", "storybook": "Storybook",
    "reduxjs": "Redux", "testing-library": "Testing Library", "playwright": "Microsoft Corporation",
    "opentelemetry": "Cloud Native Computing Foundation", "octokit": "GitHub, Inc.",
    "actions": "GitHub, Inc.", "stripe": "Stripe, Inc.", "apollo": "Apollo GraphQL",
}
# Maven groupId prefix (dotted; longest match wins)
_MAVEN_GROUPS = {
    "org.apache": "The Apache Software Foundation", "org.springframework": "VMware, Inc.",
    "com.fasterxml": "FasterXML, LLC", "com.google": "Google LLC", "io.netty": "The Netty Project",
    "org.eclipse": "Eclipse Foundation", "jakarta": "Eclipse Foundation",
    "org.bouncycastle": "Legion of the Bouncy Castle Inc.", "com.squareup": "Square, Inc.",
    "org.jetbrains": "JetBrains s.r.o.", "org.slf4j": "QOS.ch Sarl", "ch.qos.logback": "QOS.ch Sarl",
    "org.junit": "JUnit Team", "com.microsoft": "Microsoft Corporation",
    "com.amazonaws": "Amazon Web Services", "software.amazon": "Amazon Web Services",
    "org.hibernate": "Red Hat, Inc.", "org.jboss": "Red Hat, Inc.", "io.quarkus": "Red Hat, Inc.",
    "org.mockito": "Mockito", "com.h2database": "H2 Database Engine", "io.micrometer": "VMware, Inc.",
    "io.projectreactor": "VMware, Inc.",
}
# Go module path prefix (longest match wins)
_GO_PREFIXES = {
    "golang.org/x": "The Go Authors", "github.com/golang": "The Go Authors",
    "google.golang.org": "Google LLC", "github.com/google": "Google LLC",
    "k8s.io": "The Kubernetes Authors", "sigs.k8s.io": "The Kubernetes Authors",
    "github.com/kubernetes": "The Kubernetes Authors", "github.com/aws": "Amazon Web Services",
    "github.com/hashicorp": "HashiCorp, Inc.", "github.com/prometheus": "The Prometheus Authors",
    "github.com/docker": "Docker, Inc.", "github.com/moby": "Docker, Inc.",
    "github.com/microsoft": "Microsoft Corporation", "github.com/azure": "Microsoft Corporation",
    "github.com/grpc": "The gRPC Authors", "github.com/open-telemetry": "Cloud Native Computing Foundation",
}
# whole-name PyPI / npm / crates projects whose steward is public record
_NAMED = {
    ("pypi", "django"): "Django Software Foundation", ("pypi", "flask"): "Pallets",
    ("pypi", "jinja2"): "Pallets", ("pypi", "werkzeug"): "Pallets", ("pypi", "click"): "Pallets",
    ("pypi", "markupsafe"): "Pallets", ("pypi", "itsdangerous"): "Pallets",
    ("pypi", "requests"): "Python Software Foundation", ("pypi", "numpy"): "NumPy Developers",
    ("pypi", "scipy"): "SciPy Developers", ("pypi", "pandas"): "pandas Development Team",
    ("pypi", "cryptography"): "Python Cryptographic Authority", ("pypi", "pip"): "Python Packaging Authority",
    ("pypi", "setuptools"): "Python Packaging Authority", ("pypi", "wheel"): "Python Packaging Authority",
    ("pypi", "pytest"): "pytest-dev", ("pypi", "pydantic"): "Pydantic Services Inc.",
    ("npm", "react"): "Meta Platforms, Inc.", ("npm", "react-dom"): "Meta Platforms, Inc.",
    ("npm", "vue"): "Evan You", ("npm", "lodash"): "OpenJS Foundation",
    ("npm", "express"): "OpenJS Foundation", ("npm", "typescript"): "Microsoft Corporation",
}
# distro-level purl namespaces
_DISTROS = {"debian": "Debian Project", "ubuntu": "Canonical Ltd.", "alpine": "Alpine Linux Project",
            "fedora": "Fedora Project", "rhel": "Red Hat, Inc.", "centos": "CentOS Project",
            "openwrt": "OpenWrt Project", "yocto": "The Yocto Project"}

_ECO_KIND = {
    "npm": "npm", "node": "npm", "pypi": "pypi", "python": "pypi", "maven": "maven", "gradle": "maven",
    "go": "go", "golang": "go", "crates.io": "crates.io", "cargo": "crates.io", "crates": "crates.io",
    "packagist": "composer", "composer": "composer", "rubygems": "gem", "gem": "gem",
    "nuget": "nuget", "debian": "deb", "ubuntu": "deb", "alpine": "apk", "pub": "pub", "hex": "hex",
}
_PURL_KIND = {"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "go", "cargo": "crates.io",
              "composer": "composer", "gem": "gem", "nuget": "nuget", "deb": "deb", "apk": "apk",
              "rpm": "rpm", "pub": "pub", "hex": "hex"}


def _kind(pkg: Dict[str, Any]) -> Tuple[str, str]:
    """(ecosystem kind, coordinate name) from ecosystem/purl; name never empty-guessed."""
    purl = unquote(str(pkg.get("purl") or ""))
    name = str(pkg.get("name") or "")
    kind = _ECO_KIND.get(str(pkg.get("ecosystem") or "").strip().lower(), "")
    m = re.match(r"pkg:([a-z]+)/(.*?)(?:@[^@/]*)?(?:[?#].*)?$", purl, re.IGNORECASE)
    if m:
        kind = kind or _PURL_KIND.get(m.group(1).lower(), "")
        if not name:
            name = m.group(2)
    return kind, name


def _longest(table: Dict[str, str], value: str, sep: str) -> Optional[Tuple[str, str]]:
    best = None
    for prefix, org in table.items():
        if value == prefix or value.startswith(prefix + sep):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, org)
    return best


def _declared(pkg: Dict[str, Any]) -> Optional[str]:
    sup = pkg.get("supplier")
    if isinstance(sup, dict):
        sup = sup.get("name")
    sup = str(sup or "").strip()
    for prefix in ("Organization:", "Person:"):
        if sup.startswith(prefix):
            sup = sup[len(prefix):].strip()
    if sup and sup.lower() not in ("noassertion", "none", "unknown", "n/a"):
        return sup
    return None


def resolve(pkg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """``{'name', 'basis', 'derived'}`` for one package dict, or None.

    ``derived`` is True when the name is an identifier read from the coordinate
    (npm scope, Maven groupId, ...) rather than a reviewed organisation name."""
    decl = _declared(pkg)
    if decl:
        return {"name": decl, "basis": "declared", "derived": False}
    kind, name = _kind(pkg)
    low = name.lower()
    if kind and (kind, low) in _NAMED:
        return {"name": _NAMED[(kind, low)], "basis": "curated-table", "derived": False}
    if kind == "npm" and low.startswith("@") and "/" in low:
        scope = low[1:].split("/", 1)[0]
        if scope in _NPM_SCOPES:
            return {"name": _NPM_SCOPES[scope], "basis": "curated-table", "derived": False}
        return {"name": scope, "basis": "npm-scope-namespace", "derived": True}
    if kind == "maven" and ":" in name:
        group = name.split(":", 1)[0]
        hit = _longest(_MAVEN_GROUPS, group.lower(), ".")
        if hit:
            return {"name": hit[1], "basis": "curated-table", "derived": False}
        return {"name": group, "basis": "maven-groupId-namespace", "derived": True}
    if kind == "go":
        hit = _longest(_GO_PREFIXES, low, "/")
        if hit:
            return {"name": hit[1], "basis": "curated-table", "derived": False}
        parts = name.split("/")
        if parts and parts[0] in ("github.com", "gitlab.com", "bitbucket.org") and len(parts) >= 2:
            return {"name": parts[1], "basis": "go-module-path-namespace", "derived": True}
        if parts and "." in parts[0]:
            return {"name": parts[0], "basis": "go-module-host-namespace", "derived": True}
    if kind == "composer" and "/" in name:
        return {"name": name.split("/", 1)[0], "basis": "composer-vendor-namespace", "derived": True}
    if kind in ("deb", "apk", "rpm"):
        m = re.match(r"pkg:[a-z]+/([^/@]+)/", unquote(str(pkg.get("purl") or "")), re.IGNORECASE)
        distro = (m.group(1).lower() if m else {"deb": "debian", "apk": "alpine"}.get(kind, ""))
        if distro in _DISTROS:
            return {"name": _DISTROS[distro], "basis": "curated-table", "derived": False}
    return None


def apply(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """Fill ``supplier`` / ``supplier_basis`` on ``pkg`` in place when unresolved;
    never overwrites a supplier the package already carries."""
    if pkg.get("supplier_basis"):
        return pkg
    r = resolve(pkg)
    if r:
        pkg["supplier"] = r["name"]
        pkg["supplier_basis"] = r["basis"]
        pkg["supplier_derived"] = bool(r["derived"])
    return pkg


def is_derived_basis(basis: Any) -> bool:
    return str(basis or "").endswith("-namespace")


__all__ = ["resolve", "apply", "is_derived_basis"]

"""Single source of truth for the bts-sbom version (imported by the package, the
CycloneDX/SPDX writers and the HTTP User-Agents, so an emitted SBOM never claims a
stale tool version)."""
__version__ = "0.2.0"

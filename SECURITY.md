# Security Policy

## Reporting a vulnerability

Do NOT open a public issue for a security problem.

Report privately to the maintainers via the GitHub Security Advisory
("Report a vulnerability" button on this repository's Security tab). Include:
affected version, a minimal reproduction, and your assessment of impact.
You will get an acknowledgement within 7 days and a fix-or-rejection decision
within 30 days. Credit in the changelog is opt-in.

## Scope

In scope: the `bts_sbom` package — CLI (`bts-sbom`), library API, vendored
`_internal` modules. This includes anything that could cause a WRONG SECURITY
VERDICT (a fabricated pass, a silently suppressed finding, a downgraded
reachability verdict) — report those with the same severity as an RCE in the
tool itself.

Out of scope: the BTS platform repository this package was extracted from,
and vulnerabilities in the packages your projects depend on (that is exactly
what this tool reports on — use it).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | yes |

## Data handling

`bts-sbom` is local-first: it reads the manifests/SBOMs/VEX files you point it
at. Network I/O happens only for: OSV.dev queries (`scan` online mode),
deps.dev / registry metadata lookups (report enrichment), and the FIRST.org
EPSS + CISA KEV feeds. `--offline` performs zero network I/O. No telemetry,
no upload of your scan targets.

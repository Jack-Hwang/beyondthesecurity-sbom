# SBOM+ architecture

```
 source (git URL | owner/repo | folder)
        |
 workspace.prepare ----> isolated WORK COPY (origin never written; hooks off, no submodules, ext:: refused)
        |
 engine  (bts_sbom core via ONE adapter) ---> components + findings
        |   alias merge | CVSS v3 | fixed version from ECOSYSTEM/SEMVER ranges | dedupe | ruby platforms | go.sum MVS
        +--> licenses  lockfile -> deps.dev -> registry (PyPI/npm/Maven)  [raw evidence cached, normalised on read]
        +--> remediate plan (lowest clearing version) -> OSV re-verification (bump <= 3 rounds)
        +--> sbom      CycloneDX 1.5 | SPDX 2.3 | OpenVEX  (+ integrity validators)
        +--> sectors   defense | automotive | medical | finance | maritime(draft) | CRA | robot
        +--> arch      hotspots | coupling | import graph | cycles | layers | clusters | runtime EOL
        |
 patch (approval digest gate) -> manifest edit -> RE-SCAN -> regression => revert   (spinning guard)
        |
 deliver  branch | folder | inplace(--allow-origin-write) | github(--allow-push [--open-pr])
        |
 ai (EXAONE, 4-layer validation, deterministic fallback)      rag + chat (grounded, verified claims)
        |
 batch -> evidence/*.json, SBOMs, reports      loop -> golden batch + RAG/chat eval -> gate -> accept | rollback
```

Design rules
- One adapter (`engine.py`) touches the SBOM core (`bts_sbom/`, same repository), so a core change is verified in one place.
  By default the in-tree core is used; loop passes that must be reproducible pin the core with `BTS_SBOM_PATH` (a checkout or a
  `git archive` snapshot of a tag) and record `{version, path}` so a delta is never confounded by a core change.
- Every outward-facing action has its own explicit flag; nothing pushes, writes to the origin or opens a PR implicitly.
- Absent evidence is never a pass. Corrections that remove or merge findings are counted in `engine.adjustments`.
- Cached data holds RAW evidence; interpretation happens at read time, so an improvement is visible immediately.
- The analysed repository is untrusted data: it is read, never executed (no installs, no builds, no hooks).

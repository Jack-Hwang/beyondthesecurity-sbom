# ADR-0009: Cache raw third-party evidence; interpret it at read time

## Status

Accepted. Post-hoc record: `bts_sbom_app/licenses.py`'s on-disk cache already works this way; this document records
why, citing the measured acceptance criterion. Current as of 2026-11-20.

## 근거 (Context)

`licenses.resolve()`'s docstring states the rule directly: "The on-disk cache stores the RAW evidence a source
returned ({raw, source, extra}); normalisation runs at read time..." (`bts_sbom_app/licenses.py`, `CACHE_FILE =
"licenses_raw.json"`). Every cache entry keeps the untouched third-party payload (`raw`) plus which source answered
(`source`, e.g. `registry:npm`, `registry:maven`, `deps.dev`) and whether extra registries were in scope (`extra`);
`normalize(raw)` — the function that turns that payload into an SPDX expression or `unmapped`/`empty` — is called
every time the cache is read, not once when it is written.

This is measured directly: `BSA-AC-50` — "When the license normaliser changes after a miss was cached, the system
shall re-interpret the cached raw evidence with 0 remote lookups (1 cache hit re-resolved), because the cache stores
raw evidence and not the normalised outcome."

The same principle holds one level up, for whole project analyses: `pipeline.persist()` keeps the **entire** previous
analysis record alongside the current one, as a `.prev.json` file named after the project (`pipeline.py`, around the
`shutil.copyfile(cur, os.path.join(d, nm + ".prev.json"))` call), and `changes.load_previous()` / `changes.diff()`
read that full previous record to compute Hub-style change alerts — not a pre-computed diff summary stored at the
time of the earlier run.

## 결정 (Decision)

Any on-disk cache of a third-party answer in this codebase (currently: `licenses_raw.json` for deps.dev/PyPI/npm/
Maven license lookups) stores the raw payload and its provenance, never the interpreted result. The function that
turns raw evidence into a usable verdict is called at read time, on every read, so it always reflects the current
interpretation logic. The same rule is applied one layer up for whole analyses: the previous full project record is
kept (one `.prev.json` file named after the project), and the diff between two analyses is computed from two
complete records rather than carried forward as a pre-computed summary.

## 기각 대안 (Rejected alternatives)

- **Cache the normalized SPDX expression directly, skip storing the raw payload.** Rejected because it would make
  `BSA-AC-50` unenforceable: a normalizer bug fix, or a newly added SPDX mapping, could never be retro-applied to
  already-cached components without a fresh network round trip — silently freezing old interpretation mistakes
  behind a cache hit that looks like a clean pass.
- **Store only a diff summary between two analyses, not the full previous record.** Rejected because a diff
  computed once and then discarded cannot be re-derived if the diffing logic itself changes (e.g. a new alert
  threshold, a new field to compare); the product's honesty contract requires every verdict to be traceable back to
  the evidence it came from, and a thrown-away record breaks that trace.

## 결과 (Consequences)

- A change to `normalize()` (a corrected mapping, a newly recognised license string) improves every previously
  cached component for free, with 0 additional remote calls, the next time it is read — this is exactly what
  `BSA-AC-50` measures.
- The caches grow without bound by this design: `licenses_raw.json` keeps one entry per distinct
  `(ecosystem, name, version)` ever queried, and `persist()` keeps one `.prev.json` file per analysed project name
  (only the single most recent previous run, not a full history). Pruning is out of scope for this ADR; schema
  compatibility across a cache written by an older version of this code relies on the schema-version fields already
  present on project records (`bts-sbom.project.v1`, with `sbomplus.project.v1` accepted for backward
  compatibility — see `pipeline.PROJECT_SCHEMAS_ACCEPTED`), not on anything this ADR adds.

# ADR-0006: sector evidence is written as latest + append-only history, never overwritten

Status: accepted
Decider: human (project owner); Claude explored the alternatives below, the
decision itself was made by a person, not by Claude.
Related: `bts_sbom/sectors.py` (`write_evidence`), `bts_sbom_evidence/`

## Context

`bts_sbom.sectors.write_evidence()` persists a sector report (defense,
automotive, medical, finance, maritime, CRA/robot) so a later audit can
point at a specific file as the evidence for a pass/gap verdict. The same
sector gets re-scanned repeatedly as the target repository changes, so each
run needs a well-known path a caller can always read ("what is the sector
report right now") as well as a trustworthy record of what every past run
actually said ("what did the sector report say on date X", for an auditor
who must not be able to have the evidence quietly rewritten out from under
them after the fact).

## Decision

Every call to `write_evidence()` writes two files under the evidence
directory: `sector_<name>_latest.json`, which is overwritten on every run
and always reflects the most recent report, and a timestamped copy under
`history/sector_<name>_<UTC timestamp>.json`, which is never overwritten.
If two runs land in the same UTC second, a numeric suffix (`_1`, `_2`, ...)
is appended so the history copy is still never clobbered. The `latest`
pointer is a convenience view; the `history/` directory is the append-only
record of record.

## Rationale

- An auditor's honesty requirement (absence of evidence is never reported
  as a pass) depends on being able to show what a report said at a given
  time; a single overwritten-in-place file cannot do that -- every rescan
  would erase the previous evidence of a prior pass or gap verdict.
- A `latest` pointer is still needed because most callers (the CLI, the
  web UI) only want "the current answer", not a history directory listing;
  giving them a stable, predictable filename avoids every caller having to
  re-implement "find the newest timestamped file in this directory".
- Append-only-by-filename (rather than an append-only log format, or a
  database) keeps the core stdlib-only and lets each history entry be read
  on its own as one complete, self-contained JSON document -- consistent
  with the rest of the evidence directory, which is already a tree of
  individual JSON files rather than a single growing log.

## Rejected Alternatives

| Alternative | Why rejected |
| --- | --- |
| Overwrite `sector_<name>.json` in place on every run | Loses every previous report; an auditor could never show what the tool said before the most recent run, which violates "absence of evidence is never a pass" by making a past pass/gap verdict unprovable after the fact. |
| Keep only the history directory, no `latest` pointer | Every caller that just wants the current report (CLI default output, the web UI's "current status" view) would have to re-implement "list history/, sort by timestamp, take the newest" instead of reading one fixed path. |
| Single append-only log file (all reports appended to one growing JSON-lines file) | Breaks the "each evidence file is one self-contained report" convention the rest of `bts_sbom_evidence/` already uses, and a partially written last line on interruption would need its own recovery logic. |
| External database (SQLite, etc.) for history | Adds a dependency/schema a stdlib-only, file-based tool does not need; plain timestamped files are sufficient and remain readable by `cat`/any JSON tool with no extra tooling. |

## Consequences

- Benefit: a prior pass/gap verdict can always be produced as evidence,
  because the history copy for that run is never overwritten. Measured:
  2 files written per `write_evidence()` call (1 latest + 1 history),
  0 history files are ever deleted or replaced by the implementation.
- Trade-off: `history/` grows by one file per scan with no built-in
  retention/pruning; a very frequently re-scanned sector will accumulate
  many small JSON files over time.
- Follow-up: retention/pruning of old history entries, if the directory
  size becomes a problem, is a deliberate future decision (and would need
  its own ADR, since deleting old evidence has the same honesty
  implications this ADR exists to protect) -- out of scope here.

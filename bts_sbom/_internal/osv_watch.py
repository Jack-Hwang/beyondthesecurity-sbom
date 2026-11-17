"""Continuous OSV watch: turn OSV's change feed into per-component vulnerability events, in near real time.

How it works (and why it is fast):
  1. ``OsvMirror.sync`` polls the head of each ecosystem's ``modified_id.csv`` (one Range request, a 304 when
     nothing changed) and downloads ONLY the advisories that changed since the last poll.
  2. Each changed advisory lists the packages it affects.  Components of the watched inventory whose
     (ecosystem, package) appear there are the *candidates* - for a typical project that is zero, one or two
     components per hour, however many advisories OSV published.
  3. Only the candidates are re-checked, authoritatively, through the OSV API (``FastOsv``: querybatch + record
     cache) - so the local copy decides *what to look at*, OSV decides *what is vulnerable*.  Our own version
     matcher is never the source of a verdict here.
  4. The result is diffed against the last known answer per component: ``new`` / ``updated`` (severity, fix or
     affected range changed) / ``resolved`` (withdrawn, or the record no longer matches).  Each event carries the
     advisory's own ``modified`` time and the lag between that and the moment we noticed it.

Honesty: a failed feed poll, a failed advisory fetch or a candidate that could not be re-checked is reported as
an ``error`` event / non-zero exit - never silently treated as "nothing changed".  The watermark only advances
after everything it covers was processed (see ``OsvMirror.sync_ecosystem``), so a failure is retried next cycle.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from bts_sbom._internal.osv_fast import FastOsv, Key
from bts_sbom._internal.osv_mirror import OsvMirror, base_ecosystem, norm_ts, pkg_key, ts_epoch

STATE_VERSION = 2          # v2 records the mirror anchor and the pending re-checks


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_str(key: Key) -> str:
    return "\x1f".join(key)


def components_from_target(target: str) -> List[Key]:
    """Distinct exact-version (OSV ecosystem, name, version) components of a file/directory, discovered exactly as
    ``bts-sbom scan`` would (same parsers, same ecosystem normalisation, same exact-version rule)."""
    from bts_sbom.osvscanner import OsvScanner, is_exact_version, normalize_ecosystem
    scanner = OsvScanner(offline=True)
    keys: List[Key] = []
    for src in scanner.discover(target):
        for p in src.packages:
            if not is_exact_version(p.get("version")):
                continue
            k = (normalize_ecosystem(p["ecosystem"]), p["name"], p["version"])
            if k not in keys:
                keys.append(k)
    return keys


class Watcher:
    def __init__(self, components: Sequence[Key], *, mirror: Optional[OsvMirror] = None,
                 fast: Optional[FastOsv] = None, state_path: Optional[str] = None,
                 events_path: Optional[str] = None, emit: Optional[Callable[[Dict[str, Any]], None]] = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep) -> None:
        self.components: List[Key] = list(dict.fromkeys(tuple(c) for c in components))
        self.mirror = mirror or OsvMirror()
        self.fast = fast or FastOsv(mirror=self.mirror)
        self.state_path = state_path
        self.events_path = events_path
        self.emit = emit
        self.clock = clock
        self._sleep = sleep
        self.known: Dict[str, Dict[str, str]] = {}      # component -> {advisory id: modified}
        self.pending: Dict[str, List[str]] = {}         # component -> advisory ids whose authoritative re-check failed
        self._anchor: Dict[str, Any] = {}               # mirror watermark / tracking start recorded with the state file
        self._key_by_str: Dict[str, Key] = {_key_str(k): k for k in self.components}
        self.cycles = 0
        self._prepared: Optional[Dict[str, Any]] = None
        self.ecosystems = sorted({base_ecosystem(k[0]) for k in self.components if base_ecosystem(k[0])})
        self._index: Dict[Tuple[str, str], List[Key]] = {}
        for k in self.components:
            self._index.setdefault((base_ecosystem(k[0]).lower(), pkg_key(k[0], k[1])), []).append(k)

    # ------------------------------------------------------------------ state
    def _load(self) -> bool:
        if not self.state_path or not os.path.exists(self.state_path):
            return False
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if doc.get("version") != STATE_VERSION or sorted(doc.get("components") or []) != sorted(
                    _key_str(c) for c in self.components):
                return False                              # a different inventory (or an older format): do not trust it
            self.known = {k: dict(v) for k, v in (doc.get("known") or {}).items()}
            self.pending = {k: [str(i) for i in v] for k, v in (doc.get("pending") or {}).items()}
            self._anchor = dict(doc.get("mirror") or {})
            return True
        except (OSError, ValueError, AttributeError, RecursionError):
            return False

    def _anchor_matches_mirror(self) -> Tuple[bool, str]:
        """Is the mirror database this state file was written against still the one in use, and not behind it?  The state
        file and the mirror are two files; if the mirror was deleted, reset or moved, the first cycle would re-anchor the
        change feed at 'now' and silently skip everything published since the state was saved."""
        if not self._anchor:
            return False, "the state file records no mirror anchor"
        for eco in self.ecosystems:
            a = self._anchor.get(eco)
            st = self.mirror.state(eco)
            if a is None:
                return False, "no anchor recorded for %s" % eco
            if st is None:
                return False, "the mirror has no tracking history for %s (new, reset or different database?)" % eco
            if (st.get("watermark") or "") < (a.get("watermark") or ""):
                return False, "the mirror for %s is behind the state file (older database?)" % eco
            if (a.get("bootstrapped_at") is not None and st.get("bootstrapped_at") is not None
                    and st["bootstrapped_at"] > a["bootstrapped_at"] + 1):
                return False, "the mirror for %s restarted its tracking after the state file was written" % eco
        return True, ""

    def _save(self) -> None:
        if not self.state_path:
            return
        anchor: Dict[str, Any] = {}
        for eco in self.ecosystems:
            st = self.mirror.state(eco)
            if st:
                anchor[eco] = {"watermark": st.get("watermark"), "bootstrapped_at": st.get("bootstrapped_at")}
        doc = {"version": STATE_VERSION, "updated_at": _iso(self.clock()),
               "components": sorted(_key_str(c) for c in self.components), "known": self.known,
               "pending": self.pending, "mirror": anchor}
        d = os.path.dirname(os.path.abspath(self.state_path))
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".osvwatch_", dir=d)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, ensure_ascii=False)
            for attempt in range(6):                      # Windows: os.replace fails while ANY reader holds the target open
                try:
                    os.replace(tmp, self.state_path)
                    break
                except PermissionError:
                    if attempt == 5:
                        raise
                    time.sleep(0.1 * (attempt + 1))
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    # ----------------------------------------------------------------- events
    def _event(self, etype: str, key: Key, rec: Optional[Dict[str, Any]], vid: str, now: float,
               extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ev: Dict[str, Any] = {"ts": _iso(now), "type": etype,
                              "component": {"ecosystem": key[0], "name": key[1], "version": key[2]}, "id": vid}
        if rec is not None:
            try:
                from bts_sbom._internal.osv_client import OsvClient
                parsed = OsvClient()._parse_vulns([rec], key[1], key[2])[0]
                ev.update(aliases=parsed.aliases, severity=parsed.severity, cvss=parsed.cvss_score,
                          fixed_version=parsed.fixed_version, summary=(parsed.summary or "")[:240])
            except Exception:
                ev.update(aliases=rec.get("aliases") or [], summary=str(rec.get("summary") or "")[:240])
            mod = norm_ts(rec.get("modified"))
            ev["record_modified"] = mod
            ep = ts_epoch(mod)
            if ep is not None and etype in ("new", "updated"):
                ev["lag_s"] = round(max(0.0, now - ep), 1)
        if extra:
            ev.update(extra)
        return ev

    def _dispatch(self, events: Iterable[Dict[str, Any]]) -> None:
        events = list(events)
        if self.events_path and events:
            os.makedirs(os.path.dirname(os.path.abspath(self.events_path)), exist_ok=True)
            with open(self.events_path, "a", encoding="utf-8") as fh:
                for ev in events:
                    fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        if self.emit:
            for ev in events:
                self.emit(ev)

    # --------------------------------------------------------------- baseline
    def prepare(self) -> Dict[str, Any]:
        """Take the authoritative baseline of the inventory.  Idempotent.

        * matching state file AND a mirror that still matches its anchor -> ``loaded``: NO sync here.  Whatever OSV published
          since the persisted mirror watermark (including while this process was down) is picked up and evaluated by the
          first ``cycle``, so downtime changes are reported, not swallowed.
        * a state file whose mirror database is missing, reset, older or re-initialised -> it is IGNORED and a fresh baseline
          is taken (``baseline: retaken`` + a note): reporting from it would silently skip everything published in between.
        * otherwise -> anchor the change feed FIRST (so nothing published after this instant can be missed), then query the
          inventory.  Records between the old watermark and now are absorbed into the baseline."""
        if self._prepared is not None:
            return self._prepared
        rep: Dict[str, Any] = {"baseline": "loaded", "errors": [], "notes": []}
        if self._load():
            ok, why = self._anchor_matches_mirror()
            if ok:
                self._prepared = rep
                return rep
            rep["notes"].append("state file ignored: %s; a fresh baseline was taken - advisories published while this "
                                "inventory was not being tracked cannot be reported as events" % why)
            self.known, self.pending = {}, {}
        sync = self.mirror.sync(self.ecosystems)
        for r in sync["ecosystems"]:
            if r["error"]:
                rep["errors"].append("%s: %s" % (r["ecosystem"], r["error"]))
        outcomes = self.fast.query_many(self.components)
        self.known = {}
        bad = 0
        for k in self.components:
            oc = outcomes.get(k)
            if oc is None or not oc.ok:
                bad += 1
                rep["errors"].append("baseline unavailable for %s@%s: %s" % (k[1], k[2], getattr(oc, "error", "no outcome")))
                continue
            self.known[_key_str(k)] = {v["id"]: norm_ts(v.get("modified")) for v in oc.vulns if v.get("id")}
        rep.update(baseline="retaken" if rep["notes"] else "taken", components=len(self.components), baseline_failed=bad,
                   findings=sum(len(v) for v in self.known.values()))
        self._save()
        self._prepared = rep
        return rep

    # ------------------------------------------------------------------ cycle
    def _candidates(self, changes: Sequence[Dict[str, Any]]) -> Dict[Key, List[str]]:
        out: Dict[Key, List[str]] = {}
        for ch in changes:
            for eco, name in ch.get("affected") or []:
                for k in self._index.get((base_ecosystem(eco).lower(), pkg_key(eco, name)), []):
                    if ":" in k[0] and ":" in eco and k[0].lower() != eco.lower():
                        continue                          # different distro release
                    out.setdefault(k, [])
                    if ch["id"] not in out[k]:
                        out[k].append(ch["id"])
        return out

    def cycle(self) -> Dict[str, Any]:
        t0 = time.monotonic()
        started = self.clock()
        self.cycles += 1
        sync = self.mirror.sync(self.ecosystems)
        events: List[Dict[str, Any]] = []
        errors: List[str] = []
        for r in sync["ecosystems"]:
            if r["error"]:
                errors.append("%s: %s" % (r["ecosystem"], r["error"]))
                events.append({"ts": _iso(self.clock()), "type": "error", "scope": "sync", "ecosystem": r["ecosystem"],
                               "detail": r["error"]})
        changes = sync["changes"]
        cands = self._candidates(changes)
        for ks, ids in self.pending.items():          # a re-check that failed earlier is retried whatever the feed says now:
            key = self._key_by_str.get(ks)            # the feed watermark already moved past the advisory that triggered it
            if key is not None:
                known = cands.setdefault(key, [])
                known.extend(i for i in ids if i not in known)
        checked = 0
        if cands:
            outcomes = self.fast.query_many(list(cands))
            now = self.clock()
            for key, why in cands.items():
                oc = outcomes.get(key)
                ks = _key_str(key)
                if oc is None or not oc.ok:
                    msg = "re-check failed for %s@%s: %s" % (key[1], key[2], getattr(oc, "error", "no outcome"))
                    errors.append(msg)
                    self.pending[ks] = list(dict.fromkeys(self.pending.get(ks, []) + list(why)))
                    events.append({"ts": _iso(now), "type": "error", "scope": "recheck",
                                   "component": {"ecosystem": key[0], "name": key[1], "version": key[2]},
                                   "trigger": why, "detail": msg, "will_retry": True})
                    continue
                checked += 1
                self.pending.pop(ks, None)
                recs = {v["id"]: v for v in oc.vulns if v.get("id")}
                prev = self.known.get(ks)
                if prev is None:                           # baseline never succeeded for it: everything is "new"
                    prev = {}
                cur = {vid: norm_ts(r.get("modified")) for vid, r in recs.items()}
                for vid, rec in recs.items():
                    if vid not in prev:
                        events.append(self._event("new", key, rec, vid, now))
                    elif prev[vid] != cur[vid]:
                        events.append(self._event("updated", key, rec, vid, now))
                for vid in prev:
                    if vid not in cur:
                        stored = self.mirror.get_records([vid]).get(vid)
                        events.append(self._event("resolved", key, stored[1] if stored else None, vid, now,
                                                  {"reason": "withdrawn" if stored and stored[1].get("withdrawn")
                                                   else "no longer matches"}))
                self.known[ks] = cur
        try:
            self._save()
        except OSError as exc:                            # a state file we cannot write must not stop the watch
            msg = "state file not saved: %s" % exc
            errors.append(msg)
            events.append({"ts": _iso(self.clock()), "type": "error", "scope": "state", "detail": msg})
        self._dispatch(events)
        return {"cycle": self.cycles, "started": _iso(started), "elapsed_s": round(time.monotonic() - t0, 3),
                "ecosystems": [{k: r[k] for k in ("ecosystem", "mode", "action", "fetched", "new", "updated",
                                                  "deferred", "feed_status", "feed_bytes", "watermark", "error",
                                                  "ingest_lag_s")} for r in sync["ecosystems"]],
                "changed_records": len(changes), "candidate_components": len(cands), "rechecked": checked,
                "pending_rechecks": len(self.pending), "events": events, "errors": errors}

    def _failed_cycle(self, exc: BaseException) -> Dict[str, Any]:
        msg = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        ev = {"ts": _iso(self.clock()), "type": "error", "scope": "watch", "detail": msg, "will_retry": True}
        self._dispatch([ev])
        return {"cycle": self.cycles, "events": [ev], "errors": [msg]}

    def run(self, *, interval: float = 300.0, once: bool = False, max_cycles: Optional[int] = None,
            on_cycle: Optional[Callable[[Dict[str, Any]], None]] = None) -> int:
        """Run until interrupted.  Returns the exit code of the LAST state: 0 quiet, 1 new/updated findings were
        reported, 2 errors occurred.  (With ``once`` this is the cron/CI contract.)  A storage or network failure inside a
        cycle is reported as an error event and retried on the next one - it does not end a long-running watch."""
        code = 0
        n = 0
        try:
            while True:
                try:
                    if self._prepared is None:
                        prep = self.prepare()
                        code = 2 if prep["errors"] else 0
                        if self.emit:
                            self.emit({"ts": _iso(self.clock()), "type": "ready", **prep, "ecosystems": self.ecosystems,
                                       "interval_s": interval})
                    rep = self.cycle()
                except KeyboardInterrupt:
                    raise
                except Exception as exc:                  # noqa: BLE001
                    rep = self._failed_cycle(exc)
                n += 1
                bad = bool(rep["errors"])
                hits = any(e["type"] in ("new", "updated") for e in rep["events"])
                code = 2 if bad else (1 if hits else 0)
                if on_cycle:
                    on_cycle(rep)
                if once or (max_cycles is not None and n >= max_cycles):
                    break
                self._sleep(max(1.0, float(interval)))
        except KeyboardInterrupt:
            pass
        finally:
            self.fast.close()
        return code

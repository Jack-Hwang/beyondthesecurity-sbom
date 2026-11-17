"""OSV record store + incremental mirror of Google's OSV database (stdlib only).

OSV publishes its data as a public bucket (https://storage.googleapis.com/osv-vulnerabilities):
  * ``<ECOSYSTEM>/all.zip``            every record of the ecosystem (hundreds of MB for PyPI/npm/Maven)
  * ``<ECOSYSTEM>/<ID>.json``          one record
  * ``<ECOSYSTEM>/modified_id.csv``    ``<RFC3339 modified>,<ID>`` rows, NEWEST FIRST - the change feed

A consumer therefore does NOT need to re-download anything to stay current: read the head of
``modified_id.csv`` (a Range request for the first 64 KiB, or a 304 when the ETag is unchanged), stop at the
timestamp it already processed, and fetch only the records that changed.  That is what ``OsvMirror.sync`` does,
which turns "download the whole database every time" into "a few KiB per poll + a few records per change".

Two mirror modes per ecosystem (stored in ``osv_sync``):
  * ``lazy``  - only change-feed deltas and records fetched through the API are stored.  It is a *record cache*
                and a *candidate index* for watch mode.  It can NEVER prove "no vulnerability" (it simply may not
                hold the record), so ``lookup`` refuses to answer from it.
  * ``full``  - bootstrapped from ``all.zip`` and then kept current by deltas.  Complete, so a local lookup may
                answer "no advisory" - with the sync age attached so staleness is visible, not hidden.

Honesty rules carried over from the rest of the toolkit: a failed poll/fetch leaves the watermark where it was
(the same entries are retried next time), errors are recorded in ``osv_sync.last_error`` and in the report,
and nothing here ever turns "could not fetch" into "nothing changed".
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import sqlite3
import statistics
import tempfile
import time
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from bts_sbom._internal import osv_http, version_ranges

# "before every real timestamp": the watermark of an ecosystem whose feed is still empty (string-compares lower
# than any normalised RFC 3339 timestamp), so records published later are not skipped.
EPOCH_WATERMARK = "0"

MAX_RECORD_BYTES = 8 << 20            # one advisory record is a few KiB; anything near this is hostile or broken
MAX_BOOTSTRAP_BYTES = 8 << 30         # total uncompressed budget of one all.zip import

# The ecosystem directories of the OSV bucket (ecosystems.txt).  Used to canonicalise the case the user typed (the bucket is
# case-sensitive: 'pypi' is a 404, 'PyPI' is the data) and to refuse anything that is not a plain directory name.
KNOWN_ECOSYSTEMS = ("AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux", "BellSoft Hardened Containers", "Bitnami",
                    "CRAN", "Chainguard", "CleanStart", "Debian", "Docker Hardened Images", "Echo", "GHC", "GIT", "GSD",
                    "GitHub Actions", "Go", "Hackage", "Hex", "Julia", "Linux", "Mageia", "Maven", "MinimOS", "NuGet",
                    "OSS-Fuzz", "Packagist", "Pub", "PyPI", "Red Hat", "Red Hat Lightwell", "Rocky Linux", "Root",
                    "RubyGems", "SUSE", "SwiftURL", "TuxCare", "UVI", "Ubuntu", "VSCode", "Wolfi", "crates.io", "npm",
                    "opam", "openEuler", "openSUSE")
_KNOWN_LOWER = {e.lower(): e for e in KNOWN_ECOSYSTEMS}
_ECO_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,60}$")


def canonical_ecosystem(eco: str) -> str:
    """'pypi:3' -> 'PyPI'; unknown names are returned as given (they are still validated before any URL is built)."""
    base = str(eco or "").split(":", 1)[0].strip()
    return _KNOWN_LOWER.get(base.lower(), base)


def valid_ecosystem(eco: str) -> bool:
    """A bucket directory name: letters, digits, space . _ + - ; no '/', no '..' - it ends up inside a URL path."""
    return bool(_ECO_OK.match(eco or "")) and ".." not in eco


def _eco_path(eco: str) -> str:
    if not valid_ecosystem(eco):
        raise ValueError("invalid ecosystem name %r" % str(eco)[:60])
    return urllib.parse.quote(eco, safe="")


DUMP_BASE = (os.environ.get("BTS_SBOM_OSV_DUMP_BASE_URL") or "https://storage.googleapis.com/osv-vulnerabilities").rstrip("/")

# ----------------------------------------------------------------------------- names / timestamps


def base_ecosystem(eco: str) -> str:
    """'Debian:12' -> 'Debian' (bucket directories use the unqualified name)."""
    return str(eco or "").split(":", 1)[0].strip()


def pkg_key(eco: str, name: str) -> str:
    """Comparison key for a package name inside an ecosystem (PyPI names are PEP 503-normalised)."""
    n = str(name or "").strip()
    if base_ecosystem(eco).lower() == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return n.lower()


_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?\s*(Z|z|[+-]\d{2}:?\d{2})?$")


def norm_ts(value: Any) -> str:
    """Normalise an RFC 3339 timestamp to ``YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`` (UTC, 9 fraction digits) so plain
    string comparison orders timestamps correctly even when OSV emits 6- or 8-digit fractions.  '' = unparseable."""
    m = _TS_RE.match(str(value or "").strip())
    if not m:
        return ""
    date, hms, frac, tz = m.groups()
    frac = (frac or "")[:9].ljust(9, "0")
    if tz and tz.upper() != "Z":
        digits = tz[1:].replace(":", "")
        off = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
        dt = datetime.strptime(date + "T" + hms, "%Y-%m-%dT%H:%M:%S") - (off if tz[0] == "+" else -off)
        date, hms = dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")
    return "%sT%s.%sZ" % (date, hms, frac)


def ts_epoch(norm: str) -> Optional[float]:
    if not norm:
        return None
    try:
        dt = datetime.strptime(norm[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return dt.timestamp() + float("0." + norm[20:29].rstrip("Z") or "0")
    except ValueError:
        return None


def affected_pairs(record: Dict[str, Any]) -> List[Tuple[str, str]]:
    """[(ecosystem as written in the record, package name)] for every affected package of an OSV record."""
    out: List[Tuple[str, str]] = []
    for aff in record.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        if eco and name and (eco, name) not in out:
            out.append((str(eco), str(name)))
    return out


def record_affects(record: Dict[str, Any], eco: str, name: str, version: str) -> bool:
    """Does ``record`` affect ``name@version`` in ``eco``?  Mirrors the OSV API for a *version* query:
    explicit ``versions`` lists and ECOSYSTEM/SEMVER ranges count; GIT ranges (commit hashes) do not."""
    want = pkg_key(eco, name)
    qualified = ":" in str(eco)
    for aff in record.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        pe = str(pkg.get("ecosystem") or "")
        if base_ecosystem(pe).lower() != base_ecosystem(eco).lower():
            continue
        if qualified and ":" in pe and pe.lower() != str(eco).lower():
            continue
        if pkg_key(pe, pkg.get("name", "")) != want:
            continue
        if version in (aff.get("versions") or []):
            return True
        for rng in aff.get("ranges") or []:
            rtype = str((rng or {}).get("type") or "").upper()
            if rtype == "GIT":
                continue
            if version_ranges.affects(version, pe, events=(rng or {}).get("events") or [], range_type=rtype or None):
                return True
    return False


# ----------------------------------------------------------------------------- results


@dataclass
class FeedEntry:
    modified: str      # normalised
    vuln_id: str


@dataclass
class FeedRead:
    entries: List[FeedEntry] = field(default_factory=list)   # newest first, strictly newer than the watermark
    newest: str = ""                                          # newest timestamp seen in the feed head
    status: Optional[int] = None
    etag: Optional[str] = None
    reached_watermark: bool = False
    complete: bool = False                                    # watermark met OR whole file read
    bytes_read: int = 0
    malformed: int = 0
    error: Optional[str] = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS osv_record (
    vuln_id TEXT PRIMARY KEY, modified TEXT NOT NULL, withdrawn TEXT, json TEXT NOT NULL, fetched_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS osv_affects (
    ecosystem TEXT NOT NULL, package_name TEXT NOT NULL, vuln_id TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package_name, vuln_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_osv_affects_vid ON osv_affects (vuln_id);
CREATE TABLE IF NOT EXISTS osv_touch (
    ecosystem TEXT NOT NULL, package_name TEXT NOT NULL, touched TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package_name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS osv_sync (
    ecosystem TEXT PRIMARY KEY, mode TEXT NOT NULL, watermark TEXT, etag TEXT,
    last_poll REAL, last_ok REAL, last_error TEXT, records INTEGER DEFAULT 0, bootstrapped_at REAL
);
"""


def default_db_path() -> str:
    from bts_sbom._internal import osv_local_db
    return osv_local_db.DB_PATH


class OsvMirror:
    def __init__(self, db_path: Optional[str] = None, http: Optional[osv_http.HttpClient] = None,
                 dump_base: Optional[str] = None) -> None:
        self._db_path = db_path
        self.http = http or osv_http.default_client()
        self.dump_base = (dump_base or DUMP_BASE).rstrip("/")

    @property
    def db_path(self) -> str:
        return self._db_path or default_db_path()

    # ------------------------------------------------------------------ storage
    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        path = self.db_path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(path, timeout=30)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            try:
                conn.execute("PRAGMA journal_mode=WAL")      # persistent in the file; a no-op once set
            except sqlite3.DatabaseError:
                pass
            conn.executescript(_SCHEMA)                       # idempotent.  A per-process "schema already created" cache is
            conn.commit()                                     # wrong: the file can be deleted or replaced while we run
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_modified(self, ids: Sequence[str]) -> Dict[str, str]:
        """{vuln_id: normalised modified} for ids already stored (no JSON loaded)."""
        out: Dict[str, str] = {}
        ids = list(dict.fromkeys(ids))
        if not ids:
            return out
        with self._connect() as conn:
            for i in range(0, len(ids), 500):
                part = ids[i:i + 500]
                q = "SELECT vuln_id, modified FROM osv_record WHERE vuln_id IN (%s)" % ",".join("?" * len(part))
                out.update(conn.execute(q, part).fetchall())
        return out

    def get_records(self, ids: Sequence[str]) -> Dict[str, Tuple[str, Dict[str, Any]]]:
        """{vuln_id: (normalised modified, record)}."""
        out: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        ids = list(dict.fromkeys(ids))
        if not ids:
            return out
        with self._connect() as conn:
            for i in range(0, len(ids), 500):
                part = ids[i:i + 500]
                q = "SELECT vuln_id, modified, json FROM osv_record WHERE vuln_id IN (%s)" % ",".join("?" * len(part))
                for vid, mod, blob in conn.execute(q, part).fetchall():
                    try:
                        out[vid] = (mod, json.loads(blob))
                    except ValueError:
                        continue          # a corrupt row is a cache miss, never data
        return out

    def put_records(self, records: Iterable[Dict[str, Any]], *, conn: Optional[sqlite3.Connection] = None
                    ) -> Dict[str, Any]:
        """Upsert records (keeping the NEWER ``modified`` when two versions race).  Returns counts and the list
        of ``changes`` ({id, modified, kind: new|updated, affected})."""
        res: Dict[str, Any] = {"new": 0, "updated": 0, "skipped": 0, "changes": []}
        ctx = contextlib.nullcontext(conn) if conn is not None else self._connect()
        now = time.time()
        with ctx as c:
            for rec in records:
                vid = rec.get("id") if isinstance(rec, dict) else None
                mod = norm_ts(rec.get("modified")) if isinstance(rec, dict) else ""
                if not isinstance(vid, str) or not vid or not mod:
                    res["skipped"] += 1
                    continue
                row = c.execute("SELECT modified FROM osv_record WHERE vuln_id=?", (vid,)).fetchone()
                if row and row[0] > mod:
                    res["skipped"] += 1                       # we already hold a newer revision
                    continue
                c.execute("INSERT OR REPLACE INTO osv_record (vuln_id, modified, withdrawn, json, fetched_at) "
                          "VALUES (?,?,?,?,?)",
                          (vid, mod, rec.get("withdrawn") or None, json.dumps(rec, separators=(",", ":")), now))
                old_pairs = c.execute("SELECT ecosystem, package_name FROM osv_affects WHERE vuln_id=?", (vid,)).fetchall()
                c.execute("DELETE FROM osv_affects WHERE vuln_id=?", (vid,))
                pairs = affected_pairs(rec)
                c.executemany("INSERT OR IGNORE INTO osv_affects (ecosystem, package_name, vuln_id) VALUES (?,?,?)",
                              [(e, pkg_key(e, n), vid) for e, n in pairs])
                # a revision "touches" every package it lists now AND every package it used to list (a package that
                # was REMOVED from an advisory changed answer too) - this is what invalidates cached answers
                touched = {(base_ecosystem(e), p) for e, p in old_pairs} | {(base_ecosystem(e), pkg_key(e, n)) for e, n in pairs}
                c.executemany("INSERT INTO osv_touch (ecosystem, package_name, touched) VALUES (?,?,?) "
                              "ON CONFLICT(ecosystem, package_name) DO UPDATE SET touched = MAX(touched, excluded.touched)",
                              [(e, p, mod) for e, p in touched])
                kind = "updated" if row else "new"
                res[kind] += 1
                res["changes"].append({"id": vid, "modified": mod, "kind": kind, "affected": pairs,
                                       "withdrawn": bool(rec.get("withdrawn"))})
        return res

    def candidates(self, eco: str, name: str) -> List[Dict[str, Any]]:
        """Every stored record that lists ``name`` in ``eco`` (version NOT considered)."""
        base = base_ecosystem(eco)
        key = pkg_key(eco, name)
        with self._connect() as conn:
            if ":" in str(eco):
                rows = conn.execute(
                    "SELECT r.json FROM osv_affects a JOIN osv_record r ON r.vuln_id=a.vuln_id "
                    "WHERE a.package_name=? AND a.ecosystem=?", (key, eco)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT r.json FROM osv_affects a JOIN osv_record r ON r.vuln_id=a.vuln_id "
                    "WHERE a.package_name=? AND (a.ecosystem=? OR substr(a.ecosystem,1,?)=?)",
                    (key, base, len(base) + 1, base + ":")).fetchall()
        out = []
        for (blob,) in rows:
            try:
                out.append(json.loads(blob))
            except ValueError:
                continue
        return out

    def lookup(self, eco: str, name: str, version: str) -> Optional[List[Dict[str, Any]]]:
        """Local answer for name@version, or None when this mirror cannot be authoritative for ``eco``
        (never synced, or only a lazy record cache).  [] means: complete mirror, no advisory affects it."""
        st = self.state(base_ecosystem(eco))
        if not st or st["mode"] != "full":
            return None
        # OSV's own query/querybatch never return a withdrawn advisory; a local "complete" answer must not either
        return [r for r in self.candidates(eco, name) if not r.get("withdrawn") and record_affects(r, eco, name, version)]

    def validated_cache(self, keys: Sequence[Tuple[str, str, str]], *, max_age_s: float = 900.0,
                        skew_s: float = 120.0, now: Optional[float] = None
                        ) -> Tuple[Dict[Tuple[str, str, str], List[Dict[str, Any]]], Dict[str, Any]]:
        """Answers from the durable ``exact_cache`` that the change feed PROVES are still current.

        A cached answer for (ecosystem, name, version) stored at time U is reusable when
          * the ecosystem's mirror synced successfully within ``max_age_s`` (call ``sync`` first), and
          * the answer was stored while the mirror was already tracking that ecosystem (so every later change is
            in the feed), and
          * no advisory revision that lists - or used to list - that package has ``modified`` >= U - ``skew_s``.
        Everything else is returned as 'not validated' with a reason, and the caller asks OSV.

        Honest limits (reported by the caller): OSV exports its bucket a few minutes after an advisory is
        published, so this is "current as of the last feed sync", not "current this second"."""
        from collections import Counter
        from bts_sbom._internal import osv_local_db
        osv_local_db.init_db()
        now = time.time() if now is None else now
        answers: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
        why: Counter = Counter()
        states = {b: self.state(b) for b in {base_ecosystem(k[0]) for k in keys}}
        with self._connect() as conn:
            for key in keys:
                eco, name, version = key
                base = base_ecosystem(eco)
                st = states.get(base)
                if not st:
                    why["ecosystem_not_synced"] += 1
                    continue
                if not st["last_ok"] or now - st["last_ok"] > max_age_s:
                    why["sync_stale_or_failed"] += 1
                    continue
                row = conn.execute("SELECT vulns_json, updated_at FROM exact_cache "
                                   "WHERE ecosystem=? AND package_name=? AND version=?",
                                   (eco, str(name).lower(), version)).fetchone()
                if not row:
                    why["no_cached_answer"] += 1
                    continue
                blob, stored_at = row
                if st["bootstrapped_at"] is None or stored_at < st["bootstrapped_at"]:
                    why["cached_before_tracking_started"] += 1
                    continue
                t = conn.execute("SELECT touched FROM osv_touch WHERE ecosystem=? AND package_name=?",
                                 (base, pkg_key(eco, name))).fetchone()
                if t:
                    te = ts_epoch(t[0])
                    if te is None or te >= stored_at - skew_s:
                        why["advisory_changed_since_cached"] += 1
                        continue
                try:
                    answers[key] = json.loads(blob)
                except ValueError:
                    why["unreadable_cache_row"] += 1
        info = {"validated": len(answers), "not_validated": dict(why),
                "ecosystems": {b: {"last_ok_age_s": round(now - st["last_ok"], 1) if st and st["last_ok"] else None,
                                   "mode": st["mode"] if st else None} for b, st in states.items()}}
        return answers, info

    # -------------------------------------------------------------------- state
    def state(self, eco: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT ecosystem, mode, watermark, etag, last_poll, last_ok, last_error, records, "
                               "bootstrapped_at FROM osv_sync WHERE ecosystem=?", (base_ecosystem(eco),)).fetchone()
        if not row:
            return None
        keys = ("ecosystem", "mode", "watermark", "etag", "last_poll", "last_ok", "last_error", "records",
                "bootstrapped_at")
        return dict(zip(keys, row))

    def _set_state(self, eco: str, **fields: Any) -> None:
        eco = base_ecosystem(eco)
        cur = self.state(eco) or {"mode": "lazy", "watermark": None, "etag": None, "last_poll": None,
                                  "last_ok": None, "last_error": None, "records": 0, "bootstrapped_at": None}
        cur.update(fields)
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO osv_sync (ecosystem, mode, watermark, etag, last_poll, last_ok, "
                         "last_error, records, bootstrapped_at) VALUES (?,?,?,?,?,?,?,?,?)",
                         (eco, cur["mode"], cur["watermark"], cur["etag"], cur["last_poll"], cur["last_ok"],
                          cur["last_error"], cur["records"], cur["bootstrapped_at"]))

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        with self._connect() as conn:
            n_rec = conn.execute("SELECT COUNT(*) FROM osv_record").fetchone()[0]
            n_aff = conn.execute("SELECT COUNT(*) FROM osv_affects").fetchone()[0]
            rows = conn.execute("SELECT ecosystem, mode, watermark, last_poll, last_ok, last_error, records, "
                                "bootstrapped_at FROM osv_sync ORDER BY ecosystem").fetchall()
        return {
            "db_path": self.db_path, "records": n_rec, "affects_rows": n_aff,
            "ecosystems": [{"ecosystem": e, "mode": m, "watermark": w,
                            "last_poll_age_s": round(now - lp, 1) if lp else None,
                            "last_ok_age_s": round(now - lo, 1) if lo else None,
                            "last_error": le, "records": rc,
                            "bootstrapped_age_s": round(now - ba, 1) if ba else None}
                           for (e, m, w, lp, lo, le, rc, ba) in rows],
        }

    # --------------------------------------------------------------------- feed
    def _feed_url(self, eco: str) -> str:
        return "%s/%s/modified_id.csv" % (self.dump_base, _eco_path(base_ecosystem(eco)))

    def read_feed(self, eco: str, watermark: Optional[str], etag: Optional[str] = None, *,
                  page: int = 65536, max_bytes: int = 32 << 20) -> FeedRead:
        """Read ``<eco>/modified_id.csv`` newest-first until the watermark.  ``watermark=None`` reads only the head
        (to learn the newest timestamp).  Uses Range requests so a poll costs ~one page, and If-None-Match so an
        unchanged feed costs a 304.  ``complete`` is True only when the watermark was met or the WHOLE file was
        read - a byte-budget cut-off is reported as incomplete so the caller never advances past unread entries.

        Consistency: every later page is pinned to the object revision (ETag) the first page came from (If-Range).  The
        feed is appended to continuously, so a page of a NEWER revision would shift every byte offset and glue a stale
        partial line onto fresh bytes - losing the newest advisory while looking successful.  A drifting object is
        re-read from the start (a server answering a later page with the whole object is parsed from its first byte);
        malformed rows are an error, never silently skipped."""
        url = self._feed_url(eco)
        out = FeedRead()

        def finish() -> FeedRead:
            if out.malformed and not out.error:
                out.error = "feed contains %d malformed row(s); the mirror cannot be confirmed current" % out.malformed
            return out

        for _attempt in range(3):
            out.entries.clear()
            out.newest = ""
            out.malformed = 0
            out.reached_watermark = False
            out.complete = False

            def consume(lines: List[bytes]) -> bool:
                """Parse complete lines; True = stop (watermark met / head-only read done)."""
                for raw in lines:
                    line = raw.strip().decode("utf-8", "replace")
                    if not line:
                        continue
                    ts, _, vid = line.partition(",")
                    ts = norm_ts(ts)
                    vid = vid.strip()
                    if not ts or not vid:
                        out.malformed += 1
                        continue
                    if not out.newest:
                        out.newest = ts
                    # '<', not '<=': rows stamped EXACTLY at the watermark are re-examined (already-stored ones are
                    # filtered by modified), because two advisories can share a timestamp and be exported in different
                    # polls - a strict '>' would lose the second one forever.
                    if watermark is None or ts < watermark:
                        out.reached_watermark = True
                        return True
                    out.entries.append(FeedEntry(ts, vid))
                return False

            offset = 0
            carry = b""
            first = True
            pin: Optional[str] = None
            drifted = False
            while offset < max_bytes:
                headers = {"Range": "bytes=%d-%d" % (offset, offset + page - 1), "Cache-Control": "no-cache"}
                if first and etag:
                    headers["If-None-Match"] = etag
                if not first and pin:
                    headers["If-Range"] = pin
                res = self.http.get(url, headers=headers)
                if first:
                    out.status = res.status
                if res.not_modified and first:
                    out.etag = etag
                    out.reached_watermark = out.complete = True
                    return out
                if res.status == 416:                              # past the end: the file ended on a page boundary
                    consume([carry] if carry else [])
                    out.complete = True
                    return finish()
                if not res.ok:
                    out.error = res.error or ("http %s" % res.status)
                    return out
                tag = res.headers.get("etag")
                if first:
                    pin = tag
                    out.etag = tag
                elif pin and tag and tag != pin:
                    drifted = True                                 # the object changed between pages: offsets no longer line up
                    break
                out.bytes_read += len(res.body)
                whole = res.status == 200                          # server answered with the entire object
                if whole and not first:
                    carry = b""                                    # a fresh snapshot: forget everything read so far
                    out.entries.clear()
                    out.newest = ""
                    out.malformed = 0
                    out.etag = tag or out.etag
                    pin = tag or pin
                    offset = 0
                data = carry + res.body
                total = None
                m = re.match(r"bytes\s+\d+-\d+/(\d+|\*)", res.headers.get("content-range", ""))
                if m and m.group(1).isdigit():
                    total = int(m.group(1))
                at_end = whole or (total is not None and offset + len(res.body) >= total) or len(res.body) < page
                lines = data.split(b"\n")
                carry = b"" if at_end else lines.pop()
                if consume(lines):
                    out.complete = True
                    return finish()
                first = False
                if at_end:
                    out.complete = True                            # whole file read, watermark never met
                    return finish()
                offset += len(res.body)
            if not drifted:
                out.complete = False                               # byte budget exhausted with unread entries left
                return finish()
        out.error = "feed changed while it was being read (3 attempts); retry on the next poll"
        out.complete = False
        return out

    # --------------------------------------------------------------------- sync
    def _fetch_record(self, eco: str, vid: str) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
        url = "%s/%s/%s.json" % (self.dump_base, _eco_path(eco), urllib.parse.quote(vid, safe=""))
        res = self.http.get(url)
        if not res.ok:
            return vid, None, ("not found" if res.not_found else (res.error or "http %s" % res.status))
        rec = res.json()
        if not isinstance(rec, dict) or rec.get("id") != vid:
            return vid, None, "bad record body"
        return vid, rec, None

    def _bootstrap_full(self, eco: str, progress: Optional[Callable[[int], None]]) -> Dict[str, Any]:
        url = "%s/%s/all.zip" % (self.dump_base, _eco_path(eco))
        fd, tmp = tempfile.mkstemp(prefix="osv_", suffix=".zip")
        os.close(fd)
        try:
            res = self.http.download_to_file(url, tmp, retries=3, timeout=120)
            if not res.ok:
                return {"error": "all.zip download failed: %s" % (res.error or res.status)}
            count, wm, bad, oversized, budget = 0, "", 0, 0, 0
            with zipfile.ZipFile(tmp) as zf, self._connect() as conn:
                batch: List[Dict[str, Any]] = []

                def flush() -> None:
                    if batch:
                        self.put_records(batch, conn=conn)
                        conn.commit()
                        batch.clear()

                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    info = zf.getinfo(name)
                    budget += info.file_size
                    if budget > MAX_BOOTSTRAP_BYTES:
                        return {"error": "all.zip expands beyond %d bytes - refusing" % MAX_BOOTSTRAP_BYTES}
                    if info.file_size > MAX_RECORD_BYTES:
                        oversized += 1
                        continue
                    try:
                        with zf.open(info) as fh:               # the header's size can lie: bound the real read too
                            raw = fh.read(MAX_RECORD_BYTES + 1)
                        if len(raw) > MAX_RECORD_BYTES:
                            oversized += 1
                            continue
                        rec = json.loads(raw.decode("utf-8", "replace"))
                    except (ValueError, RecursionError):
                        bad += 1
                        continue
                    mod = norm_ts(rec.get("modified")) if isinstance(rec, dict) else ""
                    if not mod or not rec.get("id"):
                        bad += 1
                        continue
                    wm = max(wm, mod)
                    batch.append(rec)
                    count += 1
                    if len(batch) >= 1000:
                        flush()
                        if progress:
                            progress(count)
                flush()
            self._set_state(eco, mode="full", watermark=wm or EPOCH_WATERMARK, etag=None, last_poll=time.time(),
                            last_ok=time.time(), last_error=None, records=count, bootstrapped_at=time.time())
            return {"imported": count, "unreadable": bad, "oversized_skipped": oversized, "watermark": wm}
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            return {"error": "all.zip unreadable: %s" % exc}
        finally:
            with contextlib.suppress(OSError):
                os.remove(tmp)

    def sync_ecosystem(self, eco: str, *, full: bool = False, refull: bool = False, workers: int = 8,
                       max_fetch: int = 2000, progress: Optional[Callable[[int], None]] = None) -> Dict[str, Any]:
        eco = canonical_ecosystem(eco)
        rep: Dict[str, Any] = {"ecosystem": eco, "mode": None, "action": "", "fetched": 0, "new": 0, "updated": 0,
                               "deferred": 0, "failed": [], "changes": [], "watermark": None, "feed_status": None,
                               "feed_bytes": 0, "error": None, "ingest_lag_s": None}
        now = time.time()
        if eco in ("", "[EMPTY]"):
            rep["error"] = "no ecosystem"
            return rep
        if not valid_ecosystem(eco):
            rep["error"] = "invalid ecosystem name %r (letters, digits, space . _ + - only)" % eco[:60]
            return rep
        st = self.state(eco)
        if full and (refull or not st or st["mode"] != "full"):
            boot = self._bootstrap_full(eco, progress)
            rep["action"] = "bootstrap_full"
            if boot.get("error"):
                rep["error"] = boot["error"]
                self._set_state(eco, last_poll=now, last_error=boot["error"])
                return rep
            rep["imported"] = boot.get("imported", 0)
            st = self.state(eco)
        if st is None:                                         # first contact in lazy mode: start "from now"
            fr = self.read_feed(eco, None)
            rep["feed_status"], rep["feed_bytes"] = fr.status, fr.bytes_read
            if fr.error:
                rep["error"] = "feed: " + fr.error
                return rep
            self._set_state(eco, mode="lazy", watermark=fr.newest or EPOCH_WATERMARK, etag=None, last_poll=now,
                            last_ok=now, last_error=None, bootstrapped_at=now)   # "tracking since": see validated_cache
            rep.update(action="init_lazy", mode="lazy", watermark=fr.newest or EPOCH_WATERMARK)
            return rep
        rep["mode"] = st["mode"]
        fr = self.read_feed(eco, st["watermark"], st["etag"])
        rep["feed_status"], rep["feed_bytes"] = fr.status, fr.bytes_read
        if fr.error:
            rep["error"] = "feed: " + fr.error
            self._set_state(eco, last_poll=now, last_error=rep["error"])
            return rep
        if not st["watermark"]:
            # a full import whose records carried no usable timestamps: re-anchor on the feed head
            self._set_state(eco, watermark=fr.newest or EPOCH_WATERMARK, etag=None, last_poll=now, last_ok=now,
                            last_error=None)
            rep.update(action=rep["action"] or "reanchor", watermark=fr.newest or EPOCH_WATERMARK)
            return rep
        if not fr.complete:
            rep["error"] = ("feed delta exceeds the read budget (%d bytes) - run a full resync" % fr.bytes_read)
            self._set_state(eco, last_poll=now, last_error=rep["error"])
            return rep
        if fr.status == 304 or not fr.entries:
            truly_empty = fr.bytes_read == 0 and fr.malformed == 0 and st["watermark"] == EPOCH_WATERMARK
            if fr.status != 304 and not fr.reached_watermark and not truly_empty:
                # the feed was read to the end without a single usable row although we have seen rows before (or
                # the rows were malformed): we cannot prove nothing was missed
                rep["error"] = "feed unreadable or empty - cannot confirm the mirror is current"
                self._set_state(eco, last_poll=now, last_error=rep["error"])
                return rep
            self._set_state(eco, last_poll=now, last_ok=now, last_error=None, etag=fr.etag or st["etag"])
            rep.update(action=rep["action"] or "up_to_date", watermark=st["watermark"])
            return rep
        newest_by_id: Dict[str, str] = {}
        for e in fr.entries:
            if e.modified > newest_by_id.get(e.vuln_id, ""):
                newest_by_id[e.vuln_id] = e.modified
        have = self.get_modified(list(newest_by_id))
        todo = sorted((mod, vid) for vid, mod in newest_by_id.items() if have.get(vid, "") < mod)
        batch, deferred = todo[:max_fetch], max(0, len(todo) - max_fetch)
        fetched: List[Dict[str, Any]] = []
        failed: List[str] = []
        if batch:
            with ThreadPoolExecutor(max_workers=max(1, min(workers, len(batch))), thread_name_prefix="osvsync") as pool:
                for vid, rec, err in pool.map(lambda mv: self._fetch_record(eco, mv[1]), batch):
                    if rec is not None:
                        fetched.append(rec)
                    else:
                        failed.append("%s (%s)" % (vid, err))
        stored = self.put_records(fetched)
        rep.update(fetched=len(fetched), new=stored["new"], updated=stored["updated"], deferred=deferred,
                   failed=failed, changes=stored["changes"])
        lags = [now - e for e in (ts_epoch(c["modified"]) for c in stored["changes"]) if e is not None]
        if lags:
            rep["ingest_lag_s"] = {"max": round(max(lags), 1), "median": round(statistics.median(lags), 1)}
        if failed:
            # do NOT advance: the same entries are retried next poll (idempotent), nothing is silently skipped
            rep["error"] = "%d record fetch(es) failed" % len(failed)
            self._set_state(eco, last_poll=now, last_error=rep["error"])
            rep["action"] = "partial"
            return rep
        if deferred:
            # progress, but NOT currency: the deferred records have not been fetched, so their packages are not in osv_touch
            # yet.  last_ok stays where it was (validated_cache then refuses to vouch for this ecosystem) until a poll
            # catches up completely.
            new_wm = batch[-1][0]
            self._set_state(eco, watermark=new_wm, etag=None, last_poll=now, last_ok=None,
                            last_error="%d changed record(s) deferred (max_fetch=%d): mirror not current yet" % (deferred, max_fetch))
        else:
            new_wm = max(e.modified for e in fr.entries)
            self._set_state(eco, watermark=new_wm, etag=fr.etag, last_poll=now, last_ok=now, last_error=None)
        rep.update(action=rep["action"] or ("delta" if fetched else "up_to_date"), watermark=new_wm)
        return rep

    def sync(self, ecosystems: Iterable[str], *, full: bool = False, refull: bool = False, workers: int = 8,
             max_fetch: int = 2000, progress: Optional[Callable[[int], None]] = None) -> Dict[str, Any]:
        """Sync every (base) ecosystem.  Never raises for a network problem: failures are in the report."""
        seen: List[str] = []
        for e in ecosystems:
            b = canonical_ecosystem(e)
            if b and b not in seen:
                seen.append(b)
        t0 = time.monotonic()
        reports = [self.sync_ecosystem(e, full=full, refull=refull, workers=workers, max_fetch=max_fetch,
                                       progress=progress) for e in seen]
        changes = [c for r in reports for c in r["changes"]]
        return {"ecosystems": reports, "changes": changes, "elapsed_s": round(time.monotonic() - t0, 3),
                "ok": all(not r["error"] for r in reports), "http": self.http.snapshot()}

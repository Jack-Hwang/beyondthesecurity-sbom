"""Append-only audit log with a tamper-evident hash chain (task 10) - stdlib only.

One JSON line per sensitive action (scan, patch approve, VEX decision, LLM connect) at <evidence>/audit.jsonl:
``{"ts", "who", "action", "target", "digest", "result", "prev", "h"}`` where ``prev`` is the previous line's
``h`` (empty for the first line) and ``h`` = sha256(prev + line-without-h), so altering ANY line makes THAT
line fail verification (and every later line's prev link breaks too). Tokens, API keys, approval tokens and
URL credentials are never written (the caller passes an already-sanitized target). A per-line length cap and a
file-size cap rotate to audit-<n>.jsonl when the log grows past its bound.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from typing import Any, Dict, Optional, Tuple

from .util import ascii_safe

MAX_LINE = 2000
DEFAULT_MAX_FILE = 2_000_000
_ROTATE_RE = re.compile(r"^audit(?:-(\d+))?\.jsonl$")


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()


def _clean(value: str, limit: int = 160) -> str:
    """One ASCII-safe single line: the audit log never echoes raw request text or terminal-control bytes."""
    s = ascii_safe(str(value or "")).replace("\n", " ").replace("\r", " ").strip()
    return s[:limit]


class AuditLog:
    def __init__(self, path: str, *, max_file_bytes: int = DEFAULT_MAX_FILE, clock: Any = time.time):
        self.path = path
        self.max_file_bytes = max_file_bytes
        self._clock = clock
        self._lock = threading.Lock()

    def _rotate_target(self) -> str:
        """When the current file is past its cap, continue in audit-<n+1>.jsonl (the first file keeps its plain name)."""
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return self.path
        if size < self.max_file_bytes:
            return self.path
        numbers = [int(m.group(1) or 0) for f in os.listdir(os.path.dirname(self.path) or ".") for m in [_ROTATE_RE.match(f)] if m]
        return os.path.join(os.path.dirname(self.path), "audit-%d.jsonl" % (max(numbers or [0]) + 1))

    def append(self, who: str, action: str, target: str, result: str, digest: str = "") -> Dict[str, Any]:
        """One append-only line. Returns the stored entry. Never raises for logging problems: the caller's
        action result carries the truth; a failed audit write is reported via the returned entry's "error"."""
        with self._lock:
            entry: Dict[str, Any] = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())),
                                     "who": _clean(who), "action": _clean(action, 40), "target": _clean(target),
                                     "digest": _clean(digest, 64), "result": _clean(result, 40), "prev": self._last_hash()}
            try:
                line = json.dumps(entry, ensure_ascii=False, sort_keys=False)
                if len(line) > MAX_LINE:
                    entry["target"] = _clean(target, 60)
                    line = json.dumps(entry, ensure_ascii=False, sort_keys=False)
                entry["h"] = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
                line = json.dumps(entry, ensure_ascii=False, sort_keys=False)
                path = self._rotate_target()
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                entry["error"] = type(exc).__name__
            return entry

    def _last_hash(self) -> str:
        """The last line's ``h`` (the value the next line chains to); empty string when the file is absent/empty/unreadable."""
        try:
            with open(self.path, "rb") as fh:
                last = b""
                for chunk in fh:
                    if chunk.strip():
                        last = chunk.rstrip(b"\n")
        except OSError:
            return ""
        if not last:
            return ""
        try:
            return str(json.loads(last.decode("utf-8", errors="replace")).get("h") or "")
        except ValueError:
            return ""

    def _lines(self, path: Optional[str] = None) -> list:
        try:
            with open(path or self.path, "r", encoding="utf-8", errors="replace") as fh:
                return [ln.rstrip("\n") for ln in fh if ln.strip()]
        except OSError:
            return []

    def verify(self, path: Optional[str] = None) -> Tuple[bool, Optional[int]]:
        """(ok, first broken line number). A line fails when its own integrity hash no longer matches its content
        (it was altered) or its ``prev`` no longer chains to the previous line's ``h`` (something before it was)."""
        lines = self._lines(path)
        prev_hash = ""
        for i, line in enumerate(lines, start=1):
            try:
                entry = json.loads(line)
            except ValueError:
                return False, i
            h = entry.pop("h", None)
            body = json.dumps(entry, ensure_ascii=False, sort_keys=False)
            if h != _line_hash(body) or entry.get("prev") != prev_hash:
                return False, i
            prev_hash = h or ""
        return True, None

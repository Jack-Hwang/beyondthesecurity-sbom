"""Small shared helpers: time, hashing, atomic JSON io, subprocess wrapper, ASCII-safe console text."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def safe_name(s: str, limit: int = 48) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("._") [:limit] or "project"


def write_json(path: str, obj: Any) -> None:
    """Atomic UTF-8 JSON write (temp file + replace) so readers never see a half file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=1, sort_keys=False, default=_json_default)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def read_text(path: str, limit: int = 2_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _json_default(o: Any) -> Any:
    if isinstance(o, (set, frozenset)):
        return sorted(o, key=str)
    if isinstance(o, bytes):
        return o.decode("utf-8", errors="replace")
    return str(o)


def run(cmd: Sequence[str], cwd: Optional[str] = None, timeout: float = 120.0,
        env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """Run a command without a shell. Returns (rc, stdout, stderr); never raises on non-zero exit."""
    try:
        p = subprocess.run(list(cmd), cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=env)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout
    except FileNotFoundError as exc:
        return 127, "", "not found: %s" % exc


def tree_hash(root: str, skip_dirs: Iterable[str] = (".git",)) -> str:
    """Content hash of a directory tree (relative names + bytes). Used to prove the origin is untouched."""
    skip = set(skip_dirs)
    h = hashlib.sha256()
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in skip)
        for fn in sorted(fns):
            fp = os.path.join(dp, fn)
            try:
                rel = os.path.relpath(fp, root).replace("\\", "/")
            except ValueError:
                continue          # Windows reserved-device names (nul/con/...) normalise to a device path
            h.update(rel.encode("utf-8", errors="replace") + b"\0")
            try:
                with open(fp, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
            except OSError:
                h.update(b"<unreadable>")
    return h.hexdigest()


def code_fingerprint(root: str) -> str:
    """Short content hash of the tool itself (code + knowledge + eval sets): identifies WHICH code produced a pass,
    without needing a git commit."""
    h = hashlib.sha256()
    for sub in ("bts_sbom_app", "knowledge", "evals"):
        base = os.path.join(root, sub)
        for dp, dns, fns in os.walk(base):
            dns[:] = sorted(d for d in dns if d != "__pycache__")
            for fn in sorted(fns):
                if fn.endswith((".py", ".md", ".json")):
                    fp = os.path.join(dp, fn)
                    h.update(os.path.relpath(fp, root).replace("\\", "/").encode() + b"\0")
                    try:
                        with open(fp, "rb") as fh:
                            h.update(fh.read())
                    except OSError:
                        pass
    return h.hexdigest()[:12]


def ascii_safe(s: Any) -> str:
    """Console-safe text for cp949 terminals (CLAUDE.md rule: ASCII-only console output)."""
    return str(s).encode("ascii", errors="replace").decode("ascii")


_TYPO = {0x2014: "-", 0x2013: "-", 0x2192: "->", 0x2190: "<-", 0x00B7: ".", 0x2022: "*", 0x2018: "'", 0x2019: "'",
         0x201C: '"', 0x201D: '"', 0x2026: "...", 0x00A0: " "}


def console_text(s: Any, stream: Any = None) -> str:
    """Text for a console stream: unchanged when the stream can encode it (Korean stays Korean on cp949/UTF-8), otherwise
    typographic punctuation becomes ASCII and anything else the stream cannot show becomes '?' - never an exception."""
    import sys
    text = str(s)
    enc = getattr(stream or sys.stdout, "encoding", None)
    if not isinstance(enc, str) or not enc:
        enc = "utf-8"
    try:
        text.encode(enc)
        return text
    except (UnicodeEncodeError, LookupError):
        pass
    text = text.translate(_TYPO)
    try:
        return text.encode(enc, errors="replace").decode(enc, errors="replace")
    except LookupError:
        return text.encode("ascii", errors="replace").decode("ascii")


def kv(d: Any) -> str:
    """Compact 'key value, key value' text for a dict (reports must not embed Python repr)."""
    if d is None:
        return "-"
    if isinstance(d, dict):
        return ", ".join("%s %s" % (k, ("(" + kv(d[k]) + ")") if isinstance(d[k], dict) else d[k]) for k in sorted(d, key=str)) or "-"
    return str(d)


def clip(s: Any, n: int = 200) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def uniq(seq: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

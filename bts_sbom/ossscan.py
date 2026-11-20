"""OSS scan orchestration: choose the target (folder / archive / URL), run the scanners, merge, correct, summarise.

    prepare_target(spec)   -> PreparedTarget   folder as-is; archive extracted safely; git or archive URL fetched
    run_scan(root, ...)    -> OssReport        source / dependency / binary (+ yocto / android) merged into one report
    overview(report)       -> dict             counts per scanner, license risk tiers with obligations (the "Overview" and
                                               "License" views of the FOSSLight Scanner GUI, as data)

The analysed material is untrusted data: archives are extracted with entry/size/path limits and never executed;
git is invoked only to clone (hooks disabled, no submodules, no symlinks, dangerous transports refused); nothing in the
analysed tree is ever run.  Fetching a URL happens only because the caller passed one - there is no implicit network use.
"""
from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import os
import re
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from bts_sbom import ossreport
from bts_sbom._internal.oss_common import check_cancel, is_cancelled, safe_join
from bts_sbom.ossreport import OssReport

MAX_ENTRIES = 200_000
MAX_TOTAL_BYTES = 4 * 1024 ** 3
MAX_DOWNLOAD = 1024 ** 3
ZIP_EXT = (".zip", ".jar", ".war", ".ear", ".whl", ".aar", ".apk", ".nupkg", ".egg")
TAR_EXT = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz")
ARCHIVE_EXT = ZIP_EXT + TAR_EXT + (".bz2", ".gz", ".rpm", ".src.rpm")
MODES = ("source", "dependency", "binary")


class TargetError(ValueError):
    pass


@dataclass
class PreparedTarget:
    root: str
    kind: str                                  # folder | archive | git | archive-url
    spec: str
    warnings: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)     # e.g. rpm name/version/license/url
    _tmp: Optional[str] = None

    def cleanup(self) -> None:
        if self._tmp and os.path.isdir(self._tmp):
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def __enter__(self) -> "PreparedTarget":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.cleanup()


# ===================================================================================== safe archive extraction
class _Budget:
    def __init__(self) -> None:
        self.entries = 0
        self.total = 0

    def take(self, size: int) -> None:
        self.entries += 1
        self.total += max(0, size)
        if self.entries > MAX_ENTRIES:
            raise TargetError("archive has more than %d entries - refusing (possible bomb)" % MAX_ENTRIES)
        if self.total > MAX_TOTAL_BYTES:
            raise TargetError("archive expands beyond %d bytes - refusing (possible bomb)" % MAX_TOTAL_BYTES)


def _write_member(dest: str, name: str, stream: Any, budget: _Budget, warnings: List[str], declared: int) -> None:
    target = safe_join(dest, name)
    if target is None:
        warnings.append("skipped unsafe archive path: %r" % name[:120])
        return
    budget.take(declared)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    written = 0
    with open(target, "wb") as out:
        while True:
            check_cancel()
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            written += len(chunk)
            if written > max(declared, 0) + (1 << 20) or written > MAX_TOTAL_BYTES:
                raise TargetError("archive member %r is larger than it declares - refusing" % name[:80])
            out.write(chunk)
    budget.total += max(0, written - max(declared, 0))
    if budget.total > MAX_TOTAL_BYTES:
        raise TargetError("archive expands beyond %d bytes - refusing" % MAX_TOTAL_BYTES)


def _extract_zip(path: str, dest: str, warnings: List[str]) -> None:
    budget = _Budget()
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                warnings.append("skipped symlink in archive: %r" % info.filename[:120])
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 2000 and info.file_size > (64 << 20):
                raise TargetError("zip member %r has an absurd compression ratio - refusing" % info.filename[:80])
            with zf.open(info) as src:
                _write_member(dest, info.filename, src, budget, warnings, info.file_size)


def _extract_tar(path: str, dest: str, warnings: List[str]) -> None:
    budget = _Budget()
    with tarfile.open(path, "r:*") as tf:
        for m in tf:
            if m.isdir():
                continue
            if not m.isreg():
                warnings.append("skipped non-regular archive entry (%s): %r" % (
                    "symlink" if m.issym() or m.islnk() else "special", m.name[:120]))
                continue
            src = tf.extractfile(m)
            if src is None:
                continue
            _write_member(dest, m.name, src, budget, warnings, m.size)


def _extract_single(path: str, dest: str, opener: Callable[..., Any], warnings: List[str]) -> None:
    base = os.path.basename(path)
    name = re.sub(r"\.(bz2|gz)$", "", base) or "payload"
    with opener(path, "rb") as src:
        _write_member(dest, name, src, _Budget(), warnings, MAX_TOTAL_BYTES)
    inner = os.path.join(dest, name)
    if name.lower().endswith(TAR_EXT) or tarfile.is_tarfile(inner):
        sub = os.path.join(dest, name + ".extracted")
        os.makedirs(sub, exist_ok=True)
        _extract_tar(inner, sub, warnings)


# --- RPM -----------------------------------------------------------------------------------------------------
_RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1004: "summary", 1014: "license", 1020: "url",
             1125: "payloadcompressor"}


def _rpm_header(buf: bytes, off: int) -> Tuple[Dict[str, str], int]:
    if buf[off:off + 3] != b"\x8e\xad\xe8":
        raise TargetError("rpm: bad header magic")
    nindex = int.from_bytes(buf[off + 8:off + 12], "big")
    hsize = int.from_bytes(buf[off + 12:off + 16], "big")
    if nindex > 100_000 or hsize > 64 * 1024 * 1024:
        raise TargetError("rpm: implausible header size")
    idx_start = off + 16
    store = idx_start + nindex * 16
    meta: Dict[str, str] = {}
    for i in range(nindex):
        e = buf[idx_start + i * 16: idx_start + i * 16 + 16]
        tag, typ, o, _cnt = (int.from_bytes(e[0:4], "big"), int.from_bytes(e[4:8], "big"),
                             int.from_bytes(e[8:12], "big"), int.from_bytes(e[12:16], "big"))
        if tag in _RPM_TAGS and typ in (6, 9):
            s = buf[store + o: store + o + 4096].split(b"\x00", 1)[0]
            meta[_RPM_TAGS[tag]] = s.decode("utf-8", "replace")
    return meta, store + hsize


class _Inflater:
    """Streaming, size-capped decompressor over an open file (gzip / bzip2 / xz).

    The payload of an untrusted rpm is never inflated in one call: ``gzip.decompress`` & co. have no output limit, so a
    few KiB can expand into gigabytes before any check could run.  Here every ``read`` asks the decompressor for at most
    that many bytes, and the running total is checked against ``limit`` the moment it is exceeded."""

    CHUNK = 1 << 20

    def __init__(self, comp: str, fh: Any, limit: int) -> None:
        import zlib
        if comp in ("gzip", ""):
            self._d: Any = zlib.decompressobj(31)
            self._zlib = True
        elif comp == "bzip2":
            self._d = bz2.BZ2Decompressor()
            self._zlib = False
        elif comp in ("xz", "lzma"):
            self._d = lzma.LZMADecompressor()
            self._zlib = False
        else:
            raise TargetError("rpm payload compression %r is not supported without third-party code "
                              "(zstd needs the zstandard package)" % comp)
        self._zlib_error = zlib.error
        self._fh = fh
        self._limit = limit
        self._pending = b""
        self._buf = bytearray()
        self._done = False
        self.total = 0

    def _produce(self, maxlen: int) -> bytes:
        d = self._d
        try:
            if self._zlib:
                data = self._pending or self._fh.read(self.CHUNK)
                piece = d.decompress(data, maxlen)
                self._pending = d.unconsumed_tail
                if d.eof:
                    self._done = True
                elif not data and not piece:
                    raise TargetError("rpm payload is truncated")
            else:
                if d.eof:
                    self._done = True
                    return b""
                if d.needs_input:
                    data = self._fh.read(self.CHUNK)
                    if not data:
                        raise TargetError("rpm payload is truncated")
                    piece = d.decompress(data, maxlen)
                else:
                    piece = d.decompress(b"", maxlen)
                if d.eof:
                    self._done = True
        except (OSError, EOFError, lzma.LZMAError, self._zlib_error) as exc:
            raise TargetError("rpm payload could not be decompressed: %s" % exc)
        self.total += len(piece)
        if self.total > self._limit:
            raise TargetError("rpm payload expands beyond %d bytes - refusing (possible decompression bomb)" % self._limit)
        return piece

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = 1 << 20
        while len(self._buf) < n and not self._done:
            self._buf += self._produce(max(n - len(self._buf), 1 << 16))
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def _read_exact(stream: Any, n: int) -> bytes:
    parts: List[bytes] = []
    got = 0
    while got < n:
        b = stream.read(n - got)
        if not b:
            break
        parts.append(b)
        got += len(b)
    return b"".join(parts)


class _Limited:
    """At most ``size`` bytes of ``stream``; ``drain`` discards what a consumer left behind."""

    def __init__(self, stream: Any, size: int) -> None:
        self._s = stream
        self.remaining = size

    def read(self, n: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        want = self.remaining if n is None or n < 0 else min(n, self.remaining)
        b = self._s.read(want)
        self.remaining -= len(b)
        return b

    def drain(self) -> None:
        while self.remaining > 0:
            if not self.read(1 << 20):
                break


def _extract_rpm(path: str, dest: str, warnings: List[str], meta_out: Dict[str, Any]) -> None:
    with open(path, "rb") as fh:
        head = fh.read(64 * 1024 * 1024)
        if head[:4] != b"\xed\xab\xee\xdb":
            raise TargetError("not an RPM file (bad lead magic)")
        _sig, off = _rpm_header(head, 96)
        off = (off + 7) & ~7
        meta, payload_off = _rpm_header(head, off)
        meta_out.update({"rpm_" + k: v for k, v in meta.items()})
        comp = (meta.get("payloadcompressor") or "gzip").lower()
        del head
        fh.seek(payload_off)
        infl = _Inflater(comp, fh, MAX_TOTAL_BYTES)
        budget = _Budget()
        while True:
            hdr = _read_exact(infl, 110)
            if not hdr:
                break
            if len(hdr) < 110:
                raise TargetError("rpm payload is truncated (partial cpio header)")
            if hdr[:6] != b"070701":
                raise TargetError("rpm payload is not a newc cpio archive")
            try:
                f = [int(hdr[6 + 8 * i: 14 + 8 * i], 16) for i in range(13)]
            except ValueError:
                raise TargetError("rpm payload has a corrupt cpio header")
            mode, size, namesize = f[1], f[6], f[11]
            if namesize <= 0 or namesize > 4096:
                raise TargetError("rpm payload has an implausible cpio name length")
            raw_name = _read_exact(infl, namesize)
            if len(raw_name) < namesize:
                raise TargetError("rpm payload is truncated (partial cpio name)")
            _read_exact(infl, (-(110 + namesize)) % 4)
            name = raw_name[:-1].decode("utf-8", "replace")
            if name == "TRAILER!!!":
                break
            body = _Limited(infl, size)
            if stat.S_ISREG(mode):
                _write_member(dest, name, body, budget, warnings, size)
            else:
                budget.take(0)                      # every entry counts against MAX_ENTRIES, not only files
                if stat.S_ISLNK(mode):
                    warnings.append("skipped symlink in rpm: %r" % name[:120])
            body.drain()
            if body.remaining > 0:
                raise TargetError("rpm payload is truncated (member %r)" % name[:80])
            _read_exact(infl, (-size) % 4)
    if meta.get("name") and "src" in os.path.basename(path).lower():
        for fn in sorted(os.listdir(dest)):          # a source RPM carries the upstream tarballs: one level deeper
            full = os.path.join(dest, fn)
            if os.path.isfile(full) and fn.lower().endswith(TAR_EXT + ZIP_EXT):
                sub = os.path.join(dest, fn + ".extracted")
                os.makedirs(sub, exist_ok=True)
                try:
                    (_extract_zip if fn.lower().endswith(ZIP_EXT) else _extract_tar)(full, sub, warnings)
                except (TargetError, tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
                    warnings.append("could not extract %s from the source rpm: %s" % (fn, exc))


def is_archive(path: str) -> bool:
    return os.path.isfile(path) and path.lower().endswith(ARCHIVE_EXT)


def extract_archive(path: str, dest: str) -> Tuple[List[str], Dict[str, Any]]:
    """Extract ``path`` into ``dest`` (which must exist).  Returns (warnings, meta)."""
    low = path.lower()
    warnings: List[str] = []
    meta: Dict[str, Any] = {}
    try:
        if low.endswith(".rpm"):
            _extract_rpm(path, dest, warnings, meta)
        elif low.endswith(ZIP_EXT):
            _extract_zip(path, dest, warnings)
        elif low.endswith(TAR_EXT):
            _extract_tar(path, dest, warnings)
        elif low.endswith(".bz2"):
            _extract_single(path, dest, bz2.open, warnings)
        elif low.endswith(".gz"):
            _extract_single(path, dest, gzip.open, warnings)
        else:
            raise TargetError("unsupported archive type: %s (supported: %s)" % (os.path.basename(path), ", ".join(ARCHIVE_EXT)))
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, lzma.LZMAError) as exc:
        raise TargetError("cannot read archive %s: %s" % (os.path.basename(path), exc))
    return warnings, meta


# ============================================================================================ URL / git targets
_GIT_URL = re.compile(r"^(https://|ssh://|git://|git@[A-Za-z0-9.-]+:)")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$")


def looks_like_git_url(spec: str) -> bool:
    return bool(_GIT_URL.match(spec)) and (spec.endswith(".git") or "github.com" in spec or "gitlab" in spec
                                           or "bitbucket" in spec or spec.startswith(("ssh://", "git://", "git@")))


_HOST = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:.]+\])$")


def _valid_git_authority(url: str) -> bool:
    """The host of a git URL must be a plain hostname / IP: a leading '-' or odd characters could be read by ssh or git as
    an option (the classic '-oProxyCommand' host trick), so such URLs never reach the git command line."""
    if re.search(r"[\s\x00-\x1f\x7f]", url):
        return False
    if url.startswith("git@"):
        host = url[4:].split(":", 1)[0]
    else:
        parts = urllib.parse.urlsplit(url)
        try:
            host = parts.hostname or ""
            parts.port                      # noqa: B018 - raises ValueError for a bad port
        except ValueError:
            return False
    return bool(_HOST.match(host))


# ------------------------------------------------------------------------------------------------ SSRF guard
def _non_public_address(host: str) -> Optional[str]:
    """The first address ``host`` resolves to that is not a public one (loopback, link-local - cloud metadata -, private,
    CGNAT, multicast, reserved, unspecified), else None.  An unresolvable host is not blocked here: the fetch fails on
    its own.  (A DNS answer can change between this check and the connect; the guard narrows the SSRF surface, it is not
    a network policy - run the service where internal addresses are not reachable if that matters.)"""
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return None
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        if ip.is_multicast or not ip.is_global:
            return str(ip)
    return None


def _refuse_non_public(host: str, what: str) -> None:
    bad = _non_public_address(host)
    if bad:
        raise TargetError("refusing %s: host %r resolves to a non-public address (%s); an operator who really wants "
                          "internal hosts sets BTS_OSS_ALLOW_PRIVATE_HOSTS=1" % (what, host[:80], bad))


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Every redirect target is re-checked: a public URL may not bounce the fetch to an internal address."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise TargetError("refusing redirect to %r (only http/https)" % newurl[:80])
        _refuse_non_public(parts.hostname, "redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _git_host(url: str) -> str:
    if url.startswith("git@"):
        return url[4:].split(":", 1)[0]
    return urllib.parse.urlsplit(url).hostname or ""


def _run_cancellable(cmd: List[str], env: Dict[str, str], timeout: float) -> "subprocess.CompletedProcess[str]":
    """``subprocess.run`` that notices a cancellation within about half a second and kills the process."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    deadline = time.monotonic() + timeout
    while True:
        try:
            out, err = proc.communicate(timeout=0.5)
            return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
        except subprocess.TimeoutExpired:
            cancelled = is_cancelled()
            if cancelled or time.monotonic() > deadline:
                proc.kill()
                proc.communicate()
                if cancelled:
                    check_cancel()
                raise subprocess.TimeoutExpired(cmd, timeout)


def _git_clone(url: str, dest: str, branch: str, warnings: List[str], runner: Optional[Callable[..., Any]] = None,
               allow_private: bool = True) -> None:
    if (url.startswith("-") or re.search(r"(^|\W)(ext|fd|file)::", url) or not _GIT_URL.match(url)
            or not _valid_git_authority(url)):
        raise TargetError("refusing git source %r (unsupported or unsafe transport / host)" % url[:80])
    if not allow_private:
        _refuse_non_public(_git_host(url), "git source")
    if branch and not _REF.match(branch):
        raise TargetError("refusing branch/tag name %r" % branch[:80])
    empty_hooks = tempfile.mkdtemp(prefix="bts_nohooks_")
    try:
        cmd = ["git", "-c", "core.hooksPath=" + empty_hooks, "-c", "core.symlinks=false", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always", "-c", "protocol.git.allow=always",
               "clone", "--depth", "1", "--no-recurse-submodules", "--no-tags"]
        if branch:
            cmd += ["--branch", branch]
        if not allow_private:
            cmd[1:1] = ["-c", "http.followRedirects=false"]         # a redirect could point at an internal address
        cmd += ["--", url, dest]
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo")
        try:
            if runner is not None:
                proc = runner(cmd, capture_output=True, text=True, timeout=900, env=env)
            else:
                proc = _run_cancellable(cmd, env, 900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TargetError("git clone failed: %s" % exc)
        if proc.returncode != 0:
            raise TargetError("git clone failed: %s" % (proc.stderr or proc.stdout or "").strip()[:300])
        shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)       # history is not analysed; keep the tree only
        warnings.append("cloned %s%s (depth 1; the .git directory was removed after the clone)" % (url, (" @ " + branch) if branch else ""))
    finally:
        shutil.rmtree(empty_hooks, ignore_errors=True)


def _download(url: str, dest_file: str, opener: Optional[Callable[..., Any]] = None, allow_private: bool = True) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise TargetError("refusing to download %r (only http/https URLs)" % url[:80])
    if not allow_private:
        _refuse_non_public(parts.hostname, "download")
    req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom-oss/1"})
    if opener is None:
        opener = urllib.request.urlopen if allow_private else urllib.request.build_opener(_GuardedRedirect).open
    try:
        with opener(req, timeout=60) as resp, open(dest_file, "wb") as out:
            total = 0
            while True:
                check_cancel()
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise TargetError("download larger than %d bytes - refusing" % MAX_DOWNLOAD)
                out.write(chunk)
    except (OSError, ValueError) as exc:
        raise TargetError("download failed: %s" % exc)


def prepare_target(spec: str, *, branch: str = "", workdir: Optional[str] = None,
                   git_runner: Optional[Callable[..., Any]] = None,
                   opener: Optional[Callable[..., Any]] = None, allow_private_hosts: bool = True) -> PreparedTarget:
    """Resolve ``spec`` to a directory that the scanners can read.

    * existing directory  -> used in place (read-only for every scanner)
    * existing archive    -> extracted to a fresh temp dir (zip family, tar family, bz2, gz, rpm / src.rpm)
    * git URL             -> shallow clone to a fresh temp dir
    * http(s) archive URL -> downloaded to a temp file, then extracted

    ``allow_private_hosts=False`` (what the web service uses unless the operator opts in) refuses URLs whose host resolves
    to a loopback / link-local / private / reserved address, also after every redirect.
    """
    if os.path.isdir(spec):
        return PreparedTarget(root=os.path.abspath(spec), kind="folder", spec=spec)
    if os.path.isfile(spec) and is_archive(spec):
        tmp = tempfile.mkdtemp(prefix="bts_oss_", dir=workdir)
        try:
            warnings, meta = extract_archive(spec, tmp)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        return PreparedTarget(root=tmp, kind="archive", spec=spec, warnings=warnings, meta=meta, _tmp=tmp)
    if os.path.isfile(spec):
        raise TargetError("%s is a file but not a supported archive (supported: %s); pass a folder or a manifest folder"
                          % (spec, ", ".join(ARCHIVE_EXT)))
    if re.match(r"^[a-z]+://|^git@", spec):
        tmp = tempfile.mkdtemp(prefix="bts_oss_", dir=workdir)
        try:
            warnings: List[str] = []
            if looks_like_git_url(spec):
                dest = os.path.join(tmp, "repo")
                _git_clone(spec, dest, branch, warnings, git_runner, allow_private_hosts)
                return PreparedTarget(root=dest, kind="git", spec=spec, warnings=warnings, _tmp=tmp)
            name = os.path.basename(urllib.parse.urlsplit(spec).path) or "download"
            if not name.lower().endswith(ARCHIVE_EXT):
                raise TargetError("URL %r is neither a git repository nor a supported archive (%s)" % (spec[:80], ", ".join(ARCHIVE_EXT)))
            f = os.path.join(tmp, re.sub(r"[^A-Za-z0-9._-]", "_", name))
            _download(spec, f, opener, allow_private_hosts)
            dest = os.path.join(tmp, "extracted")
            os.makedirs(dest)
            w2, meta = extract_archive(f, dest)
            os.remove(f)
            return PreparedTarget(root=dest, kind="archive-url", spec=spec, warnings=w2, meta=meta, _tmp=tmp)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
    raise TargetError("%r is not a folder, a supported archive, or a URL" % spec)


def default_fetcher(url: str, *, limit: int = 2_000_000, timeout: float = 20.0) -> Optional[str]:
    """https-only text fetch (size and time bounded) for the OPT-IN online lookups of the dependency scanner (public registries:
    npm, PyPI, crates.io, Maven Central).  Only package coordinates are in the URL - nothing from the analysed source leaves the
    machine.  Returns None on any failure; callers record that as "license not resolved", never as an empty license."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom-oss/1", "Accept": "application/json, text/xml, */*"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(limit + 1)
    except (OSError, ValueError):
        return None
    return data[:limit].decode("utf-8", "replace") if len(data) <= limit else None


# =================================================================================================== running
def _import(name: str) -> Any:
    import importlib
    try:
        return importlib.import_module("bts_sbom._internal." + name)
    except ImportError as exc:
        raise TargetError("scanner module %s is not available in this build: %s" % (name, exc))


def run_scan(root: str, modes: Sequence[str] = MODES, *, excludes: Sequence[str] = (), correction: Any = None,
             online: bool = False, kb_files: Sequence[str] = (), engine: str = "builtin", max_files: int = 200_000,
             recursive_dependencies: bool = True, fetcher: Any = None, meta: Optional[Dict[str, Any]] = None) -> OssReport:
    """Run the selected scanners on ``root`` and merge their reports.

    ``correction``: None = use ``<root>/sbom-info.yaml`` when present; False = off; str = path of a correction file.
    Corrections apply to source and binary items only (never to dependencies), once, after the merge."""
    modes = [m.strip().lower() for m in modes if m and m.strip()]
    if modes == ["all"] or not modes:
        modes = list(MODES)
    unknown = [m for m in modes if m not in MODES]
    if unknown:
        raise ValueError("unknown scan mode(s) %s (choose from %s)" % (", ".join(unknown), ", ".join(MODES + ("all",))))
    if online and fetcher is None:
        fetcher = default_fetcher
    report = OssReport(info=ossreport.new_info(analyzed_path=root, excludes=excludes, modes=modes))
    if meta:
        report.info["target"] = {k: v for k, v in meta.items()}
    for mode in modes:
        check_cancel()
        try:
            if mode == "source":
                sub = _import("oss_source").scan(root, excludes=excludes, correction=False, max_files=max_files, engine=engine)
            elif mode == "dependency":
                sub = _import("oss_dependency").scan(root, excludes=excludes, recursive=recursive_dependencies,
                                                     online=online, fetcher=fetcher)
            else:
                sub = _import("oss_binary").scan(root, excludes=excludes, kb_files=kb_files, max_files=max_files)
        except TargetError as exc:
            report.warnings.append("%s scanner skipped: %s" % (mode, exc))
            continue
        report.merge(sub)
    if correction is not False:
        cfile = correction if isinstance(correction, str) else os.path.join(root, "sbom-info.yaml")
        if os.path.isfile(cfile):
            try:
                stats = ossreport.apply_corrections(report, ossreport.load_corrections(cfile))
                report.info.setdefault("scanners", {})["sbom-info"] = {"file": cfile, **stats}
            except ossreport.CorrectionError as exc:
                report.warnings.append("sbom-info.yaml not applied: %s" % exc)
        elif isinstance(correction, str):
            report.warnings.append("correction file %s does not exist" % correction)
    return report


# ================================================================================================== overview
def overview(report: OssReport) -> Dict[str, Any]:
    """Counts per scanner and the license risk tiers (High / Medium / Low / Needs review) with their obligations."""
    from bts_sbom._internal.license_utils import classify_license, get_license_obligations
    tiers = {"High": [], "Medium": [], "Low": [], "Needs review": []}
    order = {"strong-copyleft": "High", "network-copyleft": "High", "restricted": "High", "weak-copyleft": "Medium",
             "permissive": "Low", "public-domain": "Low"}
    seen: Dict[str, Dict[str, Any]] = {}
    for it in report.active():
        for lic in it.licenses:
            rec = seen.setdefault(lic, {"license": lic, "components": 0})
            rec["components"] += 1
    for lic, rec in seen.items():
        try:
            cat = str(classify_license(lic)).lower().replace(" ", "-")
            ob = get_license_obligations(lic)
        except Exception:
            cat, ob = "unknown", {}
        tier = order.get(cat, "Needs review")
        rec.update(category=cat, obligations=sorted(k for k, v in ob.items() if v))
        tiers[tier].append(rec)
    for t in tiers.values():
        t.sort(key=lambda r: (-r["components"], r["license"]))
    return {"counts": {k: len(report.of_kind(k)) for k in ossreport.KINDS},
            "excluded": sum(1 for i in report.items if i.exclude),
            "without_license": sum(1 for i in report.active() if not i.licenses and (i.oss_name or "") != "-"),
            "license_tiers": tiers, "warnings": list(report.warnings), "scanners": report.info.get("scanners", {})}

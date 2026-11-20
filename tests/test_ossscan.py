"""Target preparation (folder / archive / URL), safe extraction, scan orchestration and the license overview."""
from __future__ import annotations

import gzip
import io
import os
import stat
import tarfile
import zipfile

import pytest

from bts_sbom import ossreport, ossscan
from bts_sbom.ossreport import OssItem, OssReport


# ----------------------------------------------------------------------------------------------- archive safety
def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries:
            if isinstance(data, zipfile.ZipInfo):
                zf.writestr(data, "target")
            else:
                zf.writestr(name, data)


def test_zip_slip_absolute_paths_and_symlinks_are_skipped_not_extracted(tmp_path):
    z = tmp_path / "evil.zip"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    _zip(str(z), [("ok/a.txt", b"fine"), ("../evil.txt", b"x"), ("/abs.txt", b"x"), ("C:/win.txt", b"x"), ("link", link)])
    with ossscan.prepare_target(str(z)) as pt:
        assert os.path.read if False else True
        assert open(os.path.join(pt.root, "ok", "a.txt"), "rb").read() == b"fine"
        assert not os.path.exists(os.path.join(os.path.dirname(pt.root), "evil.txt"))
        assert sorted(os.listdir(pt.root)) == ["ok"]
        assert sum("unsafe archive path" in w for w in pt.warnings) == 3 and any("symlink" in w for w in pt.warnings)
        assert pt.kind == "archive"
    assert not os.path.exists(pt.root), "the temp extraction is removed on exit"


def test_tar_links_and_devices_are_skipped(tmp_path):
    t = tmp_path / "e.tar.gz"
    with tarfile.open(str(t), "w:gz") as tf:
        ti = tarfile.TarInfo("good.txt")
        ti.size = 2
        tf.addfile(ti, io.BytesIO(b"ok"))
        sl = tarfile.TarInfo("sym")
        sl.type = tarfile.SYMTYPE
        sl.linkname = "/etc/passwd"
        tf.addfile(sl)
        dev = tarfile.TarInfo("dev")
        dev.type = tarfile.CHRTYPE
        tf.addfile(dev)
        trav = tarfile.TarInfo("../../escape.txt")
        trav.size = 1
        tf.addfile(trav, io.BytesIO(b"x"))
    with ossscan.prepare_target(str(t)) as pt:
        assert os.listdir(pt.root) == ["good.txt"]
        assert any("symlink" in w for w in pt.warnings) and any("special" in w for w in pt.warnings)
        assert any("unsafe archive path" in w for w in pt.warnings)


def test_entry_limit_and_size_limit_refuse_bombs(tmp_path, monkeypatch):
    z = tmp_path / "many.zip"
    _zip(str(z), [("f%d.txt" % i, b"x") for i in range(10)])
    monkeypatch.setattr(ossscan, "MAX_ENTRIES", 3)
    with pytest.raises(ossscan.TargetError):
        ossscan.prepare_target(str(z))
    monkeypatch.setattr(ossscan, "MAX_ENTRIES", 1000)
    monkeypatch.setattr(ossscan, "MAX_TOTAL_BYTES", 5)
    with pytest.raises(ossscan.TargetError):
        ossscan.prepare_target(str(z))


def test_unsupported_and_corrupt_inputs_fail_with_a_reason(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"1")
    with pytest.raises(ossscan.TargetError, match="not a supported archive"):
        ossscan.prepare_target(str(f))
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(ossscan.TargetError, match="cannot read archive"):
        ossscan.prepare_target(str(bad))
    with pytest.raises(ossscan.TargetError):
        ossscan.prepare_target(str(tmp_path / "missing"))


def test_single_file_gz_with_tar_inside_is_unpacked_one_level(tmp_path):
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as tf:
        ti = tarfile.TarInfo("pkg/LICENSE")
        ti.size = 3
        tf.addfile(ti, io.BytesIO(b"MIT"))
    g = tmp_path / "pkg.tar.gz"
    g.write_bytes(gzip.compress(inner.getvalue()))
    with ossscan.prepare_target(str(g)) as pt:
        assert os.path.exists(os.path.join(pt.root, "pkg", "LICENSE"))


# --------------------------------------------------------------------------------------------------------- rpm
def _rpm(tmp_path, payload_files, name="demo", version="1.2", license_="GPL-2.0-only", src=False, comp="gzip",
         cpio_override=None):
    def hdr(entries):
        idx, store = b"", b""
        for tag, val in entries:
            idx += tag.to_bytes(4, "big") + (6).to_bytes(4, "big") + len(store).to_bytes(4, "big") + (1).to_bytes(4, "big")
            store += val.encode() + b"\x00"
        return b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + len(entries).to_bytes(4, "big") + len(store).to_bytes(4, "big") + idx + store

    cpio = b""
    for n, data in payload_files:
        nm = n.encode() + b"\x00"
        fields = [1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0]
        cpio += b"070701" + b"".join(b"%08X" % f for f in fields) + nm
        cpio += b"\x00" * ((-(110 + len(nm))) % 4) + data + b"\x00" * ((-len(data)) % 4)
    nm = b"TRAILER!!!\x00"
    cpio += b"070701" + b"".join(b"%08X" % f for f in [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nm), 0]) + nm
    cpio += b"\x00" * ((-(110 + len(nm))) % 4)
    if cpio_override is not None:
        cpio = cpio_override
    sig = hdr([])
    sig += b"\x00" * ((-len(sig)) % 8)
    main = hdr([(1000, name), (1001, version), (1014, license_), (1020, "https://example.org/demo"), (1125, comp)])
    import bz2 as _bz2
    import lzma as _lzma
    packer = {"gzip": gzip.compress, "bzip2": _bz2.compress, "xz": _lzma.compress}[comp]
    p = tmp_path / (name + (".src.rpm" if src else ".rpm"))
    p.write_bytes(b"\xed\xab\xee\xdb" + b"\x03\x00" + b"\x00" * 90 + sig + main + packer(cpio))
    return str(p)


def test_rpm_payload_and_metadata_are_read(tmp_path):
    p = _rpm(tmp_path, [("usr/share/doc/demo/COPYING", b"GPL text"), ("../../evil", b"x")])
    with ossscan.prepare_target(p) as pt:
        assert open(os.path.join(pt.root, "usr", "share", "doc", "demo", "COPYING"), "rb").read() == b"GPL text"
        assert pt.meta["rpm_name"] == "demo" and pt.meta["rpm_license"] == "GPL-2.0-only"
        assert any("unsafe archive path" in w for w in pt.warnings)


def test_rpm_with_unsupported_compression_says_so(tmp_path):
    p = _rpm(tmp_path, [("a", b"x")])
    raw = open(p, "rb").read().replace(b"gzip\x00", b"zstd\x00")
    open(p, "wb").write(raw)
    with pytest.raises(ossscan.TargetError, match="zstd"):
        ossscan.prepare_target(p)


def test_src_rpm_unpacks_the_upstream_tarball_one_level(tmp_path):
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as tf:
        ti = tarfile.TarInfo("demo-1.2/LICENSE")
        ti.size = 3
        tf.addfile(ti, io.BytesIO(b"MIT"))
    p = _rpm(tmp_path, [("demo-1.2.tar.gz", inner.getvalue())], src=True)
    with ossscan.prepare_target(p) as pt:
        assert os.path.exists(os.path.join(pt.root, "demo-1.2.tar.gz.extracted", "demo-1.2", "LICENSE"))


@pytest.mark.parametrize("comp", ["gzip", "bzip2", "xz"])
def test_rpm_payload_compressions_stream_correctly(tmp_path, comp):
    p = _rpm(tmp_path, [("usr/share/doc/demo/COPYING", b"GPL text " * 50000), ("b", b"two")], comp=comp)
    with ossscan.prepare_target(p) as pt:
        assert len(open(os.path.join(pt.root, "usr", "share", "doc", "demo", "COPYING"), "rb").read()) == 9 * 50000
        assert open(os.path.join(pt.root, "b"), "rb").read() == b"two"


@pytest.mark.parametrize("comp", ["gzip", "bzip2", "xz"])
def test_rpm_decompression_bomb_is_stopped_at_the_limit_not_after_inflating_everything(tmp_path, monkeypatch, comp):
    real_total = []
    orig = ossscan._Inflater._produce

    def spy(self, maxlen):
        out = orig(self, maxlen)
        real_total.append(self.total)
        return out

    monkeypatch.setattr(ossscan._Inflater, "_produce", spy)
    monkeypatch.setattr(ossscan, "MAX_TOTAL_BYTES", 5_000_000)
    p = _rpm(tmp_path, [("big", b"\x00" * 60_000_000)], comp=comp)          # ~60 MB of zeros from a tiny file
    assert os.path.getsize(p) < 200_000
    with pytest.raises(ossscan.TargetError, match="bomb|larger|beyond"):
        ossscan.prepare_target(p)
    assert max(real_total) < 5_000_000 + 4 * (1 << 20), "the decompressor must not run on past the cap"


def test_rpm_corrupt_cpio_header_is_a_target_error_not_a_crash(tmp_path):
    bad = b"070701" + b"ZZZZZZZZ" * 13 + b"x" * 40
    p = _rpm(tmp_path, [], cpio_override=bad)
    with pytest.raises(ossscan.TargetError, match="corrupt cpio|cpio"):
        ossscan.prepare_target(p)


def test_rpm_truncated_payload_is_a_target_error(tmp_path):
    good = _rpm(tmp_path, [("a", b"x" * 1000)], comp="gzip")
    raw = open(good, "rb").read()
    open(good, "wb").write(raw[:-12])
    with pytest.raises(ossscan.TargetError):
        ossscan.prepare_target(good)


# ------------------------------------------------------------------------------------------------- SSRF / cancel
def _addr(monkeypatch, ip):
    monkeypatch.setattr(ossscan.socket, "getaddrinfo", lambda host, port, *a, **k: [(2, 1, 6, "", (ip, 0))])


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.9", "172.16.5.5", "100.64.0.1",
                                "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1"])
def test_non_public_addresses_are_refused_for_downloads_and_git(tmp_path, monkeypatch, ip):
    _addr(monkeypatch, ip)
    with pytest.raises(ossscan.TargetError, match="non-public"):
        ossscan.prepare_target("https://files.example.org/pkg.zip", allow_private_hosts=False)
    with pytest.raises(ossscan.TargetError, match="non-public"):
        ossscan.prepare_target("https://git.example.org/team/repo.git", allow_private_hosts=False,
                               git_runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError("git must not run")))


def test_public_addresses_pass_the_guard_and_the_default_stays_permissive(tmp_path, monkeypatch):
    _addr(monkeypatch, "93.184.216.34")
    assert ossscan._non_public_address("files.example.org") is None
    _addr(monkeypatch, "10.0.0.5")                                 # the CLI default trusts its own user (intranet git servers)
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        os.makedirs(cmd[-1], exist_ok=True)
        return _Proc(0)

    with ossscan.prepare_target("https://git.corp.example/team/repo.git", git_runner=runner):
        pass
    assert calls and "http.followRedirects=false" not in calls[0]


def test_guarded_git_clone_disables_redirects(tmp_path, monkeypatch):
    _addr(monkeypatch, "93.184.216.34")
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        os.makedirs(cmd[-1], exist_ok=True)
        return _Proc(0)

    with ossscan.prepare_target("https://git.example.org/team/repo.git", git_runner=runner, allow_private_hosts=False):
        pass
    assert "http.followRedirects=false" in calls[0]


def test_a_redirect_to_an_internal_address_is_refused(monkeypatch):
    import urllib.request
    handler = ossscan._GuardedRedirect()
    req = urllib.request.Request("https://files.example.org/a.zip")
    _addr(monkeypatch, "169.254.169.254")
    with pytest.raises(ossscan.TargetError, match="non-public"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://metadata.example/latest/meta-data/x.zip")
    with pytest.raises(ossscan.TargetError, match="http/https"):
        handler.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")
    _addr(monkeypatch, "93.184.216.34")
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.example.org/a.zip") is not None


def test_unresolvable_host_is_not_blocked_by_the_guard(monkeypatch):
    def boom(*a, **k):
        raise OSError("no dns")
    monkeypatch.setattr(ossscan.socket, "getaddrinfo", boom)
    assert ossscan._non_public_address("nope.invalid") is None


def test_walk_and_extraction_stop_when_the_scope_is_cancelled(tmp_path):
    import threading
    from bts_sbom._internal import oss_common
    for n in range(600):
        (tmp_path / ("f%03d.txt" % n)).write_text("x", encoding="utf-8")
    ev = threading.Event()
    seen = 0
    with pytest.raises(oss_common.Cancelled):
        with oss_common.cancel_scope(ev):
            for _ in oss_common.walk(str(tmp_path)):
                seen += 1
                if seen == 10:
                    ev.set()
    assert 10 <= seen < 600
    assert not oss_common.is_cancelled(), "the scope is thread-local and ends with the with-block"
    # Cancelled is a BaseException: a scanner's tolerant 'except Exception' must not swallow it
    assert not issubclass(oss_common.Cancelled, Exception)


# ------------------------------------------------------------------------------------------------------ url / git
class _Proc:
    def __init__(self, rc=0, err=""):
        self.returncode, self.stderr, self.stdout = rc, err, ""


def test_git_clone_uses_safe_flags_and_removes_dot_git():
    calls = []

    def runner(cmd, **kw):
        calls.append((cmd, kw))
        dest = cmd[-1]
        os.makedirs(os.path.join(dest, ".git"))
        open(os.path.join(dest, "a.txt"), "w").write("x")
        return _Proc()

    with ossscan.prepare_target("https://github.com/o/r.git", branch="v1.0", git_runner=runner) as pt:
        cmd = calls[0][0]
        assert pt.kind == "git" and os.path.exists(os.path.join(pt.root, "a.txt")) and not os.path.exists(os.path.join(pt.root, ".git"))
        assert "--no-recurse-submodules" in cmd and "--depth" in cmd and "core.symlinks=false" in cmd
        assert any(c.startswith("core.hooksPath=") for c in cmd) and cmd[cmd.index("--") - 2:cmd.index("--")] == ["--branch", "v1.0"]
        assert calls[0][1]["env"]["GIT_TERMINAL_PROMPT"] == "0"


@pytest.mark.parametrize("spec", ["ext::sh -c touch /tmp/x", "-oProxyCommand=x", "file:///etc", "ftp://x/y.zip", "https://-oProxy/x.git"])
def test_dangerous_or_unsupported_url_specs_are_refused(spec):
    with pytest.raises(ossscan.TargetError):
        ossscan.prepare_target(spec, git_runner=lambda *a, **k: _Proc())


def test_bad_branch_name_and_failed_clone_are_reported():
    with pytest.raises(ossscan.TargetError, match="branch"):
        ossscan.prepare_target("https://github.com/o/r.git", branch="--upload-pack=x", git_runner=lambda *a, **k: _Proc())
    with pytest.raises(ossscan.TargetError, match="git clone failed"):
        ossscan.prepare_target("https://github.com/o/r.git", git_runner=lambda *a, **k: _Proc(128, "fatal: not found"))


def test_archive_url_is_downloaded_with_a_size_cap_and_extracted(tmp_path, monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("p/LICENSE", "MIT")

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    seen = {}

    def opener(req, timeout):
        seen["url"] = req.full_url
        return Resp(buf.getvalue())

    with ossscan.prepare_target("https://example.org/dl/pkg-1.0.zip", opener=opener) as pt:
        assert pt.kind == "archive-url" and os.path.exists(os.path.join(pt.root, "p", "LICENSE"))
    assert seen["url"].endswith("pkg-1.0.zip")
    monkeypatch.setattr(ossscan, "MAX_DOWNLOAD", 5)
    with pytest.raises(ossscan.TargetError, match="larger"):
        ossscan.prepare_target("https://example.org/dl/pkg-1.0.zip", opener=opener)
    with pytest.raises(ossscan.TargetError, match="neither a git repository nor"):
        ossscan.prepare_target("https://example.org/page.html", opener=opener)


# ---------------------------------------------------------------------------------------------- orchestration
def _fake(items, warn=None):
    class M:
        @staticmethod
        def scan(root, **kw):
            r = OssReport(info=ossreport.new_info(root), items=[OssItem(**i) for i in items], warnings=list(warn or []))
            r.info["scanners"]["fake"] = {"seen": True}
            return r
    return M


def test_run_scan_merges_modes_applies_corrections_once_and_never_to_dependencies(tmp_path, monkeypatch):
    (tmp_path / "sbom-info.yaml").write_text('''
libidn:
- version: "9.9"
  source name or path:
  - "src/a.c"
  - "package.json"
  license: MIT
''', encoding="utf-8")
    mods = {"oss_source": _fake([dict(kind="src", oss_name="x", source_path="src/a.c", licenses=["GPL-3.0-only"])]),
            "oss_dependency": _fake([dict(kind="dep", oss_name="d", source_path="package.json", licenses=["ISC"])]),
            "oss_binary": _fake([])}
    seen = {}

    def fake_import(name):
        m = mods[name]
        orig = m.scan
        m.scan = staticmethod(lambda root, **kw: (seen.setdefault(name, kw), orig(root, **kw))[1])
        return m

    monkeypatch.setattr(ossscan, "_import", fake_import)
    rep = ossscan.run_scan(str(tmp_path), ["all"])
    assert seen["oss_source"]["correction"] is False, "the orchestrator applies corrections itself, exactly once"
    src = next(i for i in rep.items if i.kind == "src")
    assert (src.oss_name, src.version, src.licenses) == ("libidn", "9.9", ["MIT"])
    assert next(i for i in rep.items if i.kind == "dep").licenses == ["ISC"]
    assert rep.info["scanners"]["sbom-info"]["corrected"] == 1 and "fake" in rep.info["scanners"]
    off = ossscan.run_scan(str(tmp_path), ["source"], correction=False)
    assert next(i for i in off.items if i.kind == "src").oss_name == "x"


def test_run_scan_reports_unavailable_scanners_and_bad_modes_honestly(tmp_path, monkeypatch):
    def boom(name):
        raise ossscan.TargetError("scanner module %s is not available" % name)

    monkeypatch.setattr(ossscan, "_import", boom)
    rep = ossscan.run_scan(str(tmp_path), ["source", "dependency"])
    assert len(rep.warnings) == 2 and all("skipped" in w for w in rep.warnings)
    with pytest.raises(ValueError):
        ossscan.run_scan(str(tmp_path), ["bogus"])
    (tmp_path / "sbom-info.yaml").write_text("pkg:\n- license: MIT\n", encoding="utf-8")
    monkeypatch.setattr(ossscan, "_import", lambda n: _fake([]))
    assert any("not applied" in w for w in ossscan.run_scan(str(tmp_path), ["source"]).warnings)


def test_overview_groups_licenses_into_risk_tiers():
    r = OssReport(items=[OssItem(kind="src", oss_name="a", licenses=["GPL-3.0-only"]),
                         OssItem(kind="dep", oss_name="b", licenses=["MIT"]),
                         OssItem(kind="dep", oss_name="c", licenses=["MIT"]),
                         OssItem(kind="dep", oss_name="d", licenses=["LGPL-2.1-only"]),
                         OssItem(kind="bin", oss_name="e", licenses=["Totally Custom License"]),
                         OssItem(kind="dep", oss_name="f", licenses=[]),
                         OssItem(kind="dep", oss_name="g", licenses=["GPL-3.0-only"], exclude=True)])
    ov = ossscan.overview(r)
    tiers = {t: [x["license"] for x in rows] for t, rows in ov["license_tiers"].items()}
    assert tiers["High"] == ["GPL-3.0-only"] and tiers["Low"] == ["MIT"] and "LGPL-2.1-only" in tiers["Medium"]
    assert "Totally Custom License" in tiers["Needs review"]
    assert ov["counts"] == {"src": 1, "bin": 1, "dep": 5} and ov["excluded"] == 1 and ov["without_license"] == 1



def test_online_lookup_is_opt_in_and_uses_the_bounded_https_fetcher(tmp_path, monkeypatch):
    seen = {}

    class M:
        @staticmethod
        def scan(root, **kw):
            seen.update(kw)
            return OssReport(info=ossreport.new_info(root))

    monkeypatch.setattr(ossscan, "_import", lambda name: M)
    ossscan.run_scan(str(tmp_path), ["dependency"])
    assert seen["online"] is False and seen["fetcher"] is None, "no network unless asked"
    ossscan.run_scan(str(tmp_path), ["dependency"], online=True)
    assert seen["online"] is True and seen["fetcher"] is ossscan.default_fetcher
    assert ossscan.default_fetcher("http://insecure.example/x") is None and ossscan.default_fetcher("file:///etc/passwd") is None

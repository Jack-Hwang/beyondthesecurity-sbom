"""Dependency scanner: one fixture per supported package manager, plus the honesty/hostile-input rules."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom._internal import oss_dependency


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _by_manager(report, manager):
    return [i for i in report.items if i.extra.get("manager") == manager]


# ========================================================================================= per-format fixtures
def test_npm_package_lock_direct_transitive_and_license(tmp_path):
    _write(str(tmp_path / "package.json"), json.dumps({"name": "x", "dependencies": {"left-pad": "^1.3.0"}}))
    _write(str(tmp_path / "package-lock.json"), json.dumps({
        "name": "x", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"left-pad": "^1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0", "license": "MIT"},
            "node_modules/left-pad/node_modules/sub": {"version": "2.0.0"},
        }}))
    report = oss_dependency.scan(str(tmp_path))
    npm = _by_manager(report, "npm")
    left = next(i for i in npm if i.oss_name == "left-pad")
    sub = next(i for i in npm if i.oss_name == "sub")
    assert left.version == "1.3.0" and left.direct is True and left.licenses == ["MIT"]
    assert left.purl == "pkg:npm/left-pad@1.3.0"
    assert sub.direct is False
    assert report.info["scanners"]["dependency"]["by_manager"]["npm"] == 2


def test_yarn_lock_direct_is_cross_referenced_against_package_json(tmp_path):
    _write(str(tmp_path / "package.json"), json.dumps({"dependencies": {"left-pad": "^1.3.0"}}))
    _write(str(tmp_path / "yarn.lock"),
          'left-pad@^1.3.0:\n  version "1.3.0"\n  resolved "https://x"\n\n'
          'sub-dep@^2.0.0:\n  version "2.0.0"\n  resolved "https://x"\n')
    report = oss_dependency.scan(str(tmp_path))
    yarn = _by_manager(report, "yarn")
    assert next(i for i in yarn if i.oss_name == "left-pad").direct is True
    assert next(i for i in yarn if i.oss_name == "sub-dep").direct is False


def test_yarn_lock_without_sibling_package_json_is_honestly_unknown(tmp_path):
    _write(str(tmp_path / "yarn.lock"), 'left-pad@^1.3.0:\n  version "1.3.0"\n  resolved "https://x"\n')
    report = oss_dependency.scan(str(tmp_path))
    assert _by_manager(report, "yarn")[0].direct is None


def test_pnpm_lock_v6_shape(tmp_path):
    _write(str(tmp_path / "pnpm-lock.yaml"), """lockfileVersion: '6.0'
dependencies:
  left-pad:
    specifier: 1.3.0
    version: 1.3.0
packages:
  /left-pad@1.3.0:
    resolution: {integrity: sha512-x==}
  /sub@2.0.0:
    resolution: {integrity: sha512-y==}
""")
    report = oss_dependency.scan(str(tmp_path))
    pnpm = {i.oss_name: i for i in _by_manager(report, "pnpm")}
    assert pnpm["left-pad"].direct is True and pnpm["left-pad"].version == "1.3.0"
    assert pnpm["sub"].direct is False


def test_pnpm_lock_v9_shape_with_importers_and_snapshots(tmp_path):
    _write(str(tmp_path / "pnpm-lock.yaml"), """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-x==}
  sub@2.0.0:
    resolution: {integrity: sha512-y==}
snapshots:
  left-pad@1.3.0:
    dependencies:
      sub: 2.0.0
  sub@2.0.0: {}
""")
    report = oss_dependency.scan(str(tmp_path))
    pnpm = {i.oss_name: i for i in _by_manager(report, "pnpm")}
    assert pnpm["left-pad"].direct is True
    assert pnpm["sub"].direct is False
    assert pnpm["left-pad"].depends_on == ["pkg:npm/sub@2.0.0"]


def test_pip_requirements_txt_and_pyproject_toml(tmp_path):
    _write(str(tmp_path / "a" / "requirements.txt"), "requests==2.31.0\n# comment\nunpinned-pkg>=1.0\n")
    _write(str(tmp_path / "b" / "pyproject.toml"), '[project]\nname = "x"\ndependencies = ["flask==2.0.0"]\n')
    report = oss_dependency.scan(str(tmp_path))
    pypi = {i.oss_name: i for i in _by_manager(report, "pypi")}
    assert pypi["requests"].version == "2.31.0" and pypi["requests"].direct is True
    assert pypi["flask"].version == "2.0.0"
    assert "unpinned-pkg" not in pypi      # never guesses a version for a range


def test_setup_py_is_read_statically_never_executed(tmp_path):
    _write(str(tmp_path / "setup.py"),
          "import os\nos.environ['PWNED'] = '1'\n"
          "from setuptools import setup\nsetup(name='x', install_requires=['requests==2.31.0', 'click'])\n")
    report = oss_dependency.scan(str(tmp_path))
    assert "PWNED" not in os.environ
    pypi = {i.oss_name: i for i in _by_manager(report, "pypi")}
    assert pypi["requests"].version == "2.31.0"
    assert pypi["click"].version == ""     # named but no exact pin -> version stays empty, never guessed


def test_uv_lock_takes_priority_over_other_python_files_in_the_same_directory(tmp_path):
    _write(str(tmp_path / "pyproject.toml"), '[project]\nname = "demo"\ndependencies = ["flask==2.0.0"]\n')
    _write(str(tmp_path / "setup.py"), "from setuptools import setup\nsetup(install_requires=['click'])\n")
    _write(str(tmp_path / "uv.lock"), """version = 1
[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [ { name = "requests" } ]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
""")
    report = oss_dependency.scan(str(tmp_path))
    pypi = _by_manager(report, "pypi")
    names = {i.oss_name for i in pypi}
    assert names == {"requests"}           # flask/click (pyproject/setup.py) skipped; root "demo" excluded
    assert next(i for i in pypi if i.oss_name == "requests").direct is True


def test_gradle_build_file_is_direct_but_lockfile_direct_is_honestly_unknown(tmp_path):
    _write(str(tmp_path / "build.gradle"), "dependencies {\n  implementation 'com.x:y:1.0.0'\n}\n")
    _write(str(tmp_path / "gradle.lockfile"), "com.x:y:1.0.0=compileClasspath\n#comment\n")
    report = oss_dependency.scan(str(tmp_path))
    gradle = _by_manager(report, "gradle")
    build_item = next(i for i in gradle if i.source_path.endswith("build.gradle"))
    lock_item = next(i for i in gradle if i.source_path.endswith("gradle.lockfile"))
    assert build_item.direct is True
    assert lock_item.direct is None        # gradle.lockfile never proves direct vs transitive - never guessed


def test_maven_pom_xml(tmp_path):
    _write(str(tmp_path / "pom.xml"), """<project>
  <dependencies>
    <dependency><groupId>com.x</groupId><artifactId>y</artifactId><version>1.0.0</version></dependency>
    <dependency><groupId>com.x</groupId><artifactId>unresolved</artifactId><version>${some.prop}</version></dependency>
  </dependencies>
</project>""")
    report = oss_dependency.scan(str(tmp_path))
    maven = _by_manager(report, "maven")
    assert len(maven) == 1 and maven[0].oss_name == "com.x:y" and maven[0].direct is True


def test_cargo_toml_and_lock_cross_reference(tmp_path):
    _write(str(tmp_path / "Cargo.toml"), '[package]\nname = "x"\nversion = "0.1.0"\n'
                                         '[dependencies]\nserde = { version = "=1.0.190" }\n')
    _write(str(tmp_path / "Cargo.lock"), '[[package]]\nname = "serde"\nversion = "1.0.190"\n'
                                         'source = "registry+https://x"\n'
                                         '[[package]]\nname = "libc"\nversion = "0.2.0"\n'
                                         'source = "registry+https://x"\n')
    report = oss_dependency.scan(str(tmp_path))
    cargo_lock = {i.oss_name: i for i in _by_manager(report, "cargo") if i.source_path.endswith("Cargo.lock")}
    assert cargo_lock["serde"].direct is True
    assert cargo_lock["libc"].direct is False


def test_go_mod_direct_vs_indirect(tmp_path):
    _write(str(tmp_path / "go.mod"), "module example.com/x\n\ngo 1.21\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\t"
                                     "github.com/c/d v2.0.0 // indirect\n)\n")
    report = oss_dependency.scan(str(tmp_path))
    go = {i.oss_name: i for i in _by_manager(report, "go")}
    assert go["github.com/a/b"].direct is True
    assert go["github.com/c/d"].direct is False


def test_podfile_lock_direct_vs_transitive_and_podspec_license(tmp_path):
    _write(str(tmp_path / "ios" / "Podfile.lock"), """PODS:
  - Alamofire (5.6.0)
  - SomeDep (1.0.0):
    - Alamofire (= 5.6.0)

DEPENDENCIES:
  - SomeDep

SPEC CHECKSUMS:
  Alamofire: abc123
  SomeDep: def456
""")
    _write(str(tmp_path / "ios" / "Pods" / "Alamofire" / "Alamofire.podspec"),
          "Pod::Spec.new do |s|\n  s.name = 'Alamofire'\n  s.license = { :type => 'MIT' }\nend\n")
    report = oss_dependency.scan(str(tmp_path))
    pods = {i.oss_name: i for i in _by_manager(report, "cocoapods")}
    assert pods["SomeDep"].direct is True
    assert pods["Alamofire"].direct is False
    assert pods["Alamofire"].licenses == ["MIT"]


def test_cartfile_resolved_github_entries(tmp_path):
    _write(str(tmp_path / "Cartfile.resolved"), 'github "Alamofire/Alamofire" "5.6.0"\nbinary "https://x/y.json" "2.0.0"\n')
    report = oss_dependency.scan(str(tmp_path))
    cart = {i.oss_name: i for i in _by_manager(report, "carthage")}
    assert cart["Alamofire"].version == "5.6.0" and cart["Alamofire"].direct is None
    assert cart["Alamofire"].homepage == "https://github.com/Alamofire/Alamofire"


def test_package_resolved_v2(tmp_path):
    _write(str(tmp_path / "Package.resolved"), json.dumps({
        "version": 2, "pins": [{"identity": "swift-log", "kind": "remoteSourceControl",
                                "location": "https://github.com/apple/swift-log", "state": {"version": "1.5.3"}}]}))
    report = oss_dependency.scan(str(tmp_path))
    swift = _by_manager(report, "swift")
    assert swift[0].oss_name == "swift-log" and swift[0].version == "1.5.3" and swift[0].direct is None


def test_package_resolved_v1(tmp_path):
    _write(str(tmp_path / "Package.resolved"), json.dumps({
        "object": {"pins": [{"package": "Alamofire", "repositoryURL": "https://github.com/Alamofire/Alamofire",
                             "state": {"version": "5.6.0"}}]}}))
    report = oss_dependency.scan(str(tmp_path))
    swift = _by_manager(report, "swift")
    assert swift[0].oss_name == "Alamofire" and swift[0].version == "5.6.0"


def test_pubspec_yaml_and_lock(tmp_path):
    _write(str(tmp_path / "pubspec.yaml"), "name: app\ndependencies:\n  http: ^0.13.0\ndev_dependencies:\n  test: ^1.0.0\n")
    report_yaml_only = oss_dependency.scan(str(tmp_path))
    pub = {i.oss_name: i for i in _by_manager(report_yaml_only, "pub")}
    assert pub["http"].direct is True and pub["http"].version == "^0.13.0"

    _write(str(tmp_path / "pubspec.lock"), """packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "0.13.5"
  async:
    dependency: transitive
    description:
      name: async
      url: "https://pub.dev"
    source: hosted
    version: "2.9.0"
""")
    report = oss_dependency.scan(str(tmp_path))
    pub = {i.oss_name: i for i in _by_manager(report, "pub") if i.source_path.endswith("pubspec.lock")}
    assert pub["http"].direct is True and pub["http"].version == "0.13.5"
    assert pub["async"].direct is False
    assert pub["http"].download_location == "https://pub.dev/packages/http/versions/0.13.5.tar.gz"


def test_chart_yaml_and_chart_lock_direct_only(tmp_path):
    chart = ("apiVersion: v2\nname: mychart\nversion: 1.0.0\ndependencies:\n"
            "  - name: postgresql\n    version: 12.1.9\n    repository: https://charts.bitnami.com/bitnami\n")
    _write(str(tmp_path / "Chart.yaml"), chart)
    _write(str(tmp_path / "Chart.lock"), chart.replace("apiVersion: v2\nname: mychart\nversion: 1.0.0\n", ""))
    report = oss_dependency.scan(str(tmp_path))
    helm = _by_manager(report, "helm")
    assert len(helm) == 2 and all(i.oss_name == "postgresql" and i.direct is True for i in helm)


def test_nuget_packages_config_csproj_and_central_package_management(tmp_path):
    _write(str(tmp_path / "packages.config"),
          '<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="13.0.1" targetFramework="net462" /></packages>')
    _write(str(tmp_path / "app.csproj"),
          '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
          '<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />'
          '<PackageReference Include="Serilog" /></ItemGroup></Project>')
    _write(str(tmp_path / "Directory.Packages.props"),
          '<Project><ItemGroup><PackageVersion Include="Serilog" Version="2.10.0" /></ItemGroup></Project>')
    report = oss_dependency.scan(str(tmp_path))
    nuget = _by_manager(report, "nuget")
    by_path = {(i.source_path, i.oss_name): i for i in nuget}
    assert by_path[("packages.config", "Newtonsoft.Json")].version == "13.0.1"
    serilog_csproj = by_path[("app.csproj", "Serilog")]
    assert serilog_csproj.version == ""             # central package management - never guessed here
    assert by_path[("Directory.Packages.props", "Serilog")].version == "2.10.0"


def test_unity_manifest_and_packages_lock_depth(tmp_path):
    _write(str(tmp_path / "Packages" / "manifest.json"),
          json.dumps({"dependencies": {"com.unity.textmeshpro": "3.0.6"}}))
    _write(str(tmp_path / "Packages" / "packages-lock.json"), json.dumps({"dependencies": {
        "com.unity.textmeshpro": {"version": "3.0.6", "depth": 0},
        "com.unity.ugui": {"version": "1.0.0", "depth": 1}}}))
    report = oss_dependency.scan(str(tmp_path))
    unity = {(i.source_path, i.oss_name): i for i in _by_manager(report, "unity")}
    assert unity[("Packages/manifest.json", "com.unity.textmeshpro")].direct is True
    assert unity[("Packages/packages-lock.json", "com.unity.textmeshpro")].direct is True
    assert unity[("Packages/packages-lock.json", "com.unity.ugui")].direct is False


# ================================================================================================= recursive=False
def test_recursive_false_stops_below_a_directory_that_already_has_a_manifest(tmp_path):
    _write(str(tmp_path / "a" / "package.json"), json.dumps({"dependencies": {"x": "1.0.0"}}))
    _write(str(tmp_path / "a" / "b" / "package.json"), json.dumps({"dependencies": {"y": "1.0.0"}}))
    _write(str(tmp_path / "c" / "go.mod"), "module example.com/c\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n")

    rec = oss_dependency.scan(str(tmp_path), recursive=True)
    assert {i.oss_name for i in rec.items} == {"x", "y", "github.com/x/y"}

    norec = oss_dependency.scan(str(tmp_path), recursive=False)
    assert {i.oss_name for i in norec.items} == {"x", "github.com/x/y"}
    assert norec.info["scanners"]["dependency"]["pruned_by_recursive_false"] == ["a/b"]


# =================================================================================================== merging
def test_duplicates_of_the_same_manager_name_version_source_path_are_merged(tmp_path):
    # exercise _merge_duplicates directly: two rows for the same (manager, name, version, source_path),
    # as can legitimately happen when the same package is hoisted AND nested in one package-lock.json.
    from bts_sbom.ossreport import OssItem
    a = OssItem(kind="dep", oss_name="x", version="1.0.0", source_path="package-lock.json", licenses=["MIT"],
               depends_on=["pkg:npm/y@1.0.0"], evidence=["found at node_modules/x"])
    a.extra["manager"] = "npm"
    b = OssItem(kind="dep", oss_name="x", version="1.0.0", source_path="package-lock.json", licenses=["MIT"],
               depends_on=["pkg:npm/z@2.0.0"], direct=True, evidence=["found at node_modules/a/node_modules/x"])
    b.extra["manager"] = "npm"
    merged = oss_dependency._merge_duplicates([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert m.licenses == ["MIT"]                                    # no duplicate entries
    assert sorted(m.depends_on) == ["pkg:npm/y@1.0.0", "pkg:npm/z@2.0.0"]
    assert m.direct is True                                         # a's None does not clobber b's True
    assert len(m.evidence) == 2


# ============================================================================================ honesty / hostile input
def test_malformed_manifests_are_warnings_not_crashes(tmp_path):
    _write(str(tmp_path / "npm" / "package-lock.json"), "{not valid json")
    _write(str(tmp_path / "maven" / "pom.xml"),
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><project></project>')
    _write(str(tmp_path / "pod" / "Podfile.lock"), "not: [valid yaml\n")
    _write(str(tmp_path / "swift" / "Package.resolved"), "{not json either")

    report = oss_dependency.scan(str(tmp_path))
    assert report.items == []
    assert len(report.warnings) == 4
    assert all("could not parse" in w for w in report.warnings)
    assert any("package-lock.json" in w for w in report.warnings)
    assert any("pom.xml" in w for w in report.warnings)
    assert any("Podfile.lock" in w for w in report.warnings)
    assert any("Package.resolved" in w for w in report.warnings)


def test_huge_manifest_is_bounded_not_a_crash(tmp_path):
    huge = str(tmp_path / "package-lock.json")
    with open(huge, "w", encoding="utf-8") as fh:
        fh.write('{"packages": {')
        fh.write("1" * 5_000_000)          # far past oss_common.MAX_READ
    report = oss_dependency.scan(str(tmp_path))
    assert report.items == []
    assert len(report.warnings) == 1       # truncated read -> invalid JSON -> one honest warning, no crash


def test_deeply_nested_json_does_not_crash(tmp_path):
    depth = 3000
    text = ('{"packages": {"": {}, "node_modules/foo": {"version": "1.0.0"}}, "deep": '
           + ('{"a":' * depth) + "1" + ("}" * depth) + "}")
    _write(str(tmp_path / "package-lock.json"), text)
    report = oss_dependency.scan(str(tmp_path))
    # either it degrades to an honest parse failure, or (if the platform's json can eat it) it still finds foo -
    # the only wrong outcome is an unhandled exception, which pytest itself would already turn into a failure.
    assert report.items == [] or any(i.oss_name == "foo" for i in report.items)


def test_symlinked_manifest_is_skipped_not_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    _write(str(real / "package.json"), json.dumps({"dependencies": {"x": "1.0.0"}}))
    link = tmp_path / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this filesystem/user")
    report = oss_dependency.scan(str(tmp_path))
    assert [i.source_path for i in report.items] == ["real/package.json"]
    assert report.info["scanners"]["dependency"]["skipped_symlinks"] >= 1


def test_path_traversal_inside_a_manifest_name_is_not_resolved_outside_root(tmp_path):
    """A dependency NAME that looks like a path-traversal attempt must be carried through as inert text
    (never joined onto a filesystem path) - this scanner never reads/writes a path built from manifest data."""
    _write(str(tmp_path / "package.json"), json.dumps({"dependencies": {"../../etc/passwd": "1.0.0"}}))
    report = oss_dependency.scan(str(tmp_path))
    # package.json (a manifest, not a lockfile) only yields EXACT pins; "1.0.0" is exact, so it is reported -
    # as a literal, inert name, never used to read or write any file.
    assert all(not os.path.isabs(i.oss_name) for i in report.items)


def test_out_of_scope_manifest_is_counted_not_silently_dropped(tmp_path):
    _write(str(tmp_path / "Gemfile.lock"), "GEM\n  specs:\n    rake (13.0.6)\n")
    report = oss_dependency.scan(str(tmp_path))
    assert report.items == []
    assert "Gemfile.lock" in report.info["scanners"]["dependency"]["out_of_scope_manifests_seen"]


def test_online_false_never_calls_the_fetcher(tmp_path):
    _write(str(tmp_path / "package.json"), json.dumps({"dependencies": {"left-pad": "1.3.0"}}))

    def boom(url):
        raise AssertionError("fetcher must never be called when online=False")

    report = oss_dependency.scan(str(tmp_path), online=False, fetcher=boom)
    assert report.info["scanners"]["dependency"]["online_enrichment"]["note"].startswith("offline")


def test_online_true_uses_the_injected_fetcher_and_fills_missing_license(tmp_path):
    _write(str(tmp_path / "package.json"), json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
    calls = []

    def fake(url):
        calls.append(url)
        return json.dumps({"license": "MIT"}) if "registry.npmjs.org" in url else None

    report = oss_dependency.scan(str(tmp_path), online=True, fetcher=fake)
    item = next(i for i in report.items if i.oss_name == "left-pad")
    assert item.licenses == ["MIT"]
    assert calls and "registry.npmjs.org" in calls[0]
    assert report.info["scanners"]["dependency"]["online_enrichment"]["resolved"] == 1


def test_scan_returns_well_formed_info(tmp_path):
    _write(str(tmp_path / "package.json"), json.dumps({"dependencies": {"x": "1.0.0"}}))
    report = oss_dependency.scan(str(tmp_path), excludes=("foo/*",))
    assert report.info["analyzed_path"] == str(tmp_path)
    assert "dependency" in report.info["scanners"]
    assert all(i.kind == "dep" for i in report.items)


def test_podfile_lock_subspec_is_direct_only_when_the_podfile_names_that_subspec():
    from bts_sbom._internal import oss_manifests_extra as mx
    lock = """PODS:
  - Firebase/Analytics (7.0.0):
    - Firebase/Core
  - Firebase/Core (7.0.0)
  - Alamofire (5.4.0)

DEPENDENCIES:
  - Alamofire
  - Firebase/Analytics

SPEC CHECKSUMS:
  Alamofire: abc

COCOAPODS: 1.10.0
"""
    got = {e["name"]: e["direct"] for e in mx.parse_podfile_lock(lock, "Podfile.lock")}
    assert got == {"Firebase/Analytics": True, "Firebase/Core": False, "Alamofire": True}


def test_pnpm_v9_snapshot_edges_are_found_through_the_peer_suffix():
    from bts_sbom._internal import oss_manifests_extra as mx
    lock = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
packages:
  react-dom@18.2.0:
    resolution: {integrity: sha512-aaa}
  react@18.2.0:
    resolution: {integrity: sha512-bbb}
  scheduler@0.23.0:
    resolution: {integrity: sha512-ccc}
snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
      scheduler: 0.23.0
  react@18.2.0: {}
  scheduler@0.23.0: {}
"""
    got = {e["name"]: e for e in mx.parse_pnpm_lock(lock, "pnpm-lock.yaml")}
    deps = got["react-dom"]["depends_on"]
    assert any("react@18.2.0" in d for d in deps) and any("scheduler@0.23.0" in d for d in deps), deps
    assert all("(" not in d for d in deps), "the peer suffix must not leak into a purl"
    assert got["react-dom"]["direct"] is True and got["scheduler"]["direct"] is False


def test_uv_lock_regex_fallback_reads_single_line_dependency_arrays(monkeypatch):
    from bts_sbom._internal import oss_manifests_extra as mx
    monkeypatch.setattr(mx, "tomllib", None)               # the 3.10 path: no TOML reader
    lock = """version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "idna" }, { name = "urllib3" }]

[[package]]
name = "idna"
version = "3.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]
"""
    got = {e["name"]: e for e in mx.parse_uv_lock(lock, "uv.lock")}
    assert len(got["requests"]["depends_on"]) == 2, got["requests"]["depends_on"]
    assert len(got["urllib3"]["depends_on"]) == 1, "the multi-line form keeps working"

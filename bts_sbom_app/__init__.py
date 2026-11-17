"""BTS-SBOM - SBOM, open-source license and vulnerability analysis, approved patching, legacy-architecture
analysis, EXAONE-assisted proposals and a grounded RAG chatbot, across regulated industries.

Pure standard library; the SBOM/OSV core is the ``bts_sbom`` package.
"""


def _read_version():
    """The distribution version lives in bts_sbom/_version.py (read as text: importing bts_sbom here would bypass the
    BTS_SBOM_PATH core pin that engine.py applies later). Falls back to the installed metadata."""
    import os
    import re
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with open(os.path.join(here, "bts_sbom", "_version.py"), "r", encoding="utf-8") as fh:
            m = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read())
        if m:
            return m.group(1)
    except OSError:
        pass
    try:
        from importlib.metadata import version
        return version("bts-sbom")
    except Exception:
        return "0+unknown"


__version__ = _read_version()

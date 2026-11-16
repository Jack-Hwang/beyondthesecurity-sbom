"""Launcher usable under ``python -I`` (isolated mode ignores cwd/PYTHONPATH, so the repo root is inserted explicitly).

    python -I -X utf8 run_bts_sbom_app.py scan https://github.com/OWASP/NodeGoat.git

Use this form whenever the tool reads code fetched from the internet.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bts_sbom_app.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

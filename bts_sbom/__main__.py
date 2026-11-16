"""`python -m bts_sbom` — bare invocation runs the self-SBOM demo (see cli.py)."""
import sys

from bts_sbom.cli import main

if __name__ == "__main__":
    sys.exit(main())

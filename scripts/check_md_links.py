# -*- coding: utf-8 -*-
"""Markdown relative-link checker (backlog C39): every [text](target) link in the repo's *.md files whose
target is a RELATIVE path must resolve to an existing file. http(s)://, mailto:, anchors (#...) and bare
angle-bracket targets are skipped. Exit 1 when a dead relative link exists - CI can gate on it.

Run: python scripts/check_md_links.py [roots...]   (default: repo root, docs skipped only by being included)
Honesty: the checker reports file+line of every dead link; it never guesses a rewrite.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.parse

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
SKIP_PREFIX = ("http://", "https://", "mailto:", "#", "<")


def check(root: str) -> list:
    """All dead relative links under ``root`` as (file, line, target) tuples."""
    dead = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__", "node_modules", "_attic", ".zcode")]
        for fn in fns:
            if not fn.endswith(".md"):
                continue
            path = os.path.join(dp, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except (OSError, UnicodeDecodeError):
                continue
            for i, line in enumerate(lines, 1):
                for m in LINK.finditer(line):
                    target = m.group(1).strip()
                    if not target or target.startswith(SKIP_PREFIX):
                        continue
                    t = urllib.parse.unquote(target.split("#")[0])
                    if not t:
                        continue                                   # pure-anchor link: nothing to resolve on disk
                    resolved = os.path.normpath(os.path.join(dp, t))
                    if not os.path.exists(resolved):
                        dead.append((os.path.relpath(path, root) if root != "." else path, i, target))
    return dead


def main(argv: list) -> int:
    roots = argv[1:] or ["."]
    dead = []
    for r in roots:
        dead += check(r)
    for f, ln, t in dead:
        print("DEAD %s:%d -> %s" % (f, ln, t))
    print("%d dead relative link(s)" % len(dead))
    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

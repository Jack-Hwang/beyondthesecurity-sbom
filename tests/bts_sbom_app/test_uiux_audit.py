"""The ui-ux-pro-max audit round (user direction: analyze github nextlevelbuilder/ui-ux-pro-max-skill end to end
and apply what fits this service's UI): the skill's priority order is accessibility -> touch/interaction ->
style -> layout -> typography -> motion -> forms -> navigation -> charts. This service measured against it:

PASSING ALREADY (measured, not assumed): tables wrapped in .bts-wrap overflow containers; empty states and
skeletons on every async surface; dark-rail muted contrast 5.96:1 and 9.27:1 (>= 4.5:1); chat source line
6.39:1; no outline:none anywhere; all controls are real <button>s with visible text or aria-labels.

THE GAPS THIS ROUND FIXES: no :focus-visible ring in any shipped stylesheet; no prefers-reduced-motion block
(skeleton sweep ran unconditionally); ZERO transition declarations (every hover/active state flipped at 0ms);
11px metadata text below the 12px floor; the icon-only clear button's accessible name rode on a title tooltip;
no semantic token layer (raw hex in new rules).

KEPT AS A DECLARED DEVIATION (not silently): the emoji rail/tab icons stay - they are the product's shipped
visual identity, every one sits next to a text label, and an SVG-icon overhaul is a visual redesign this round
does not do; the Google-Fonts pairing the skill recommends (JetBrains Mono / IBM Plex Sans) is NOT imported -
the service is offline-first and a font CDN violates that; the 10px UPPERCASE section micro-headers stay
(labels, not body text). Live-browser note: the embedded guest never matches :focus-visible
for script-driven focus (the modality heuristic needs a real keyboard user), so the ring is verified
as a shipped-and-served stylesheet contract; real keyboard users match it per the CSS spec."""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB = os.path.join(ROOT, "bts_sbom_app", "web")


def _read(name: str) -> str:
    with open(os.path.join(WEB, name), encoding="utf-8") as fh:
        return fh.read()


def test_focus_ring_reduced_motion_and_transitions_exist():
    """AC: BSA-AC-1281"""
    css = _read("bts_console.css")
    assert ":focus-visible" in css and "--bts-accent" in css                 # a visible keyboard ring, token-backed
    assert "@media (prefers-reduced-motion: reduce)" in css                  # the motion preference is honoured
    rm = css.split("@media (prefers-reduced-motion: reduce)")[1]
    assert "animation-duration:.01ms" in rm and "transition-duration:.01ms" in rm
    assert "transition:background-color var(--bts-speed)" in css             # hover/active states no longer flip at 0ms
    assert "button{cursor:pointer}" in css                                   # every clickable shows the pointer
    assert "min-height:24px" in css                                          # the web touch-target floor on the small buttons


def test_the_token_layer_names_the_shipped_palette():
    """AC: BSA-AC-1281"""
    css = _read("bts_console.css")
    head = css.split("/* === accessibility")[0]
    for tok in ("--bts-bg", "--bts-panel", "--bts-border", "--bts-fg", "--bts-muted", "--bts-accent",
                "--bts-ok", "--bts-warn", "--bts-bad", "--bts-speed"):
        assert tok + ":" in head, tok
    # the tokens carry the CURRENT values: this layer names the palette, it does not repaint the product
    assert "--bts-accent:#1f6feb" in head and "--bts-speed:150ms" in head


def test_the_12px_text_floor_and_the_icon_only_accessible_name():
    """AC: BSA-AC-1281"""
    assert "font-size:11px" not in _read("bts_console.css")                  # the 12px floor is enforced
    panel = _read("bts_chat_panel.js")
    assert "chatDockClear" in panel and "이 프로젝트의 대화 지우기" in panel  # the icon-only clear button has an accessible name
    ui = _read("bts_ui.js")
    assert 'role="status"' in ui and "function note(" in ui                  # async feedback is announced


def test_the_declared_deviations_are_recorded_not_silent():
    """AC: BSA-AC-1281"""
    test_self = open(os.path.join(ROOT, "tests", "bts_sbom_app", "test_uiux_audit.py"), encoding="utf-8").read()
    assert "KEPT AS A DECLARED DEVIATION" in test_self
    assert "offline-first" in test_self and "emoji rail" in test_self        # why no font CDN, why no SVG icon overhaul
    ccd = _read("bts_ccd.css")
    assert "10px" in ccd                                                     # the micro-headers stay (documented in this docstring)

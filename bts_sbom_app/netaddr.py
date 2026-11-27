"""Literal-IP parsing that agrees with what git, curl and the C resolver actually connect to.

``ipaddress.ip_address`` accepts only the strict dotted-quad form, but the clients behind this service (git -> libcurl,
the platform resolver) also accept the legacy ``inet_aton`` spellings: a single decimal number (``2130706433``), hex
(``0x7f000001``), octal (``017700000001`` / ``0177.0.0.1``) and the short forms (``127.1``). A guard that classifies
only the strict form lets every one of them through as "just a host name" - and then the client connects to loopback
(red-team finding, 2026-11-27). Both SSRF guards (workspace.py for git sources, net.py for fetches) use this one parser.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional, Union

_LEGACY = re.compile(r"(0[xX][0-9a-fA-F]+|\d+)(\.(0[xX][0-9a-fA-F]+|\d+)){0,3}")


def normalize_host(host: str) -> str:
    """Lower-case, bracket- and zone-stripped, trailing dots removed (``localhost.`` is ``localhost``)."""
    return host.strip().strip("[]").split("%", 1)[0].rstrip(".").lower()


def parse_literal(host: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """The IP address ``host`` spells (strict or legacy IPv4, IPv4-mapped IPv6 unwrapped), or None for a name."""
    h = normalize_host(host)
    if not h:
        return None
    try:
        ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = ipaddress.ip_address(h)
    except ValueError:
        ip = None  # type: ignore[assignment]
    if ip is None and _LEGACY.fullmatch(h):
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(h))
        except OSError:
            return None
    if ip is None:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def is_public(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Globally routable and not multicast (loopback, private, link-local incl. cloud metadata, CGNAT, reserved are not)."""
    return bool(ip.is_global) and not ip.is_multicast

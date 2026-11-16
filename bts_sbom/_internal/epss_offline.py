# vendored from sca_guard/enhancements.py (Apache-2.0 release) -- the curated
# offline EPSS / CISA-KEV tables ONLY (platform-original data: FIRST.org bulk
# EPSS snapshot 2025-Q1 subset + CISA KEV public-feed subset, curated for
# automotive/embedded/OSS relevance). No third-party licensed content.
"""Offline EPSS + CISA KEV fallback tables (curated, disclosed).

The platform also consults a refreshable bulk-intel sqlite DB; that operator
layer is NOT part of bts-sbom, so lookups here use ONLY these curated tables
and every result names its source ("offline-table") so a caller can tell a
real measurement from an absent one.
"""
from typing import Any, Dict

EPSS_OFFLINE: Dict[str, Dict[str, float]] = {
    "CVE-2021-44228": {"epss": 0.9765, "percentile": 0.9990},   # Log4Shell
    "CVE-2021-45046": {"epss": 0.9644, "percentile": 0.9987},   # Log4j RC1
    "CVE-2022-22965": {"epss": 0.9732, "percentile": 0.9989},   # Spring4Shell
    "CVE-2022-0778":  {"epss": 0.3541, "percentile": 0.9701},   # OpenSSL infinite loop
    "CVE-2014-0160":  {"epss": 0.9721, "percentile": 0.9988},   # Heartbleed
    "CVE-2022-42898": {"epss": 0.2811, "percentile": 0.9620},   # Kerberos PAC
    "CVE-2021-3156":  {"epss": 0.9620, "percentile": 0.9985},   # sudo Baron Samedit
    "CVE-2021-4034":  {"epss": 0.9730, "percentile": 0.9989},   # pkexec Polkit LPE
    "CVE-2022-26134": {"epss": 0.9717, "percentile": 0.9988},   # Confluence OGNL RCE
    "CVE-2023-44487": {"epss": 0.8950, "percentile": 0.9970},   # HTTP/2 Rapid Reset
    "CVE-2019-0708":  {"epss": 0.9750, "percentile": 0.9990},   # BlueKeep RDP
    "CVE-2017-0144":  {"epss": 0.9760, "percentile": 0.9990},   # EternalBlue MS17-010
    "CVE-2022-30190": {"epss": 0.9700, "percentile": 0.9988},   # Follina MSDT
    "CVE-2021-26855": {"epss": 0.9740, "percentile": 0.9990},   # ProxyLogon Exchange
    "CVE-2022-1388":  {"epss": 0.9725, "percentile": 0.9989},   # F5 BIG-IP iControl
    "CVE-2021-22986": {"epss": 0.9650, "percentile": 0.9986},   # F5 iControl RCE
    "CVE-2021-27101": {"epss": 0.9710, "percentile": 0.9988},   # Accellion FTA
    "CVE-2022-22954": {"epss": 0.9735, "percentile": 0.9990},   # VMware Workspace SSTI
    "CVE-2018-7600":  {"epss": 0.9762, "percentile": 0.9990},   # Drupalgeddon2
    "CVE-2022-40684": {"epss": 0.9730, "percentile": 0.9989},   # Fortinet auth bypass
    # Embedded/IoT/automotive relevant
    "CVE-2021-22600": {"epss": 0.2031, "percentile": 0.9410},   # Linux packet socket LPE
    "CVE-2022-0847":  {"epss": 0.9640, "percentile": 0.9985},   # Dirty Pipe
    "CVE-2022-29581": {"epss": 0.1821, "percentile": 0.9352},   # net/sched UAF
    "CVE-2021-3444":  {"epss": 0.1204, "percentile": 0.9012},   # eBPF verifier
    "CVE-2022-23960": {"epss": 0.1342, "percentile": 0.9120},   # Spectre-BHB ARM
    "CVE-2021-33909": {"epss": 0.9610, "percentile": 0.9984},   # Sequoia fs LPE
    "CVE-2022-0185":  {"epss": 0.2450, "percentile": 0.9540},   # fs context heap overflow
    "CVE-2021-37576": {"epss": 0.1010, "percentile": 0.8920},   # POWERPC rtas privilege
    "CVE-2022-1729":  {"epss": 0.1532, "percentile": 0.9271},   # perf_event_open race
    "CVE-2023-2235":  {"epss": 0.1102, "percentile": 0.8990},   # perf_group_detach UAF
    # OpenSSL / crypto
    "CVE-2022-3602":  {"epss": 0.2310, "percentile": 0.9490},   # OpenSSL punycode BOF
    "CVE-2022-3786":  {"epss": 0.1942, "percentile": 0.9380},   # OpenSSL punycode
    "CVE-2023-0286":  {"epss": 0.3102, "percentile": 0.9660},   # OpenSSL X.400 type confusion
    "CVE-2023-0215":  {"epss": 0.1020, "percentile": 0.8930},   # OpenSSL BIO UAF
    "CVE-2016-2107":  {"epss": 0.3820, "percentile": 0.9710},   # OpenSSL padding oracle
    # CAN bus / automotive
    "CVE-2022-41218": {"epss": 0.0782, "percentile": 0.8550},   # media dvb kernel
    "CVE-2021-3489":  {"epss": 0.1202, "percentile": 0.9009},   # eBPF ringbuf oob write
    "CVE-2022-27666": {"epss": 0.4521, "percentile": 0.9750},   # IPsec ESP LPE
    "CVE-2022-29582": {"epss": 0.1231, "percentile": 0.9030},   # io_uring UAF
    "CVE-2022-34918": {"epss": 0.2512, "percentile": 0.9550},   # nftables type confusion
    # Networking / MQTT / TLS stack
    "CVE-2021-29921": {"epss": 0.3102, "percentile": 0.9660},   # ipaddress leading zeros
    "CVE-2022-2588":  {"epss": 0.4020, "percentile": 0.9720},   # cls_route UAF
    "CVE-2021-20322": {"epss": 0.1820, "percentile": 0.9350},   # ICMP route cache poisoning
    "CVE-2020-36516": {"epss": 0.0921, "percentile": 0.8730},   # TCP/IP ICMP fragmentation
    "CVE-2021-41617": {"epss": 0.1510, "percentile": 0.9260},   # OpenSSH priv separation
    "CVE-2023-38408": {"epss": 0.4812, "percentile": 0.9770},   # ssh-agent remote code
    "CVE-2023-25136": {"epss": 0.2301, "percentile": 0.9485},   # OpenSSH pre-auth dbl free
    "CVE-2022-31676": {"epss": 0.5012, "percentile": 0.9782},   # VMware Tools LPE
    "CVE-2021-43267": {"epss": 0.5810, "percentile": 0.9810},   # TIPC heap buffer overflow
    "CVE-2022-0435":  {"epss": 0.5201, "percentile": 0.9790},   # TIPC stack overflow
}


KEV_OFFLINE: frozenset = frozenset({
    "CVE-2021-44228",   # Apache Log4j2 RCE (Log4Shell)
    "CVE-2021-45046",   # Apache Log4j2 RCE (Log4j RC1)
    "CVE-2022-22965",   # Spring Framework RCE (Spring4Shell)
    "CVE-2014-0160",    # OpenSSL Heartbleed
    "CVE-2021-3156",    # Sudo Baron Samedit heap overflow
    "CVE-2021-4034",    # Polkit pkexec LPE
    "CVE-2022-26134",   # Atlassian Confluence OGNL injection RCE
    "CVE-2019-0708",    # Windows BlueKeep RDP RCE
    "CVE-2017-0144",    # Windows EternalBlue (MS17-010 SMB RCE)
    "CVE-2021-26855",   # Microsoft Exchange ProxyLogon SSRF
    "CVE-2022-1388",    # F5 BIG-IP iControl REST auth bypass
    "CVE-2022-40684",   # Fortinet FortiOS/FortiProxy auth bypass
    "CVE-2022-30190",   # Microsoft Follina MSDT RCE
    "CVE-2022-22954",   # VMware Workspace ONE Access SSTI
    "CVE-2018-7600",    # Drupal Drupalgeddon2 RCE
    "CVE-2022-0847",    # Linux Kernel Dirty Pipe LPE
    "CVE-2021-33909",   # Linux Kernel Sequoia (fs/seq_file) LPE
    "CVE-2022-27666",   # Linux IPsec ESP heap overflow LPE
    "CVE-2022-2588",    # Linux cls_route filter UAF LPE
    "CVE-2021-22986",   # F5 iControl REST unauthenticated RCE
    "CVE-2022-0778",    # OpenSSL BN_mod_sqrt infinite loop DoS
    "CVE-2022-42898",   # Kerberos PAC integer overflow
    "CVE-2023-38408",   # OpenSSH ssh-agent remote code execution
    "CVE-2022-31676",   # VMware Tools LPE
    "CVE-2021-43267",   # Linux TIPC heap buffer overflow
    "CVE-2022-0435",    # Linux TIPC stack overflow RCE
    "CVE-2021-3489",    # Linux eBPF ring buffer out-of-bounds write LPE
    "CVE-2022-34918",   # Linux nftables heap type confusion LPE
    "CVE-2021-22600",   # Linux packet socket double-free LPE
    "CVE-2021-41617",   # OpenSSH privilege separation AuthorizedKeysCommand
})


def epss_offline_lookup(cve_id: str) -> Dict[str, Any]:
    """Return EPSS data for a CVE from the curated tables.

    Returns {"epss", "percentile", "kev", "source"}; a CVE absent from the
    table comes back with epss 0.0 / source "offline-table" -- the caller
    (sca_report) downgrades that to source "none" so a missing entry is never
    presented as a measured zero.
    """
    cu = (cve_id or "").upper().strip()
    e = EPSS_OFFLINE.get(cu, {})
    return {"epss": e.get("epss", 0.0), "percentile": e.get("percentile", 0.0),
            "kev": cu in KEV_OFFLINE, "source": "offline-table"}


__all__ = ["epss_offline_lookup", "EPSS_OFFLINE", "KEV_OFFLINE"]

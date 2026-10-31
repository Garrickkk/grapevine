"""Host discovery: finding which addresses have a live device behind them.

Port-scanning every address in a /24 network means probing 254 addresses,
most of them usually empty. Discovery finds the live hosts cheaply first,
so only those get a full port scan.

grapevine uses two techniques, neither of which needs admin rights:

1. TCP ping. Try to connect to a few common ports. ANY answer proves the
   host is up: a completed handshake (port open) or a refusal (an RST
   packet, port closed). Only silence is inconclusive.

2. ARP cache. Before your computer can send anything to an address on
   your local network, it has to ask "who has 192.168.1.23?" (ARP). A
   device that answers gets recorded, with its MAC address, in the
   operating system's ARP cache, even if it then ignores every TCP probe,
   as phones and firewalled PCs often do. Reading the cache after the TCP
   ping reveals those hosts too.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import threading
from dataclasses import dataclass

from scanner import FILTERED, OPEN, run_parallel, scan_port

# Ports used for the TCP ping, most likely to answer first: web servers
# (routers, printers, cameras), SSH (Linux), SMB and RDP (Windows).
DISCOVERY_PORTS = (80, 443, 22, 445, 3389)

IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAC = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")


@dataclass
class HostStatus:
    up: bool = False
    reason: str = ""  # how we know it's up, e.g. "tcp/443 open" or "arp reply"
    mac: str = ""     # only known for hosts on the local network


def discover(ips: list[str], timeout: float, workers: int,
             probe=scan_port) -> dict[str, HostStatus]:
    """Find out which of the given IPs are up."""
    status = {ip: HostStatus() for ip in ips}
    lock = threading.Lock()

    # Order the probes port by port (every host's port 80, then every host's
    # port 443, ...) so a host that answers early has its later probes skipped.
    tasks = [(ip, port) for port in DISCOVERY_PORTS for ip in ips]

    def ping(task: tuple[str, int]) -> None:
        ip, port = task
        if status[ip].up:
            return
        state = probe(ip, port, timeout)
        if state == FILTERED:
            return
        with lock:
            if not status[ip].up:
                status[ip].up = True
                status[ip].reason = f"tcp/{port} {'open' if state == OPEN else 'refused'}"

    run_parallel(ping, tasks, workers)

    # The probes above made the OS send ARP requests to every local address,
    # so the ARP cache now lists the local devices that exist.
    arp = read_arp_cache()
    for ip, host in status.items():
        mac = arp.get(ip)
        if mac:
            host.mac = mac
            if not host.up:
                host.up = True
                host.reason = "arp reply"
    return status


def looks_intercepted(status: dict[str, HostStatus]) -> str | None:
    """Spot results that are probably fake: every host "up" for the same reason.

    Some networks have a transparent proxy or firewall that completes TCP
    handshakes for ANY address on certain ports (often 80/443). Then every
    address in a range looks up. On a real network it's very unlikely that
    every single address is in use and answers on the same port, so this
    returns that shared reason (e.g. "tcp/80 open") as a warning sign.
    """
    hosts = list(status.values())
    if len(hosts) < 4 or not all(host.up for host in hosts):
        return None
    reasons = {host.reason for host in hosts}
    if len(reasons) == 1:
        reason = reasons.pop()
        if reason.endswith(" open"):
            return reason
    return None


def reverse_dns(ips: list[str], workers: int) -> dict[str, str]:
    """Look up the hostname of each IP (e.g. 192.168.1.1 -> router.home)."""
    def lookup(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return ""
    names = run_parallel(lookup, ips, workers)
    return {ip: name for ip, name in zip(ips, names) if name}


# --------------------------------------------------------------------------
# ARP cache
# --------------------------------------------------------------------------

def read_arp_cache() -> dict[str, str]:
    """Return {ip: mac} for devices in the operating system's ARP cache."""
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/net/arp", encoding="ascii", errors="replace") as f:
                return parse_arp_table(f.read())
        command = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-an"]
        result = subprocess.run(command, capture_output=True, text=True,
                                errors="replace", timeout=10)
        return parse_arp_table(result.stdout)
    except (OSError, subprocess.SubprocessError):
        return {}  # no ARP cache available; TCP ping results still stand


def parse_arp_table(text: str) -> dict[str, str]:
    """Pull IP/MAC pairs out of an ARP table, in any of these formats:

    Linux  /proc/net/arp:  192.168.1.1  0x1  0x2  a4:2b:b0:12:34:56  *  wlan0
    Windows   arp -a:      192.168.1.1           a4-2b-b0-12-34-56     dynamic
    macOS     arp -an:     ? (192.168.1.1) at a4:2b:b0:12:34:56 on en0 ...

    Entries without a usable MAC are skipped: unanswered requests (shown as
    "(incomplete)" or an all-zero MAC), broadcast and multicast addresses.
    """
    entries: dict[str, str] = {}
    for line in text.splitlines():
        ip = IPV4.search(line)
        mac = MAC.search(line)
        if not ip or not mac:
            continue
        normal = normalize_mac(mac.group(1))
        if normal == "00:00:00:00:00:00" or is_multicast(normal):
            continue
        entries[ip.group(1)] = normal
    return entries


def normalize_mac(mac: str) -> str:
    """'A4-2B-B0-1-2-3' -> 'a4:2b:b0:01:02:03'."""
    return ":".join(f"{int(part, 16):02x}" for part in re.split(r"[:-]", mac))


def is_multicast(mac: str) -> bool:
    """Lowest bit of the first byte set = group address (incl. broadcast)."""
    return bool(int(mac[:2], 16) & 0x01)


def is_randomized(mac: str) -> bool:
    """Second-lowest bit of the first byte set = locally administered address.

    Real network cards have a manufacturer-assigned (global) MAC. Phones
    and laptops now often use a random one per Wi-Fi network for privacy,
    and virtual machines and containers get made-up ones. Both kinds always
    have this bit set, so the MAC can't be traced to a manufacturer.
    """
    return bool(int(mac[:2], 16) & 0x02)

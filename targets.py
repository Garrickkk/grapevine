"""Parsing what to scan: target hosts and port lists."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

# Safety limit: stops a typo like 10.0.0.0/8 from queuing 16 million hosts.
MAX_HOSTS = 4096  # a /20

# "192.168.1.10-50": a range in the last part of the address
SHORT_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
# "192.168.1.10-192.168.1.50": a range between two full addresses
FULL_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")


@dataclass(frozen=True)
class Target:
    ip: str
    name: str | None = None  # the hostname the user typed, if any


def parse_targets(specs: list[str]) -> list[Target]:
    """Expand target strings into a list of hosts to scan.

    Each spec can be an IP ("192.168.1.10"), a CIDR network
    ("192.168.1.0/24"), a range ("192.168.1.10-50" or
    "192.168.1.10-192.168.1.50"), a hostname ("scanme.nmap.org"),
    or a comma-separated mix of these. Duplicates are removed.
    """
    targets: dict[str, Target] = {}
    for spec in specs:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            for target in _expand(part):
                # Keep the first occurrence, but prefer a version with the
                # hostname the user typed (it's used for TLS and HTTP).
                if target.ip not in targets or (target.name and not targets[target.ip].name):
                    targets[target.ip] = target
            if len(targets) > MAX_HOSTS:
                raise ValueError(f"too many hosts ({len(targets)}); the limit is {MAX_HOSTS}")
    if not targets:
        raise ValueError("no targets given")
    return list(targets.values())


def _expand(part: str) -> list[Target]:
    if "/" in part:
        return _expand_network(part)

    full = FULL_RANGE.match(part)
    if full:
        start, end = _ipv4(full.group(1), part), _ipv4(full.group(2), part)
        return _expand_range(int(start), int(end), part)

    short = SHORT_RANGE.match(part)
    if short:
        prefix, first, last = short.groups()
        start, end = _ipv4(prefix + first, part), _ipv4(prefix + last, part)
        return _expand_range(int(start), int(end), part)

    try:
        address = ipaddress.ip_address(part)
    except ValueError:
        return [_resolve(part)]
    if address.version != 4:
        raise ValueError(f"'{part}' is IPv6, which grapevine doesn't support yet")
    return [Target(str(address))]


def _expand_network(part: str) -> list[Target]:
    try:
        network = ipaddress.ip_network(part, strict=False)
    except ValueError:
        raise ValueError(f"invalid network '{part}'") from None
    if network.version != 4:
        raise ValueError(f"'{part}' is IPv6, which grapevine doesn't support yet")
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"'{part}' has {network.num_addresses} addresses; the limit is {MAX_HOSTS} "
            "(a /20). Scan it in smaller pieces."
        )
    # Skip the network and broadcast addresses, which aren't real hosts.
    # /31 and /32 networks have no such addresses, so keep everything.
    addresses = network if network.prefixlen >= 31 else network.hosts()
    return [Target(str(ip)) for ip in addresses]


def _expand_range(start: int, end: int, part: str) -> list[Target]:
    if start > end:
        raise ValueError(f"invalid range '{part}' (start is bigger than end)")
    if end - start + 1 > MAX_HOSTS:
        raise ValueError(f"'{part}' has {end - start + 1} addresses; the limit is {MAX_HOSTS}")
    return [Target(str(ipaddress.IPv4Address(n))) for n in range(start, end + 1)]


def _ipv4(text: str, part: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        raise ValueError(f"invalid range '{part}'") from None


def _resolve(name: str) -> Target:
    try:
        return Target(socket.gethostbyname(name), name)
    except (socket.gaierror, UnicodeError):
        raise ValueError(f"could not resolve host '{name}'") from None


def parse_ports(spec: str) -> list[int]:
    """Parse "80", "1-1024", "22,80,443" or a mix like "22,80-90"."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                if start > end:
                    raise ValueError(f"invalid range '{part}' (start is bigger than end)")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError as exc:
            if "invalid range" in str(exc):
                raise
            raise ValueError(f"invalid port '{part}'") from None
    if not ports:
        raise ValueError("no ports given")
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is out of range (1-65535)")
    return sorted(ports)

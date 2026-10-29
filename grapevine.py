#!/usr/bin/env python3
"""grapevine v0.1: a simple TCP port scanner.

Scans one host and reports each port as open, closed or filtered.
Supports a sequential mode and a threaded (concurrent) mode so the
speed difference can be measured.

Only scan hosts you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import errno
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.0"

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> str:
    """Try a TCP connect to ip:port and return the port's state.

    connect_ex() returns an error code instead of raising an exception,
    which makes it easy to tell *why* a connection failed:

    - 0             -> handshake completed, something is listening  -> open
    - ECONNREFUSED  -> host answered with RST, nothing listening    -> closed
    - timeout       -> no answer at all, likely dropped by firewall -> filtered
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
        except socket.timeout:
            return FILTERED
        except OSError:
            return FILTERED

    if code == 0:
        return OPEN
    if code == errno.ECONNREFUSED or code == getattr(errno, "WSAECONNREFUSED", -1):
        return CLOSED
    # EAGAIN/EWOULDBLOCK/ETIMEDOUT etc. all mean we got no reply in time.
    return FILTERED


def scan_sequential(ip: str, ports: list[int], timeout: float) -> dict[int, str]:
    """Scan ports one after another."""
    return {port: scan_port(ip, port, timeout) for port in ports}


def scan_concurrent(ip: str, ports: list[int], timeout: float, workers: int) -> dict[int, str]:
    """Scan ports using a thread pool.

    Threads help even with Python's GIL because the program spends almost
    all its time *waiting* on the network, and the GIL is released while
    a thread waits on I/O.
    """
    with ThreadPoolExecutor(max_workers=workers) as pool:
        states = pool.map(lambda p: scan_port(ip, p, timeout), ports)
        return dict(zip(ports, states))


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


def resolve(target: str) -> str:
    """Turn a hostname or IP into an IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"could not resolve host '{target}'") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="grapevine: hear what every port has to say. TCP port scanner (v0.1).",
        epilog="Only scan hosts you own or have permission to test. "
               "scanme.nmap.org is allowed for practice.",
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help='ports to scan: "80", "1-1024", "22,80,443" (default: 1-1024)')
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="seconds to wait for each port (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="number of threads (default: 100)")
    parser.add_argument("--sequential", action="store_true",
                        help="scan one port at a time (for comparing speed)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="show closed and filtered ports too")
    parser.add_argument("--version", action="version", version=f"grapevine {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        ip = resolve(args.target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.timeout <= 0 or args.workers < 1:
        print("error: timeout must be > 0 and workers must be >= 1", file=sys.stderr)
        return 2

    mode = "sequential" if args.sequential else f"concurrent, {args.workers} threads"
    shown_target = args.target if args.target == ip else f"{args.target} ({ip})"
    print(f"Scanning {shown_target}: {len(ports)} port(s), {mode}\n")

    start = time.perf_counter()
    try:
        if args.sequential:
            results = scan_sequential(ip, ports, args.timeout)
        else:
            results = scan_concurrent(ip, ports, args.timeout, args.workers)
    except KeyboardInterrupt:
        print("\nScan cancelled.")
        return 130
    elapsed = time.perf_counter() - start

    counts = {OPEN: 0, CLOSED: 0, FILTERED: 0}
    for state in results.values():
        counts[state] += 1

    rows = [(p, s) for p, s in results.items() if args.all or s == OPEN]
    if rows:
        print(f"{'PORT':<10}STATE")
        for port, state in rows:
            print(f"{str(port) + '/tcp':<10}{state}")
    else:
        print("No open ports found.")

    print(f"\n{counts[OPEN]} open, {counts[CLOSED]} closed, "
          f"{counts[FILTERED]} filtered — finished in {elapsed:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

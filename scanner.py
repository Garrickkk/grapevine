"""Port scanning for grapevine: TCP connect probes, run many at a time."""

from __future__ import annotations

import errno
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

T = TypeVar("T")
R = TypeVar("R")


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
        except OSError:  # includes socket.timeout
            return FILTERED

    if code == 0:
        return OPEN
    if code == errno.ECONNREFUSED or code == getattr(errno, "WSAECONNREFUSED", -1):
        return CLOSED
    # EAGAIN/EWOULDBLOCK/ETIMEDOUT/EHOSTUNREACH etc. all mean no usable reply.
    return FILTERED


def run_parallel(func: Callable[[T], R], items: list[T], workers: int) -> list[R]:
    """Call func on every item using a pool of threads; results keep the input order.

    Threads help even with Python's GIL because the work is almost all
    *waiting* on the network, and the GIL is released while a thread waits.

    If interrupted (Ctrl+C), queued work is cancelled so the program stops
    after the probes already in flight, instead of finishing every probe.
    """
    if not items:
        return []
    pool = ThreadPoolExecutor(max_workers=min(workers, len(items)))
    try:
        results = list(pool.map(func, items))
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown()
    return results


def scan_ports(tasks: list[tuple[str, int]], timeout: float, workers: int,
               sequential: bool = False) -> dict[tuple[str, int], str]:
    """Scan a list of (ip, port) pairs and return the state of each."""
    if sequential:
        states = [scan_port(ip, port, timeout) for ip, port in tasks]
    else:
        states = run_parallel(lambda task: scan_port(task[0], task[1], timeout), tasks, workers)
    return dict(zip(tasks, states))

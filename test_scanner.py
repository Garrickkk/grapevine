"""Tests for port scanning. Run with:  python -m unittest -v"""

import socket
import threading
import time
import unittest
from unittest import mock

import scanner

# Windows retries refused connections for ~2 seconds before reporting them,
# so closed-port checks need a generous timeout to work on every OS.
CLOSED_TIMEOUT = 3.0


def free_port() -> int:
    """Find a port number with nothing listening on it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestScanPort(unittest.TestCase):
    def setUp(self):
        # A real listening socket on localhost acts as an "open" service.
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.open_port = self.server.getsockname()[1]

    def tearDown(self):
        self.server.close()

    def test_open(self):
        self.assertEqual(scanner.scan_port("127.0.0.1", self.open_port), scanner.OPEN)

    def test_closed(self):
        self.assertEqual(scanner.scan_port("127.0.0.1", free_port(), CLOSED_TIMEOUT), scanner.CLOSED)

    def test_filtered_on_timeout(self):
        # Simulate a firewall silently dropping packets.
        with mock.patch("socket.socket.connect_ex", side_effect=socket.timeout):
            self.assertEqual(scanner.scan_port("127.0.0.1", 9999), scanner.FILTERED)

    def test_sequential_and_concurrent_agree(self):
        tasks = [("127.0.0.1", p) for p in (self.open_port, free_port(), free_port())]
        seq = scanner.scan_ports(tasks, CLOSED_TIMEOUT, workers=10, sequential=True)
        con = scanner.scan_ports(tasks, CLOSED_TIMEOUT, workers=10)
        self.assertEqual(seq, con)
        self.assertEqual(con[("127.0.0.1", self.open_port)], scanner.OPEN)


class TestRunParallel(unittest.TestCase):
    def test_keeps_input_order(self):
        # Later items finish first, but results still come back in order.
        def slow_for_small(n):
            time.sleep((5 - n) * 0.01)
            return n * 10
        self.assertEqual(scanner.run_parallel(slow_for_small, [1, 2, 3, 4], 4), [10, 20, 30, 40])

    def test_empty(self):
        self.assertEqual(scanner.run_parallel(lambda x: x, [], 10), [])

    def test_error_cancels_queued_work(self):
        # Like Ctrl+C: once something goes wrong, the remaining work shouldn't run.
        calls = []
        lock = threading.Lock()

        def work(n):
            with lock:
                calls.append(n)
            time.sleep(0.01)
            if n == 0:
                raise RuntimeError("stop")
        with self.assertRaises(RuntimeError):
            scanner.run_parallel(work, list(range(50)), workers=1)
        time.sleep(0.1)
        self.assertLess(len(calls), 5)


if __name__ == "__main__":
    unittest.main()

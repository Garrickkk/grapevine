"""Tests for grapevine v0.1. Run with:  python -m unittest -v"""

import contextlib
import io
import socket
import unittest
from unittest import mock

import grapevine


def free_port() -> int:
    """Find a port number with nothing listening on it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(grapevine.parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(grapevine.parse_ports("20-23"), [20, 21, 22, 23])

    def test_list_and_mix(self):
        self.assertEqual(grapevine.parse_ports("443, 22,80-81"), [22, 80, 81, 443])

    def test_duplicates_removed(self):
        self.assertEqual(grapevine.parse_ports("80,80,79-80"), [79, 80])

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            grapevine.parse_ports("70000")

    def test_zero(self):
        with self.assertRaises(ValueError):
            grapevine.parse_ports("0")

    def test_reversed_range(self):
        with self.assertRaises(ValueError):
            grapevine.parse_ports("100-10")

    def test_not_a_number(self):
        with self.assertRaises(ValueError):
            grapevine.parse_ports("http")


# Windows retries refused connections for ~2 seconds before reporting them,
# so closed-port checks need a generous timeout to work on every OS.
CLOSED_TIMEOUT = 3.0


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
        self.assertEqual(grapevine.scan_port("127.0.0.1", self.open_port), grapevine.OPEN)

    def test_closed(self):
        self.assertEqual(grapevine.scan_port("127.0.0.1", free_port(), CLOSED_TIMEOUT), grapevine.CLOSED)

    def test_filtered_on_timeout(self):
        # Simulate a firewall silently dropping packets.
        with mock.patch("socket.socket.connect_ex", side_effect=socket.timeout):
            self.assertEqual(grapevine.scan_port("127.0.0.1", 9999), grapevine.FILTERED)

    def test_sequential_and_concurrent_agree(self):
        ports = [self.open_port, free_port(), free_port()]
        seq = grapevine.scan_sequential("127.0.0.1", ports, CLOSED_TIMEOUT)
        con = grapevine.scan_concurrent("127.0.0.1", ports, CLOSED_TIMEOUT, workers=10)
        self.assertEqual(seq, con)
        self.assertEqual(con[self.open_port], grapevine.OPEN)


class TestCLI(unittest.TestCase):
    def run_cli(self, args):
        """Run the CLI, capturing its error output so it doesn't clutter test results."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = grapevine.main(args)
        return code, err.getvalue()

    def test_bad_port_exit_code(self):
        code, err = self.run_cli(["127.0.0.1", "-p", "99999"])
        self.assertEqual(code, 2)
        self.assertIn("out of range", err)

    def test_bad_host_exit_code(self):
        code, err = self.run_cli(["no-such-host.invalid", "-p", "80"])
        self.assertEqual(code, 2)
        self.assertIn("could not resolve", err)


if __name__ == "__main__":
    unittest.main()

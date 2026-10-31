"""Tests for parsing targets and ports. Run with:  python -m unittest -v"""

import socket
import unittest
from unittest import mock

from targets import MAX_HOSTS, Target, parse_ports, parse_targets


def ips(specs):
    return [t.ip for t in parse_targets(specs)]


class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_list_and_mix(self):
        self.assertEqual(parse_ports("443, 22,80-81"), [22, 80, 81, 443])

    def test_duplicates_removed(self):
        self.assertEqual(parse_ports("80,80,79-80"), [79, 80])

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_zero(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-10")

    def test_not_a_number(self):
        with self.assertRaises(ValueError):
            parse_ports("http")


class TestParseTargets(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(parse_targets(["10.0.0.1"]), [Target("10.0.0.1")])

    def test_cidr_skips_network_and_broadcast(self):
        self.assertEqual(ips(["192.168.1.0/30"]), ["192.168.1.1", "192.168.1.2"])

    def test_slash_24_has_254_hosts(self):
        hosts = ips(["192.168.1.0/24"])
        self.assertEqual(len(hosts), 254)
        self.assertEqual((hosts[0], hosts[-1]), ("192.168.1.1", "192.168.1.254"))

    def test_cidr_with_host_bits_set(self):
        self.assertEqual(ips(["192.168.1.77/30"]), ["192.168.1.77", "192.168.1.78"])

    def test_slash_31_and_32_keep_every_address(self):
        self.assertEqual(ips(["10.0.0.0/31"]), ["10.0.0.0", "10.0.0.1"])
        self.assertEqual(ips(["10.0.0.5/32"]), ["10.0.0.5"])

    def test_short_range(self):
        self.assertEqual(ips(["10.0.0.8-10"]), ["10.0.0.8", "10.0.0.9", "10.0.0.10"])

    def test_full_range_across_octets(self):
        self.assertEqual(ips(["10.0.0.254-10.0.1.1"]),
                         ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"])

    def test_commas_and_multiple_arguments(self):
        self.assertEqual(ips(["10.0.0.1,10.0.0.3", "10.0.0.2"]),
                         ["10.0.0.1", "10.0.0.3", "10.0.0.2"])

    def test_duplicates_removed(self):
        self.assertEqual(ips(["10.0.0.1-2", "10.0.0.2"]), ["10.0.0.1", "10.0.0.2"])

    def test_typed_hostname_wins_over_duplicate_ip(self):
        with mock.patch("socket.gethostbyname", return_value="10.0.0.2"):
            targets = parse_targets(["10.0.0.1-2", "server.lab"])
        self.assertEqual(targets, [Target("10.0.0.1"), Target("10.0.0.2", "server.lab")])

    def test_hostname_is_resolved_and_remembered(self):
        with mock.patch("socket.gethostbyname", return_value="45.33.32.156"):
            self.assertEqual(parse_targets(["scanme.nmap.org"]),
                             [Target("45.33.32.156", "scanme.nmap.org")])

    def test_hyphenated_hostname_is_not_a_range(self):
        with mock.patch("socket.gethostbyname", return_value="10.0.0.9") as resolve:
            self.assertEqual(ips(["my-server.local"]), ["10.0.0.9"])
        resolve.assert_called_once_with("my-server.local")

    def test_unresolvable_host(self):
        with mock.patch("socket.gethostbyname", side_effect=socket.gaierror):
            with self.assertRaisesRegex(ValueError, "could not resolve"):
                parse_targets(["no-such-host.invalid"])

    def test_too_many_hosts(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            parse_targets(["10.0.0.0/8"])

    def test_limit_counts_across_arguments(self):
        with self.assertRaisesRegex(ValueError, "too many hosts"):
            parse_targets(["10.0.0.0/20", "10.1.0.0/20"])

    def test_biggest_allowed_network(self):
        self.assertEqual(len(parse_targets(["10.0.0.0/20"])), MAX_HOSTS - 2)

    def test_ipv6_rejected_clearly(self):
        for spec in ("::1", "2001:db8::/120"):
            with self.assertRaisesRegex(ValueError, "IPv6"):
                parse_targets([spec])

    def test_bad_ranges(self):
        for spec in ("10.0.0.50-10", "10.0.0.1-300", "10.0.0.9-10.0.0.1"):
            with self.assertRaises(ValueError, msg=spec):
                parse_targets([spec])

    def test_bad_network(self):
        with self.assertRaisesRegex(ValueError, "invalid network"):
            parse_targets(["10.0.0.0/33"])

    def test_empty(self):
        with self.assertRaises(ValueError):
            parse_targets([" , "])


if __name__ == "__main__":
    unittest.main()

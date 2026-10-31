"""Tests for host discovery. Run with:  python -m unittest -v"""

import socket
import unittest
from unittest import mock

import discovery
from scanner import CLOSED, FILTERED, OPEN

LINUX_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:2b:b0:12:34:56     *        wlan0
192.168.1.23     0x1         0x2         3a:8f:11:22:33:44     *        wlan0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
"""

WINDOWS_ARP = """\

Interface: 192.168.1.5 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-12-34-56     dynamic
  192.168.1.23          3a-8f-11-22-33-44     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

MACOS_ARP = """\
? (192.168.1.1) at a4:2b:b0:12:34:56 on en0 ifscope [ethernet]
? (192.168.1.23) at 3a:8f:11:22:33:44 on en0 ifscope [ethernet]
? (192.168.1.40) at 0:1c:b3:9:a:b on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""

EXPECTED = {"192.168.1.1": "a4:2b:b0:12:34:56", "192.168.1.23": "3a:8f:11:22:33:44"}


class TestArpParsing(unittest.TestCase):
    def test_linux_skips_incomplete_entries(self):
        self.assertEqual(discovery.parse_arp_table(LINUX_ARP), EXPECTED)

    def test_windows_skips_broadcast_and_multicast(self):
        self.assertEqual(discovery.parse_arp_table(WINDOWS_ARP), EXPECTED)

    def test_macos_pads_short_octets_and_skips_incomplete(self):
        expected = dict(EXPECTED, **{"192.168.1.40": "00:1c:b3:09:0a:0b"})
        self.assertEqual(discovery.parse_arp_table(MACOS_ARP), expected)

    def test_garbage(self):
        self.assertEqual(discovery.parse_arp_table("no arp entries here\n\n"), {})

    def test_normalize_mac(self):
        self.assertEqual(discovery.normalize_mac("A4-2B-B0-1-2-3"), "a4:2b:b0:01:02:03")

    def test_randomized_mac(self):
        self.assertTrue(discovery.is_randomized("3a:8f:11:22:33:44"))   # 0x3a has bit 0x02
        self.assertFalse(discovery.is_randomized("a4:2b:b0:12:34:56"))  # manufacturer MAC

    def test_read_arp_cache_survives_missing_command(self):
        with mock.patch("sys.platform", "darwin"), \
             mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertEqual(discovery.read_arp_cache(), {})

    def test_read_arp_cache_uses_arp_command_on_windows(self):
        result = mock.Mock(stdout=WINDOWS_ARP)
        with mock.patch("sys.platform", "win32"), \
             mock.patch("subprocess.run", return_value=result) as run:
            self.assertEqual(discovery.read_arp_cache(), EXPECTED)
        self.assertEqual(run.call_args.args[0], ["arp", "-a"])


def fake_network(answers):
    """A probe function: answers maps (ip, port) -> state; anything else is silent."""
    calls = []

    def probe(ip, port, timeout):
        calls.append((ip, port))
        return answers.get((ip, port), FILTERED)
    return probe, calls


class TestDiscover(unittest.TestCase):
    def setUp(self):
        # Keep the real ARP cache of the machine running the tests out of it.
        patcher = mock.patch.object(discovery, "read_arp_cache", return_value={})
        self.arp = patcher.start()
        self.addCleanup(patcher.stop)

    def test_open_refused_and_silent_hosts(self):
        probe, _ = fake_network({("10.0.0.1", 443): OPEN, ("10.0.0.2", 22): CLOSED})
        status = discovery.discover(["10.0.0.1", "10.0.0.2", "10.0.0.3"], 1.0, 10, probe)
        self.assertEqual((status["10.0.0.1"].up, status["10.0.0.1"].reason), (True, "tcp/443 open"))
        self.assertEqual((status["10.0.0.2"].up, status["10.0.0.2"].reason), (True, "tcp/22 refused"))
        self.assertFalse(status["10.0.0.3"].up)

    def test_silent_host_gets_every_probe(self):
        probe, calls = fake_network({})
        discovery.discover(["10.0.0.3"], 1.0, 1, probe)
        self.assertEqual(sorted(port for _, port in calls), sorted(discovery.DISCOVERY_PORTS))

    def test_host_found_early_skips_remaining_probes(self):
        # One worker so probes run in order: port 80 answers, the rest are skipped.
        probe, calls = fake_network({("10.0.0.1", 80): OPEN})
        discovery.discover(["10.0.0.1"], 1.0, 1, probe)
        self.assertEqual(calls, [("10.0.0.1", 80)])

    def test_arp_finds_hosts_that_ignore_tcp(self):
        self.arp.return_value = {"10.0.0.7": "3a:8f:11:22:33:44", "10.0.0.1": "a4:2b:b0:12:34:56"}
        probe, _ = fake_network({("10.0.0.1", 80): OPEN})
        status = discovery.discover(["10.0.0.1", "10.0.0.7", "10.0.0.8"], 1.0, 10, probe)
        self.assertEqual((status["10.0.0.7"].up, status["10.0.0.7"].reason), (True, "arp reply"))
        self.assertEqual(status["10.0.0.7"].mac, "3a:8f:11:22:33:44")
        # A host found by TCP keeps its TCP reason but gains its MAC.
        self.assertEqual(status["10.0.0.1"].reason, "tcp/80 open")
        self.assertEqual(status["10.0.0.1"].mac, "a4:2b:b0:12:34:56")
        self.assertFalse(status["10.0.0.8"].up)

    def test_arp_entries_outside_targets_are_ignored(self):
        self.arp.return_value = {"192.168.99.99": "a4:2b:b0:12:34:56"}
        probe, _ = fake_network({})
        status = discovery.discover(["10.0.0.1"], 1.0, 10, probe)
        self.assertEqual(list(status), ["10.0.0.1"])

    def test_real_probe_on_localhost(self):
        # Localhost always answers: open, or refused with an RST.
        status = discovery.discover(["127.0.0.1"], 3.0, 10)
        self.assertTrue(status["127.0.0.1"].up)
        self.assertRegex(status["127.0.0.1"].reason, r"^tcp/\d+ (open|refused)$")


class TestLooksIntercepted(unittest.TestCase):
    def status(self, *reasons):
        return {f"10.0.0.{i}": discovery.HostStatus(bool(r), r) for i, r in enumerate(reasons, 1)}

    def test_every_host_same_open_port(self):
        self.assertEqual(discovery.looks_intercepted(self.status(*["tcp/80 open"] * 6)), "tcp/80 open")

    def test_mixed_reasons_are_normal(self):
        self.assertIsNone(discovery.looks_intercepted(
            self.status("tcp/80 open", "tcp/22 open", "tcp/80 open", "tcp/80 refused")))

    def test_some_hosts_down_is_normal(self):
        self.assertIsNone(discovery.looks_intercepted(self.status(*["tcp/80 open"] * 5, "")))

    def test_too_few_hosts_to_judge(self):
        self.assertIsNone(discovery.looks_intercepted(self.status(*["tcp/80 open"] * 3)))

    def test_all_refused_is_not_flagged(self):
        # Refusals (RST) come from real hosts, e.g. a range of loopback addresses.
        self.assertIsNone(discovery.looks_intercepted(self.status(*["tcp/80 refused"] * 6)))


class TestReverseDns(unittest.TestCase):
    def test_names_found_and_missing(self):
        def fake_lookup(ip):
            if ip == "10.0.0.1":
                return ("router.home", [], [ip])
            raise socket.herror("not found")
        with mock.patch("socket.gethostbyaddr", side_effect=fake_lookup):
            self.assertEqual(discovery.reverse_dns(["10.0.0.1", "10.0.0.2"], 5),
                             {"10.0.0.1": "router.home"})


if __name__ == "__main__":
    unittest.main()

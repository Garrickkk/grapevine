"""Tests for grapevine's service detection. Run with:  python -m unittest -v"""

import socket
import threading
import unittest

import grapevine
import services


def mysql_packet(payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


class TestIdentify(unittest.TestCase):
    """Feed realistic banners to identify() and check what it concludes."""

    def test_ssh(self):
        info = services.identify(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", 22)
        self.assertEqual((info.name, info.product, info.version), ("ssh", "OpenSSH", "9.6p1"))
        self.assertIn("Ubuntu-3ubuntu13", info.extra)
        self.assertTrue(info.confirmed)

    def test_ssh_dropbear(self):
        info = services.identify(b"SSH-2.0-dropbear_2022.83\r\n", 22)
        self.assertEqual((info.product, info.version), ("dropbear", "2022.83"))

    def test_http_with_server_header(self):
        data = b"HTTP/1.1 200 OK\r\nDate: x\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n"
        info = services.identify(data, 80)
        self.assertEqual((info.name, info.product, info.version, info.extra),
                         ("http", "nginx", "1.24.0", "Ubuntu"))

    def test_http_without_server_header(self):
        info = services.identify(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 8080)
        self.assertEqual((info.name, info.product), ("http", ""))
        self.assertEqual(info.banner, "HTTP/1.1 404 Not Found")

    def test_http_server_without_version(self):
        info = services.identify(b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n", 443)
        self.assertEqual((info.product, info.version), ("cloudflare", ""))

    def test_ftp(self):
        info = services.identify(b"220 (vsFTPd 3.0.5)\r\n", 21)
        self.assertEqual((info.name, info.product, info.version), ("ftp", "vsFTPd", "3.0.5"))

    def test_ftp_on_unusual_port(self):
        info = services.identify(b"220 ProFTPD 1.3.8 Server ready.\r\n", 9921)
        self.assertEqual((info.name, info.product, info.version), ("ftp", "ProFTPD", "1.3.8"))

    def test_smtp(self):
        info = services.identify(b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", 25)
        self.assertEqual((info.name, info.product), ("smtp", "Postfix"))

    def test_smtp_exim_with_version(self):
        info = services.identify(b"220 mx.example.com ESMTP Exim 4.97 Mon, 1 Jan\r\n", 25)
        self.assertEqual((info.product, info.version), ("Exim", "4.97"))

    def test_pop3_and_imap(self):
        self.assertEqual(services.identify(b"+OK Dovecot ready.\r\n", 110).name, "pop3")
        imap = services.identify(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", 143)
        self.assertEqual((imap.name, imap.product), ("imap", "Dovecot"))

    def test_redis_reply_to_http_probe(self):
        info = services.identify(b"-ERR unknown command 'HEAD', with args beginning with: \r\n", 6379)
        self.assertEqual(info.name, "redis")

    def test_redis_needing_password(self):
        self.assertEqual(services.identify(b"-NOAUTH Authentication required.\r\n", 6380).name, "redis")

    def test_mysql(self):
        payload = b"\x0a8.0.36-0ubuntu0.22.04.1\x00" + b"\x00" * 20
        info = services.identify(mysql_packet(payload), 3306)
        self.assertEqual((info.name, info.product, info.version), ("mysql", "MySQL", "8.0.36"))

    def test_mariadb(self):
        payload = b"\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00" + b"\x00" * 20
        info = services.identify(mysql_packet(payload), 3306)
        self.assertEqual((info.product, info.version), ("MariaDB", "10.11.6"))

    def test_mysql_access_denied(self):
        payload = b"\xff\x6a\x04Host '10.0.0.5' is not allowed to connect to this MySQL server"
        info = services.identify(mysql_packet(payload), 3306)
        self.assertEqual(info.name, "mysql")
        self.assertIn("not allowed", info.extra)

    def test_unknown_banner_keeps_banner_and_guesses(self):
        info = services.identify(b"WELCOME TO MY CUSTOM THING\r\n", 22)
        self.assertEqual(info.name, "ssh")       # guessed from port 22...
        self.assertFalse(info.confirmed)         # ...but marked as unconfirmed
        self.assertEqual(info.label, "ssh?")
        self.assertEqual(info.banner, "WELCOME TO MY CUSTOM THING")

    def test_nothing_received(self):
        self.assertIsNone(services.identify(b"", 80))

    def test_binary_garbage_is_cleaned(self):
        info = services.identify(b"\x00\x01\xffhello\x1b[31m\r\n", 4444)
        self.assertTrue(all(" " <= ch <= "~" for ch in info.banner))


class TestServiceInfo(unittest.TestCase):
    def test_label_and_details(self):
        info = services.ServiceInfo("http", "nginx", "1.24.0", "Ubuntu; TLSv1.3", tls=True)
        self.assertEqual(info.label, "ssl/http")
        self.assertEqual(info.details, "nginx 1.24.0 (Ubuntu; TLSv1.3)")

    def test_guess_label(self):
        self.assertEqual(services.guess_from_port(5432).label, "postgresql?")
        self.assertEqual(services.guess_from_port(54321).label, "unknown")


class FakeService:
    """A tiny TCP server on localhost that behaves like a real service."""

    def __init__(self, greeting: bytes = b"", reply: bytes = b""):
        self.greeting, self.reply = greeting, reply
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(3)
                    if self.greeting:
                        conn.sendall(self.greeting)
                    if self.reply:
                        conn.recv(1024)
                        conn.sendall(self.reply)
                    else:
                        conn.recv(1024)
                except OSError:
                    pass

    def close(self):
        self.sock.close()


class TestDetectLive(unittest.TestCase):
    """Run detect() against fake services listening on localhost."""

    def test_service_that_speaks_first(self):
        svc = FakeService(greeting=b"SSH-2.0-OpenSSH_9.6p1\r\n")
        try:
            info = services.detect("127.0.0.1", svc.port, timeout=2.0)
        finally:
            svc.close()
        self.assertEqual((info.name, info.product, info.version), ("ssh", "OpenSSH", "9.6p1"))

    def test_silent_service_gets_http_probe(self):
        svc = FakeService(reply=b"HTTP/1.0 200 OK\r\nServer: TestServer/2.1\r\n\r\n")
        try:
            info = services.detect("127.0.0.1", svc.port, timeout=0.5)
        finally:
            svc.close()
        self.assertEqual((info.name, info.product, info.version), ("http", "TestServer", "2.1"))

    def test_completely_silent_service(self):
        svc = FakeService()
        try:
            info = services.detect("127.0.0.1", svc.port, timeout=0.5)
        finally:
            svc.close()
        self.assertFalse(info.confirmed)

    def test_detect_services_in_parallel(self):
        ssh = FakeService(greeting=b"SSH-2.0-OpenSSH_9.6p1\r\n")
        ftp = FakeService(greeting=b"220 (vsFTPd 3.0.5)\r\n")
        try:
            infos = grapevine.detect_services("127.0.0.1", [ssh.port, ftp.port], 2.0, workers=10)
        finally:
            ssh.close()
            ftp.close()
        self.assertEqual(infos[ssh.port].name, "ssh")
        self.assertEqual(infos[ftp.port].name, "ftp")


if __name__ == "__main__":
    unittest.main()

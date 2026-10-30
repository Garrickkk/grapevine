"""Service detection for grapevine: banner grabbing and fingerprinting.

An open port only tells you *something* is listening. This module talks to
the service to find out *what* it is:

1. Connect and wait briefly: many protocols (SSH, FTP, SMTP, MySQL, POP3,
   IMAP) send a greeting ("banner") as soon as you connect.
2. If the service stays silent, send a probe. Most silent services are web
   servers, so the probe is a minimal HTTP request.
3. Match the response against known patterns to get the service name,
   product and version, e.g.  "SSH-2.0-OpenSSH_9.6p1"  ->  ssh / OpenSSH 9.6p1.
4. If nothing useful comes back, fall back to guessing from the port number,
   and mark the result as unconfirmed.

Ports that usually use TLS (443, 993, ...) get a TLS handshake first.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass

# What usually runs on well-known ports. Only used when the service itself
# doesn't tell us, so these results are shown as guesses ("http?").
PORT_GUESSES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle", 3000: "http",
    3306: "mysql", 3389: "ms-wbt-server", 5000: "http", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http", 8080: "http-proxy",
    8443: "https-alt", 8888: "http", 9000: "http", 27017: "mongodb",
}

# Ports where we try a TLS handshake before anything else.
TLS_PORTS = frozenset({443, 465, 636, 853, 993, 995, 8443})

# Ports where the service almost certainly waits for us to speak first (web
# servers), so we skip waiting for a greeting and probe immediately.
CLIENT_SPEAKS_FIRST = frozenset({80, 81, 443, 591, 3000, 5000, 8000, 8008,
                                 8080, 8081, 8443, 8888, 9000})

HTTP_PROBE = "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: grapevine\r\n\r\n"

MAX_READ = 4096


@dataclass
class ServiceInfo:
    name: str                 # e.g. "ssh", "http", "mysql"
    product: str = ""         # e.g. "OpenSSH", "nginx"
    version: str = ""         # e.g. "9.6p1", "1.24.0"
    extra: str = ""           # extra details, e.g. "Ubuntu", "TLSv1.3"
    banner: str = ""          # cleaned-up first line of what the service sent
    tls: bool = False         # True if we spoke to it over TLS
    confirmed: bool = True    # False if only guessed from the port number

    @property
    def label(self) -> str:
        """Service name as shown in the SERVICE column, e.g. 'ssl/http' or 'http?'."""
        name = ("ssl/" if self.tls else "") + self.name
        if not self.confirmed and self.name != "unknown":
            name += "?"
        return name

    @property
    def details(self) -> str:
        """Text for the VERSION column, e.g. 'OpenSSH 9.6p1 (protocol 2.0)'."""
        text = " ".join(part for part in (self.product, self.version) if part)
        if self.extra:
            text = f"{text} ({self.extra})" if text else self.extra
        return text


# --------------------------------------------------------------------------
# Talking to the service
# --------------------------------------------------------------------------

def detect(ip: str, port: int, timeout: float = 2.0, hostname: str | None = None) -> ServiceInfo:
    """Find out what service is running on an open port."""
    host = hostname or ip

    if port in TLS_PORTS:
        info = _detect_tls(ip, port, timeout, host)
        if info is not None:
            return info
        # Handshake failed: the port isn't speaking TLS, try plain TCP.

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            data = _converse(sock, port, host)
    except OSError:
        data = b""

    return identify(data, port) or guess_from_port(port)


def _detect_tls(ip: str, port: int, timeout: float, host: str) -> ServiceInfo | None:
    """Do a TLS handshake, then identify the service inside the encrypted channel."""
    context = ssl.create_default_context()
    # We're identifying the service, not trusting it, so don't reject
    # self-signed or mismatched certificates.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            # server_hostname enables SNI, so virtual hosts return the right site.
            sni = None if _is_ip(host) else host
            with context.wrap_socket(raw, server_hostname=sni) as tls_sock:
                tls_version = tls_sock.version() or "TLS"
                data = _converse(tls_sock, port, host)
    except OSError:  # includes ssl.SSLError
        return None

    info = identify(data, port) or guess_from_port(port)
    info.tls = True
    if info.name in ("https", "https-alt"):
        info.name = "http"  # shown as "ssl/http", like Nmap does
    info.extra = f"{info.extra}; {tls_version}" if info.extra else tls_version
    return info


def _converse(sock: socket.socket, port: int, host: str) -> bytes:
    """Read the service's greeting, or send an HTTP probe if it stays quiet."""
    data = b"" if port in CLIENT_SPEAKS_FIRST else _read(sock)
    if not data:
        try:
            sock.sendall(HTTP_PROBE.format(host=host).encode())
        except OSError:
            return b""
        data = _read(sock)
    return data


def _read(sock: socket.socket) -> bytes:
    """Read what the service sends, up to MAX_READ bytes."""
    try:
        data = sock.recv(MAX_READ)
    except OSError:  # includes timeouts
        return b""
    if not data:
        return b""
    # Responses can arrive in several pieces; collect anything that follows
    # closely behind the first piece.
    chunks = [data]
    total = len(data)
    sock.settimeout(0.3)
    try:
        while total < MAX_READ:
            more = sock.recv(MAX_READ - total)
            if not more:
                break
            chunks.append(more)
            total += len(more)
    except OSError:
        pass
    return b"".join(chunks)


def _is_ip(text: str) -> bool:
    try:
        socket.inet_aton(text)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# Identifying the service from what it sent (pure functions, easy to test)
# --------------------------------------------------------------------------

def guess_from_port(port: int) -> ServiceInfo:
    """Fallback when the service gives us nothing: guess from the port number."""
    return ServiceInfo(name=PORT_GUESSES.get(port, "unknown"), confirmed=False)


def identify(data: bytes, port: int) -> ServiceInfo | None:
    """Work out the service from the raw bytes it sent. None if it sent nothing."""
    if not data:
        return None

    # MySQL sends a binary greeting, so check it before decoding as text.
    mysql = parse_mysql(data)
    if mysql:
        return mysql

    text = data.decode("utf-8", errors="replace")
    first_line = clean(text.splitlines()[0]) if text.strip() else ""

    if text.startswith("SSH-"):
        return parse_ssh(first_line)
    if text.startswith("HTTP/"):
        return parse_http(text)
    if text.startswith(("+PONG", "-NOAUTH", "-DENIED")) or (
        text.startswith("-ERR") and "command" in text.lower()
    ):
        # Redis replies to our HTTP probe with an "unknown command" error.
        return ServiceInfo("redis", "Redis", banner=first_line)
    if text.startswith("+OK"):
        return ServiceInfo("pop3", _find_product(first_line, POP_IMAP_PRODUCTS), banner=first_line)
    if text.startswith("* OK"):
        return ServiceInfo("imap", _find_product(first_line, POP_IMAP_PRODUCTS), banner=first_line)
    if text.startswith("220"):
        return parse_220(first_line, port)

    # Something answered, but we don't recognise it. Keep the banner so the
    # user can judge for themselves.
    info = guess_from_port(port)
    info.banner = first_line
    return info


def parse_ssh(line: str) -> ServiceInfo:
    """'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13' -> ssh / OpenSSH 9.6p1."""
    match = re.match(r"SSH-([\d.]+)-(\S+)(?:\s+(.*))?", line)
    if not match:
        return ServiceInfo("ssh", banner=line)
    protocol, software, comment = match.groups()
    product, _, version = software.partition("_")
    extra = f"protocol {protocol}" + (f"; {comment}" if comment else "")
    return ServiceInfo("ssh", product, version, extra, banner=line)


def parse_http(text: str) -> ServiceInfo:
    """Read the status line and Server header, e.g. 'nginx/1.24.0 (Ubuntu)'."""
    lines = text.splitlines()
    status = clean(lines[0])
    server = ""
    for line in lines[1:]:
        if not line.strip():
            break  # end of headers
        name, _, value = line.partition(":")
        if name.strip().lower() == "server":
            server = clean(value.strip())
            break

    banner = f"{status} | Server: {server}" if server else status
    if not server:
        return ServiceInfo("http", banner=banner)
    # "nginx/1.24.0 (Ubuntu)" -> product, version, extra
    match = re.match(r"([^/\s]+)(?:/(\S+))?(?:\s+(.*))?", server)
    product, version, extra = match.groups() if match else (server, None, None)
    extra = (extra or "").strip().strip("()")
    return ServiceInfo("http", product, version or "", extra, banner=banner)


# Known FTP and SMTP software, as (regex, product name). The regex's first
# group, if present, is the version.
FTP_PRODUCTS = [
    (r"vsFTPd ([\d.]+)", "vsFTPd"),
    (r"ProFTPD ([\d.]+\w*)", "ProFTPD"),
    (r"FileZilla Server(?: version)? ([\d.]+\w*)", "FileZilla Server"),
    (r"Pure-FTPd", "Pure-FTPd"),
    (r"Microsoft FTP Service", "Microsoft ftpd"),
]
SMTP_PRODUCTS = [
    (r"Postfix", "Postfix"),
    (r"Exim ([\d.]+)", "Exim"),
    (r"Sendmail ([\d.]+\S*)", "Sendmail"),
    (r"Microsoft ESMTP", "Microsoft ESMTP"),
]
POP_IMAP_PRODUCTS = [(r"Dovecot", "Dovecot"), (r"Courier", "Courier")]


def parse_220(line: str, port: int) -> ServiceInfo:
    """'220' greetings are used by both FTP and SMTP, so look for clues."""
    lower = line.lower()
    if "ftp" in lower or port in (21, 2121):
        product, version = _find_product_version(line, FTP_PRODUCTS)
        return ServiceInfo("ftp", product, version, banner=line)
    if "smtp" in lower or "mail" in lower or port in (25, 465, 587):
        product, version = _find_product_version(line, SMTP_PRODUCTS)
        return ServiceInfo("smtp", product, version, banner=line)
    info = guess_from_port(port)
    info.banner = line
    return info


def parse_mysql(data: bytes) -> ServiceInfo | None:
    """Decode MySQL's binary greeting packet.

    Packet layout: 3-byte length, 1-byte sequence number (0), then payload.
    Payload byte 0 is 0x0a (protocol 10) followed by a null-terminated
    version string; or 0xff for an error (e.g. "Host ... is not allowed").
    """
    if len(data) < 6 or data[3] != 0:
        return None
    length = int.from_bytes(data[:3], "little")
    payload = data[4:4 + length]
    if length < 2 or len(payload) < 2:
        return None

    if payload[0] == 0x0A:
        raw_version = payload[1:].split(b"\0", 1)[0]
        try:
            version = raw_version.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not re.match(r"\d+\.\d+", version):
            return None
        mariadb = re.search(r"([\d.]+)-MariaDB", version)
        if mariadb:
            return ServiceInfo("mysql", "MariaDB", mariadb.group(1), banner=version)
        return ServiceInfo("mysql", "MySQL", version.split("-")[0], banner=version)

    if payload[0] == 0xFF:
        # Error packet: 2-byte error code, optional "#SQLSTATE", then message.
        message = payload[3:].decode("utf-8", errors="replace")
        if message.startswith("#"):
            message = message[6:]
        return ServiceInfo("mysql", extra="refused us: " + clean(message), banner=clean(message))
    return None


def _find_product(line: str, products: list[tuple[str, str]]) -> str:
    return _find_product_version(line, products)[0]


def _find_product_version(line: str, products: list[tuple[str, str]]) -> tuple[str, str]:
    for pattern, product in products:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            version = match.group(1) if match.groups() else ""
            return product, version
    return "", ""


def clean(text: str, limit: int = 100) -> str:
    """Make raw service output safe to print: printable characters only, trimmed."""
    # ASCII only, so output never breaks on terminals with limited encodings.
    printable = "".join(ch if " " <= ch <= "~" else "." for ch in text).strip()
    return printable[:limit]

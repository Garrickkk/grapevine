# grapevine

**Hear what every port has to say.** A TCP port and network scanner written in Python, built step by step to learn how tools like Nmap work.

## Features

- **Host discovery:** finds live hosts with TCP ping and the ARP cache, including devices that ignore all probes
- **Port scanning:** threaded TCP connect scan with open / closed / filtered states
- **Service detection:** identifies SSH, HTTP(S), FTP, SMTP, MySQL, Redis and more, with versions
- **Flexible targets:** single IPs, CIDR networks, ranges and hostnames
- No dependencies, no admin rights needed

## Usage

Requires Python 3.10+.

```bash
python grapevine.py 192.168.1.0/24 -sn            # who's on my network?
python grapevine.py 192.168.1.0/24                # discover hosts, then scan ports 1-1024
python grapevine.py 192.168.1.1-20 -p 22,80,443   # a range of hosts, specific ports
python grapevine.py 192.168.1.30 -Pn              # scan even if the host looks down
```

| Option | Description |
|---|---|
| `-p` | Ports: `80`, `1-1024`, `22,80,443` (default `1-1024`) |
| `-sn` | Only discover hosts, don't scan ports |
| `-Pn` | Skip discovery, treat every host as up |
| `-n` | Don't look up hostnames |
| `-t` | Connection timeout in seconds (default `1.0`) |
| `-w` | Number of threads (default `100`) |
| `-a` | Also show closed and filtered ports |
| `-b` | Show raw service banners |
| `--no-detect` | Skip service detection |

> **Windows:** refused connections take ~2 s to report on Windows, so use `-t 3` for accurate results.

## Example

From a simulated test network:

```
$ python grapevine.py 127.0.1.0/28 -p 1-1024,3306,3389,8080
Scanning 127.0.1.0/28 (14 hosts): 1027 port(s), concurrent, 100 threads

Discovering hosts...  3 of 14 up (1.02s)
Scanning ports...     3 host(s) x 1027 port(s) (0.35s)
Detecting services... 9 open port(s) (6.03s)

127.0.1.1 (router.lab)
  Host is up: tcp/80 open
  PORT      STATE     SERVICE         VERSION
  53/tcp    open      domain?
  80/tcp    open      http            lighttpd 1.4.59
  443/tcp   open      ssl/http        lighttpd 1.4.59 (TLSv1.3)

127.0.1.2 (server.lab)
  Host is up: tcp/80 open
  PORT      STATE     SERVICE         VERSION
  22/tcp    open      ssh             OpenSSH 9.6p1 (protocol 2.0; Ubuntu-3ubuntu13)
  80/tcp    open      http            nginx 1.24.0 (Ubuntu)
  3306/tcp  open      mysql           MySQL 8.0.36

127.0.1.3 (desktop.lab)
  Host is up: tcp/80 refused
  PORT      STATE     SERVICE         VERSION
  135/tcp   open      msrpc?
  445/tcp   open      microsoft-ds?
  3389/tcp  open      ms-wbt-server?

? = guessed from the port number; the service didn't say what it is

14 host(s) scanned, 3 up | 9 open, 3072 closed, 0 filtered port(s) | finished in 7.40s
```

## How it works

1. **Discover:** probe a few common ports and read the ARP cache to find which hosts are up.
2. **Scan:** try a TCP handshake on each port of each live host: completed = **open**, refused = **closed**, no reply = **filtered**.
3. **Detect:** read each open port's greeting (or send an HTTP/TLS request) and match it to a product and version.

## Roadmap

- [x] v0.1: port scanner
- [x] v0.2: service and version detection
- [x] v0.3: network scanning and host discovery
- [ ] v0.4: SYN (half-open) scanning with scapy
- [ ] v1.0: CVE lookups, scan history, HTML reports

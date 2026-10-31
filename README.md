# grapevine

**Hear what every port has to say.** A TCP port and network scanner written in Python, built step by step to learn how scanners like Nmap work.

> ⚠️ **Only scan hosts and networks you own or have explicit written permission to test.** Unauthorized scanning can break the law (including Indonesia's UU ITE) and your ISP's or university's rules. For practice, use your own home network, lab VMs, or `scanme.nmap.org`, which the Nmap project explicitly allows. Scanning a whole network you don't own is far more noticeable than scanning one host.

## Version history

| Version | What it adds | Status |
|---|---|---|
| v0.1 | Single-host TCP connect scan, open/closed/filtered states, threaded scanning | ✅ done |
| v0.2 | Banner grabbing, service and version detection, TLS support | ✅ done |
| **v0.3** | Network scanning: CIDR ranges, host discovery (TCP ping + ARP), MAC addresses, hostnames | ✅ current |
| v0.4 | SYN (half-open) scan with scapy | planned |
| v1.0 | CVE lookups, SQLite scan history, HTML reports | planned |

## Usage

Requires Python 3.10+. No dependencies; standard library only.

```bash
python grapevine.py 192.168.1.0/24 -sn            # who's on my network? (no port scan)
python grapevine.py 192.168.1.0/24                # find live hosts, scan ports 1-1024 on each
python grapevine.py 192.168.1.1-20 -p 22,80,443   # a range of hosts, specific ports
python grapevine.py 192.168.1.1 192.168.1.50      # several targets
python grapevine.py scanme.nmap.org -p 1-1000     # a hostname
python grapevine.py 192.168.1.1 -p 1-65535 -w 500 # all ports, 500 threads
python grapevine.py 192.168.1.30 -Pn              # scan even if the host ignores discovery
python grapevine.py 192.168.1.1 -b                # also show raw service banners
```

> **Windows users:** Windows waits about 2 seconds before reporting a refused connection, so with the default 1 s timeout, closed ports may appear as *filtered*, and hosts that only refuse connections may be missed by discovery (hosts on your local network are still found through ARP). Add `-t 3` for accurate results (see Lessons learned).

### Targets

| Format | Example |
|---|---|
| Single IP | `192.168.1.1` |
| Network (CIDR) | `192.168.1.0/24` (254 hosts; network and broadcast addresses skipped) |
| Range | `192.168.1.10-50` or `192.168.1.10-192.168.1.50` |
| Hostname | `scanme.nmap.org` |
| Several | `192.168.1.1,192.168.1.5` or separate arguments |

Up to 4096 hosts (a /20) per scan, so a typo like `/8` can't queue 16 million hosts. IPv4 only.

### Options

| Option | Description |
|---|---|
| `-p, --ports` | `80`, `1-1024`, `22,80,443` or a mix (default `1-1024`) |
| `-sn, --discover-only` | Only find which hosts are up; skip port scanning |
| `-Pn, --skip-discovery` | Treat every host as up (for hosts that ignore discovery probes) |
| `-n, --no-dns` | Don't look up hostnames of live hosts |
| `-t, --timeout` | Seconds to wait when connecting to each port (default `1.0`) |
| `-w, --workers` | Number of threads (default `100`) |
| `--sequential` | Scan ports one at a time (for comparing speed) |
| `-a, --all` | Show closed and filtered ports too |
| `-b, --banners` | Show the raw banner each service sent |
| `--no-detect` | Skip service detection |
| `--detect-timeout` | Seconds to wait for a service to answer (default `2.0`) |

`-sn`, `-Pn` and `-n` mean the same as in Nmap, so the habits transfer.

### Example: scanning a network

Run against a test lab: a simulated /28 network with a router, a Linux server, a Windows-style desktop, a firewalled host, and empty addresses that silently drop packets the way unused addresses on a real network do.

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

Only 3 of the 14 addresses were port scanned, which is the whole point of discovery. A service name ending in `?` is only a guess from the port number.

### Example: who's on my network?

```
$ python grapevine.py 127.0.1.0/28 -sn
Discovering hosts in 127.0.1.0/28 (14 hosts)

Discovering hosts...  3 of 14 up (1.02s)

HOST             NAME                      REASON            MAC
127.0.1.1        router.lab                tcp/80 open
127.0.1.2        server.lab                tcp/80 open
127.0.1.3        desktop.lab               tcp/80 refused

14 host(s) scanned, 3 up | finished in 1.02s
```

On a real home network the **MAC** column fills in for every device on your local network, and phones that ignore all TCP probes still show up with the reason `arp reply`. A MAC marked `(random or virtual)` belongs to a phone or laptop using a private Wi-Fi address, or to a virtual machine.

### Example: a host hiding behind a firewall

The lab's fifth host (127.0.1.4) drops everything except port 8080, so discovery can't see it. `-Pn` skips discovery and finds it anyway:

```
$ python grapevine.py 127.0.1.4 -p 8000-8100
Host seems down: no reply on tcp/80, 443, 22, 445, 3389 and no ARP reply.
If it's up but blocking these probes, try -Pn.

$ python grapevine.py 127.0.1.4 -p 8000-8100 -Pn
127.0.1.4
  Host is up: assumed (-Pn)
  PORT      STATE     SERVICE         VERSION
  8080/tcp  open      http            Werkzeug 3.0.1 (Python/3.12.3)

1 host(s) scanned, 1 up | 1 open, 0 closed, 100 filtered port(s) | finished in 1.03s
```

With `-b`, each service's raw banner is shown underneath its line:

```
  22/tcp    open      ssh             OpenSSH 9.6p1 (protocol 2.0; Ubuntu-3ubuntu13)
            |_ SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
```

## How it works

A scan runs in three phases: **discover** which hosts are up, **scan** their ports, then **detect** what's running on each open port.

### 1. Host discovery

Port-scanning every address of a /24 network means 254 hosts × 1024 ports ≈ 260,000 probes, most of them to empty addresses. Discovery finds the live hosts cheaply first (in `discovery.py`), using two techniques that need no admin rights:

**TCP ping.** grapevine tries to connect to ports 80, 443, 22, 445 and 3389, the ports most likely to be open on routers, web devices, Linux and Windows machines. *Any* answer proves the host is up: a completed handshake (open) or a refusal (an `RST` packet, closed). Only silence is inconclusive. Probes are ordered port by port, so a host that answers on port 80 isn't probed again on 443, 22 and so on.

**ARP cache.** Before your computer can send anything to an address on your local network, it has to broadcast "who has 192.168.1.23?" (ARP), and the device answers with its MAC address. The operating system records that answer in its ARP cache, **even if the device then ignores every TCP probe**, as phones and firewalled PCs often do. So after the TCP ping, grapevine reads the ARP cache (`/proc/net/arp` on Linux, `arp -a` on Windows and macOS) and marks those devices as up too. This only works on your own local network, because ARP doesn't cross routers.

Then, for each live host, grapevine looks up its hostname with reverse DNS (home routers usually name devices, e.g. `router.home`). A hostname you typed always takes priority.

`-sn` stops after this phase. `-Pn` skips it, for hosts that ignore all discovery probes.

### 2. TCP connect scan

For each port the scanner tries to complete a full TCP three-way handshake (`SYN → SYN/ACK → ACK`) using `socket.connect_ex()`. Unlike `connect()`, which raises exceptions, `connect_ex()` returns an error code, so the result can be classified cleanly:

| What happens | Meaning | State |
|---|---|---|
| Handshake completes (code `0`) | A service is listening | **open** |
| Host replies with `RST` (`ECONNREFUSED`) | Host is up, nothing listening | **closed** |
| No reply before timeout | Packet probably dropped by a firewall | **filtered** |

All (host, port) pairs go into one shared thread pool, so scanning many hosts is as parallel as scanning one. A connect scan needs no special privileges, but every completed connection can show up in the target's logs. Stealthier SYN scanning is planned for v0.4.

### 3. Service detection

An open port only proves *something* is listening. Service detection (in `services.py`) talks to each open port to find out *what*:

1. **Listen for a greeting.** Many protocols announce themselves the moment you connect: SSH sends `SSH-2.0-OpenSSH_9.6p1`, FTP and SMTP send a `220` line, MySQL sends a binary handshake packet containing its version. Leading blank lines, and the text some SSH servers send before their version line, are skipped.
2. **Probe if it stays silent.** Web servers wait for the client to speak first, so grapevine sends a minimal `GET / HTTP/1.0` request and reads the `Server` header. (`GET` rather than `HEAD`, because some embedded web servers ignore `HEAD`.) On common web ports it skips waiting and probes immediately.
3. **TLS first on encrypted ports.** On ports like 443 and 993 it performs a TLS handshake, records the TLS version, then identifies the service inside the encrypted channel. If the handshake fails, it falls back to plain TCP, which catches plain HTTP on port 443.
4. **TLS retry everywhere else.** When a TLS server receives plain text, it hangs up without a word. So if any service closes the connection without sending anything, grapevine retries over TLS. This finds HTTPS on non-standard ports like 4443 or 9443, which admin panels often use. A service that merely stays silent (times out) isn't retried, because silence alone doesn't suggest TLS.
5. **Match patterns.** The response is matched against known formats to extract the product and version, e.g. `Server: nginx/1.24.0 (Ubuntu)` → nginx 1.24.0.
6. **Fall back to a guess.** If nothing useful comes back, the service is guessed from the port number and marked with `?`, so guesses are never presented as facts.

About TLS: certificates aren't verified, because the goal is to identify the service, not to trust it. When scanning by hostname, grapevine sends SNI so servers hosting several sites return the right one. It also accepts outdated protocol versions (TLS 1.0 and 1.1) that Python refuses by default, because old routers and IoT devices still use them, and seeing `TLSv1` in the results is itself a security finding: those versions have known weaknesses and were officially deprecated in 2021 (RFC 8996).

Some detections come from clever side effects. Redis doesn't speak HTTP, but `GET` happens to be a Redis command too, so Redis answers the HTTP probe with a distinctive error (`-ERR wrong number of arguments for 'get' command`). MariaDB reports itself with a MySQL-compatible version string (`5.5.5-10.11.6-MariaDB`), which grapevine decodes to the real version.

All banner text is reduced to plain printable ASCII before printing, so a malicious or broken service can't inject terminal control codes into your output.

### Why threads help (despite the GIL)

Python's Global Interpreter Lock lets only one thread run Python code at a time. Threads still speed up scanning because a scanner spends nearly all its time **waiting for network replies**, and the GIL is released while a thread waits on I/O. While one thread waits for port 22 to time out, others are probing ports 23, 24, 25 and so on. All three phases run in parallel this way.

## Benchmarks

Measured on a Linux machine.

**Port scan, filtered host** (timeout `0.5s`; no replies, so every port waits for the full timeout):

| Mode | Ports | Time |
|---|---|---|
| Sequential | 20 | 10.02 s (≈ 100 s for 200 ports) |
| 10 threads | 200 | 10.02 s |
| 100 threads | 200 | 1.04 s |

Time ≈ `ports × timeout ÷ threads`, so concurrency gives roughly a 100× speedup with 100 threads.

**Port scan, localhost** (timeout `0.5s`; every port refuses instantly):

| Mode | Ports | Time |
|---|---|---|
| Sequential | 1024 | 0.04 s |
| 100 threads | 1024 | 0.14 s |

Here threads are **slower**: when replies are instant there is no waiting to overlap, so the cost of creating and coordinating threads dominates. Concurrency pays off only when the bottleneck is waiting.

**Discovery, empty /24** (timeout `1.0s`; the worst case, where all 254 addresses stay silent and each needs all 5 probes):

| Threads | Time |
|---|---|
| 100 (default) | 13.05 s |
| 250 | 6.03 s |

Time ≈ `silent hosts × 5 probes × timeout ÷ threads` = 254 × 5 × 1 ÷ 100 ≈ 12.7 s. Live hosts usually answer the first probe, so real networks are a little faster.

**Service detection cost:** in the network example above, scanning 3,081 ports took 0.35 s but identifying the 9 open ones took 6.03 s. Detection is slow because of silent services: grapevine has to wait out timeouts (and try TLS) before concluding a service won't identify itself. Use `--no-detect` when you only need open ports.

## Lessons learned

- **Results can lie, and banners help catch it.** In v0.1, port 80 on an unreachable address showed as *open*. Running v0.2 against it revealed the banner `HTTP/1.1 426 Upgrade Required`: a transparent proxy on the network was completing the handshake on the address's behalf. A connect scan only proves *something* answered; service detection shows *what* answered.
- **The same proxy fooled discovery.** In v0.3, discovering a remote range made *every* address look up, all for the same reason: `tcp/80 open`. Real networks are never that uniform, so grapevine now warns when every host answers identically on an open port.
- **A test network must fail the way a real one does.** On a real network, unused addresses stay silent. On a test machine, unused loopback addresses actively *refuse* connections, which made every address look "up". The lab only became realistic after adding firewall rules (`iptables`) to silently drop packets to empty addresses and to hide one host behind a firewall.
- **Silence isn't absence.** A device can be on the network and ignore every probe. The ARP cache still knows it exists, which is how phones show up even though they have no open ports.
- **Timeouts are a trade-off.** Too short, and slow-responding open ports are misreported as filtered, or a slow service's banner is missed. Too long, and scanning takes forever.
- **Test against messy services, not just well-behaved ones.** grapevine's first test lab only had tidy fake services, and everything passed. A second lab of awkward ones (HTTPS on port 9443, an old TLS 1.0 server, SSH with a login notice before its version line, a banner starting with a blank line) exposed four detection gaps, all fixed before release.
- **Packet loss can hide open ports.** On a real network, a single dropped packet makes an open port look *filtered*. Nmap retransmits probes to compensate; grapevine doesn't yet, so a port that should be open can occasionally be missed. Re-running the scan or raising `-t` helps.
- **Not every protocol speaks first.** Some services greet you immediately, others wait for a request, and some never respond to anything you don't speak their protocol for. A scanner has to handle all three.
- **Operating systems behave differently.** When a closed port refuses a connection, Linux and macOS report it instantly, but Windows retries for about 2 seconds first. With a short timeout, closed ports on Windows can show up as *filtered*. On Windows, use `-t 3` when you need an accurate closed/filtered split.
- **More threads isn't always better.** Every thread holds an open socket, and the OS limits how many files a program may have open (only 256 by default on macOS). Too many threads used to crash grapevine; it now stops with a clear message telling you to lower `-w`. Huge thread counts can also look like a flood to the target network.

## Project structure

```
grapevine/
├── grapevine.py          # command-line interface and report
├── targets.py            # parsing targets (IPs, networks, ranges) and ports
├── discovery.py          # host discovery: TCP ping, ARP cache, reverse DNS
├── scanner.py            # TCP connect scanning and the shared thread pool
├── services.py           # banner grabbing and service identification
├── test_grapevine.py     # end-to-end tests of the command line
├── test_targets.py       # tests for target and port parsing
├── test_discovery.py     # tests for discovery, incl. ARP output from Linux/Windows/macOS
├── test_scanner.py       # tests for port scanning
└── test_services.py      # tests for service detection
```

## Running tests

```bash
python -m unittest -v
```

The tests need no network access or extra software. Highlights:

- **Scanning:** a real listening socket on localhost for "open", an unused port for "closed", a simulated timeout for "filtered".
- **Discovery:** a fake network (a probe function that decides which hosts answer how) tests the TCP ping logic, and real ARP output samples from Linux, Windows and macOS test the ARP parser, including incomplete, broadcast and multicast entries.
- **Service detection:** realistic banners (OpenSSH, nginx, vsFTPd, Postfix, MySQL, MariaDB, Redis…) plus live detection against fake services on localhost, including real TLS services using a throwaway test certificate embedded in `test_services.py`.
- **Command line:** full runs of the program, checking its output, exit codes and error messages.

The tests were also checked by deliberately breaking the code (for example, no longer counting a refused connection as "host is up") and confirming the tests fail.

## Disclaimer

For educational purposes and authorized testing only.

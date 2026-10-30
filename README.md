# grapevine

**Hear what every port has to say.** A TCP port and network scanner written in Python, built step by step to learn how scanners like Nmap work.

> ⚠️ **Only scan hosts you own or have explicit written permission to test.** Unauthorized scanning can break the law (including Indonesia's UU ITE) and your ISP's or university's rules. For practice, use your own machine, your home network, lab VMs, or `scanme.nmap.org`, which the Nmap project explicitly allows.

## Version history

| Version | What it adds | Status |
|---|---|---|
| v0.1 | Single-host TCP connect scan, open/closed/filtered states, threaded scanning | ✅ done |
| **v0.2** | Banner grabbing, service and version detection, TLS support | ✅ current |
| v0.3 | CIDR ranges and host discovery (network scanner) | planned |
| v0.4 | SYN (half-open) scan with scapy | planned |
| v1.0 | CVE lookups, SQLite scan history, HTML reports | planned |

## Usage

Requires Python 3.10+. No dependencies; standard library only.

```bash
python grapevine.py 127.0.0.1                     # ports 1-1024, with service detection
python grapevine.py scanme.nmap.org -p 22,80,443  # specific ports
python grapevine.py 192.168.1.1 -p 1-65535 -w 500 # all ports, 500 threads
python grapevine.py 192.168.1.1 -b                # also show raw banners
python grapevine.py 192.168.1.1 --no-detect       # ports only, skip detection
python grapevine.py 127.0.0.1 -p 1-100 -a         # also show closed/filtered
```

> **Windows users:** closed ports can take ~2 s to be reported on Windows, so with the default 1 s timeout they may appear as *filtered*. Add `-t 3` for accurate results (see Lessons learned).

| Option | Description |
|---|---|
| `-p, --ports` | `80`, `1-1024`, `22,80,443` or a mix (default `1-1024`) |
| `-t, --timeout` | Seconds to wait when connecting to each port (default `1.0`) |
| `-w, --workers` | Number of threads (default `100`) |
| `--sequential` | Scan ports one at a time (service detection still runs in parallel) |
| `-a, --all` | Show closed and filtered ports too |
| `-b, --banners` | Show the raw banner each service sent |
| `--no-detect` | Skip service detection |
| `--detect-timeout` | Seconds to wait for a service to answer (default `2.0`) |

### Example output

Run against a local test lab of simulated services:

```
$ python grapevine.py 127.0.0.1 -p 1100,2121,2222,2525,3306,3307,6379,8000,8443,9999
Scanning 127.0.0.1: 10 port(s), concurrent, 100 threads

PORT      STATE     SERVICE         VERSION
1100/tcp  open      pop3            Dovecot
2121/tcp  open      ftp             vsFTPd 3.0.5
2222/tcp  open      ssh             OpenSSH 9.6p1 (protocol 2.0; Ubuntu-3ubuntu13)
2525/tcp  open      smtp            Postfix
3306/tcp  open      mysql           MySQL 8.0.36
3307/tcp  open      mysql           MariaDB 10.11.6
6379/tcp  open      redis           Redis
8000/tcp  open      http            SimpleHTTP 0.6 (Python/3.13.18)
8443/tcp  open      ssl/http        nginx 1.24.0 (Ubuntu; TLSv1.3)
9999/tcp  open      unknown

10 open, 0 closed, 0 filtered - finished in 2.02s (port scan 0.01s, service detection 2.01s)
```

With `-b`, each service's raw banner is shown underneath:

```
2222/tcp  open      ssh             OpenSSH 9.6p1 (protocol 2.0; Ubuntu-3ubuntu13)
          |_ SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
```

A service name ending in `?` (e.g. `postgresql?`) is only a guess from the port number, because the service didn't send anything that identifies it.

## How it works

### 1. TCP connect scan

For each port the scanner tries to complete a full TCP three-way handshake (`SYN → SYN/ACK → ACK`) using `socket.connect_ex()`. Unlike `connect()`, which raises exceptions, `connect_ex()` returns an error code, so the result can be classified cleanly:

| What happens | Meaning | State |
|---|---|---|
| Handshake completes (code `0`) | A service is listening | **open** |
| Host replies with `RST` (`ECONNREFUSED`) | Host is up, nothing listening | **closed** |
| No reply before timeout | Packet probably dropped by a firewall | **filtered** |

A connect scan needs no special privileges, but every completed connection can show up in the target's logs. Stealthier SYN scanning is planned for v0.4.

### 2. Service detection

An open port only proves *something* is listening. Service detection (in `services.py`) talks to each open port to find out *what*:

1. **Listen for a greeting.** Many protocols announce themselves the moment you connect: SSH sends `SSH-2.0-OpenSSH_9.6p1`, FTP and SMTP send a `220` line, MySQL sends a binary handshake packet containing its version.
2. **Probe if it stays silent.** Web servers wait for the client to speak first, so grapevine sends a minimal `HEAD / HTTP/1.0` request and reads the `Server` header. On common web ports it skips waiting and probes immediately.
3. **TLS first on encrypted ports.** On ports like 443 and 993 it performs a TLS handshake, records the TLS version, then identifies the service inside the encrypted channel. Certificates aren't verified, because the goal is to identify the service, not to trust it. When scanning by hostname, it sends SNI so servers hosting several sites return the right one.
4. **Match patterns.** The response is matched against known formats to extract the product and version, e.g. `Server: nginx/1.24.0 (Ubuntu)` → nginx 1.24.0.
5. **Fall back to a guess.** If nothing useful comes back, the service is guessed from the port number and marked with `?`, so guesses are never presented as facts.

Some detections come from clever side effects. Redis doesn't understand HTTP, but its reply to the HTTP probe (`-ERR unknown command 'HEAD'`) is distinctive enough to identify it. MariaDB reports itself with a MySQL-compatible version string (`5.5.5-10.11.6-MariaDB`), which grapevine decodes to the real version.

All banner text is reduced to plain printable ASCII before printing, so a malicious or broken service can't inject terminal control codes into your output.

### 3. Why threads help (despite the GIL)

Python's Global Interpreter Lock lets only one thread run Python code at a time. Threads still speed up scanning because a scanner spends nearly all its time **waiting for network replies**, and the GIL is released while a thread waits on I/O. While one thread waits for port 22 to time out, others are probing ports 23, 24, 25 and so on. Service detection runs in parallel the same way.

## Benchmarks

Measured on a Linux machine with timeout `0.5s`.

**Filtered host** (no replies, so every port waits for the full timeout):

| Mode | Ports | Time |
|---|---|---|
| Sequential | 20 | 10.02 s (≈ 100 s for 200 ports) |
| 10 threads | 200 | 10.02 s |
| 100 threads | 200 | 1.04 s |

Time ≈ `ports × timeout ÷ threads`, so concurrency gives roughly a 100× speedup with 100 threads.

**Localhost** (every port refuses instantly):

| Mode | Ports | Time |
|---|---|---|
| Sequential | 1024 | 0.04 s |
| 100 threads | 1024 | 0.14 s |

Here threads are **slower**: when replies are instant there is no waiting to overlap, so the cost of creating and coordinating threads dominates. Concurrency pays off only when the bottleneck is waiting.

**Service detection cost:** in the example above, finding the 10 open ports took 0.01 s but identifying them took 2.01 s. Detection is slow because of silent services: grapevine has to wait out the full detect timeout before concluding a service won't talk. Use `--no-detect` when you only need open ports.

## Lessons learned

- **Results can lie, and banners help catch it.** In v0.1, port 80 on an unreachable address showed as *open*. Running v0.2 against it revealed the banner `HTTP/1.1 426 Upgrade Required`: a transparent proxy on the network was completing the handshake on the address's behalf. A connect scan only proves *something* answered; service detection shows *what* answered.
- **Timeouts are a trade-off.** Too short, and slow-responding open ports are misreported as filtered, or a slow service's banner is missed. Too long, and scanning takes forever.
- **Not every protocol speaks first.** Some services greet you immediately, others wait for a request, and some never respond to anything you don't speak their protocol for. A scanner has to handle all three.
- **Operating systems behave differently.** When a closed port refuses a connection, Linux and macOS report it instantly, but Windows retries for about 2 seconds first. With a short timeout, closed ports on Windows can show up as *filtered*. Open ports aren't affected. On Windows, use `-t 3` when you need an accurate closed/filtered split.
- **More threads isn't always better.** Very high thread counts can hit the OS limit on open file descriptors and can look like a flood to the target network.

## Project structure

```
grapevine/
├── grapevine.py         # port scanning and command-line interface
├── services.py          # banner grabbing and service identification
├── test_grapevine.py    # tests for scanning and the CLI
└── test_services.py     # tests for service detection
```

## Running tests

```bash
python -m unittest -v
```

The scanning tests open a real listening socket on localhost for the "open" case, use an unused port for "closed", and simulate a timeout for "filtered". The service detection tests check each parser against realistic banners (OpenSSH, nginx, vsFTPd, Postfix, MySQL, MariaDB, Redis…) and run live detection against fake services on localhost. No network access is needed.

## Disclaimer

For educational purposes and authorized testing only.

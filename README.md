# grapevine

**Hear what every port has to say.** A TCP port and network scanner written in Python, built step by step to learn how scanners like Nmap work.

> ⚠️ **Only scan hosts you own or have explicit written permission to test.** Unauthorized scanning can break the law (including Indonesia's UU ITE) and your ISP's or university's rules. For practice, use your own machine, your home network, lab VMs, or `scanme.nmap.org`, which the Nmap project explicitly allows.

## Version history

| Version | What it adds | Status |
|---|---|---|
| **v0.1** | Single-host TCP connect scan, open/closed/filtered states, threaded scanning | ✅ current |
| v0.2 | Banner grabbing and service detection | planned |
| v0.3 | CIDR ranges and host discovery (network scanner) | planned |
| v0.4 | SYN (half-open) scan with scapy | planned |
| v1.0 | CVE lookups, SQLite scan history, HTML reports | planned |

## Usage

Requires Python 3.10+. No dependencies; standard library only.

```bash
python grapevine.py 127.0.0.1                     # ports 1-1024, 100 threads
python grapevine.py scanme.nmap.org -p 22,80,443  # specific ports
python grapevine.py 192.168.1.1 -p 1-65535 -w 500 # all ports, 500 threads
python grapevine.py 127.0.0.1 --sequential        # one port at a time
python grapevine.py 127.0.0.1 -p 1-100 -a         # also show closed/filtered
```

> **Windows users:** closed ports can take ~2 s to be reported on Windows, so with the default 1 s timeout they may appear as *filtered*. Add `-t 3` for accurate results (see Lessons learned).

| Option | Description |
|---|---|
| `-p, --ports` | `80`, `1-1024`, `22,80,443` or a mix (default `1-1024`) |
| `-t, --timeout` | Seconds to wait per port (default `1.0`) |
| `-w, --workers` | Number of threads (default `100`) |
| `--sequential` | Scan one port at a time |
| `-a, --all` | Show closed and filtered ports too |

Example output (with `python -m http.server 8000` running locally):

```
$ python grapevine.py 127.0.0.1 -p 7999-8001 -a
Scanning 127.0.0.1: 3 port(s), concurrent, 100 threads

PORT      STATE
7999/tcp  closed
8000/tcp  open
8001/tcp  closed

1 open, 2 closed, 0 filtered — finished in 0.00s
```

## How it works

### TCP connect scan

For each port the scanner tries to complete a full TCP three-way handshake (`SYN → SYN/ACK → ACK`) using `socket.connect_ex()`. Unlike `connect()`, which raises exceptions, `connect_ex()` returns an error code, so the result can be classified cleanly:

| What happens | Meaning | State |
|---|---|---|
| Handshake completes (code `0`) | A service is listening | **open** |
| Host replies with `RST` (`ECONNREFUSED`) | Host is up, nothing listening | **closed** |
| No reply before timeout | Packet probably dropped by a firewall | **filtered** |

A connect scan needs no special privileges, but every completed connection can show up in the target's logs. Stealthier SYN scanning is planned for v0.4.

### Why threads help (despite the GIL)

Python's Global Interpreter Lock lets only one thread run Python code at a time. Threads still speed up scanning because a scanner spends nearly all its time **waiting for network replies**, and the GIL is released while a thread waits on I/O. While one thread waits for port 22 to time out, others are probing ports 23, 24, 25 and so on.

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

## Lessons learned

- **Timeouts are a trade-off.** Too short, and slow-responding open ports are misreported as filtered. Too long, and scanning a firewalled host takes forever.
- **Results can lie.** While testing, port 80 on an unreachable address showed as *open*: a transparent proxy on the network completed the handshake on the address's behalf. A connect scan only proves *something* answered, not that the target did. Verifying with banners (v0.2) helps catch this.
- **Operating systems behave differently.** When a closed port refuses a connection, Linux and macOS report it instantly, but Windows retries for about 2 seconds first. With a short timeout, closed ports on Windows can show up as *filtered*. Open ports aren't affected. On Windows, use `-t 3` when you need an accurate closed/filtered split.
- **More threads isn't always better.** Very high thread counts can hit the OS limit on open file descriptors and can look like a flood to the target network.

## Running tests

```bash
python -m unittest -v
```

The tests open a real listening socket on localhost for the "open" case, use an unused port for "closed", and simulate a timeout for "filtered", so no network access is needed.

## Disclaimer

For educational purposes and authorized testing only.

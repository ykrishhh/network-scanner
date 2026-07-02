# Network Scanner

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge)
![Issues](https://img.shields.io/badge/Issues-Welcome-blue?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/ykrishhh/network-scanner?style=for-the-badge&color=yellow)

A high-performance Python network scanner for security auditing, port scanning, service detection, and OS fingerprinting. Built for security researchers and penetration testers.

**Keywords**: `network-scanner` `port-scanner` `python` `security` `nmap` `network-security` `penetration-testing` `cybersecurity` `scapy` `socket`

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command-Line Arguments](#command-line-arguments)
- [Output Formats](#output-formats)
- [Core Scanner Code](#core-scanner-code)
- [Port Scanning Techniques](#port-scanning-techniques)
- [Service Detection](#service-detection)
- [OS Fingerprinting](#os-fingerprinting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

- **Multi-threaded port scanning** — SYN, TCP Connect, and UDP scans across thousands of ports concurrently
- **Service detection** — Identify running services and their versions on open ports
- **OS fingerprinting** — Detect target operating system via TCP/IP stack behavior analysis
- **Network discovery** — ARP scanning for local network host enumeration
- **Multiple output formats** — JSON, CSV, XML, and plain text reports
- **Stealth scanning** — SYN half-open scans avoid completing the TCP handshake
- **Custom port ranges** — Target specific ports or scan all 65535
- **CIDR notation support** — Enumerate entire subnets like `192.168.1.0/24`
- **Banner grabbing** — Capture service banners for fingerprinting software versions

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Root/sudo privileges required for raw socket operations (SYN scans)

### From Source

```bash
git clone https://github.com/ykrishhh/network-scanner.git
cd network-scanner
pip install -r requirements.txt
```

### Via pip

```bash
pip install network-scanner-ykrish
```

### Dependencies

```
scapy>=2.5.0
python-nmap>=0.7.1
netifaces>=0.11.0
colorama>=0.4.6
rich>=13.0.0
```

---

## Usage

### Basic Port Scan

```bash
# Scan common ports on a single target
sudo python scanner.py -t 192.168.1.1

# Scan a specific port range
sudo python scanner.py -t 192.168.1.1 -p 1-1024

# Target individual ports
sudo python scanner.py -t 192.168.1.1 -p 22,80,443,8080
```

### Network Discovery

```bash
# Enumerate an entire /24 subnet
sudo python scanner.py -t 192.168.1.0/24 --discover

# Local ARP sweep
sudo python scanner.py --arp-scan
```

### Stealth and Advanced Modes

```bash
# SYN scan with OS fingerprinting
sudo python scanner.py -t 10.0.0.0/24 -sS -O --service-detection

# UDP scan against DNS and SNMP
sudo python scanner.py -t 192.168.1.1 -sU -p 53,123,161 --timeout 5

# Export results to JSON
sudo python scanner.py -t 192.168.1.1 -o json -f results.json
```

---

## Command-Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target IP, hostname, or CIDR range | Required |
| `--ports` | `-p` | Port specification (e.g., `1-1024`, `22,80,443`) | Top 1000 |
| `--scan-type` | `-s` | Scan method: `syn`, `tcp`, `udp`, `ack` | `syn` |
| `--discover` | `-d` | Enable host discovery | `false` |
| `--arp-scan` | `-a` | ARP sweep for local network | `false` |
| `--os-detect` | `-O` | Perform OS fingerprinting | `false` |
| `--service-detect` | `-sV` | Identify service versions | `false` |
| `--timeout` | `-T` | Connection timeout (seconds) | `3` |
| `--threads` | `-j` | Concurrent thread count | `100` |
| `--output` | `-o` | Format: `text`, `json`, `csv`, `xml` | `text` |
| `--file` | `-f` | Write output to file path | stdout |
| `--verbose` | `-v` | Enable verbose logging | `false` |

---

## Output Formats

### JSON Report

```json
{
  "scan_info": {
    "target": "192.168.1.1",
    "scan_type": "SYN",
    "started": "2024-01-15T10:30:00Z",
    "completed": "2024-01-15T10:32:15Z",
    "hosts_scanned": 1,
    "open_ports_found": 5
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "state": "up",
      "os_guess": "Linux 4.15 - 5.8",
      "ports": [
        {
          "port": 22,
          "state": "open",
          "service": "ssh",
          "version": "OpenSSH 8.2p1",
          "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
        },
        {
          "port": 80,
          "state": "open",
          "service": "http",
          "version": "nginx 1.18.0"
        }
      ]
    }
  ]
}
```

### CSV Export

```csv
ip,hostname,port,state,service,version
192.168.1.1,router.local,22,open,ssh,OpenSSH 8.2p1
192.168.1.1,router.local,80,open,http,nginx 1.18.0
192.168.1.1,router.local,443,open,https,nginx 1.18.0
```

---

## Core Scanner Code

### Complete Working Scanner

```python
#!/usr/bin/env python3
"""
network-scanner: Core scanning engine
Author: ykrishhh
"""

import socket
import threading
import ipaddress
import json
import csv
import sys
import argparse
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

# Service database for common ports
SERVICE_DB = {
    21: ("ftp", "File Transfer Protocol"),
    22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet Remote Access"),
    25: ("smtp", "Simple Mail Transfer Protocol"),
    53: ("dns", "Domain Name System"),
    80: ("http", "Hypertext Transfer Protocol"),
    110: ("pop3", "Post Office Protocol v3"),
    135: ("msrpc", "Microsoft RPC"),
    139: ("netbios-ssn", "NetBIOS Session Service"),
    143: ("imap", "Internet Message Access Protocol"),
    443: ("https", "HTTP Secure"),
    445: ("microsoft-ds", "SMB Direct"),
    993: ("imaps", "IMAP over SSL"),
    995: ("pop3s", "POP3 over SSL"),
    1433: ("ms-sql-s", "Microsoft SQL Server"),
    1521: ("oracle", "Oracle Database"),
    3306: ("mysql", "MySQL Database"),
    3389: ("ms-wbt-server", "Remote Desktop Protocol"),
    5432: ("postgresql", "PostgreSQL Database"),
    5900: ("vnc", "Virtual Network Computing"),
    6379: ("redis", "Redis Key-Value Store"),
    8080: ("http-proxy", "HTTP Proxy"),
    8443: ("https-alt", "HTTPS Alternate"),
    27017: ("mongodb", "MongoDB Database"),
}


class PortScanner:
    """High-speed port scanner with multiple scan techniques."""

    def __init__(self, target, port_range=None, max_threads=200, timeout=2):
        self.target = target
        self.ports = port_range or self._default_ports()
        self.max_threads = max_threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()

    @staticmethod
    def _default_ports():
        """Return the most commonly targeted ports."""
        return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 993, 995, 1433, 3306, 3389,
                5432, 5900, 8080, 8443]

    def resolve_host(self):
        """Translate hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] Resolved {self.target} -> {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Failed to resolve hostname: {self.target}")
            sys.exit(1)

    def tcp_connect_probe(self, ip, port):
        """Attempt a full TCP connection to determine port state."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect_ex((ip, port))
            service_name = SERVICE_DB.get(port, ("unknown", ""))[0]
            banner = self._grab_banner(sock)
            return {
                "port": port,
                "state": "open",
                "service": service_name,
                "banner": banner.strip() if banner else ""
            }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return {"port": port, "state": "closed", "service": "", "banner": ""}
        finally:
            sock.close()

    def _grab_banner(self, sock):
        """Read a service banner after connecting."""
        try:
            sock.settimeout(2)
            return sock.recv(1024).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def scan(self):
        """Execute the port scan across all threads."""
        ip = self.resolve_host()
        print(f"[*] Scanning {len(self.ports)} ports on {ip} with {self.max_threads} threads")
        start_time = datetime.now()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.tcp_connect_probe, ip, port): port
                for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result["state"] == "open":
                    with self.lock:
                        self.open_ports.append(result)
                    print(f"  [OPEN] {result['port']}/{result['service']}")

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n[+] Scan complete: {len(self.open_ports)} open ports found in {elapsed:.2f}s")
        return self.open_ports


def arp_discover(subnet):
    """Discover live hosts on a local subnet via ARP."""
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print("[-] scapy required for ARP discovery: pip install scapy")
        return []

    arp = ARP(pdst=str(subnet))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    answered, _ = srp(packet, timeout=3, verbose=False)

    hosts = []
    for _, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
        print(f"  [+] {received.psrc}  ({received.hwsrc})")
    return hosts


def syn_scan(target_ip, port):
    """Perform a SYN half-open scan on a single port."""
    try:
        from scapy.all import IP, TCP, sr1, RandShort
    except ImportError:
        return {"port": port, "state": "error", "detail": "scapy not installed"}

    src_port = RandShort()
    syn = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")
    response = sr1(syn, timeout=2, verbose=False)

    if response is None:
        return {"port": port, "state": "filtered"}
    elif response[TCP].flags == 0x12:
        rst = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
        sr1(rst, timeout=1, verbose=False)
        return {"port": port, "state": "open"}
    elif response[TCP].flags == 0x14:
        return {"port": port, "state": "closed"}
    return {"port": port, "state": "unknown"}


def os_fingerprint(target_ip):
    """Determine OS based on TCP window size and TTL patterns."""
    try:
        from scapy.all import IP, TCP, sr1
    except ImportError:
        return {"os": "unknown", "detail": "scapy required"}

    probes = [
        ({"flags": "S", "window": 1024}, "Linux"),
        ({"flags": "S", "window": 8192}, "Windows"),
        ({"flags": "S", "window": 65535}, "FreeBSD"),
    ]

    for params, os_name in probes:
        pkt = IP(dst=target_ip) / TCP(
            dport=80,
            flags=params["flags"],
            window=params["window"]
        )
        resp = sr1(pkt, timeout=2, verbose=False)
        if resp and resp.haslayer(TCP):
            ttl = resp[IP].ttl
            win = resp[TCP].window
            if ttl <= 64 and win == 1024:
                return {"os": "Linux/Unix", "ttl": ttl, "window": win}
            elif 64 < ttl <= 128 and win == 8192:
                return {"os": "Windows", "ttl": ttl, "window": win}
            elif ttl > 128:
                return {"os": "Network Device/Other", "ttl": ttl, "window": win}
    return {"os": "unknown"}


def export_results(results, fmt="json", filepath=None):
    """Write scan results in the requested format."""
    if fmt == "json":
        content = json.dumps(results, indent=2)
    elif fmt == "csv":
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["port", "state", "service", "banner"])
        writer.writeheader()
        for r in results:
            writer.writerow(r)
        content = buf.getvalue()
    else:
        content = "\n".join(
            f"  {r['port']}/{r['service']:15s} {r['state']:10s} {r.get('banner','')}"
            for r in results
        )

    if filepath:
        with open(filepath, "w") as f:
            f.write(content)
        print(f"[+] Results saved to {filepath}")
    else:
        print(content)


def build_parser():
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Port scanning and service detection tool"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")
    parser.add_argument("-p", "--ports", help="Comma-separated ports or range (e.g. 1-1024)")
    parser.add_argument("-s", "--scan-type", choices=["tcp", "syn"], default="tcp",
                        help="Scanning technique to use")
    parser.add_argument("-j", "--threads", type=int, default=200, help="Thread count")
    parser.add_argument("-T", "--timeout", type=float, default=2, help="Socket timeout")
    parser.add_argument("-o", "--output", choices=["text", "json", "csv"], default="json")
    parser.add_argument("-f", "--file", help="Write results to file")
    parser.add_argument("--discover", action="store_true", help="Run ARP host discovery")
    parser.add_argument("-O", "--os-detect", action="store_true", help="Fingerprint remote OS")
    parser.add_argument("-sV", "--service-detection", action="store_true")
    return parser


def parse_ports(port_str):
    """Convert a port string into a list of integers."""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return ports


if __name__ == "__main__":
    args = build_parser().parse_args()
    ports = parse_ports(args.ports) if args.ports else None

    scanner = PortScanner(
        target=args.target,
        port_range=ports,
        max_threads=args.threads,
        timeout=args.timeout
    )
    results = scanner.scan()
    export_results(results, fmt=args.output, filepath=args.file)

    if args.os_detect:
        ip = scanner.resolve_host()
        os_info = os_fingerprint(ip)
        print(f"\n[+] OS Fingerprint: {os_info}")
```

---

## Port Scanning Techniques

### TCP Connect Scan (`-sT`)

Completes the full three-way handshake. Reliable but easily logged by the target.

```
Scanner -> SYN     -> Target
Scanner <- SYN-ACK <- Target
Scanner -> ACK     -> Target
```

### SYN Stealth Scan (`-sS`)

Sends a SYN and never completes the handshake. Faster and stealthier but requires root privileges.

```
Scanner -> SYN     -> Target
Scanner <- SYN-ACK <- Target
Scanner -> RST     -> Target   (connection torn down)
```

### UDP Scan (`-sU`)

Sends empty datagrams. Slow because most systems rate-limit ICMP port-unreachable messages. Useful for DNS (53), SNMP (161), and NTP (123).

### ACK Scan (`-sA`)

Probes firewall rules by checking whether packets are filtered or returned with RST.

---

## Service Detection

The scanner matches open ports against a local database of known services, then attempts banner grabbing to extract version strings.

```python
def detect_service(ip, port):
    """Connect to an open port and read its banner."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((ip, port))
        # Send a generic request to trigger a banner
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(4096).decode("utf-8", errors="ignore")
        return banner.split("\n")[0].strip()
    except Exception:
        return SERVICE_DB.get(port, ("unknown", ""))[0]
    finally:
        sock.close()
```

---

## OS Fingerprinting

Operates by analyzing TCP window size, TTL values, and option field patterns in probe responses.

| OS Family | Typical TTL | Typical Window Size |
|-----------|-------------|---------------------|
| Linux     | 64          | 29200, 5840, 1024  |
| Windows   | 128         | 8192, 65535        |
| macOS     | 64          | 65535              |
| Cisco IOS | 255         | 4128, 65535        |
| FreeBSD   | 64          | 65535              |

---

## Contributing

Contributions welcome. Fork the repo, create a feature branch, and open a pull request.

```bash
git checkout -b feature/your-feature
git commit -m "Add your feature"
git push origin feature/your-feature
```

---

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal. Always obtain written authorization before scanning. The author assumes no liability for misuse.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

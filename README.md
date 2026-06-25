# 🛡 CodeAlpha Network Sniffer

> A professional, enterprise-grade network packet analyzer built with **Python**, **Scapy**, and **Rich**.  
> Captures, dissects, and reports on live network traffic in real time.

---

## ✨ Features

- 🔍 **Live packet capture** on any network interface using Scapy
- 🎨 **Colourised terminal output** — each protocol has its own colour (TCP=blue, UDP=green, DNS=cyan, HTTP=magenta, ICMP=yellow)
- 🧩 **Deep protocol dissection** — Ethernet → IP → TCP/UDP/ICMP → DNS/HTTP
- 📊 **Real-time statistics** — protocol distribution, packet counts, byte totals
- 🗂 **Session tracker** — monitors unique src:port → dst:port flows
- 🔬 **Hex + ASCII dump** — Wireshark-style payload viewer (`--verbose` mode)
- 📄 **HTML & JSON report export** — polished, self-contained report auto-saved after capture
- 🎛 **BPF filter support** — filter by protocol, port, or IP using standard Berkeley Packet Filter syntax
- 🖥 **Cross-platform** — Windows (Npcap) · Linux · macOS

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/AbdelAziz/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
```

### 2. Create a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Install packet capture driver

| OS | Driver | Notes |
|---|---|---|
| Windows | [Npcap](https://npcap.com/#download) | Check "WinPcap API-compatible mode" during install |
| Linux | libpcap (pre-installed on most distros) | Run with `sudo` |
| macOS | libpcap (pre-installed) | Run with `sudo` |

---

## 🎮 Usage

```bash
# List available network interfaces
python sniffer.py --list-interfaces

# Capture 100 packets on Wi-Fi
python sniffer.py -i "Wi-Fi" -c 100

# Capture only DNS traffic (infinite, press Ctrl+C to stop)
python sniffer.py -i eth0 -f "udp port 53"

# Capture TCP with hex dump of payloads
python sniffer.py -i eth0 -c 200 -f "tcp port 80" -v

# Save HTML report to a specific path
python sniffer.py -i "Wi-Fi" -c 500 -o reports/my_capture.html

# Save JSON report
python sniffer.py -i eth0 -c 100 -o reports/capture.json
```

### CLI Flags

| Flag | Description | Default |
|---|---|---|
| `-i` / `--interface` | Network interface to capture on | Auto-detect |
| `-c` / `--count` | Packets to capture (0 = infinite) | `0` |
| `-f` / `--filter` | BPF filter string | None (capture all) |
| `-o` / `--output` | Output file (`.html` or `.json`) | Auto-timestamped HTML |
| `-v` / `--verbose` | Show hex+ASCII dump per packet | Off |
| `--list-interfaces` | Print interfaces and exit | — |

---

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer.py              ← Main entry point & capture engine
├── parsers/
│   ├── ip_parser.py        ← IP header dissection
│   ├── tcp_parser.py       ← TCP flags, ports, sequence numbers
│   ├── udp_parser.py       ← UDP header fields
│   ├── icmp_parser.py      ← ICMP type/code decoder
│   ├── dns_parser.py       ← DNS query & response parser
│   └── http_parser.py      ← HTTP/1.x request & response parser
├── core/
│   ├── session_tracker.py  ← Tracks unique network sessions
│   └── hex_dump.py         ← Hex + ASCII payload formatter
├── output/
│   ├── json_exporter.py    ← JSON report writer
│   └── html_exporter.py    ← Self-contained HTML report generator
├── reports/                ← Auto-generated capture reports
├── screenshots/            ← Demo screenshots for README
├── requirements.txt
└── README.md
```

---

## 🧪 BPF Filter Examples

```bash
# Only TCP traffic
python sniffer.py -i eth0 -f "tcp"

# Only DNS queries
python sniffer.py -i eth0 -f "udp port 53"

# Only HTTP traffic
python sniffer.py -i eth0 -f "tcp port 80"

# Traffic to/from a specific IP
python sniffer.py -i eth0 -f "host 8.8.8.8"

# Exclude ARP traffic
python sniffer.py -i eth0 -f "not arp"
```

---

## 🛠 Technologies

| Library | Purpose |
|---|---|
| [Scapy](https://scapy.net/) | Packet capture and protocol dissection |
| [Rich](https://rich.readthedocs.io/) | Colourised terminal output and tables |
| [Colorama](https://pypi.org/project/colorama/) | Windows ANSI colour support |
| Python stdlib | argparse, signal, threading, json, re |

---

## ⚠️ Important Note

This tool is built for **educational and ethical purposes** as part of the CodeAlpha Cyber Security Internship.  
Always obtain proper authorisation before capturing traffic on any network.

---

## 👤 Author

**AbdelAziz Moustafa**  
Computer Science — Cyber Security, Pharos University, Alexandria  
[LinkedIn](https://linkedin.com/in/abdelaziz) · [GitHub](https://github.com/AbdelAziz)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

*CodeAlpha Internship — Cyber Security Task 1*

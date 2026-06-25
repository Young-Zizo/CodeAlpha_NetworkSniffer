#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          CodeAlpha Network Sniffer — Task 1                  ║
║          Author : AbdelAziz Moustafa                         ║
║          GitHub : CodeAlpha_NetworkSniffer                   ║
╚══════════════════════════════════════════════════════════════╝

A professional packet analyzer built with Scapy and Rich.
Captures, dissects, and reports on live network traffic.

Usage:
    python sniffer.py --list-interfaces
    python sniffer.py -i "Wi-Fi" -c 100 -f "tcp" -v
    python sniffer.py -i eth0 -c 200 -f "udp port 53" -o reports/dns.html
"""

import argparse
import sys
import signal
import time
import threading
from datetime import datetime

# ── Scapy imports ──────────────────────────────────────────────────────────────
# Suppress Scapy's IPv6 warning on import
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (
    sniff,
    get_if_list,
    conf,
    IP, IPv6,
    TCP, UDP, ICMP,
    DNS, DNSQR, DNSRR,
    Raw,
    Ether,
)

# ── Rich imports ───────────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns
from rich import box
from rich.style import Style

# ── Internal modules ───────────────────────────────────────────────────────────
from parsers.ip_parser    import parse_ip
from parsers.tcp_parser   import parse_tcp
from parsers.udp_parser   import parse_udp
from parsers.icmp_parser  import parse_icmp
from parsers.dns_parser   import parse_dns
from parsers.http_parser  import parse_http
from core.session_tracker import SessionTracker
from core.hex_dump        import hex_dump_rich as hex_dump
from output.json_exporter import export_json
from output.html_exporter import export_html

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════

console = Console()

# All captured packets stored as list of dicts for export
captured_packets: list[dict] = []

# Protocol counters  {protocol_name: {"count": int, "bytes": int}}
protocol_stats: dict[str, dict] = {}

# Session tracker instance (manages src/dst pair state)
session_tracker = SessionTracker()

# CLI arguments (populated after parse_args())
args = None

# Capture start time
start_time: float = 0.0

# Flag to signal graceful shutdown
stop_event = threading.Event()

# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOL COLOUR MAP
# ══════════════════════════════════════════════════════════════════════════════

PROTO_STYLE: dict[str, str] = {
    "TCP":   "bold blue",
    "UDP":   "bold green",
    "ICMP":  "bold yellow",
    "DNS":   "bold cyan",
    "HTTP":  "bold magenta",
    "IPv6":  "bold bright_blue",
    "OTHER": "dim white",
}


def proto_style(name: str) -> str:
    return PROTO_STYLE.get(name.upper(), PROTO_STYLE["OTHER"])


# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

def print_banner(interface: str, bpf_filter: str, packet_limit: int) -> None:
    """Print the startup banner with capture configuration."""
    title = Text()
    title.append("🛡  CodeAlpha Network Sniffer", style="bold white")

    lines = [
        f"[bold]Interface :[/bold]  [cyan]{interface}[/cyan]",
        f"[bold]BPF Filter:[/bold]  [yellow]{bpf_filter or 'none (capture all)'}[/yellow]",
        f"[bold]Pkt Limit :[/bold]  [green]{'∞  (Ctrl+C to stop)' if packet_limit == 0 else packet_limit}[/green]",
        f"[bold]Started   :[/bold]  [white]{datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}[/white]",
        "",
        "[dim]Tip: Use -v for hex dumps · Use -o <file.html> to export a report[/dim]",
    ]

    console.print(Panel(
        "\n".join(lines),
        title="[bold white]🛡  CodeAlpha Network Sniffer[/bold white]",
        subtitle="[dim]github.com/AbdelAziz/CodeAlpha_NetworkSniffer[/dim]",
        border_style="bright_blue",
        padding=(1, 2),
    ))


# ══════════════════════════════════════════════════════════════════════════════
# STATISTICS TABLE (rendered live and on-demand)
# ══════════════════════════════════════════════════════════════════════════════

def build_stats_table() -> Table:
    """Build a Rich table from the current protocol_stats dict."""
    table = Table(
        title="[bold]Protocol Statistics[/bold]",
        box=box.ROUNDED,
        border_style="bright_black",
        show_header=True,
        header_style="bold white on grey23",
        min_width=52,
    )
    table.add_column("Protocol", style="bold", min_width=10)
    table.add_column("Packets",  justify="right", min_width=10)
    table.add_column("Bytes",    justify="right", min_width=12)
    table.add_column("Share",    justify="right", min_width=10)

    total_pkts = sum(v["count"] for v in protocol_stats.values()) or 1

    for proto, data in sorted(protocol_stats.items(), key=lambda x: -x[1]["count"]):
        share = data["count"] / total_pkts * 100
        bar   = "█" * int(share / 5)   # 1 block per 5%
        table.add_row(
            Text(proto, style=proto_style(proto)),
            str(data["count"]),
            f'{data["bytes"]:,} B',
            f"{bar}  {share:.1f}%",
        )

    return table


def build_session_table() -> Table:
    """Build a Rich table of the top 10 active sessions."""
    table = Table(
        title="[bold]Top Sessions[/bold]",
        box=box.ROUNDED,
        border_style="bright_black",
        show_header=True,
        header_style="bold white on grey23",
        min_width=72,
    )
    table.add_column("Source",      min_width=22)
    table.add_column("→", justify="center", min_width=3)
    table.add_column("Destination", min_width=22)
    table.add_column("Pkts",  justify="right", min_width=6)
    table.add_column("Bytes", justify="right", min_width=10)

    top = session_tracker.top(10)
    for sess in top:
        src = f"{sess['src_ip']}:{sess['src_port']}"
        dst = f"{sess['dst_ip']}:{sess['dst_port']}"
        table.add_row(
            Text(src, style="cyan"),
            Text("→", style="dim"),
            Text(dst, style="yellow"),
            str(sess["packets"]),
            f"{sess['bytes']:,} B",
        )

    return table


def print_stats_summary() -> None:
    """Print final statistics tables after capture ends."""
    elapsed = time.time() - start_time
    total   = sum(v["count"] for v in protocol_stats.values())

    console.print()
    console.print(Panel(
        f"[bold green]✓ Capture complete[/bold green]\n"
        f"  Packets  : [white]{total}[/white]\n"
        f"  Duration : [white]{elapsed:.1f}s[/white]\n"
        f"  Rate     : [white]{total/elapsed:.1f} pkt/s[/white]",
        border_style="green",
    ))
    console.print()
    console.print(build_stats_table())
    console.print()
    console.print(build_session_table())


# ══════════════════════════════════════════════════════════════════════════════
# PACKET CALLBACK — the heart of Phase 3
# ══════════════════════════════════════════════════════════════════════════════

def packet_callback(packet) -> None:
    """
    Called by Scapy for every captured packet.

    Responsibilities:
      1. Determine which protocol layers are present.
      2. Route to the correct parser(s) to extract fields.
      3. Update protocol_stats and session_tracker.
      4. Print a colourised one-line summary to the terminal.
      5. Optionally print a hex dump (--verbose mode).
      6. Append metadata to captured_packets for export.
    """

    # ── 1. Determine packet size ───────────────────────────────────────────────
    pkt_len  = len(packet)
    pkt_time = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm

    # ── 2. Extract IP layer info ───────────────────────────────────────────────
    ip_info  = {}
    proto    = "OTHER"

    if packet.haslayer(IP):
        ip_info = parse_ip(packet)
        proto   = "IP"
    elif packet.haslayer(IPv6):
        ip_info = {
            "src": str(packet[IPv6].src),
            "dst": str(packet[IPv6].dst),
            "ttl": packet[IPv6].hlim,
            "len": pkt_len,
        }
        proto = "IPv6"

    src_ip  = ip_info.get("src", "?")
    dst_ip  = ip_info.get("dst", "?")

    # ── 3. Determine transport-layer protocol and extract info ─────────────────
    transport_info = {}
    src_port = 0
    dst_port = 0
    extra    = ""   # short descriptive string appended to the output line

    if packet.haslayer(DNS):
        # DNS sits on top of UDP — check DNS before UDP so it gets labelled DNS
        proto          = "DNS"
        transport_info = parse_dns(packet)
        src_port       = transport_info.get("src_port", 0)
        dst_port       = transport_info.get("dst_port", 0)
        extra          = transport_info.get("summary", "")

    elif packet.haslayer(TCP):
        proto          = "TCP"
        transport_info = parse_tcp(packet)
        src_port       = transport_info.get("src_port", 0)
        dst_port       = transport_info.get("dst_port", 0)
        flags          = transport_info.get("flags_str", "")
        extra          = flags

        # HTTP detection — plain TCP port 80 with Raw payload
        if packet.haslayer(Raw) and (src_port == 80 or dst_port == 80):
            http_info = parse_http(packet)
            if http_info:
                proto = "HTTP"
                extra = http_info.get("summary", flags)
                transport_info.update(http_info)

    elif packet.haslayer(UDP):
        proto          = "UDP"
        transport_info = parse_udp(packet)
        src_port       = transport_info.get("src_port", 0)
        dst_port       = transport_info.get("dst_port", 0)

    elif packet.haslayer(ICMP):
        proto          = "ICMP"
        transport_info = parse_icmp(packet)
        extra          = transport_info.get("type_str", "")

    # ── 4. Update protocol statistics ─────────────────────────────────────────
    if proto not in protocol_stats:
        protocol_stats[proto] = {"count": 0, "bytes": 0}
    protocol_stats[proto]["count"] += 1
    protocol_stats[proto]["bytes"] += pkt_len

    # ── 5. Update session tracker ──────────────────────────────────────────────
    if src_ip != "?" and dst_ip != "?":
        session_tracker.update(src_ip, dst_ip, src_port, dst_port, pkt_len)

    # ── 6. Build and print one-line colourised summary ─────────────────────────
    style   = proto_style(proto)
    src_str = f"{src_ip}:{src_port}" if src_port else src_ip
    dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

    line = Text()
    line.append(f"[{pkt_time}] ", style="dim white")
    line.append(f"{proto:<5}", style=style)
    line.append(f"  {src_str:<26}", style="cyan")
    line.append("→ ", style="dim")
    line.append(f"{dst_str:<26}", style="yellow")
    line.append(f"  {extra:<12}", style="white")
    line.append(f"  {pkt_len}B", style="dim green")

    console.print(line)

    # ── 7. Optional hex dump (--verbose) ──────────────────────────────────────
    if args and args.verbose and packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        if raw_bytes:
            console.print(hex_dump(raw_bytes), style="dim")

    # ── 8. Store packet metadata for export ───────────────────────────────────
    record = {
        "time":      pkt_time,
        "proto":     proto,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "length":    pkt_len,
        "extra":     extra,
        **ip_info,
        **transport_info,
    }
    captured_packets.append(record)


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE LISTING
# ══════════════════════════════════════════════════════════════════════════════

def list_interfaces() -> None:
    """Pretty-print all available network interfaces."""
    interfaces = get_if_list()
    table = Table(
        title="[bold]Available Network Interfaces[/bold]",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=True,
        header_style="bold white on grey23",
    )
    table.add_column("#",         justify="right",  style="dim", min_width=4)
    table.add_column("Interface", style="bold cyan", min_width=30)

    for idx, iface in enumerate(interfaces, start=1):
        marker = "  ← [green]default[/green]" if iface == conf.iface else ""
        table.add_row(str(idx), iface + marker)

    console.print(table)
    console.print(
        "\n[dim]Use the interface name with [bold]-i[/bold] / [bold]--interface[/bold][/dim]\n"
        "[dim]Example:  python sniffer.py -i \"Wi-Fi\" -c 100[/dim]\n"
    )


# ══════════════════════════════════════════════════════════════════════════════
# GRACEFUL SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════

def handle_sigint(sig, frame) -> None:
    """Handle Ctrl+C: print stats and export if requested."""
    console.print("\n\n[bold yellow]⚠  Capture interrupted by user.[/bold yellow]")
    finalize()
    sys.exit(0)


def finalize() -> None:
    """Print final stats and export reports."""
    print_stats_summary()

    if args and args.output:
        path = args.output
        if path.endswith(".json"):
            export_json(captured_packets, protocol_stats, session_tracker, path)
            console.print(f"\n[bold green]✓ JSON report saved →[/bold green] [cyan]{path}[/cyan]")
        else:
            export_html(captured_packets, protocol_stats, session_tracker, path)
            console.print(f"\n[bold green]✓ HTML report saved →[/bold green] [cyan]{path}[/cyan]")
    elif captured_packets:
        # Auto-save HTML report to reports/ directory
        ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = f"reports/capture_{ts}.html"
        export_html(captured_packets, protocol_stats, session_tracker, path)
        console.print(f"\n[bold green]✓ HTML report auto-saved →[/bold green] [cyan]{path}[/cyan]")


# ══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════════════════

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="CodeAlpha Network Sniffer — Professional packet analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py --list-interfaces
  python sniffer.py -i "Wi-Fi" -c 100
  python sniffer.py -i eth0 -c 500 -f "tcp port 80" -v
  python sniffer.py -i eth0 -c 200 -f "udp port 53" -o reports/dns_capture.html
        """,
    )

    parser.add_argument(
        "-i", "--interface",
        default=None,
        metavar="IFACE",
        help="Network interface to sniff on (default: auto-detect)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        metavar="N",
        help="Number of packets to capture. 0 = infinite (default: 0)",
    )
    parser.add_argument(
        "-f", "--filter",
        default=None,
        metavar="BPF",
        help='BPF filter string, e.g. "tcp port 80" or "udp port 53"',
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Output file path for the report (.html or .json)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show hex+ASCII dump for every packet payload",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List all available network interfaces and exit",
    )

    return parser


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    global args, start_time

    parser = build_arg_parser()
    args   = parser.parse_args()

    # ── --list-interfaces ──────────────────────────────────────────────────────
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # ── Resolve interface ──────────────────────────────────────────────────────
    interface = args.interface or str(conf.iface)

    # Validate interface exists
    if interface not in get_if_list():
        console.print(
            f"[bold red]✗ Interface '[cyan]{interface}[/cyan]' not found.[/bold red]\n"
            f"  Run [bold]python sniffer.py --list-interfaces[/bold] to see available interfaces."
        )
        sys.exit(1)

    # ── Print banner ───────────────────────────────────────────────────────────
    print_banner(interface, args.filter, args.count)

    # ── Register Ctrl+C handler ────────────────────────────────────────────────
    signal.signal(signal.SIGINT, handle_sigint)

    # ── Start capture ──────────────────────────────────────────────────────────
    start_time = time.time()

    console.print(
        f"\n[bold green]▶  Sniffing on [cyan]{interface}[/cyan] …"
        f"{'  (press Ctrl+C to stop)' if args.count == 0 else f'  capturing {args.count} packets'}[/bold green]\n"
    )

    try:
        sniff(
            iface   = interface,
            prn     = packet_callback,        # called for every packet
            count   = args.count,             # 0 = sniff forever
            filter  = args.filter,            # BPF filter (None = capture all)
            store   = False,                  # don't store in memory — we handle that
        )
    except PermissionError:
        console.print(
            "\n[bold red]✗ Permission denied.[/bold red]\n"
            "  On Linux/Mac, run with [bold]sudo[/bold].\n"
            "  On Windows, make sure Npcap is installed and run as Administrator."
        )
        sys.exit(1)
    except OSError as e:
        console.print(f"\n[bold red]✗ OS Error: {e}[/bold red]")
        sys.exit(1)

    # ── Capture finished normally (--count reached) ────────────────────────────
    finalize()


if __name__ == "__main__":
    main()

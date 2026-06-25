"""
parsers/tcp_parser.py
─────────────────────
Extracts TCP (Layer 4) header fields from a Scapy packet.
"""

from scapy.all import TCP

# TCP flag bit positions
TCP_FLAGS: dict[str, int] = {
    "FIN": 0x001,
    "SYN": 0x002,
    "RST": 0x004,
    "PSH": 0x008,
    "ACK": 0x010,
    "URG": 0x020,
    "ECE": 0x040,
    "CWR": 0x080,
}

# Well-known port → service name
WELL_KNOWN_PORTS: dict[int, str] = {
    20:   "FTP-data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017:"MongoDB",
}


def decode_flags(flags_int: int) -> list[str]:
    """Decode raw integer flags into list of strings."""
    set_flags = []
    for name, bit in TCP_FLAGS.items():
        if flags_int & bit:
            set_flags.append(name)
    return set_flags


def parse_tcp(packet) -> dict:
    """
    Parse the TCP layer of a packet.
    """
    if not packet.haslayer(TCP):
        return {}

    tcp = packet[TCP]

    flags_int  = int(tcp.flags)
    flags_list = decode_flags(flags_int)
    flags_str  = " ".join(flags_list) if flags_list else "—"

    try:
        payload_len = len(bytes(tcp.payload))
    except Exception:
        payload_len = 0

    return {
        "src_port":   int(tcp.sport),
        "dst_port":   int(tcp.dport),
        "src_svc":    WELL_KNOWN_PORTS.get(int(tcp.sport), ""),
        "dst_svc":    WELL_KNOWN_PORTS.get(int(tcp.dport), ""),
        "flags_int":  flags_int,
        "flags_list": flags_list,
        "flags_str":  flags_str,
        "seq":        int(tcp.seq),
        "ack":        int(tcp.ack),
        "window":     int(tcp.window),
        "data_off":   int(tcp.dataofs) * 4,
        "checksum":   int(tcp.chksum),
        "payload_len": payload_len,
    }
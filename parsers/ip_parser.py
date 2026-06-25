"""
parsers/ip_parser.py
────────────────────
Extracts fields from the IP (Layer 3) header of a Scapy packet.
Returns a plain dict so the caller never needs to import Scapy layers directly.
"""

from scapy.all import IP

# IP protocol number → human-readable name
PROTO_MAP: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6-in-IPv4",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

# IP flags bitmask → string
FLAGS_MAP: dict[int, str] = {
    0x0: "",
    0x1: "MF",       # More Fragments
    0x2: "DF",       # Don't Fragment
    0x3: "MF+DF",
}


def parse_ip(packet) -> dict:
    """
    Parse the IP layer of a packet.

    Returns:
        dict with keys:
            src       – source IP address (str)
            dst       – destination IP address (str)
            ttl       – time-to-live (int)
            proto_num – IP protocol number (int)
            proto_str – human-readable protocol name (str)
            length    – total IP datagram length in bytes (int)
            flags_str – DF / MF flags as string (str)
            frag_off  – fragment offset (int)
            tos       – type of service byte (int)
            checksum  – header checksum (int)
            version   – IP version, always 4 here (int)
    """
    if not packet.haslayer(IP):
        return {}

    ip = packet[IP]

    flags_val = int(ip.flags)
    flags_str = FLAGS_MAP.get(flags_val, str(flags_val))

    return {
        "src":       str(ip.src),
        "dst":       str(ip.dst),
        "ttl":       int(ip.ttl),
        "proto_num": int(ip.proto),
        "proto_str": PROTO_MAP.get(int(ip.proto), f"proto-{ip.proto}"),
        "length":    int(ip.len),
        "flags_str": flags_str,
        "frag_off":  int(ip.frag),
        "tos":       int(ip.tos),
        "checksum":  int(ip.chksum) if ip.chksum else 0,
        "version":   int(ip.version),
    }

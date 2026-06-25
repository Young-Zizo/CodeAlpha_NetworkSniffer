"""
parsers/udp_parser.py
─────────────────────
Extracts UDP (Layer 4) header fields from a Scapy packet.
"""

from scapy.all import UDP

WELL_KNOWN_UDP_PORTS: dict[int, str] = {
    53:   "DNS",
    67:   "DHCP-server",
    68:   "DHCP-client",
    69:   "TFTP",
    123:  "NTP",
    161:  "SNMP",
    162:  "SNMP-trap",
    500:  "IKE/VPN",
    514:  "Syslog",
    1194: "OpenVPN",
    1900: "SSDP/UPnP",
    4500: "IKE-NAT",
    5353: "mDNS",
    5355: "LLMNR",
}


def parse_udp(packet) -> dict:
    """
    Parse the UDP layer of a packet.
    """
    if not packet.haslayer(UDP):
        return {}

    udp = packet[UDP]

    try:
        payload_len = len(bytes(udp.payload))
    except Exception:
        payload_len = 0

    return {
        "src_port":   int(udp.sport),
        "dst_port":   int(udp.dport),
        "src_svc":    WELL_KNOWN_UDP_PORTS.get(int(udp.sport), ""),
        "dst_svc":    WELL_KNOWN_UDP_PORTS.get(int(udp.dport), ""),
        "length":     int(udp.len),
        "checksum":   int(udp.chksum),
        "payload_len": payload_len,
    }
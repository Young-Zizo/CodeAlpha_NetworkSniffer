"""
parsers/icmp_parser.py
──────────────────────
Extracts ICMP header fields and decodes type/code combinations
into human-readable descriptions.
"""

from scapy.all import ICMP

# ICMP type → (name, {code → meaning})
ICMP_TYPES: dict[int, tuple[str, dict[int, str]]] = {
    0:  ("Echo Reply",        {0: "Echo reply"}),
    3:  ("Destination Unreachable", {
            0: "Net unreachable",
            1: "Host unreachable",
            2: "Protocol unreachable",
            3: "Port unreachable",
            4: "Fragmentation needed",
            5: "Source route failed",
            6: "Dest network unknown",
            7: "Dest host unknown",
            9: "Network admin prohibited",
           10: "Host admin prohibited",
           11: "TOS net unreachable",
           12: "TOS host unreachable",
           13: "Comm admin prohibited",
        }),
    4:  ("Source Quench",     {0: "Source quench"}),
    5:  ("Redirect",          {
            0: "Redirect for network",
            1: "Redirect for host",
            2: "Redirect for TOS & network",
            3: "Redirect for TOS & host",
        }),
    8:  ("Echo Request",      {0: "Echo request (ping)"}),
    9:  ("Router Advertisement", {}),
    10: ("Router Solicitation",  {}),
    11: ("Time Exceeded",     {
            0: "TTL exceeded in transit",
            1: "Fragment reassembly exceeded",
        }),
    12: ("Parameter Problem",  {}),
    13: ("Timestamp Request",  {0: "Timestamp request"}),
    14: ("Timestamp Reply",   {0: "Timestamp reply"}),
    30: ("Traceroute",        {}),
}


def parse_icmp(packet) -> dict:
    """
    Parse the ICMP layer of a packet.
    """
    if not packet.haslayer(ICMP):
        return {}

    icmp = packet[ICMP]

    type_num = int(icmp.type)
    code_num = int(icmp.code)

    type_entry = ICMP_TYPES.get(type_num, ("Unknown", {}))
    type_str   = type_entry[0]
    code_str   = type_entry[1].get(code_num, f"code-{code_num}")

    pkt_id  = getattr(icmp, "id",  0) or 0
    pkt_seq = getattr(icmp, "seq", 0) or 0

    summary = type_str
    if type_num in (0, 8):
        summary = f"{type_str} (id={pkt_id} seq={pkt_seq})"

    return {
        "type_num": type_num,
        "type_str": type_str,
        "code_num": code_num,
        "code_str": code_str,
        "checksum": int(icmp.chksum),
        "id":       pkt_id,
        "seq":      pkt_seq,
        "summary":  summary,
    }
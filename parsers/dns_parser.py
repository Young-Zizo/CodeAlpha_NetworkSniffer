"""
parsers/dns_parser.py
─────────────────────
Extracts DNS query and response fields from a Scapy packet.
Handles both questions and answer records.
"""

from scapy.all import DNS, DNSQR, DNSRR, UDP

# DNS record type number → name
QTYPE_MAP: dict[int, str] = {
    1:   "A",
    2:   "NS",
    5:   "CNAME",
    6:   "SOA",
    12:  "PTR",
    15:  "MX",
    16:  "TXT",
    28:  "AAAA",
    33:  "SRV",
    255: "ANY",
}

# DNS response code → meaning
RCODE_MAP: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _decode_name(name_bytes) -> str:
    """Safely decode a DNS name field to a plain string."""
    if isinstance(name_bytes, bytes):
        try:
            return name_bytes.decode("utf-8").rstrip(".")
        except Exception:
            return repr(name_bytes)
    return str(name_bytes).rstrip(".")


def parse_dns(packet) -> dict:
    """
    Parse the DNS layer of a packet.

    Returns:
        dict with keys:
            src_port    – source UDP port (int)
            dst_port    – destination UDP port (int)
            is_response – True if this is a DNS response (bool)
            id          – DNS transaction ID (int)
            rcode       – response code number (int)
            rcode_str   – response code name (str)
            questions   – list of {name, qtype, qtype_str} dicts
            answers     – list of {name, rtype, rtype_str, ttl, rdata} dicts
            summary     – one-line description for terminal display (str)
    """
    if not packet.haslayer(DNS):
        return {}

    dns = packet[DNS]

    src_port = int(packet[UDP].sport) if packet.haslayer(UDP) else 0
    dst_port = int(packet[UDP].dport) if packet.haslayer(UDP) else 0

    is_response = bool(dns.qr)   # qr=0 → query, qr=1 → response
    rcode       = int(dns.rcode)

    # ── Parse questions ────────────────────────────────────────────────────────
    questions = []
    if dns.qdcount and dns.qdcount > 0:
        qr = dns.qd
        while qr and isinstance(qr, DNSQR):
            qtype_num = int(qr.qtype)
            questions.append({
                "name":      _decode_name(qr.qname),
                "qtype":     qtype_num,
                "qtype_str": QTYPE_MAP.get(qtype_num, f"type-{qtype_num}"),
            })
            qr = qr.payload if hasattr(qr, "payload") and isinstance(qr.payload, DNSQR) else None

    # ── Parse answer records ───────────────────────────────────────────────────
    answers = []
    if is_response and dns.ancount and dns.ancount > 0:
        rr = dns.an
        while rr and isinstance(rr, DNSRR):
            rtype_num = int(rr.type)
            try:
                rdata = str(rr.rdata)
            except Exception:
                rdata = "?"
            answers.append({
                "name":      _decode_name(rr.rrname),
                "rtype":     rtype_num,
                "rtype_str": QTYPE_MAP.get(rtype_num, f"type-{rtype_num}"),
                "ttl":       int(rr.ttl),
                "rdata":     rdata,
            })
            rr = rr.payload if hasattr(rr, "payload") and isinstance(rr.payload, DNSRR) else None

    # ── Build summary string ───────────────────────────────────────────────────
    if questions:
        q   = questions[0]
        dir_arrow = "←" if is_response else "→"
        if is_response and answers:
            summary = f"{q['qtype_str']}? {q['name']}  {dir_arrow}  {answers[0]['rdata']}"
        else:
            summary = f"{q['qtype_str']}? {q['name']}"
    else:
        summary = "DNS (no question)"

    return {
        "src_port":    src_port,
        "dst_port":    dst_port,
        "is_response": is_response,
        "id":          int(dns.id),
        "rcode":       rcode,
        "rcode_str":   RCODE_MAP.get(rcode, f"rcode-{rcode}"),
        "questions":   questions,
        "answers":     answers,
        "summary":     summary,
    }

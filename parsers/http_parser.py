"""
parsers/http_parser.py
──────────────────────
Detects and parses plain-text HTTP/1.x from TCP Raw payloads.
"""

import re
from scapy.all import Raw, TCP

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}

RE_REQUEST  = re.compile(rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE) (\S+) HTTP/([\d.]+)", re.IGNORECASE)
RE_RESPONSE = re.compile(rb"^HTTP/([\d.]+) (\d{3}) (.+?)(?:\r\n|\n)", re.IGNORECASE)
RE_HOST     = re.compile(rb"Host: ([^\r\n]+)", re.IGNORECASE)
RE_UA       = re.compile(rb"User-Agent: ([^\r\n]+)", re.IGNORECASE)
RE_CT       = re.compile(rb"Content-Type: ([^\r\n]+)", re.IGNORECASE)
RE_CL       = re.compile(rb"Content-Length: (\d+)", re.IGNORECASE)


def parse_http(packet) -> dict:
    """
    Try to parse HTTP from a TCP packet's Raw payload.
    """
    if not packet.haslayer(Raw) or not packet.haslayer(TCP):
        return {}

    raw = bytes(packet[Raw].load)
    
    req_match = RE_REQUEST.match(raw)
    if req_match:
        method  = req_match.group(1).decode("utf-8", errors="replace").upper()
        uri     = req_match.group(2).decode("utf-8", errors="replace")
        version = req_match.group(3).decode("utf-8", errors="replace")

        host_match = RE_HOST.search(raw)
        host = host_match.group(1).decode("utf-8", errors="replace").strip() if host_match else ""

        ua_match = RE_UA.search(raw)
        user_agent = ua_match.group(1).decode("utf-8", errors="replace").strip() if ua_match else ""

        result = {
            "is_request":     True,
            "is_response":    False,
            "method":         method,
            "uri":            uri,
            "version":        version,
            "host":           host,
            "status_code":    0,
            "status_text":    "",
            "user_agent":     user_agent,
            "content_type":   "",
            "content_length": 0,
            "summary":        f"{method} {host}{uri}  HTTP/{version}",
        }
        return result

    resp_match = RE_RESPONSE.match(raw)
    if resp_match:
        version     = resp_match.group(1).decode("utf-8", errors="replace")
        status_code = int(resp_match.group(2))
        status_text = resp_match
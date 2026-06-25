"""
core/session_tracker.py
───────────────────────
Tracks network sessions (unique src_ip:port → dst_ip:port flows)
in memory during a capture session.
"""

from dataclasses import dataclass

@dataclass
class Session:
    src_ip:   str
    src_port: int
    dst_ip:   str
    dst_port: int
    packets:  int = 0
    bytes:    int = 0


class SessionTracker:
    def __init__(self) -> None:
        self._sessions: dict[tuple, Session] = {}

    def update(
        self,
        src_ip:   str,
        dst_ip:   str,
        src_port: int,
        dst_port: int,
        pkt_len:  int,
    ) -> None:
        key = (src_ip, src_port, dst_ip, dst_port)

        if key not in self._sessions:
            self._sessions[key] = Session(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

        sess = self._sessions[key]
        sess.packets += 1
        sess.bytes   += pkt_len

    def top(self, n: int = 10) -> list[dict]:
        sorted_sessions = sorted(
            self._sessions.values(),
            key=lambda s: s.packets,
            reverse=True,
        )
        return [
            {
                "src_ip":   s.src_ip,
                "src_port": s.src_port,
                "dst_ip":   s.dst_ip,
                "dst_port": s.dst_port,
                "packets":  s.packets,
                "bytes":    s.bytes,
            }
            for s in sorted_sessions[:n]
        ]

    def all(self) -> list[dict]:
        return [
            {
                "src_ip":   s.src_ip,
                "src_port": s.src_port,
                "dst_ip":   s.dst_ip,
                "dst_port": s.dst_port,
                "packets":  s.packets,
                "bytes":    s.bytes,
            }
            for s in self._sessions.values()
        ]
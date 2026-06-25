"""
output/json_exporter.py
───────────────────────
Exports captured packet metadata and statistics to a JSON file.
"""

import json
from datetime import datetime
from pathlib import Path

def export_json(
    packets:       list[dict],
    proto_stats:   dict[str, dict],
    session_tracker,
    output_path:   str,
) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    report = {
        "meta": {
            "generated_at":  datetime.now().isoformat(),
            "total_packets": len(packets),
            "tool":          "CodeAlpha Network Sniffer",
            "author":        "AbdelAziz Moustafa",
        },
        "stats":    proto_stats,
        "sessions": session_tracker.all(),
        "packets":  packets,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
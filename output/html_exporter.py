"""
output/html_exporter.py
───────────────────────
Generates a polished, self-contained single-file HTML report
from captured packet data. No external CSS/JS dependencies.
"""

from datetime import datetime
from pathlib import Path

# ── Inline CSS ─────────────────────────────────────────────────────────────────
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0f1117;
    color: #e2e8f0;
    font-size: 14px;
    line-height: 1.6;
}
.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }

/* ── Header ──────────────────────────────────────────────────────────────── */
.header {
    background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
}
.header-icon { font-size: 3rem; }
.header h1 { font-size: 1.8rem; font-weight: 700; color: #63b3ed; }
.header .subtitle { color: #a0aec0; margin-top: 0.25rem; font-size: 0.95rem; }

/* ── Summary Cards ──────────────────────────────────────────────────────── */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
.card { background: #1a202c; border: 1px solid #2d3748; border-radius: 10px; padding: 1.5rem; display: flex; flex-direction: column; }
.card-title { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #a0aec0; margin-bottom: 0.5rem; }
.card-value { font-size: 1.75rem; font-weight: 700; color: #fff; }

/* ── Sections ────────────────────────────────────────────────────────────── */
.section { background: #1a202c; border: 1px solid #2d3748; border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; }
.section h2 { font-size: 1.2rem; font-weight: 600; color: #cbd5e0; margin-bottom: 1.25rem; padding-bottom: 0.5rem; border-bottom: 2px solid #2d3748; }

/* ── Progress Bars (Charts) ──────────────────────────────────────────────── */
.bar-row { margin-bottom: 1rem; }
.bar-labels { display: flex; justify-content: space-between; margin-bottom: 0.25rem; font-size: 0.9rem; }
.bar-track { background: #2d3748; height: 10px; border-radius: 5px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 5px; }

/* ── Tables ──────────────────────────────────────────────────────────────── */
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th { background: #2d3748; color: #cbd5e0; font-weight: 600; padding: 0.75rem 1rem; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
td { padding: 0.75rem 1rem; border-bottom: 1px solid #2d3748; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
tr:hover td { background: #232d3f; }

/* ── Protocol Badges ─────────────────────────────────────────────────────── */
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
.bg-tcp  { background: rgba(66, 153, 225, 0.2); color: #63b3ed; border: 1px solid #4299e1; }
.bg-udp  { background: rgba(72, 187, 120, 0.2); color: #68d391; border: 1px solid #48bb78; }
.bg-icmp { background: rgba(236, 201, 75, 0.2); color: #f6e05e; border: 1px solid #ecc94a; }
.bg-dns  { background: rgba(0, 184, 212, 0.2);  color: #00e5ff; border: 1px solid #00b8d4; }
.bg-http { background: rgba(213, 63, 140, 0.2); color: #f687b3; border: 1px solid #d53f8c; }
.bg-other{ background: rgba(160, 174, 192, 0.2); color: #cbd5e0; border: 1px solid #a0aec0; }

.footer { text-align: center; color: #718096; font-size: 0.85rem; margin-top: 3rem; }
"""

def export_html(
    packets:       list[dict],
    proto_stats:   dict[str, dict],
    session_tracker,
    output_path:   str,
) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    total_pkts = len(packets)
    total_bytes = sum(d["bytes"] for d in proto_stats.values())
    total_kb = total_bytes / 1024

    # 1. Build Summary Cards
    cards_html = f"""
    <div class="cards">
      <div class="card">
        <span class="card-title">Total Packets</span>
        <span class="card-value">{total_pkts}</span>
      </div>
      <div class="card">
        <span class="card-title">Traffic Volume</span>
        <span class="card-value">{total_kb:.2f} KB</span>
      </div>
      <div class="card">
        <span class="card-title">Unique Sessions</span>
        <span class="card-value">{len(session_tracker.all())}</span>
      </div>
    </div>
    """

    # 2. Build Protocol Distribution Bars
    colors = {"TCP": "#4299e1", "UDP": "#48bb78", "ICMP": "#ecc94a", "DNS": "#00b8d4", "HTTP": "#d53f8c", "Other": "#a0aec0"}
    bars = []
    proto_rows = []

    for proto, data in proto_stats.items():
        pct = (data["count"] / total_pkts * 100) if total_pkts > 0 else 0
        if data["count"] > 0 or True:
            color = colors.get(proto, "#a0aec0")
            bars.append(f"""
            <div class="bar-row">
              <div class="bar-labels">
                <span>{proto}</span>
                <span>{data['count']} ({pct:.1f}%)</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" style="width: {pct}%; background-color: {color};"></div>
              </div>
            </div>
            """)
            
            proto_rows.append(f"""
            <tr>
              <td><span class="badge bg-{proto.lower()}">{proto}</span></td>
              <td>{data['count']}</td>
              <td>{data['bytes']/1024:.2f} KB</td>
              <td>{pct:.1f}%</td>
            </tr>
            """)

    # 3. Build Top Sessions Rows
    sess_rows = []
    for flow in session_tracker.top(15):
        src = f"{flow['src_ip']}:{flow['src_port']}" if flow['src_port'] else flow['src_ip']
        dst = f"{flow['dst_ip']}:{flow['dst_port']}" if flow['dst_port'] else flow['dst_ip']
        sess_rows.append(f"""
        <tr>
          <td>{src}</td>
          <td>{dst}</td>
          <td>{flow['packets']}</td>
          <td>{flow['bytes']/1024:.2f} KB</td>
        </tr>
        """)

    if not sess_rows:
        sess_rows.append("<tr><td colspan='4' style='text-align:center; color:#718096;'>No active sessions recorded</td></tr>")

    # 4. Build Packet Log Rows (Limit to last 500)
    pkt_rows = []
    for pkt in packets[-500:]:
        p_lower = pkt["proto"].lower()
        pkt_rows.append(f"""
        <tr>
          <td>{pkt.get('time','')}</td>
          <td><span class="badge bg-{p_lower}">{pkt.get('proto','?')}</span></td>
          <td style="color:#63b3ed;">{pkt.get('src', pkt.get('src_ip','?'))}</td>
          <td style="color:#63b3ed;">{pkt.get('dst', pkt.get('dst_ip','?'))}</td>
          <td>{pkt.get('info', pkt.get('extra',''))}</td>
          <td>{pkt.get('size', pkt.get('length',0))} B</td>
        </tr>
        """)

    if not pkt_rows:
        pkt_rows.append("<tr><td colspan='6' style='text-align:center; color:#718096;'>No packets logged</td></tr>")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 5. Full HTML Assembly
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CodeAlpha Network Sniffer Report</title>
  <style>{_CSS}</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="header-icon">🛡️</div>
    <div>
      <h1>CodeAlpha Network Sniffer Report</h1>
      <div class="subtitle">
        Captured by AbdelAziz Moustafa &nbsp;|&nbsp;
        github.com/AbdelAziz/CodeAlpha_NetworkSniffer
      </div>
    </div>
  </div>

  {cards_html}

  <div class="section">
    <h2>Protocol Distribution</h2>
    {"".join(bars)}
  </div>

  <div class="section">
    <h2>Protocol Statistics</h2>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Protocol</th><th>Packets</th><th>Data</th><th>Share</th></tr></thead>
        <tbody>{"".join(proto_rows)}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2>Top Sessions (by packet count)</h2>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Source</th><th>Destination</th><th>Packets</th><th>Data</th></tr></thead>
        <tbody>{"".join(sess_rows)}</tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2>Packet Log (last 500)</h2>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Protocol</th><th>Source</th>
            <th>Destination</th><th>Info</th><th>Size</th>
          </tr>
        </thead>
        <tbody>{"".join(pkt_rows)}</tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    CodeAlpha Internship — Cyber Security Task 1 &nbsp;|&nbsp;
    Built with Python 3 + Scapy + Rich &nbsp;|&nbsp;
    {generated_at}
  </div>

</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
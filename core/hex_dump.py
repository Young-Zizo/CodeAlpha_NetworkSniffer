"""
core/hex_dump.py
────────────────
Classic hex + ASCII side-by-side dump of raw bytes.
"""

_PRINTABLE = set(range(0x20, 0x7F))
MAX_DUMP_BYTES = 256

def hex_dump_rich(data: bytes, max_bytes: int = MAX_DUMP_BYTES) -> str:
    if not data:
        return ""

    data = data[:max_bytes]
    lines: list[str] = []

    for offset in range(0, len(data), 16):
        chunk = data[offset: offset + 16]

        hex_parts: list[str] = []
        ascii_parts: list[str] = []

        for i, byte in enumerate(chunk):
            hex_parts.append(f"[cyan]{byte:02x}[/cyan]")
            if i == 7:
                hex_parts.append(" ")
            ascii_parts.append(
                f"[yellow]{chr(byte)}[/yellow]" if byte in _PRINTABLE else "[dim].[/dim]"
            )

        pad_needed = 16 - len(chunk)
        if pad_needed > 0:
            for i in range(pad_needed):
                hex_parts.append("  ")
                if (len(chunk) + i) == 7:
                    hex_parts.append(" ")

        hex_str = " ".join(hex_parts)
        ascii_str = "".join(ascii_parts)

        lines.append(f"  [dim]{offset:04x}[/dim]   {hex_str}   {ascii_str}")

    return "\n".join(lines)
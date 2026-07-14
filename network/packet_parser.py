# Dynamic Scapy checks
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    pass

def parse_scapy_packet(pkt):
    """Parse raw scapy packet into standard dict structure."""
    if not SCAPY_AVAILABLE or not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    ttl = ip_layer.ttl
    proto = "OTHER"
    src_port = None
    dst_port = None
    flags = "N/A"

    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    # Extract payload bytes
    payload_bytes = b""
    if pkt.haslayer(TCP) and pkt[TCP].payload:
        payload_bytes = bytes(pkt[TCP].payload)
    elif pkt.haslayer(UDP) and pkt[UDP].payload:
        payload_bytes = bytes(pkt[UDP].payload)
    else:
        payload_bytes = bytes(pkt.payload)

    payload_len = len(payload_bytes)
    payload_hex = format_hex_dump(payload_bytes)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": len(pkt),
        "info": pkt.summary(),
        "ttl": ttl,
        "flags": flags,
        "payload_len": payload_len,
        "payload_hex": payload_hex
    }

def format_hex_dump(payload_bytes):
    """Format raw bytes into Wireshark-style hex dump."""
    payload_len = len(payload_bytes)
    if payload_len > 0:
        hex_lines = []
        for i in range(0, min(payload_len, 256), 16):
            chunk = payload_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{i:04x}   {hex_part:<48}   {ascii_part}")
        payload_hex = "\n".join(hex_lines)
        if payload_len > 256:
            payload_hex += f"\n... ({payload_len - 256} more bytes truncated)"
        return payload_hex
    return "No payload"

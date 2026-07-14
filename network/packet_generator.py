import random

def generate_mock_packet(payload_dump_cb):
    """Generates mock packet details structure."""
    # Pull from a pool of IPs
    common_ips = ["192.168.1.15", "192.168.1.100", "8.8.8.8", "1.1.1.1", "142.250.190.46"]
    
    # Decide if this packet is normal (75% chance) or rule-triggering (25% chance)
    is_suspicious = random.random() < 0.25
    
    if is_suspicious:
        # Generate something that will trigger rules
        trigger_type = random.choice(["ssh_blocked_ip", "rdp_subnet", "icmp_ping", "ddos_blocked_ip"])
        
        if trigger_type == "ssh_blocked_ip":
            src_ip = "198.51.100.5" # Matches Rule 1
            dst_ip = "192.168.1.10"
            protocol = "TCP"
            src_port = random.randint(49152, 65535)
            dst_port = 22
            info = "TCP Connection Request [SYN]"
        elif trigger_type == "rdp_subnet":
            src_ip = f"192.168.1.{random.randint(2, 254)}" # Matches Rule 2 (192.168.1.0/24 subnet)
            dst_ip = "192.168.1.10"
            protocol = "TCP"
            src_port = random.randint(49152, 65535)
            dst_port = 3389
            info = "RDP Connection Attempt"
        elif trigger_type == "icmp_ping":
            src_ip = random.choice(common_ips)
            dst_ip = "192.168.1.10"
            protocol = "ICMP"
            src_port = None
            dst_port = None
            info = "ICMP Echo Request (ping)" # Matches Rule 3
        else: # ddos_blocked_ip
            src_ip = "203.0.113.12" # Matches Rule 4 (if enabled)
            dst_ip = "192.168.1.10"
            protocol = "TCP"
            src_port = random.randint(49152, 65535)
            dst_port = 80
            info = "HTTP GET /index.html"
    else:
        # Regular normal traffic
        src_ip = random.choice(common_ips)
        dst_ip = "192.168.1.10"
        protocol = random.choice(["TCP", "UDP", "UDP", "TCP"])  # Weight UDP/TCP
        
        if protocol == "TCP":
            dst_port = random.choice([80, 443, 8080])
            src_port = random.randint(49152, 65535)
            if dst_port == 443:
                info = "TLS Handshake Client Hello"
            elif dst_port == 80:
                info = "HTTP GET /api/v1/status"
            else:
                info = "TCP Packet [ACK]"
        else: # UDP
            dst_port = random.choice([53, 123])
            src_port = random.randint(49152, 65535)
            if dst_port == 53:
                info = f"DNS Query: {random.choice(['google.com', 'github.com', 'stackoverflow.com'])}"
            else:
                info = "NTP Time Sync"

    # TTL
    ttl = random.choice([64, 128, 54, 112])
    
    # Flags
    if protocol == "TCP":
        flags = random.choice(["S (SYN)", "A (ACK)", "PA (PSH, ACK)", "FA (FIN, ACK)"])
    else:
        flags = "N/A"
        
    # Payload
    payload_len, payload_hex = payload_dump_cb(protocol, dst_port, info)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": payload_len + (40 if protocol == "TCP" else 28),
        "info": info,
        "ttl": ttl,
        "flags": flags,
        "payload_len": payload_len,
        "payload_hex": payload_hex
    }

def generate_payload_dump(protocol, dst_port, info):
    """Generates mock payload content and outputs it as a hex/ascii Wireshark-style dump."""
    payload_str = ""
    if protocol == "TCP":
        if dst_port == 80:
            payload_str = f"GET /api/v1/status HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n"
        elif dst_port == 443:
            payload_str = "\x16\x03\x01\x00\xba\x01\x00\x00\xb6\x03\x03\xab\xcd\xef\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20session_id_data_for_tls_handshake"
        elif dst_port == 22:
            payload_str = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"
        elif dst_port == 3389:
            payload_str = "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        else:
            payload_str = f"TCP Payload Data. Info: {info}. Sequence: {random.randint(1000, 9999)}"
    elif protocol == "UDP":
        if dst_port == 53:
            payload_str = f"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        elif dst_port == 123:
            payload_str = f"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        else:
            payload_str = f"UDP Datagram Data. Size: {random.randint(10, 100)}"
    elif protocol == "ICMP":
        payload_str = "abcdefghijklmnopqrstuvwabcdefghi"
    else:
        payload_str = "Raw Raw Raw Sentry Sentry Sentry Payload"

    payload_bytes = payload_str.encode('utf-8', errors='ignore') if isinstance(payload_str, str) else payload_str
    payload_len = len(payload_bytes)
    
    hex_lines = []
    for i in range(0, min(payload_len, 256), 16):
        chunk = payload_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{i:04x}   {hex_part:<48}   {ascii_part}")
        
    return payload_len, "\n".join(hex_lines)

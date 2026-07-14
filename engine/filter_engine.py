import ipaddress

def ip_matches(rule_ip, packet_ip):
    """Check if an IP matches a rule pattern (wildcard, exact, or CIDR)."""
    if not rule_ip or rule_ip == "*":
        return True
    if not packet_ip:
        return False
    
    # Exact match
    if rule_ip == packet_ip:
        return True
    
    # CIDR Subnet match
    try:
        if "/" in rule_ip:
            network = ipaddress.ip_network(rule_ip, strict=False)
            ip = ipaddress.ip_address(packet_ip)
            return ip in network
    except ValueError:
        pass
        
    return False

def port_matches(rule_port, packet_port):
    """Check if a port matches a rule pattern (wildcard or exact)."""
    if not rule_port or rule_port == "*":
        return True
    if packet_port is None:
        return False
    
    try:
        return str(rule_port).strip() == str(packet_port).strip()
    except (ValueError, TypeError):
        return False

def protocol_matches(rule_proto, packet_proto):
    """Check if a protocol matches a rule pattern (wildcard or exact, case-insensitive)."""
    if not rule_proto or rule_proto == "*":
        return True
    if not packet_proto:
        return False
    return rule_proto.upper() == packet_proto.upper()

def evaluate_packet(packet, rules):
    """
    Evaluate packet against the loaded enabled rules.
    Returns (action, matched_rule_id, reason).
    First matching rule wins based on priority value descending.
    Defaults to ALLOW if no rules match.
    """
    # Sort active rules by priority descending
    sorted_rules = sorted(rules, key=lambda r: r.get("priority", 50), reverse=True)
    for rule in sorted_rules:
        if not rule.get("enabled", True):
            continue
            
        if (ip_matches(rule.get("src_ip"), packet.get("src_ip")) and
            ip_matches(rule.get("dst_ip"), packet.get("dst_ip")) and
            port_matches(rule.get("src_port"), packet.get("src_port")) and
            port_matches(rule.get("dst_port"), packet.get("dst_port")) and
            protocol_matches(rule.get("protocol"), packet.get("protocol"))):
            
            return rule.get("action", "BLOCK").upper(), rule.get("id"), rule.get("reason", "Rule violation")
            
    return "ALLOW", None, "Default Policy"

import json
import os
import uuid
import config

DEFAULT_RULES = [
    {
        "id": "rule_1",
        "priority": 100,
        "src_ip": "198.51.100.5",
        "dst_ip": "*",
        "src_port": "*",
        "dst_port": "22",
        "protocol": "TCP",
        "action": "BLOCK",
        "reason": "Known malicious SSH brute-forcer",
        "enabled": True
    },
    {
        "id": "rule_2",
        "priority": 90,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "*",
        "src_port": "*",
        "dst_port": "3389",
        "protocol": "TCP",
        "action": "BLOCK",
        "reason": "Block RDP from local subnet",
        "enabled": True
    },
    {
        "id": "rule_3",
        "priority": 50,
        "src_ip": "*",
        "dst_ip": "*",
        "src_port": "*",
        "dst_port": "*",
        "protocol": "ICMP",
        "action": "BLOCK",
        "reason": "Ping sweep mitigation",
        "enabled": True
    },
    {
        "id": "rule_4",
        "priority": 20,
        "src_ip": "203.0.113.12",
        "dst_ip": "*",
        "src_port": "*",
        "dst_port": "80",
        "protocol": "TCP",
        "action": "BLOCK",
        "reason": "Suspected DDoS botnet IP",
        "enabled": False
    }
]

def load_rules():
    """Load filtering rules from JSON file, initializing with defaults if missing."""
    filepath = config.RULES_FILE
    if not os.path.exists(filepath):
        save_rules(DEFAULT_RULES)
        return DEFAULT_RULES
    try:
        with open(filepath, 'r') as f:
            rules = json.load(f)
            
        # Migrate existing rules (inject priority if missing)
        updated = False
        default_priorities = {"rule_1": 100, "rule_2": 90, "rule_3": 50, "rule_4": 20}
        for rule in rules:
            if "priority" not in rule:
                rule["priority"] = default_priorities.get(rule["id"], 50)
                updated = True
                
        if updated:
            save_rules(rules)
            
        return rules
    except Exception as e:
        print(f"Error loading rules, using defaults: {e}")
        return DEFAULT_RULES

def save_rules(rules):
    """Save rules to JSON file."""
    try:
        with open(config.RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving rules: {e}")
        return False

import unittest
import sys
import os

# Adjust path so we can import from engine package
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.filter_engine import evaluate_packet, ip_matches, port_matches, protocol_matches

class TestFilterEngine(unittest.TestCase):
    
    def test_ip_matches(self):
        # Wildcard IP
        self.assertTrue(ip_matches("*", "192.168.1.1"))
        self.assertTrue(ip_matches(None, "192.168.1.1"))
        
        # Exact IP Match
        self.assertTrue(ip_matches("192.168.1.1", "192.168.1.1"))
        self.assertFalse(ip_matches("192.168.1.1", "192.168.1.2"))
        
        # CIDR Subnet Match
        self.assertTrue(ip_matches("192.168.1.0/24", "192.168.1.50"))
        self.assertTrue(ip_matches("192.168.1.0/24", "192.168.1.254"))
        self.assertFalse(ip_matches("192.168.1.0/24", "192.168.2.1"))
        self.assertTrue(ip_matches("10.0.0.0/8", "10.254.12.19"))
        self.assertFalse(ip_matches("10.0.0.0/8", "192.168.1.1"))

    def test_port_matches(self):
        # Wildcard Port
        self.assertTrue(port_matches("*", 80))
        self.assertTrue(port_matches(None, 80))
        
        # Exact Port Match
        self.assertTrue(port_matches(80, 80))
        self.assertTrue(port_matches("80", 80))
        self.assertTrue(port_matches(80, "80"))
        self.assertFalse(port_matches(80, 443))
        
        # Port match when packet port is None
        self.assertFalse(port_matches(80, None))

    def test_protocol_matches(self):
        # Wildcard Protocol
        self.assertTrue(protocol_matches("*", "TCP"))
        self.assertTrue(protocol_matches(None, "TCP"))
        
        # Case Insensitive Protocol Matches
        self.assertTrue(protocol_matches("TCP", "tcp"))
        self.assertTrue(protocol_matches("udp", "UDP"))
        self.assertTrue(protocol_matches("ICMP", "Icmp"))
        self.assertFalse(protocol_matches("TCP", "UDP"))

    def test_evaluate_packet(self):
        # Mock Rule Base
        test_rules = [
            {
                "id": "rule_ssh_block",
                "priority": 100,
                "src_ip": "198.51.100.5",
                "dst_ip": "*",
                "src_port": "*",
                "dst_port": "22",
                "protocol": "TCP",
                "action": "BLOCK",
                "reason": "SSH Attack Threat",
                "enabled": True
            },
            {
                "id": "rule_rdp_block",
                "priority": 90,
                "src_ip": "192.168.1.0/24",
                "dst_ip": "*",
                "src_port": "*",
                "dst_port": "3389",
                "protocol": "TCP",
                "action": "BLOCK",
                "reason": "RDP Blocked on Local Network",
                "enabled": True
            },
            {
                "id": "rule_icmp_block",
                "priority": 50,
                "src_ip": "*",
                "dst_ip": "*",
                "src_port": "*",
                "dst_port": "*",
                "protocol": "ICMP",
                "action": "BLOCK",
                "reason": "Block Pings",
                "enabled": True
            },
            {
                "id": "rule_disabled",
                "priority": 20,
                "src_ip": "203.0.113.12",
                "dst_ip": "*",
                "src_port": "*",
                "dst_port": "80",
                "protocol": "TCP",
                "action": "BLOCK",
                "reason": "DDoS Threat",
                "enabled": False
            }
        ]

        # 1. Matches rule_ssh_block -> Should BLOCK
        pkt1 = {"src_ip": "198.51.100.5", "dst_ip": "192.168.1.10", "src_port": 51234, "dst_port": 22, "protocol": "TCP"}
        action, rule_id, reason = evaluate_packet(pkt1, test_rules)
        self.assertEqual(action, "BLOCK")
        self.assertEqual(rule_id, "rule_ssh_block")
        self.assertEqual(reason, "SSH Attack Threat")

        # 2. Matches rule_rdp_block (subnet match) -> Should BLOCK
        pkt2 = {"src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "src_port": 51234, "dst_port": 3389, "protocol": "TCP"}
        action, rule_id, reason = evaluate_packet(pkt2, test_rules)
        self.assertEqual(action, "BLOCK")
        self.assertEqual(rule_id, "rule_rdp_block")

        # 3. Matches rule_icmp_block (ICMP protocol) -> Should BLOCK
        pkt3 = {"src_ip": "8.8.8.8", "dst_ip": "192.168.1.10", "src_port": None, "dst_port": None, "protocol": "ICMP"}
        action, rule_id, reason = evaluate_packet(pkt3, test_rules)
        self.assertEqual(action, "BLOCK")
        self.assertEqual(rule_id, "rule_icmp_block")

        # 4. Triggers disabled rule -> Should ALLOW (falls through to default)
        pkt4 = {"src_ip": "203.0.113.12", "dst_ip": "192.168.1.10", "src_port": 51234, "dst_port": 80, "protocol": "TCP"}
        action, rule_id, reason = evaluate_packet(pkt4, test_rules)
        self.assertEqual(action, "ALLOW")
        self.assertEqual(rule_id, None)
        self.assertEqual(reason, "Default Policy")

if __name__ == '__main__':
    unittest.main()

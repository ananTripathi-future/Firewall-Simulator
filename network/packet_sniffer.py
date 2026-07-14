import threading
import time
import random
import datetime
import queue

# Sibling package imports
from network.packet_parser import parse_scapy_packet, SCAPY_AVAILABLE
from network.packet_generator import generate_mock_packet, generate_payload_dump

# SCAPY sniff import
if SCAPY_AVAILABLE:
    try:
        from scapy.all import sniff
    except ImportError:
        pass

class PacketSniffer:
    def __init__(self, rules_loader_cb, packet_callback=None):
        self.rules_loader_cb = rules_loader_cb  # Callback to load current rules
        self.packet_callback = packet_callback  # Callback when a packet is filtered
        self.mode = "simulation"                # "live" or "simulation"
        self.running = False
        self.thread = None
        self.scapy_available = SCAPY_AVAILABLE
        self.error_message = None
        self.packet_id_counter = 0

        if not SCAPY_AVAILABLE:
            self.error_message = "Scapy library is not installed. Live mode unavailable."

    def start(self):
        """Start the background sniffer/generator thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the background thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)

    def set_mode(self, mode):
        """Dynamically switch between live and simulation modes."""
        if mode == "live":
            if not self.scapy_available:
                return False, "Scapy is not installed. Run 'pip install scapy'."
            try:
                # Attempt a quick 0.1s sniff to verify interface access
                sniff(count=1, timeout=0.1)
                self.mode = "live"
                self.error_message = None
                return True, "Switched to Live Mode."
            except Exception as e:
                self.error_message = f"Live mode error (Npcap missing or admin privileges required): {str(e)}"
                self.mode = "simulation"
                return False, self.error_message
        else:
            self.mode = "simulation"
            self.error_message = None
            return True, "Switched to Simulation Mode."

    def _run(self):
        """Main loop executing sniffing or simulation based on current mode."""
        print(f"PacketSniffer thread started. Default mode: {self.mode}")
        
        while self.running:
            if self.mode == "live" and self.scapy_available:
                try:
                    sniff(prn=self._process_scapy_packet, store=0, count=5, timeout=1.0)
                except Exception as e:
                    print(f"Scapy sniffing failed: {e}")
                    self.error_message = f"Live sniffing failed: {str(e)}"
                    self.mode = "simulation"  # Graceful fallback
            else:
                # Simulation Mode
                pkt_data = generate_mock_packet(generate_payload_dump)
                self._filter_and_dispatch(pkt_data)
                # Sleep a random short duration between simulated packets
                time.sleep(random.uniform(0.2, 1.2))

    def _process_scapy_packet(self, pkt):
        """Callback for Scapy sniffing."""
        if not self.running or self.mode != "live":
            return
        pkt_data = parse_scapy_packet(pkt)
        if pkt_data:
            self._filter_and_dispatch(pkt_data)

    def _filter_and_dispatch(self, packet_data):
        """Pass the packet through the rules and notify the callback."""
        # Increment packet ID counter and add to packet
        self.packet_id_counter += 1
        packet_data["id"] = self.packet_id_counter

        # 1. Fetch current rules
        rules = self.rules_loader_cb()
        
        # 2. Evaluate
        from engine.filter_engine import evaluate_packet
        action, rule_id, reason = evaluate_packet(packet_data, rules)
        
        # 3. Add timestamp and result metadata
        packet_data["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        packet_data["action"] = action
        packet_data["rule_id"] = rule_id
        packet_data["reason"] = reason
        
        # 4. Dispatch
        if self.packet_callback:
            try:
                self.packet_callback(packet_data)
            except Exception as e:
                print(f"Error executing packet callback: {e}")

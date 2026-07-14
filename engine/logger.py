import os
import json
import csv
import threading
import config

log_lock = threading.Lock()

def log_packet(packet):
    """Log packet evaluation to exports/logs.json and exports/logs.csv in a thread-safe manner."""
    json_path = os.path.join(config.EXPORT_DIR, 'logs.json')
    csv_path = os.path.join(config.EXPORT_DIR, 'logs.csv')
    
    with log_lock:
        # 1. Log to JSON
        logs = []
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    logs = json.load(f)
            except Exception:
                logs = []
        
        # Keep clean copy
        log_pkt = packet.copy()
        logs.append(log_pkt)
        
        # Cap historical files to prevent unbounded disk growth
        if len(logs) > 1000:
            logs = logs[-1000:]
            
        try:
            with open(json_path, 'w') as f:
                json.dump(logs, f, indent=4)
        except Exception as e:
            print(f"Error logging packet to JSON: {e}")
            
        # 2. Log to CSV
        file_exists = os.path.exists(csv_path)
        fieldnames = ["id", "timestamp", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "length", "action", "rule_id", "reason"]
        
        try:
            with open(csv_path, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                if not file_exists:
                    writer.writeheader()
                writer.writerow(packet)
        except Exception as e:
            print(f"Error logging packet to CSV: {e}")

def clear_logs():
    """Clear CSV and JSON export files."""
    json_path = os.path.join(config.EXPORT_DIR, 'logs.json')
    csv_path = os.path.join(config.EXPORT_DIR, 'logs.csv')
    with log_lock:
        for path in [json_path, csv_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"Error removing log file {path}: {e}")

from flask import Flask, render_template, jsonify, request, Response
import os
import queue
import threading
import uuid
from collections import deque
import json

import config
from engine.rule_manager import load_rules, save_rules
from engine.logger import log_packet, clear_logs as file_clear_logs
from network.packet_sniffer import PacketSniffer

app = Flask(__name__)

# Track active clients for SSE
listeners = []
listeners_lock = threading.Lock()

# Rolling buffer of recent packets to populate the UI on load
recent_packets = deque(maxlen=config.MAX_LOG_HISTORY)
recent_packets_lock = threading.Lock()

def packet_callback(packet):
    """Callback triggered whenever a packet is filtered by the sniffer thread."""
    # 1. Store in rolling buffer
    with recent_packets_lock:
        recent_packets.append(packet)
        
    # 2. Save evaluation record to CSV and JSON exports
    log_packet(packet)
        
    # 3. Broadcast to all connected SSE clients
    with listeners_lock:
        for q in listeners:
            try:
                # Use non-blocking put to avoid slowing down the sniffer if a client is slow
                q.put_nowait(packet)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(packet)
                except Exception:
                    pass

# Initialize and start the sniffer
sniffer = PacketSniffer(rules_loader_cb=load_rules, packet_callback=packet_callback)
sniffer.start()

@app.route('/')
def index():
    """Render the dashboard template."""
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Retrieve current sniffer state."""
    return jsonify({
        "mode": sniffer.mode,
        "scapy_available": sniffer.scapy_available,
        "error": sniffer.error_message,
        "active_rules_count": len([r for r in load_rules() if r.get("enabled", True)])
    })

@app.route('/api/toggle_mode', methods=['POST'])
def toggle_mode():
    """Toggle sniffer mode between live and simulation."""
    data = request.json or {}
    target_mode = data.get("mode", "simulation")
    
    if target_mode not in ["live", "simulation"]:
        return jsonify({"success": False, "error": "Invalid mode specified"}), 400
        
    success, message = sniffer.set_mode(target_mode)
    return jsonify({
        "success": success,
        "message": message,
        "mode": sniffer.mode,
        "error": sniffer.error_message
    })

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Get the current list of filtering rules."""
    return jsonify(load_rules())

@app.route('/api/rules', methods=['POST'])
def add_rule():
    """Add a new traffic filtering rule."""
    data = request.json or {}
    
    # Validation
    action = data.get("action", "BLOCK").upper()
    if action not in ["ALLOW", "BLOCK"]:
        return jsonify({"success": False, "error": "Action must be ALLOW or BLOCK"}), 400
        
    try:
        priority = int(data.get("priority", 50))
    except (ValueError, TypeError):
        priority = 50
        
    new_rule = {
        "id": f"rule_{uuid.uuid4().hex[:8]}",
        "priority": priority,
        "src_ip": data.get("src_ip", "*") or "*",
        "dst_ip": data.get("dst_ip", "*") or "*",
        "src_port": data.get("src_port", "*") or "*",
        "dst_port": data.get("dst_port", "*") or "*",
        "protocol": (data.get("protocol", "*") or "*").upper(),
        "action": action,
        "reason": data.get("reason", "Custom user block rule"),
        "enabled": data.get("enabled", True)
    }
    
    current_rules = load_rules()
    current_rules.append(new_rule)
    save_rules(current_rules)
    
    return jsonify({"success": True, "rule": new_rule})

@app.route('/api/rules/<rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Update or toggle an existing rule."""
    data = request.json or {}
    current_rules = load_rules()
    
    rule_found = False
    for rule in current_rules:
        if rule["id"] == rule_id:
            # Update specific fields if present in request
            if "enabled" in data:
                rule["enabled"] = bool(data["enabled"])
            if "priority" in data:
                try:
                    rule["priority"] = int(data["priority"])
                except (ValueError, TypeError):
                    pass
            if "src_ip" in data:
                rule["src_ip"] = data["src_ip"]
            if "dst_ip" in data:
                rule["dst_ip"] = data["dst_ip"]
            if "src_port" in data:
                rule["src_port"] = data["src_port"]
            if "dst_port" in data:
                rule["dst_port"] = data["dst_port"]
            if "protocol" in data:
                rule["protocol"] = data["protocol"].upper()
            if "action" in data:
                rule["action"] = data["action"].upper()
            if "reason" in data:
                rule["reason"] = data["reason"]
            rule_found = True
            break
            
    if not rule_found:
        return jsonify({"success": False, "error": "Rule not found"}), 404
        
    save_rules(current_rules)
    return jsonify({"success": True, "message": "Rule updated successfully"})

@app.route('/api/rules/<rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete a rule."""
    current_rules = load_rules()
    updated_rules = [r for r in current_rules if r["id"] != rule_id]
    
    if len(current_rules) == len(updated_rules):
         return jsonify({"success": False, "error": "Rule not found"}), 404
         
    save_rules(updated_rules)
    return jsonify({"success": True, "message": "Rule deleted successfully"})

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Retrieve the rolling buffer of recent packets."""
    with recent_packets_lock:
        return jsonify(list(recent_packets))

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs_endpoint():
    """Clear historical logs from backend buffer and files."""
    with recent_packets_lock:
        recent_packets.clear()
    file_clear_logs()
    return jsonify({"success": True, "message": "Logs cleared"})

@app.route('/api/stream')
def event_stream():
    """Server-Sent Events endpoint to stream filtered packet events in real-time."""
    def event_generator():
        q = queue.Queue(maxsize=100)
        with listeners_lock:
            listeners.append(q)
            
        try:
            yield f"event: ping\ndata: {json.dumps({'status': 'connected'})}\n\n"
            while True:
                packet = q.get()
                yield f"data: {json.dumps(packet)}\n\n"
        except GeneratorExit:
            pass
        finally:
            with listeners_lock:
                if q in listeners:
                    listeners.remove(q)
                    
    return Response(event_generator(), mimetype='text/event-stream')

if __name__ == '__main__':
    # Ensure static and templates folders exist
    os.makedirs(os.path.join(app.root_path, 'templates'), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, 'static'), exist_ok=True)
    
    # Run the server
    print(f"Starting Firewall Simulator dashboard on http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)

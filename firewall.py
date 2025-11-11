import socket
import threading
import json
import time
from typing import List, Dict, Any
from flask import Flask, request, jsonify

# --- Firewall Rule Structure ---
class Rule:
    def __init__(self, id: int, action: str, src_ip_cidr: str, dst_ip_cidr: str, src_port: int, dst_port: int,
                 proto: str, priority: int, enabled: bool = True):
        self.id = id
        self.action = action  # "allow" or "deny"
        self.src_ip_cidr = src_ip_cidr
        self.dst_ip_cidr = dst_ip_cidr
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto  # "TCP" or "UDP"
        self.priority = priority  # lower = higher priority
        self.enabled = enabled

    def to_dict(self):
        return vars(self)

# --- Rule Engine: Filtering, Conflicts, Management ---
class RuleEngine:
    def __init__(self):
        self.rules: List[Rule] = []
        self.lock = threading.Lock()
        self.next_id = 1

    def add_rule(self, rule: Dict[str, Any]) -> (Rule, List[str]):
        with self.lock:
            new_rule = Rule(id=self.next_id, **rule)
            conflicts = self.detect_conflicts(new_rule)
            self.rules.append(new_rule)
            self.rules.sort(key=lambda r: r.priority)
            self.next_id += 1
            return new_rule, conflicts

    def remove_rule(self, rule_id: int):
        with self.lock:
            self.rules = [r for r in self.rules if r.id != rule_id]

    def update_rule(self, rule_id: int, data: Dict[str, Any]):
        with self.lock:
            for r in self.rules:
                if r.id == rule_id:
                    for k, v in data.items():
                        setattr(r, k, v)
                    conflicts = self.detect_conflicts(r)
                    return r, conflicts
        return None, []

    def get_rules(self):
        with self.lock:
            return [r.to_dict() for r in self.rules]

    def match(self, packet) -> (str, Rule):
        # Prioritize by rule priority and first match
        for rule in sorted(self.rules, key=lambda r: r.priority):
            if not rule.enabled:
                continue
            if rule.proto == packet['proto'] \
               and self.cidr_match(packet['src_ip'], rule.src_ip_cidr) \
               and self.cidr_match(packet['dst_ip'], rule.dst_ip_cidr) \
               and (rule.src_port == packet['src_port'] or rule.src_port == 0) \
               and (rule.dst_port == packet['dst_port'] or rule.dst_port == 0):
                return rule.action, rule
        return 'allow', None  # Default allow

    def cidr_match(self, ip: str, cidr: str) -> bool:
        if cidr == "0.0.0.0/0":
            return True
        net, mask = cidr.split('/')
        mask = int(mask)
        ip_bin = self.ip_to_bin(ip)
        net_bin = self.ip_to_bin(net)
        return ip_bin[:mask] == net_bin[:mask]

    @staticmethod
    def ip_to_bin(ip: str) -> str:
        return ''.join([f"{int(x):08b}" for x in ip.split('.')])

    def detect_conflicts(self, new_rule: Rule) -> List[str]:
        """Look for exact duplicates and overlapping rules with different action but same match"""
        conflicts = []
        for r in self.rules:
            if r.id == new_rule.id:
                continue
            same_match = (
                r.src_ip_cidr == new_rule.src_ip_cidr and
                r.dst_ip_cidr == new_rule.dst_ip_cidr and
                r.src_port == new_rule.src_port and
                r.dst_port == new_rule.dst_port and
                r.proto == new_rule.proto
            )
            if same_match and r.action == new_rule.action:
                conflicts.append(f"Duplicate of rule {r.id}")
            if same_match and r.action != new_rule.action:
                conflicts.append(f"Conflict with rule {r.id} ({r.action} vs {new_rule.action})")
        return conflicts

# --- Event Logger ---
class EventLogger:
    def __init__(self, filename='fw_events.log.jsonl'):
        self.filename = filename
        self.lock = threading.Lock()

    def log(self, event: Dict[str, Any]):
        with self.lock:
            with open(self.filename, 'a') as f:
                f.write(json.dumps(event) + '\n')

# --- TCP Proxy Example (Only for demo) ---
def proxy_tcp(listen_host, listen_port, target_host, target_port, rule_engine: RuleEngine, logger: EventLogger):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listen_host, listen_port))
    s.listen(5)
    print(f"TCP proxy listening on {listen_host}:{listen_port} -> {target_host}:{target_port}")
    while True:
        client_sock, client_addr = s.accept()
        src_ip, src_port = client_addr
        dst_ip, dst_port = target_host, target_port

        packet_info = {'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port, 'proto': "TCP"}
        action, rule = rule_engine.match(packet_info)
        if action == 'deny':
            logger.log({
                "timestamp": time.time(),
                "action": 'deny',
                "proto": "TCP",
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "reason": f"Rule {rule.id}" if rule else "No rule"
            })
            client_sock.close()
            continue
        threading.Thread(target=handle_tcp, args=(client_sock, target_host, target_port)).start()

def handle_tcp(client_sock, target_host, target_port):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((target_host, target_port))
        # Forwarding, simplified
        threading.Thread(target=forward, args=(client_sock, server_sock)).start()
        threading.Thread(target=forward, args=(server_sock, client_sock)).start()
    except Exception as e:
        client_sock.close()

def forward(source, dest):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            dest.sendall(data)
    except Exception as e:
        source.close()
        dest.close()

# --- Minimal Flask API ---
app = Flask(__name__)
rule_engine = RuleEngine()
logger = EventLogger()

@app.route('/rules', methods=['GET'])
def get_rules():
    return jsonify(rule_engine.get_rules())

@app.route('/rules', methods=['POST'])
def add_rule():
    data = request.json
    rule, conflicts = rule_engine.add_rule(data)
    return jsonify({"rule": rule.to_dict(), "conflicts": conflicts})

@app.route('/rules/<int:rule_id>', methods=['PATCH'])
def update_rule(rule_id):
    data = request.json
    rule, conflicts = rule_engine.update_rule(rule_id, data)
    if rule:
        return jsonify({"rule": rule.to_dict(), "conflicts": conflicts})
    else:
        return jsonify({"error": "Rule not found"}), 404

@app.route('/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    rule_engine.remove_rule(rule_id)
    return jsonify({"result": "deleted"})

@app.route('/reload', methods=['POST'])
def reload():
    # Just a stub for demo — rules are always hot-loaded
    return jsonify({"result": "reloaded"})

# --- MAIN: Запуск API і proxy-demo ---
def main():
    # Запустити API у потоці
    threading.Thread(target=lambda: app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)).start()
    # Запустити простий TCP proxy (для demo: слухає 12345 і проксуює на 80)
    proxy_tcp("127.0.0.1", 12345, "example.com", 80, rule_engine, logger)

if __name__ == "__main__":
    main()

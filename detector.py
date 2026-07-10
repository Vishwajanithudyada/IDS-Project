# detector.py
from scapy.all import IP, TCP
from collections import defaultdict
import time

class IntrusionDetector:
    def __init__(self):
        self.port_scan_tracker = defaultdict(set)
        self.alert_threshold = 10
        self.time_window = 60
        self.timestamps = defaultdict(list)
        self.alerts = []
        self.alerted_ips = set()  # ← Duplicate fix

    def detect_port_scan(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()

            self.timestamps[src_ip] = [
                t for t in self.timestamps[src_ip]
                if current_time - t < self.time_window
            ]

            self.port_scan_tracker[src_ip].add(dst_port)
            self.timestamps[src_ip].append(current_time)

            if len(self.port_scan_tracker[src_ip]) > self.alert_threshold:
                alert = self.generate_alert(src_ip, dst_port)
                return alert
        return None

    def generate_alert(self, src_ip, dst_port):
        # Duplicate alerts නැතිකිරීම
        if src_ip in self.alerted_ips:
            return None

        self.alerted_ips.add(src_ip)

        alert = {
            'type': 'PORT_SCAN_DETECTED',
            'src_ip': src_ip,
            'ports_scanned': len(self.port_scan_tracker[src_ip]),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': 'HIGH'
        }
        self.alerts.append(alert)
        print(f"\n🚨 ALERT! Port Scan Detected!")
        print(f"   Source IP  : {src_ip}")
        print(f"   Ports hit  : {len(self.port_scan_tracker[src_ip])}")
        print(f"   Time       : {alert['timestamp']}")
        return alert
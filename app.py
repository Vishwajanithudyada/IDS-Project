# app.py
from flask import Flask, render_template, jsonify
from detector import IntrusionDetector
from logger import log_event, log_alert
from scapy.all import sniff, IP, TCP
import threading
import time

app = Flask(__name__)
detector = IntrusionDetector()

# Stats track කරන්න
stats = {
    'total_packets': 0,
    'total_alerts': 0,
    'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
    'recent_packets': [],
    'alerts': []
}

def process_packet(packet):
    """Packet process කරන function"""
    if IP in packet:
        stats['total_packets'] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Recent packets list update කරන්න (last 10 only)
        packet_info = {
            'time': time.strftime('%H:%M:%S'),
            'src': src_ip,
            'dst': dst_ip,
            'protocol': 'TCP' if TCP in packet else 'OTHER'
        }
        stats['recent_packets'].insert(0, packet_info)
        stats['recent_packets'] = stats['recent_packets'][:10]

        # Port scan check කරන්න
        alert = detector.detect_port_scan(packet)
        if alert:
            stats['total_alerts'] += 1
            stats['alerts'].insert(0, alert)
            log_alert(alert)

        log_event('PACKET', {'src': src_ip, 'dst': dst_ip})

def start_sniffing():
    """Background thread එකේ sniff කරන්න"""
    sniff(prn=process_packet, store=False)

# Background thread start කරන්න
thread = threading.Thread(target=start_sniffing, daemon=True)
thread.start()

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_packets': stats['total_packets'],
        'total_alerts': stats['total_alerts'],
        'start_time': stats['start_time'],
        'recent_packets': stats['recent_packets'],
        'alerts': stats['alerts']
    })

if __name__ == '__main__':
    print("🛡️ IDS Dashboard: http://127.0.0.1:5000")
    app.run(debug=False)
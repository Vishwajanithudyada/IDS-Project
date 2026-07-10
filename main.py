# main.py
from packet_capture import start_capture
from detector import IntrusionDetector
from logger import log_event, log_alert, generate_report
from scapy.all import IP, TCP

# Detector object හදන්න
detector = IntrusionDetector()

def process_packet(packet):
    """සෑම packet එකක්ම process කරන function"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Event log කරන්න
        log_event('PACKET_CAPTURED', {
            'src': src_ip,
            'dst': dst_ip
        })
        
        # Port scan check කරන්න
        alert = detector.detect_port_scan(packet)
        if alert:
            log_alert(alert)

def main():
    print("=" * 50)
    print("   🛡️ Python IDS - Intrusion Detection System")
    print("=" * 50)
    print("[*] Monitoring පටන් ගනිමින්... (Ctrl+C to stop)\n")
    
    try:
        # Capture පටන් කරන්න (100 packets)
        start_capture(process_packet, count=100)
        
    except KeyboardInterrupt:
        print("\n[*] IDS නවත්වමින்...")
        
    finally:
        # Report generate කරන්න
        if detector.alerts:
            generate_report(detector.alerts)
            print(f"[✓] {len(detector.alerts)} alerts detected!")
        else:
            print("[✓] Threats detect නොවීය.")

if __name__ == "__main__":
    main()
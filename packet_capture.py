# packet_capture.py
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    """එන සෑම packet එකක්ම analyze කරන function"""
    if IP in packet:
        src_ip = packet[IP].src      # යවන IP
        dst_ip = packet[IP].dst      # ලැබෙන IP
        protocol = packet[IP].proto  # Protocol (TCP/UDP)
        
        info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'packet': packet
        }
        return info
    return None

def start_capture(callback, count=0, interface=None):
    """Network traffic capture කරන්න පටන් ගන්න"""
    print("[*] Packet capture පටන් ගනිමින්...")
    sniff(
        iface=interface,
        prn=callback,
        count=count,
        store=False
    )
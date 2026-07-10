# logger.py
import logging
import json
import os
from datetime import datetime

# Logs folder නැත්නම් හදන්න
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)

# Logger setup
logging.basicConfig(
    filename='logs/ids_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_event(event_type, details):
    """Security event log කරන්න"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'details': details
    }
    logging.info(json.dumps(log_entry))
    return log_entry

def log_alert(alert):
    """Alert log කරන්න"""
    logging.warning(f"ALERT: {json.dumps(alert)}")

def generate_report(alerts):
    """Report file හදන්න"""
    report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    with open(report_path, 'w') as f:
        f.write("=" * 50 + "\n")
        f.write("   IDS Security Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Alerts: {len(alerts)}\n\n")
        
        for i, alert in enumerate(alerts, 1):
            f.write(f"Alert #{i}\n")
            f.write(f"  Type     : {alert['type']}\n")
            f.write(f"  Source   : {alert['src_ip']}\n")
            f.write(f"  Severity : {alert['severity']}\n")
            f.write(f"  Time     : {alert['timestamp']}\n\n")
    
    print(f"[✓] Report saved: {report_path}")
    return report_path
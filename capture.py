from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
import time
import logging
import requests
import sqlite3

# Configuration
INTERFACE = "enp0s3"
CAPTURE_INTERVAL = 10
SPIKE_THRESHOLD = 2.0
PACKET_RATE_THRESHOLD = 100
SYN_THRESHOLD = 50
TRAFFIC_LOG_FILE = "traffic_alerts.log"
THREAT_LOG_FILE = "threat_alerts.log"
MAX_ALERTS = 5
MAX_THREAT_CHECKS = 50
ABUSEIPDB_API_KEY = "Your_API_Key"

# Logging setup
traffic_logger = logging.getLogger("TrafficAlerts")
traffic_logger.setLevel(logging.WARNING)
traffic_handler = logging.FileHandler(TRAFFIC_LOG_FILE)
traffic_handler.setLevel(logging.WARNING)
traffic_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
traffic_handler.setFormatter(traffic_formatter)
traffic_logger.addHandler(traffic_handler)

threat_logger = logging.getLogger("ThreatAlerts")
threat_logger.setLevel(logging.WARNING)
threat_handler = logging.FileHandler(THREAT_LOG_FILE)
threat_handler.setLevel(logging.WARNING)
threat_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
threat_handler.setFormatter(threat_formatter)
threat_logger.addHandler(threat_handler)

# Shared metrics
metrics = {
    "bandwidth": 0.0,
    "top_src_ips": [],
    "top_dst_ips": [],
    "packet_rate": 0.0,
    "avg_rate": 0.0,
    "spike_detected": False,
    "traffic_alerts": [],
    "threat_alerts": [],
    "threat_ips": {},
    "protocols": {"tcp": 0, "udp": 0, "icmp": 0, "syn_count": 0}
}
packet_count = 0
total_bytes = 0
src_ip_counts = Counter()
dst_ip_counts = Counter()
packet_rates = []

# Database setup
def init_db():
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packet_counts 
                 (timestamp TEXT, total_packets INTEGER, tcp INTEGER, udp INTEGER, icmp INTEGER, syn_count INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS source_ips (ip TEXT, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS dest_ips (ip TEXT, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_alerts (timestamp TEXT, message TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS threat_alerts (timestamp TEXT, message TEXT)''')
    conn.commit()
    conn.close()

def save_to_db(timestamp):
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    c.execute('INSERT INTO packet_counts VALUES (?, ?, ?, ?, ?, ?)',
              (timestamp, packet_count, metrics["protocols"]["tcp"], metrics["protocols"]["udp"],
               metrics["protocols"]["icmp"], metrics["protocols"]["syn_count"]))
    for ip, count in src_ip_counts.items():
        c.execute('INSERT INTO source_ips VALUES (?, ?)', (ip, timestamp))
    for ip, count in dst_ip_counts.items():
        c.execute('INSERT INTO dest_ips VALUES (?, ?)', (ip, timestamp))
    for alert in metrics["traffic_alerts"]:
        if alert.startswith(timestamp):
            c.execute('INSERT INTO traffic_alerts VALUES (?, ?)', (timestamp, alert))
    for alert in metrics["threat_alerts"]:
        if alert.startswith(timestamp):
            c.execute('INSERT INTO threat_alerts VALUES (?, ?)', (timestamp, alert))
    conn.commit()
    conn.close()

def check_threat_ip(ip):
    if ip in metrics["threat_ips"]:
        return metrics["threat_ips"][ip]
    if not ABUSEIPDB_API_KEY or ip.startswith(('192.168.', '10.', '172.')):
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()
        if data["data"]["abuseConfidenceScore"] > 50:
            threat_info = f"Threat detected (Score: {data['data']['abuseConfidenceScore']})"
            metrics["threat_ips"][ip] = threat_info
            return threat_info
        metrics["threat_ips"][ip] = None
        return None
    except Exception as e:
        threat_logger.error(f"Threat check failed for {ip}: {e}")
        return None

def packet_handler(packet):
    global packet_count, total_bytes
    if IP in packet:
        packet_count += 1
        total_bytes += len(packet)
        src_ip_counts[packet[IP].src] += 1
        dst_ip_counts[packet[IP].dst] += 1
        if TCP in packet:
            metrics["protocols"]["tcp"] += 1
            if packet[TCP].flags & 2:
                metrics["protocols"]["syn_count"] += 1
        elif UDP in packet:
            metrics["protocols"]["udp"] += 1
        elif ICMP in packet:
            metrics["protocols"]["icmp"] += 1

def calculate_metrics(socketio):
    global packet_count, total_bytes
    while True:
        metrics["protocols"] = {"tcp": 0, "udp": 0, "icmp": 0, "syn_count": 0}
        sniff(iface=INTERFACE, prn=packet_handler, timeout=CAPTURE_INTERVAL)
        
        if packet_count > 0:
            bandwidth = total_bytes / CAPTURE_INTERVAL
            all_src_ips = list(src_ip_counts.items())
            all_dst_ips = list(dst_ip_counts.items())
            threat_results = {}
            for ip, count in (all_src_ips + all_dst_ips)[:MAX_THREAT_CHECKS]:
                threat_results[ip] = check_threat_ip(ip)
            top_src_ips = [(ip, count, threat_results.get(ip)) for ip, count in src_ip_counts.most_common(5)]
            top_dst_ips = [(ip, count, threat_results.get(ip)) for ip, count in dst_ip_counts.most_common(5)]
            current_rate = packet_count / CAPTURE_INTERVAL
            packet_rates.append(current_rate)
            if len(packet_rates) > 5:
                packet_rates.pop(0)
            avg_rate = sum(packet_rates) / len(packet_rates) if packet_rates else 0
            spike_detected = current_rate > avg_rate * SPIKE_THRESHOLD and avg_rate > 0
        else:
            bandwidth = 0.0
            top_src_ips = [("No traffic", 0, None)]
            top_dst_ips = [("No traffic", 0, None)]
            current_rate = 0.0
            avg_rate = sum(packet_rates) / len(packet_rates) if packet_rates else 0
            spike_detected = False
            threat_results = {}

        metrics.update({
            "bandwidth": bandwidth,
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "packet_rate": current_rate,
            "avg_rate": avg_rate,
            "spike_detected": spike_detected
        })

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        if spike_detected or current_rate > PACKET_RATE_THRESHOLD:
            alert_msg = (
                f"interface={INTERFACE}, packet_rate={current_rate:.2f}, "
                f"avg_rate={avg_rate:.2f}, bandwidth={bandwidth:.2f}, "
                f"spike_detected={spike_detected}"
            )
            traffic_logger.warning(f"Traffic Alert: {alert_msg}")
            metrics["traffic_alerts"].insert(0, f"{timestamp} - Spike: {current_rate:.2f} packets/sec")
        if metrics["protocols"]["syn_count"] > SYN_THRESHOLD:
            syn_msg = f"interface={INTERFACE}, syn_count={metrics['protocols']['syn_count']}, potential_syn_flood=True"
            traffic_logger.warning(f"SYN Flood Alert: {syn_msg}")
            metrics["traffic_alerts"].insert(0, f"{timestamp} - SYN Flood: {metrics['protocols']['syn_count']} SYNs")
        for ip, count, threat in [(ip, c, threat_results.get(ip)) for ip, c in all_src_ips + all_dst_ips]:
            if threat:
                threat_msg = f"interface={INTERFACE}, ip={ip}, count={count}, threat_info={threat}"
                threat_logger.warning(f"Threat Alert: {threat_msg}")
                metrics["threat_alerts"].insert(0, f"{timestamp} - Threat IP: {ip} ({threat})")
        
        if len(metrics["traffic_alerts"]) > MAX_ALERTS:
            metrics["traffic_alerts"] = metrics["traffic_alerts"][:MAX_ALERTS]
        if len(metrics["threat_alerts"]) > MAX_ALERTS:
            metrics["threat_alerts"] = metrics["threat_alerts"][:MAX_ALERTS]

        # Emit metrics to all connected clients
        socketio.emit('update', metrics)
        print("Emitted metrics:", metrics)  # Debug output

        save_to_db(timestamp)
        packet_count = 0
        total_bytes = 0
        src_ip_counts.clear()
        dst_ip_counts.clear()

def start_capture(socketio):
    init_db()
    print(f"Starting packet capture on {INTERFACE}...")
    print(f"Traffic alerts logged to {TRAFFIC_LOG_FILE}, Threat alerts logged to {THREAT_LOG_FILE}")
    calculate_metrics(socketio)

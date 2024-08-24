import socket
import threading
import time
import subprocess
from collections import defaultdict, deque
from scapy.all import *

# Configuration
BLOCKED_IPS = set()
ATTACKED_PORTS = set()
CLOSED_PORTS = {}  # Track closed ports and their closure time

IP_REQUEST_COUNT = defaultdict(int)
PORT_ACCESS_COUNT = defaultdict(int)
SESSION_COUNT = defaultdict(int)
SESSION_START = defaultdict(float)
CONNECTION_DURATIONS = defaultdict(list)
TRAFFIC_VOLUME = deque(maxlen=60)  # Store traffic volume for the last 60 seconds
CONNECTION_COUNT = defaultdict(int)

SESSION_TIMEOUT = 600  # Session timeout in seconds
TRAFFIC_CHECK_INTERVAL = 1  # Interval to check traffic volume in seconds
REQUEST_THRESHOLD = 100  # Threshold for number of requests from a single IP
PORT_ACCESS_THRESHOLD = 100  # Threshold for port access frequency
CONNECTION_COUNT_THRESHOLD = 50  # Threshold for the number of connections
PORT_REOPEN_DELAY = 3600  # Time to reopen a closed port in seconds

# Extract features from a packet for heuristic analysis
def extract_features(packet):
    features = {
        'packet_length': len(packet),
        'src_ip': packet[IP].src if IP in packet else None,
        'dst_ip': packet[IP].dst if IP in packet else None,
        'protocol': packet.proto if IP in packet else None,
        'src_port': packet.sport if TCP in packet else None,
        'dst_port': packet.dport if TCP in packet else None,
    }

    # Update request rate and connection metrics
    src_ip = packet[IP].src if IP in packet else None
    if src_ip:
        IP_REQUEST_COUNT[src_ip] += 1
        current_time = time.time()
        session_start = SESSION_START.get(src_ip, current_time)
        if current_time - session_start > SESSION_TIMEOUT:
            SESSION_COUNT[src_ip] = 0
            SESSION_START[src_ip] = current_time
        SESSION_COUNT[src_ip] += 1

    if src_ip:
        CONNECTION_DURATIONS[src_ip].append(time.time() - SESSION_START[src_ip])
    
    if IP in packet:
        TRAFFIC_VOLUME.append(len(packet))
    
    return features

# Detect DDoS attack based on simple heuristics
def detect_ddos(features):
    src_ip = features['src_ip']
    dst_port = features['dst_port']
    if src_ip and IP_REQUEST_COUNT[src_ip] > REQUEST_THRESHOLD:
        print(f"High request rate detected from IP: {src_ip}")
        return True
    if dst_port and PORT_ACCESS_COUNT[dst_port] > PORT_ACCESS_THRESHOLD:
        print(f"High access frequency detected on port: {dst_port}")
        return True
    if len(CONNECTION_COUNT) > CONNECTION_COUNT_THRESHOLD:
        print("High number of connections detected")
        return True
    return False

# Monitor and analyze network traffic
def monitor_traffic():
    print("Monitoring traffic...")
    sniff(filter="ip", prn=process_packet, store=0)

# Process each captured packet
def process_packet(packet):
    features = extract_features(packet)
    if detect_ddos(features):
        print("DDoS attack detected!")
        attacked_port = identify_attacked_port(packet)
        mitigate_attack(packet, attacked_port)

# Identify which port is under attack
def identify_attacked_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].dport
    return None

# Block the malicious IP
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        print(f"Blocking IP: {ip}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip)

# Close the port that is being attacked
def close_port(port):
    if port and port not in ATTACKED_PORTS:
        print(f"Closing port: {port}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
        ATTACKED_PORTS.add(port)
        CLOSED_PORTS[port] = time.time()  # Record the time when the port was closed

# Reopen the closed port after a delay
def reopen_ports():
    current_time = time.time()
    ports_to_reopen = [port for port, close_time in CLOSED_PORTS.items()
                       if current_time - close_time > PORT_REOPEN_DELAY]
    
    for port in ports_to_reopen:
        print(f"Reopening port: {port}")
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
        ATTACKED_PORTS.discard(port)
        CLOSED_PORTS.pop(port, None)

# Mitigate the detected attack
def mitigate_attack(packet, port):
    if IP in packet:
        source_ip = packet[IP].src
        block_ip(source_ip)
    close_port(port)

# Main function to start monitoring traffic and reopening ports
def main():
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.start()
    
    while True:
        reopen_ports()
        time.sleep(TRAFFIC_CHECK_INTERVAL)

if __name__ == "__main__":
    main()

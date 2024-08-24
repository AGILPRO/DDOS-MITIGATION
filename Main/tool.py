import socket
import threading
import time
import pickle
import numpy as np
import pandas as pd
from scapy.all import *
import subprocess
from collections import defaultdict, deque

# Load the trained machine learning model
with open('ddos_model.pkl', 'rb') as f:
    model = pickle.load(f)

BLOCKED_IPS = set()
ATTACKED_PORTS = set()
IP_REQUEST_COUNT = defaultdict(int)
PORT_ACCESS_COUNT = defaultdict(int)
SESSION_COUNT = defaultdict(int)
SESSION_START = defaultdict(float)
CONNECTION_DURATIONS = defaultdict(list)
TRAFFIC_VOLUME = deque(maxlen=60)  # Store traffic volume for the last 60 seconds
CONNECTION_COUNT = defaultdict(int)

SESSION_TIMEOUT = 600  # Session timeout in seconds
TRAFFIC_CHECK_INTERVAL = 1  # Interval to check traffic volume in seconds

# Extract features from a packet for model prediction
def extract_features(packet):
    features = {
        'packet_length': len(packet),
        'src_ip': packet[IP].src if IP in packet else None,
        'dst_ip': packet[IP].dst if IP in packet else None,
        'protocol': packet.proto if IP in packet else None,
        'src_port': packet.sport if TCP in packet else None,
        'dst_port': packet.dport if TCP in packet else None,
        'http_method': None,  # Placeholder for HTTP method
        'http_host': None,    # Placeholder for HTTP host
        'http_user_agent': None,  # Placeholder for HTTP User-Agent
        'request_rate': 0,
        'payload_size_variety': 0,
        'unique_ips': len(IP_REQUEST_COUNT),
        'port_access_frequency': PORT_ACCESS_COUNT.get(packet[TCP].dport if TCP in packet else None, 0),
        'session_frequency': SESSION_COUNT.get(packet[IP].src if IP in packet else None, 0),
        'connection_duration': np.mean(CONNECTION_DURATIONS.get(packet[IP].src if IP in packet else None, [0])),
        'traffic_volume': np.sum(TRAFFIC_VOLUME),
        'burstiness': calculate_burstiness()
    }

    # Update request rate, session count, and traffic volume
    src_ip = packet[IP].src if IP in packet else None
    if src_ip:
        IP_REQUEST_COUNT[src_ip] += 1
        current_time = time.time()
        session_start = SESSION_START.get(src_ip, current_time)
        if current_time - session_start > SESSION_TIMEOUT:
            SESSION_COUNT[src_ip] = 0
            SESSION_START[src_ip] = current_time
        SESSION_COUNT[src_ip] += 1

    # Track connection duration
    if src_ip:
        CONNECTION_DURATIONS[src_ip].append(time.time() - SESSION_START[src_ip])
    
    # Extract application layer features if packet contains HTTP
    if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
        if Raw in packet:
            payload = packet[Raw].load.decode(errors='ignore')
            if 'HTTP' in payload:
                headers = payload.split('\r\n')
                for header in headers:
                    if header.startswith('GET ') or header.startswith('POST '):
                        features['http_method'] = header.split(' ')[0]
                    elif header.startswith('Host: '):
                        features['http_host'] = header.split(' ')[1]
                    elif header.startswith('User-Agent: '):
                        features['http_user_agent'] = header.split(' ')[1]
    
    # Update payload size variation
    features['payload_size_variety'] = np.std([len(packet[Raw].load) for packet in sniff(count=100, filter="ip") if Raw in packet])

    return features

# Calculate burstiness based on traffic volume
def calculate_burstiness():
    if len(TRAFFIC_VOLUME) < 2:
        return 0
    volume_changes = np.diff(TRAFFIC_VOLUME)
    burstiness = np.std(volume_changes) / np.mean(volume_changes)
    return burstiness

# Predict whether traffic is part of a DDoS attack
def is_attack(features):
    df = pd.DataFrame([features])
    prediction = model.predict(df)
    return prediction[0] == 1

# Monitor and analyze network traffic
def monitor_traffic():
    print("Monitoring traffic...")
    sniff(filter="ip", prn=process_packet, store=0)

# Process each captured packet
def process_packet(packet):
    features = extract_features(packet)
    if is_attack(features):
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

# Mitigate the detected attack
def mitigate_attack(packet, port):
    if IP in packet:
        source_ip = packet[IP].src
        block_ip(source_ip)
    close_port(port)

# Main function to start monitoring traffic
def main():
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.start()
    monitor_thread.join()

if __name__ == "__main__":
    main()

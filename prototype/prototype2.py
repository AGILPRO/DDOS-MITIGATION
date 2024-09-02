import socket
import threading
import time
import subprocess
import numpy as np
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from collections import defaultdict, deque

# Initialize data structures
BLOCKED_IPS = set()
ATTACKED_PORTS = set()
IP_REQUEST_COUNT = defaultdict(int)
PORT_ACCESS_COUNT = defaultdict(int)
SESSION_COUNT = defaultdict(int)
SESSION_START = defaultdict(float)
CONNECTION_DURATIONS = defaultdict(list)
TRAFFIC_VOLUME = deque(maxlen=60)
CONNECTION_COUNT = defaultdict(int)

# Configuration constants
SESSION_TIMEOUT = 600
TRAFFIC_CHECK_INTERVAL = 1
ALERT_THRESHOLD = 1000
PACKET_CAPTURE_LIMIT = 100  # Limit for packet capture

def calculate_burstiness():
    if len(TRAFFIC_VOLUME) < 2:
        return 0
    volume_changes = np.diff(TRAFFIC_VOLUME)
    burstiness = np.std(volume_changes) / np.mean(volume_changes)
    print(f"Burstiness calculated: {burstiness}")
    return burstiness

def extract_features(packet):
    try:
        print("Extracting features from packet...")
        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

        # Calculate payload size if Raw layer exists
        payload_size = len(packet[Raw].load) if Raw in packet else 0

        # Calculate payload size variety
        payload_sizes = [len(pkt[Raw].load) for pkt in scapy.sniff(count=100, filter="ip") if Raw in pkt]
        payload_size_variety = np.std(payload_sizes) if payload_sizes else 0

        # Calculate features
        features = {
            'packet_length': len(packet),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': packet[IP].proto if IP in packet else None,
            'src_port': src_port,
            'dst_port': dst_port,
            'payload_size': payload_size,
            'flags': packet[TCP].flags if TCP in packet else None,
            'request_rate': IP_REQUEST_COUNT.get(src_ip, 0),
            'payload_size_variety': payload_size_variety,
            'unique_ips': len(IP_REQUEST_COUNT),
            'port_access_frequency': PORT_ACCESS_COUNT.get(dst_port, 0),
            'session_frequency': SESSION_COUNT.get(src_ip, 0),
            'connection_duration': np.mean(CONNECTION_DURATIONS.get(src_ip, [0])),
            'traffic_volume': np.sum(TRAFFIC_VOLUME),
            'burstiness': calculate_burstiness()
        }

        print(f"Extracted features: {features}")
        return features

    except Exception as e:
        print(f"Error extracting features: {e}")
        return {}

def detect_ddos(features):
    print("Detecting DDoS attack...")
    if (features.get('packet_length', 0) > 100 or
        features.get('request_rate', 0) > 10 or
        features.get('session_frequency', 0) > 10 or
        features.get('connection_duration', 0) > 60 or
        features.get('burstiness', 0) > 1.5):
        print("DDoS attack detected based on features!")
        return True
    print("No DDoS attack detected.")
    return False

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Local IP Address: {local_ip}")
    return local_ip

def monitor_traffic(interface=None):
    print("Monitoring traffic...")
    local_ip = get_local_ip()
    try:
        # Capture packets with destination IP matching the local IP
        packets = scapy.sniff(count=PACKET_CAPTURE_LIMIT, filter=f"ip dst {local_ip}", iface=interface)
        # Analyze the captured packets
        analyze_packets(packets)
    except Exception as e:
        print(f"Error in sniffing packets: {e}")

def analyze_packets(packets):
    ip_counts = defaultdict(int)

    # Count the number of packets from each IP
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            ip_counts[src_ip] += 1

    # Check if any IP exceeds a normal range (e.g., more than 10 packets)
    for ip, count in ip_counts.items():
        if count > 10:
            print(f"IP {ip} has sent {count} packets. This might be suspicious.")
            IP_REQUEST_COUNT[ip] = count

            # Process the last packet from this IP to extract features and check for DDoS
            last_packet = [pkt for pkt in packets if IP in pkt and pkt[IP].src == ip][-1]
            features = extract_features(last_packet)
            if detect_ddos(features):
                print("Initiating mitigation...")
                attacked_port = identify_attacked_port(last_packet)
                mitigate_attack(last_packet, attacked_port)
        else:
            print(f"IP {ip} is within normal range with {count} packets.")

def identify_attacked_port(packet):
    print("Identifying attacked port...")
    if TCP in packet:
        print(f"Attacked port identified: {packet[TCP].dport}")
        return packet[TCP].dport
    elif UDP in packet:
        print(f"Attacked port identified: {packet[UDP].dport}")
        return packet[UDP].dport
    print("No attacked port identified.")
    return None

import subprocess

def block_ip(ip):
    if ip not in BLOCKED_IPS:
        print(f"Blocking IP: {ip}")
        rule_name = f"Block_{ip}"
        try:
            # First, try to delete any existing rule with the same name
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], check=False)

            # Add the new rule to block the IP
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"], check=True)
            BLOCKED_IPS.add(ip)
            print(f"IP {ip} has been blocked.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}. Error: {e}")



def close_port(port):
    if port and port not in ATTACKED_PORTS:
        print(f"Closing port: {port}")
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Close Port {port}", "dir=in", "action=block", f"protocol=TCP", f"localport={port}"], check=True)
        ATTACKED_PORTS.add(port)
        print(f"Port {port} has been closed.")

def mitigate_attack(packet, port):
    print("Mitigating attack...")
    if IP in packet:
        source_ip = packet[IP].src
        block_ip(source_ip)
    close_port(port)
    print("Attack mitigation completed.")

def main():
    interface = input("Enter the network interface (leave empty for default): ")
    monitor_thread = threading.Thread(target=monitor_traffic, args=(interface,))
    monitor_thread.start()
    monitor_thread.join()

if __name__ == "__main__":
    main()
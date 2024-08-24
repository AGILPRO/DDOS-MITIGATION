import socket
import threading
import time
import pickle
import numpy as np
import pandas as pd
from scapy.all import *
import subprocess

# Load the trained model
with open('ddos_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Configuration
TARGET_IP = '127.0.0.1'
BLOCKED_IPS = set()  # To keep track of blocked IPs
ATTACKED_PORTS = set()  # To keep track of ports under attack

def extract_features(packet):
    # Example feature extraction
    return {
        'request_rate': np.random.rand() * 100,
        'packet_size': len(packet),
        'source_ip_variety': len(set([p[IP].src for p in packet])),
    }

def is_attack(features):
    df = pd.DataFrame([features])
    prediction = model.predict(df)
    return prediction[0] == 1

def monitor_traffic():
    # Capture network traffic and predict if it's an attack
    print("Monitoring traffic...")
    packets = sniff(filter="ip", timeout=DURATION)
    
    for packet in packets:
        features = extract_features(packet)
        if is_attack(features):
            print("DDoS attack detected!")
            attacked_port = identify_attacked_port(packet)
            mitigate_attack(packet, attacked_port)
            break

def identify_attacked_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].dport
    return None

def block_ip(ip):
    # Add a rule to block the IP using iptables
    print(f"Blocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

def unblock_ip(ip):
    # Remove the rule to unblock the IP using iptables
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        BLOCKED_IPS.discard(ip)
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")

def close_port(port):
    # Add a rule to block the port using iptables
    print(f"Closing port: {port}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
        ATTACKED_PORTS.add(port)
    except subprocess.CalledProcessError as e:
        print(f"Error closing port {port}: {e}")

def reopen_port(port):
    # Remove the rule to reopen the port using iptables
    print(f"Reopening port: {port}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
        ATTACKED_PORTS.discard(port)
    except subprocess.CalledProcessError as e:
        print(f"Error reopening port {port}: {e}")

def mitigate_attack(packet, port):
    # Extract the source IP from the packet and block it
    if IP in packet:
        source_ip = packet[IP].src
        if source_ip not in BLOCKED_IPS:
            block_ip(source_ip)
    
    if port is not None and port not in ATTACKED_PORTS:
        close_port(port)

def main():
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.start()
    monitor_thread.join()

if __name__ == "__main__":
    main()

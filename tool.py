import socket
import threading
import time
import pickle
import numpy as np
import pandas as pd
from scapy.all import sniff, IP
from sklearn.preprocessing import StandardScaler

# Load the trained model and scaler
with open('ddos_model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# Configuration
LOG_FILE = 'ddos_log.txt'  # Log file for attack details

def extract_features(packet):
    try:
        # Extract relevant features from the packet
        packet_size = len(packet)
        source_ip = packet[IP].src
        return {
            'packet_size': packet_size,
            'source_ip': source_ip,
            # Add more feature extractions as needed
        }
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def preprocess_features(features):
    try:
        df = pd.DataFrame([features])
        scaled_features = scaler.transform(df)
        return scaled_features
    except Exception as e:
        print(f"Error preprocessing features: {e}")
        return None

def is_attack(features):
    try:
        processed_features = preprocess_features(features)
        if processed_features is not None:
            prediction = model.predict(processed_features)
            return prediction[0] == 1
    except Exception as e:
        print(f"Error predicting attack: {e}")
    return False

def log_attack(packet):
    with open(LOG_FILE, 'a') as log:
        log.write(f"Potential DDoS attack detected from {packet[IP].src} at {time.ctime()}\n")

def mitigate_attack():
    # Implement advanced mitigation strategies here
    print("Mitigating attack...")
    # Example: Use a firewall rule to block traffic or rate-limit requests

def monitor_traffic():
    # Capture network traffic and predict if it's an attack
    print("Monitoring traffic...")
    packets = sniff(filter="ip")  # Continuously sniff packets
    
    for packet in packets:
        features = extract_features(packet)
        if features is not None:
            if is_attack(features):
                print("DDoS attack detected!")
                log_attack(packet)
                mitigate_attack()
                break

def main():
    try:
        monitor_thread = threading.Thread(target=monitor_traffic)
        monitor_thread.start()
        monitor_thread.join()
    except Exception as e:
        print(f"Error in main execution: {e}")

if __name__ == "__main__":
    main()

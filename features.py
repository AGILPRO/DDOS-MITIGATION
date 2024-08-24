import pandas as pd
from scapy.all import sniff

# Function to extract features from packets
def extract_features(packet):
    # Example feature extraction; this should be adapted to your specific needs
    features = {
        'packet_length': len(packet),
        'src_ip': packet[IP].src if IP in packet else None,
        'dst_ip': packet[IP].dst if IP in packet else None,
        'protocol': packet.proto if IP in packet else None,
        'src_port': packet.sport if TCP in packet else None,
        'dst_port': packet.dport if TCP in packet else None,
    }
    return features

# Capture packets and extract features
def capture_and_label_data(duration=60):
    packets = sniff(timeout=duration)
    data = [extract_features(packet) for packet in packets]
    df = pd.DataFrame(data)
    return df

# Label the data manually or programmatically
df = capture_and_label_data()
df['label'] = 0  # 0 for normal traffic, 1 for DDoS attack traffic
df.to_csv('traffic_data.csv', index=False)

import pickle
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, Raw
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ddos_fixed_parameters import TRAFFIC_VOLUME, CONNECTION_DURATIONS, IP_REQUEST_COUNT, SESSION_COUNT, SESSION_START, calculate_burstiness

# Load the trained machine learning model
with open('ddos_model.pkl', 'rb') as f:
    model = pickle.load(f)

def extract_features_ml(packet):
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

    features['payload_size_variety'] = np.std([len(packet[Raw].load) for packet in sniff(count=100, filter="ip") if Raw in packet])

    return features

def is_attack(features):
    df = pd.DataFrame([features])
    prediction = model.predict(df)
    return prediction[0] == 1

def send_alert_email(subject, message):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = ALERT_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))
    
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(EMAIL_USER, EMAIL_PASS)
    server.sendmail(EMAIL_USER, ALERT_EMAIL, msg.as_string())
    server.quit()

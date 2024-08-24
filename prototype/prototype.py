import socket
import threading
import time
import subprocess
from scapy.all import *
from collections import defaultdict, deque
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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
ALERT_THRESHOLD = 1000  # Threshold for sending an alert to the admin
ALERT_EMAIL = "admin@example.com"  # Replace with admin's email address

# Email configuration
SMTP_SERVER = "smtp.example.com"  # Replace with your SMTP server
SMTP_PORT = 587
EMAIL_USER = "your_email@example.com"  # Replace with your email
EMAIL_PASS = "your_email_password"  # Replace with your email password

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

def extract_features(packet):
    features = {
        'packet_length': len(packet),
        'src_ip': packet[IP].src if IP in packet else None,
        'dst_ip': packet[IP].dst if IP in packet else None,
        'protocol': packet.proto if IP in packet else None,
        'src_port': packet.sport if TCP in packet else None,
        'dst_port': packet.dport if TCP in packet else None,
        'payload_size': len(packet[Raw].load) if Raw in packet else 0,
        'flags': packet[TCP].flags if TCP in packet else None
    }
    return features

def detect_ddos(features):
    # Example heuristic features for detecting DDoS attacks
    # This is a basic example and can be expanded
    if features.get('packet_length', 0) > 1000 or features.get('flags') == 'S':
        return True
    return False

def monitor_traffic():
    print("Monitoring traffic...")
    sniff(filter="ip", prn=process_packet, store=0)

def process_packet(packet):
    src_ip = packet[IP].src if IP in packet else None
    if src_ip:
        IP_REQUEST_COUNT[src_ip] += 1
    
    if sum(IP_REQUEST_COUNT.values()) > ALERT_THRESHOLD:
        send_alert_email("DDoS Alert", f"High request rate detected. Total requests: {sum(IP_REQUEST_COUNT.values())}")
        print("Admin alerted via email.")
    
    features = extract_features(packet)
    if detect_ddos(features):
        print("DDoS attack detected!")
        attacked_port = identify_attacked_port(packet)
        mitigate_attack(packet, attacked_port)

def identify_attacked_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].dport
    return None

def block_ip(ip):
    if ip not in BLOCKED_IPS:
        print(f"Blocking IP: {ip}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip)

def close_port(port):
    if port and port not in ATTACKED_PORTS:
        print(f"Closing port: {port}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
        ATTACKED_PORTS.add(port)

def mitigate_attack(packet, port):
    if IP in packet:
        source_ip = packet[IP].src
        block_ip(source_ip)
    close_port(port)

def main():
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.start()
    monitor_thread.join()

if __name__ == "__main__":
    main()

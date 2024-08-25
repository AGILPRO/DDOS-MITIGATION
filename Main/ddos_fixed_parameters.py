import subprocess
import time
from scapy.all import IP, TCP, UDP, sniff
from collections import defaultdict, deque

BLOCKED_IPS = set()
ATTACKED_PORTS = set()
IP_REQUEST_COUNT = defaultdict(int)
PORT_ACCESS_COUNT = defaultdict(int)
SESSION_COUNT = defaultdict(int)
SESSION_START = defaultdict(float)
CONNECTION_DURATIONS = defaultdict(list)
TRAFFIC_VOLUME = deque(maxlen=60)  # Store traffic volume for the last 60 seconds

SESSION_TIMEOUT = 600  # Session timeout in seconds
ALERT_THRESHOLD = 1000  # Threshold for sending an alert to the admin
PACKET_COUNT_THRESHOLD = 100  # Threshold for packet count per IP
SESSION_TIME_THRESHOLD = 1200  # Threshold for session time in seconds
TTL_THRESHOLD = 128  # Threshold for TTL value
PACKET_RATE_THRESHOLD = 50  # Number of packets from a single IP within a timestamp

def extract_features_fixed(packet):
    features = {
        'packet_length': len(packet),
        'src_ip': packet[IP].src if IP in packet else None,
        'dst_ip': packet[IP].dst if IP in packet else None,
        'protocol': packet.proto if IP in packet else None,
        'src_port': packet.sport if TCP in packet else None,
        'dst_port': packet.dport if TCP in packet else None,
        'request_rate': 0,
        'payload_size_variety': 0,
        'unique_ips': len(IP_REQUEST_COUNT),
        'port_access_frequency': PORT_ACCESS_COUNT.get(packet[TCP].dport if TCP in packet else None, 0),
        'session_frequency': SESSION_COUNT.get(packet[IP].src if IP in packet else None, 0),
        'connection_duration': np.mean(CONNECTION_DURATIONS.get(packet[IP].src if IP in packet else None, [0])),
        'traffic_volume': np.sum(TRAFFIC_VOLUME),
        'burstiness': calculate_burstiness(),
        'ttl': packet[IP].ttl if IP in packet else None  # TTL value
    }

    src_ip = packet[IP].src if IP in packet else None
    if src_ip:
        IP_REQUEST_COUNT[src_ip] += 1
        current_time = time.time()
        session_start = SESSION_START.get(src_ip, current_time)
        if current_time - session_start > SESSION_TIMEOUT:
            SESSION_COUNT[src_ip] = 0
            SESSION_START[src_ip] = current_time
        SESSION_COUNT[src_ip] += 1

        CONNECTION_DURATIONS[src_ip].append(time.time() - SESSION_START[src_ip])
    
    return features

def calculate_burstiness():
    if len(TRAFFIC_VOLUME) < 2:
        return 0
    volume_changes = np.diff(TRAFFIC_VOLUME)
    burstiness = np.std(volume_changes) / np.mean(volume_changes)
    return burstiness

def check_general_ddos_conditions(packet):
    src_ip = packet[IP].src if IP in packet else None

    if not src_ip:
        return False

    # Check if the packet count from a single IP exceeds the threshold
    if IP_REQUEST_COUNT[src_ip] > PACKET_COUNT_THRESHOLD:
        print(f"Packet count exceeded for IP: {src_ip}")
        block_ip(src_ip)
        return True
    
    # Check if session time for the IP exceeds the threshold
    if SESSION_COUNT.get(src_ip, 0) * SESSION_TIMEOUT > SESSION_TIME_THRESHOLD:
        print(f"Session time exceeded for IP: {src_ip}")
        block_ip(src_ip)
        return True
    
    # Check if TTL value is unusually high
    ttl = packet[IP].ttl if IP in packet else None
    if ttl and ttl > TTL_THRESHOLD:
        print(f"High TTL value detected: {ttl}")
        block_ip(src_ip)
        return True

    # Check if a large number of packets from a single IP within a timestamp
    timestamp = int(time.time())
    packet_counts = defaultdict(int)
    for pkt in sniff(count=100, timeout=1, filter="ip"):
        if IP in pkt:
            packet_counts[pkt[IP].src] += 1
    if packet_counts.get(src_ip, 0) > PACKET_RATE_THRESHOLD:
        print(f"Large number of packets from IP: {src_ip}")
        block_ip(src_ip)
        return True

    return False

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

def mitigate_attack_fixed(packet, port):
    if IP in packet:
        source_ip = packet[IP].src
        block_ip(source_ip)
    close_port(port)

def process_packet(packet):
    if check_general_ddos_conditions(packet):
        print("General DDoS condition detected!")
        attacked_port = identify_attacked_port(packet)
        mitigate_attack_fixed(packet, attacked_port)

def identify_attacked_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].dport
    return None

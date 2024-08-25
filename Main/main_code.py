import threading
from scapy.all import sniff, IP
from ddos_fixed_parameters import mitigate_attack_fixed
from ddos_ml_parameters import extract_features_ml, is_attack, send_alert_email

# Define the port hopping module import
import port_hopping  # Make sure this module is in the same directory or adjust the path

def process_packet(packet):
    src_ip = packet[IP].src if IP in packet else None
    if src_ip:
        IP_REQUEST_COUNT[src_ip] += 1
    
    if sum(IP_REQUEST_COUNT.values()) > ALERT_THRESHOLD:
        send_alert_email("DDoS Alert", f"High request rate detected. Total requests: {sum(IP_REQUEST_COUNT.values())}")
        print("Admin alerted via email.")
    
    features = extract_features_ml(packet)
    if is_attack(features):
        print("DDoS attack detected!")
        attacked_port = identify_attacked_port(packet)
        mitigate_attack_fixed(packet, attacked_port)
        port_hopping.change_port()  # Call the port hopping function

def identify_attacked_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].dport
    return None

def monitor_traffic():
    current_port = port_hopping.get_current_port()
    print(f"Monitoring traffic on port {current_port}")
    sniff(filter=f"tcp and port {current_port}", prn=process_packet, store=0)

def main():
    monitor_thread = threading.Thread(target=monitor_traffic)
    monitor_thread.start()
    monitor_thread.join()

if __name__ == "__main__":
    main()

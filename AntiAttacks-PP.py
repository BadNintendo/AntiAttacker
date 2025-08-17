import socket
import select
import json
import logging
import threading
from datetime import datetime
import re

# 🖍️ Styled console output: green background, black text, white for digits/symbols
def styled_print(message):
    styled = ""
    for char in message:
        if re.match(r'[0-9\W]', char):  # digits or symbols
            styled += "\033[31m" + char + "\033[0m"
        else:
            styled += "\033[31m" + char + "\033[0m"
    print(styled)

# 🧾 Logging setup
def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')

# 🧠 Attack detection validators
def detect_packet_injection(data):
    return bool(re.search(r'suspicious_pattern', data.decode('utf-8')))

def detect_command_injection(data):
    patterns = [r';\s*(rm|shutdown|exec|wget|curl)', r'\b(eval|os\.system)\b']
    return any(re.search(p, data.decode('utf-8'), re.IGNORECASE) for p in patterns)

def detect_sql_injection(data):
    patterns = [r"(\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b).*--", r"' OR '1'='1"]
    return any(re.search(p, data.decode('utf-8'), re.IGNORECASE) for p in patterns)

def detect_xss(data):
    return bool(re.search(r'<script.*?>.*?</script>', data.decode('utf-8'), re.IGNORECASE))

def detect_unicode_obfuscation(data):
    return bool(re.search(r'[\u202e\u200f\u200e]', data.decode('utf-8')))

def detect_oversized_payload(data, max_size=8192):
    return len(data) > max_size

# 🧩 Rate limiting tracker
connections = {}
def detect_rate_limiting(address):
    current_time = datetime.now()
    if address not in connections:
        connections[address] = []
    connections[address].append(current_time)
    connections[address] = [time for time in connections[address] if (current_time - time).seconds < 60]

    if len(connections[address]) > 100:
        warning_message = f"Rate limiting alert for {address}"
        logging.warning(warning_message)
        styled_print(warning_message)

# 🛡️ Traffic logger + attack scanner
def log_traffic(protocol, address, data):
    message = f"{protocol} from {address}: {data.decode('utf-8')}"
    logging.info(message)
    styled_print(message)

    alerts = []
    if detect_packet_injection(data): alerts.append("Packet injection")
    if detect_command_injection(data): alerts.append("Command injection")
    if detect_sql_injection(data): alerts.append("SQL injection")
    if detect_xss(data): alerts.append("XSS attempt")
    if detect_unicode_obfuscation(data): alerts.append("Unicode obfuscation")
    if detect_oversized_payload(data): alerts.append("Oversized payload")

    for alert in alerts:
        warning_message = f"{alert} detected from {address}"
        logging.warning(warning_message)
        styled_print(warning_message)

    detect_rate_limiting(address)

# 🧠 Attack summary from logs
def detect_attack(log_file):
    with open(log_file, 'r') as file:
        lines = file.readlines()

    attack_ips = set()
    attack_methods = {
        'DDoS': [],
        'Phishing': [],
        'Malware': [],
        'Unauthorized Access': []
    }

    for line in lines:
        if "attack detected" in line:
            parts = line.split(' ')
            ip = parts[-1].strip()
            method = identify_attack_method(line)
            attack_ips.add(ip)
            if method in attack_methods:
                attack_methods[method].append(ip)

    for ip in attack_ips:
        styled_print(f"Possible attack from IP: {ip}")

    for method, ips in attack_methods.items():
        styled_print(f"\n{method} Attacks:")
        for ip in ips:
            styled_print(f" - {ip}")

def identify_attack_method(log_entry):
    if "DDoS" in log_entry: return 'DDoS'
    elif "Phishing" in log_entry: return 'Phishing'
    elif "Malware" in log_entry: return 'Malware'
    elif "Unauthorized access" in log_entry: return 'Unauthorized Access'
    else: return 'Unknown'

# 🔧 Request processor
def process_request(data):
    return {"message": "Request processed successfully"}

# 🔌 TCP handler
def handle_tcp_connection(tcp_socket):
    connection, client_address = tcp_socket.accept()
    try:
        data = connection.recv(4096)
        if data:
            log_traffic('TCP', client_address, data)
            result = process_request(data)
            response = json.dumps(result).encode('utf-8')
            connection.sendall(response)
    except Exception as e:
        logging.error(f"TCP error: {e}")
        styled_print(f"TCP error: {e}")
    finally:
        connection.close()

# 📡 UDP handler
def handle_udp_connection(udp_socket):
    try:
        data, address = udp_socket.recvfrom(4096)
        if data:
            log_traffic('UDP', address, data)
            result = process_request(data)
            response = json.dumps(result).encode('utf-8')
            udp_socket.sendto(response, address)
    except Exception as e:
        logging.error(f"UDP error: {e}")
        styled_print(f"UDP error: {e}")

# 🔁 Socket watcher
def watch_sockets(sockets_list):
    while True:
        read_sockets, _, _ = select.select(sockets_list, [], [])
        for notified_socket in read_sockets:
            if notified_socket == sockets_list[0]:
                handle_tcp_connection(sockets_list[0])
            elif notified_socket == sockets_list[1]:
                handle_udp_connection(sockets_list[1])

# 🧵 Data handler thread
def handle_data(tcp_socket, udp_socket):
    while True:
        read_sockets, _, _ = select.select([tcp_socket, udp_socket], [], [])
        for notified_socket in read_sockets:
            if notified_socket == tcp_socket:
                handle_tcp_connection(tcp_socket)
            elif notified_socket == udp_socket:
                handle_udp_connection(udp_socket)

# 🚀 Server bootstrap
def combined_server(host='0.0.0.0', port=80, log_file='server_log.txt'):
    setup_logging(log_file)
    logging.info("Server starting...")

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((host, port))
    tcp_socket.listen(5)
    logging.info(f"TCP server is listening on {host}:{port}...")
    styled_print(f"TCP server is listening on {host}:{port}...")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((host, port))
    logging.info(f"UDP server is listening on {host}:{port}...")
    styled_print(f"UDP server is listening on {host}:{port}...")

    sockets_list = [tcp_socket, udp_socket]

    socket_thread = threading.Thread(target=watch_sockets, args=(sockets_list,))
    data_thread = threading.Thread(target=handle_data, args=(tcp_socket, udp_socket))

    socket_thread.start()
    data_thread.start()

    socket_thread.join()
    data_thread.join()

# 🏁 Entry point
if __name__ == "__main__":
    banner = '██████╗ersonal\n██╔══██╗ortection\n██████╔╝\n██╔═══╝\n██║Server starting...\n╚═╝'
    styled_print(banner)
    combined_server()
    detect_attack('server_log.txt')

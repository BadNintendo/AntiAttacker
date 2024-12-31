import socket
import select
import json
import logging
import threading
from datetime import datetime
import re

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, 
                        format='%(asctime)s %(levelname)s %(message)s')

def combined_server(host='0.0.0.0', port=80, log_file='server_log.txt'):
    setup_logging(log_file)
    logging.info("Server starting...")
    print("Server starting...")

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((host, port))
    tcp_socket.listen(5)
    logging.info(f"TCP server is listening on {host}:{port}...")
    print(f"TCP server is listening on {host}:{port}...")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((host, port))
    logging.info(f"UDP server is listening on {host}:{port}...")
    print(f"UDP server is listening on {host}:{port}...")

    sockets_list = [tcp_socket, udp_socket]

    # Create threads
    socket_thread = threading.Thread(target=watch_sockets, args=(sockets_list,))
    data_thread = threading.Thread(target=handle_data, args=(tcp_socket, udp_socket))

    socket_thread.start()
    data_thread.start()

    socket_thread.join()
    data_thread.join()

def watch_sockets(sockets_list):
    while True:
        read_sockets, _, _ = select.select(sockets_list, [], [])
        for notified_socket in read_sockets:
            if notified_socket == sockets_list[0]:  # TCP socket
                handle_tcp_connection(sockets_list[0])
            elif notified_socket == sockets_list[1]:  # UDP socket
                handle_udp_connection(sockets_list[1])

def handle_data(tcp_socket, udp_socket):
    while True:
        read_sockets, _, _ = select.select([tcp_socket, udp_socket], [], [])
        for notified_socket in read_sockets:
            if notified_socket == tcp_socket:
                handle_tcp_connection(tcp_socket)
            elif notified_socket == udp_socket:
                handle_udp_connection(udp_socket)

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
        print(f"TCP error: {e}")
    finally:
        connection.close()

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
        print(f"UDP error: {e}")

def log_traffic(protocol, address, data):
    message = f"{protocol} from {address}: {data.decode('utf-8')}"
    logging.info(message)
    print(message)
    if detect_packet_injection(data):
        warning_message = f"Possible packet injection from {address}"
        logging.warning(warning_message)
        print(warning_message)
    detect_rate_limiting(address)

def detect_packet_injection(data):
    packet_injection_pattern = re.compile(r'suspicious_pattern')  # Replace with actual pattern
    return bool(packet_injection_pattern.search(data.decode('utf-8')))

connections = {}
def detect_rate_limiting(address):
    current_time = datetime.now()
    if address not in connections:
        connections[address] = []
    connections[address].append(current_time)
    connections[address] = [time for time in connections[address] if (current_time - time).seconds < 60]
    
    if len(connections[address]) > 100:  # Example threshold
        warning_message = f"Rate limiting alert for {address}"
        logging.warning(warning_message)
        print(warning_message)

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
        print(f"Possible attack from IP: {ip}")
        
    for method, ips in attack_methods.items():
        print(f"\n{method} Attacks:")
        for ip in ips:
            print(f" - {ip}")

def identify_attack_method(log_entry):
    if "DDoS" in log_entry:
        return 'DDoS'
    elif "Phishing" in log_entry:
        return 'Phishing'
    elif "Malware" in log_entry:
        return 'Malware'
    elif "Unauthorized access" in log_entry:
        return 'Unauthorized Access'
    else:
        return 'Unknown'

def process_request(data):
    return {"message": "Request processed successfully"}

if __name__ == "__main__":
    combined_server()
    detect_attack('server_log.txt')

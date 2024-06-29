import socket
import struct
import time
import random
from scapy.all import *

# Dictionary to store flow information
flows = {}

# Function to generate flow ID
def generate_flow_id(src_ip, dst_ip, src_port, dst_port, proto):
    return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"

# Function to get protocol name
def get_protocol_name(proto):
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocol_map.get(proto, "OTHER")

# Function to parse packet and extract features
def parse_packet(packet):
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    if eth_protocol == 8:  # IP protocol
        ip_header = packet[eth_length:20+eth_length]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        protocol = iph[6]
        src_addr = socket.inet_ntoa(iph[8])
        dst_addr = socket.inet_ntoa(iph[9])

        if protocol == 6:  # TCP
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcph[0]
            dst_port = tcph[1]
            flags = tcph[5]
            window = tcph[6]
            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'flags': flags,
                'window': window,
                'packet_len': len(packet)
            }

        elif protocol == 17:  # UDP
            u = iph_length + eth_length
            udp_header = packet[u:u+8]
            udph = struct.unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]
            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'flags': None,
                'window': None,
                'packet_len': len(packet)
            }

        elif protocol == 1:  # ICMP
            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': None,
                'dst_port': None,
                'protocol': protocol,
                'flags': None,
                'window': None,
                'packet_len': len(packet)
            }

# Function to handle each packet received
def packet_callback(packet):
    parsed_packet = parse_packet(bytes(packet))
    if parsed_packet:
        flow_id = generate_flow_id(
            parsed_packet['src_addr'],
            parsed_packet['dst_addr'],
            parsed_packet['src_port'],
            parsed_packet['dst_port'],
            parsed_packet['protocol']
        )
        if flow_id not in flows:
            flows[flow_id] = {
                "FLOW_ID": flow_id,
                "PROTOCOL_MAP": get_protocol_name(parsed_packet['protocol']),
                "L4_SRC_PORT": parsed_packet['src_port'],
                "IPV4_SRC_ADDR": parsed_packet['src_addr'],
                "L4_DST_PORT": parsed_packet['dst_port'],
                "IPV4_DST_ADDR": parsed_packet['dst_addr'],
                "FIRST_SWITCHED": int(time.time()),
                "FLOW_DURATION_MILLISECONDS": 0,
                "LAST_SWITCHED": int(time.time()),
                "PROTOCOL": parsed_packet['protocol'],
                "TCP_FLAGS": parsed_packet['flags'],
                "TCP_WIN_MAX_IN": parsed_packet['window'],
                "TCP_WIN_MAX_OUT": parsed_packet['window'],
                "TCP_WIN_MIN_IN": parsed_packet['window'],
                "TCP_WIN_MIN_OUT": parsed_packet['window'],
                "TCP_WIN_MSS_IN": None,
                "TCP_WIN_SCALE_IN": None,
                "TCP_WIN_SCALE_OUT": None,
                "SRC_TOS": None,
                "DST_TOS": None,
                "TOTAL_FLOWS_EXP": 1,
                "MIN_IP_PKT_LEN": parsed_packet['packet_len'],
                "MAX_IP_PKT_LEN": parsed_packet['packet_len'],
                "TOTAL_PKTS_EXP": 1,
                "TOTAL_BYTES_EXP": parsed_packet['packet_len'],
                "IN_BYTES": parsed_packet['packet_len'],
                "IN_PKTS": 1,
                "OUT_BYTES": 0,
                "OUT_PKTS": 0,
                "ANALYSIS_TIMESTAMP": int(time.time()),
                "ANOMALY": 0,
                "ALERT": "None",
                "ID": random.randint(100000, 999999)
            }
            print(f"New Flow Created: {flows[flow_id]}")
        else:
            flow = flows[flow_id]
            flow["LAST_SWITCHED"] = int(time.time())
            flow["FLOW_DURATION_MILLISECONDS"] = (flow["LAST_SWITCHED"] - flow["FIRST_SWITCHED"]) * 1000
            flow["TOTAL_PKTS_EXP"] += 1
            flow["TOTAL_BYTES_EXP"] += parsed_packet['packet_len']
            flow["IN_BYTES"] += parsed_packet['packet_len']
            flow["IN_PKTS"] += 1
            flow["MIN_IP_PKT_LEN"] = min(flow["MIN_IP_PKT_LEN"], parsed_packet['packet_len'])
            flow["MAX_IP_PKT_LEN"] = max(flow["MAX_IP_PKT_LEN"], parsed_packet['packet_len'])
            flow["ANALYSIS_TIMESTAMP"] = int(time.time())
            print(f"Flow Updated: {flow}")

# Main function to capture packets
def main():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("PermissionError: Please run this script with elevated privileges (sudo).")
        return

    while True:
        packet, addr = s.recvfrom(65536)
        packet_callback(packet)

if __name__ == "__main__":
    main()

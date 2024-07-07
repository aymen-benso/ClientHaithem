import os
import socket
import struct
import time
import csv
import numpy as np
from scapy.all import *

# Dictionary to store flow information
flows = {}

# Function to generate flow ID
def generate_flow_id(src_ip, dst_ip, src_port, dst_port, proto):
    return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"

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

            packet_len = len(packet)
            flow_duration = 0  # Placeholder for flow duration calculation

            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'flags': flags,
                'window': window,
                'packet_len': packet_len,
                'flow_duration': flow_duration,
                'FIRST_SWITCHED': int(time.time()),
                'LAST_SWITCHED': int(time.time()),
                'ANALYSIS_TIMESTAMP': int(time.time()),
                'TOTAL_PKTS_EXP': 1,
                'TOTAL_BYTES_EXP': packet_len
            }

        elif protocol == 17:  # UDP
            u = iph_length + eth_length
            udp_header = packet[u:u+8]
            udph = struct.unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]
            packet_len = len(packet)

            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'flags': None,
                'window': None,
                'packet_len': packet_len,
                'FIRST_SWITCHED': int(time.time()),
                'LAST_SWITCHED': int(time.time()),
                'ANALYSIS_TIMESTAMP': int(time.time()),
                'TOTAL_PKTS_EXP': 1,
                'TOTAL_BYTES_EXP': packet_len
            }

        elif protocol == 1:  # ICMP
            packet_len = len(packet)

            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': None,
                'dst_port': None,
                'protocol': protocol,
                'flags': None,
                'window': None,
                'packet_len': packet_len,
                'FIRST_SWITCHED': int(time.time()),
                'LAST_SWITCHED': int(time.time()),
                'ANALYSIS_TIMESTAMP': int(time.time()),
                'TOTAL_PKTS_EXP': 1,
                'TOTAL_BYTES_EXP': packet_len
            }

# Function to handle packet callback
def packet_callback(packet):
    parsed_packet = parse_packet(bytes(packet))
    filename = 'flow.csv'

    if parsed_packet:
        flow_id = generate_flow_id(
            parsed_packet['src_addr'],
            parsed_packet['dst_addr'],
            parsed_packet['src_port'],
            parsed_packet['dst_port'],
            parsed_packet['protocol']
        )

        if flow_id not in flows:
            flows[flow_id] = parsed_packet
            print(f"New Flow Created: {flows[flow_id]}")
        else:
            flow = flows[flow_id]
            flow_duration = (time.time() - flow['FIRST_SWITCHED']) * 1000
            flow['flow_duration'] = flow_duration
            flow['LAST_SWITCHED'] = int(time.time())
            flow['TOTAL_PKTS_EXP'] += 1
            flow['TOTAL_BYTES_EXP'] += parsed_packet['packet_len']

            # Update other flow features here
            # Example:
            # flow['fwd_pkt_len_mean'] = ...

            print(f"Flow Updated: {flow}")

            # Write flow to CSV
            with open(filename, 'a') as f:
                writer = csv.DictWriter(f, fieldnames=flow.keys())
                if os.stat(filename).st_size == 0:
                    writer.writeheader()
                writer.writerow(flow)

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

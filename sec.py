import socket
import struct
import time
import random
import csv
from scapy.all import *

class PacketSniffer:
    def __init__(self, csv_file='packet_flows.csv'):
        self.flows = {}
        self.csv_file = csv_file
        self.init_csv()

    def init_csv(self):
        with open(self.csv_file, 'w', newline='') as csvfile:
            fieldnames = [
                "FLOW_ID", "PROTOCOL_MAP", "L4_SRC_PORT", "IPV4_SRC_ADDR",
                "L4_DST_PORT", "IPV4_DST_ADDR", "FIRST_SWITCHED", "FLOW_DURATION_MILLISECONDS",
                "LAST_SWITCHED", "PROTOCOL", "TCP_FLAGS", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
                "TCP_WIN_MIN_IN", "TCP_WIN_MIN_OUT", "TCP_WIN_MSS_IN", "TCP_WIN_SCALE_IN",
                "TCP_WIN_SCALE_OUT", "SRC_TOS", "DST_TOS", "TOTAL_FLOWS_EXP", "MIN_IP_PKT_LEN",
                "MAX_IP_PKT_LEN", "TOTAL_PKTS_EXP", "TOTAL_BYTES_EXP", "IN_BYTES", "IN_PKTS",
                "OUT_BYTES", "OUT_PKTS", "ANALYSIS_TIMESTAMP", "ANOMALY", "ALERT", "ID"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

    def write_to_csv(self, flow):
        with open(self.csv_file, 'a', newline='') as csvfile:
            fieldnames = [
                "FLOW_ID", "PROTOCOL_MAP", "L4_SRC_PORT", "IPV4_SRC_ADDR",
                "L4_DST_PORT", "IPV4_DST_ADDR", "FIRST_SWITCHED", "FLOW_DURATION_MILLISECONDS",
                "LAST_SWITCHED", "PROTOCOL", "TCP_FLAGS", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
                "TCP_WIN_MIN_IN", "TCP_WIN_MIN_OUT", "TCP_WIN_MSS_IN", "TCP_WIN_SCALE_IN",
                "TCP_WIN_SCALE_OUT", "SRC_TOS", "DST_TOS", "TOTAL_FLOWS_EXP", "MIN_IP_PKT_LEN",
                "MAX_IP_PKT_LEN", "TOTAL_PKTS_EXP", "TOTAL_BYTES_EXP", "IN_BYTES", "IN_PKTS",
                "OUT_BYTES", "OUT_PKTS", "ANALYSIS_TIMESTAMP", "ANOMALY", "ALERT", "ID"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow(flow)

    def generate_flow_id(self, src_ip, dst_ip, src_port, dst_port, proto):
        return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"

    def get_protocol_name(self, proto):
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocol_map.get(proto, "OTHER")

    def parse_packet(self, packet):
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

    def process_packet(self, packet):
        parsed_packet = self.parse_packet(packet)
        if parsed_packet:
            flow_id = self.generate_flow_id(
                parsed_packet['src_addr'],
                parsed_packet['dst_addr'],
                parsed_packet['src_port'],
                parsed_packet['dst_port'],
                parsed_packet['protocol']
            )
            if flow_id not in self.flows:
                new_flow = {
                    "FLOW_ID": flow_id,
                    "PROTOCOL_MAP": self.get_protocol_name(parsed_packet['protocol']),
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
                self.flows[flow_id] = new_flow
                self.write_to_csv(new_flow)
                print(f"New Flow Created: {self.flows[flow_id]}")
            else:
                flow = self.flows[flow_id]
                flow["LAST_SWITCHED"] = int(time.time())
                flow["FLOW_DURATION_MILLISECONDS"] = (flow["LAST_SWITCHED"] - flow["FIRST_SWITCHED"]) * 1000
                flow["TOTAL_PKTS_EXP"] += 1
                flow["TOTAL_BYTES_EXP"] += parsed_packet['packet_len']
                flow["IN_BYTES"] += parsed_packet['packet_len']
                flow["IN_PKTS"] += 1
                flow["MIN_IP_PKT_LEN"] = min(flow["MIN_IP_PKT_LEN"], parsed_packet['packet_len'])
                flow["MAX_IP_PKT_LEN"] = max(flow["MAX_IP_PKT_LEN"], parsed_packet['packet_len'])
                flow["ANALYSIS_TIMESTAMP"] = int(time.time())
                self.write_to_csv(flow)
                print(f"Flow Updated: {flow}")

    def capture_packets(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("PermissionError: Please run this script with elevated privileges (sudo).")
            return

        while True:
            packet, addr = s.recvfrom(65536)
            self.process_packet(packet)

if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.capture_packets()




"""

import socket
import struct
import time
import random
from scapy.all import *

class PacketSniffer:
    def __init__(self):
        self.flows = {}

    def generate_flow_id(self, src_ip, dst_ip, src_port, dst_port, proto):
        return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"

    def get_protocol_name(self, proto):
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocol_map.get(proto, "OTHER")

    def parse_packet(self, packet):
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

    def process_packet(self, packet):
        parsed_packet = self.parse_packet(bytes(packet))
        if parsed_packet:
            flow_id = self.generate_flow_id(
                parsed_packet['src_addr'],
                parsed_packet['dst_addr'],
                parsed_packet['src_port'],
                parsed_packet['dst_port'],
                parsed_packet['protocol']
            )
            if flow_id not in self.flows:
                self.flows[flow_id] = {
                    "FLOW_ID": flow_id,
                    "PROTOCOL_MAP": self.get_protocol_name(parsed_packet['protocol']),
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
                print(f"New Flow Created: {self.flows[flow_id]}")
            else:
                flow = self.flows[flow_id]
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

    def capture_packets(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("PermissionError: Please run this script with elevated privileges (sudo).")
            return

        while True:
            packet, addr = s.recvfrom(65536)
            self.process_packet(packet)
"""
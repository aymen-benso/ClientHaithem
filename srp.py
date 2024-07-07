import os
import socket
import struct
from sys import flags
import time
import random
import numpy as np
from scapy.all import *


flows = {}


def generate_flow_id(src_ip, dst_ip, src_port, dst_port, proto):
    return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"


def get_protocol_name(proto):
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocol_map.get(proto, "OTHER")


def parse_packet(packet):
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    filename = 'flow.csv'

    if eth_protocol == 8:  
        ip_header = packet[eth_length:20+eth_length]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        protocol = iph[6]
        src_addr = socket.inet_ntoa(iph[8])
        dst_addr = socket.inet_ntoa(iph[9])

        if protocol == 6: 
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcph[0]
            dst_port = tcph[1]
            flags = tcph[5]
            window = tcph[6]

            # Calculate the 72 features
            flow_duration = 0  # Calculate flow duration
            tot_fwd_pkts = 1  # Total forward packets
            tot_bwd_pkts = 0  # Total backward packets
            totlen_fwd_pkts = len(packet)  # Total length of forward packets
            totlen_bwd_pkts = 0  # Total length of backward packets
            fwd_pkt_len_max = len(packet)  # Maximum length of forward packets
            fwd_pkt_len_min = len(packet)  # Minimum length of forward packets
            fwd_pkt_len_mean = len(packet)  # Mean length of forward packets
            fwd_pkt_len_std = 0  # Standard deviation of forward packet lengths
            bwd_pkt_len_max = 0  # Maximum length of backward packets
            bwd_pkt_len_min = 0  # Minimum length of backward packets
            bwd_pkt_len_mean = 0  # Mean length of backward packets
            bwd_pkt_len_std = 0  # Standard deviation of backward packet lengths
            flow_iat_mean = 0  # Mean of flow inter-arrival time
            flow_iat_std = 0  # Standard deviation of flow inter-arrival time
            flow_iat_max = 0  # Maximum flow inter-arrival time
            flow_iat_min = 0  # Minimum flow inter-arrival time
            fwd_iat_tot = 0  # Total forward inter-arrival time
            fwd_iat_mean = 0  # Mean forward inter-arrival time
            fwd_iat_std = 0  # Standard deviation of forward inter-arrival time
            fwd_iat_max = 0  # Maximum forward inter-arrival time
            fwd_iat_min = 0  # Minimum forward inter-arrival time
            bwd_iat_tot = 0  # Total backward inter-arrival time
            bwd_iat_mean = 0  # Mean backward inter-arrival time
            bwd_iat_std = 0  # Standard deviation of backward inter-arrival time
            bwd_iat_max = 0  # Maximum backward inter-arrival time
            bwd_iat_min = 0  # Minimum backward inter-arrival time
            fwd_psh_flags = 0  # Number of times the PSH flag was set in the forward direction
            bwd_psh_flags = 0  # Number of times the PSH flag was set in the backward direction
            fwd_urg_flags = 0  # Number of times the URG flag was set in the forward direction
            bwd_urg_flags = 0  # Number of times the URG flag was set in the backward direction
            fwd_header_len = 0  # Length of the forward packet header
            bwd_header_len = 0  # Length of the backward packet header
            fwd_pkts_s = 1  # Number of forward packets per second
            bwd_pkts_s = 0  # Number of backward packets per second
            pkt_len_min = len(packet)  # Minimum packet length
            pkt_len_max = len(packet)  # Maximum packet length
            pkt_len_mean = len(packet)  # Mean packet length
            pkt_len_std = 0  # Standard deviation of packet lengths
            pkt_len_var = 0  # Variance of packet lengths
            fin_flag_cnt = 0  # Number of packets with FIN flag
            syn_flag_cnt = 0  # Number of packets with SYN flag
            rst_flag_cnt = 0  # Number of packets with RST flag
            ack_flag_cnt = 0  # Number of packets with ACK flag
            urg_flag_cnt = 0  # Number of packets with URG flag
            cwe_flag_count = 0  # Number of packets with CWE flag
            ece_flag_cnt = 0  # Number of packets with ECE flag
            down_up_ratio = 0  # Ratio of downlink to uplink packets
            pkt_size_avg = len(packet)  # Average packet size
            fwd_seg_size_avg = len(packet)  # Average size of forward segments
            bwd_seg_size_avg = 0  # Average size of backward segments
            fwd_byts_b_avg = len(packet)  # Average number of forward bytes per bulk
            fwd_pkts_b_avg = 1  # Average number of forward packets per bulk
            fwd_blk_rate_avg = 0  # Average rate of forward bulk rate
            bwd_byts_b_avg = 0  # Average number of backward bytes per bulk
            bwd_pkts_b_avg = 0  # Average number of backward packets per bulk
            bwd_blk_rate_avg = 0  # Average rate of backward bulk rate
            subflow_fwd_pkts = 1  # Number of forward packets in a sub-flow
            subflow_fwd_byts = len(packet)  # Number of forward bytes in a sub-flow
            subflow_bwd_pkts = 0  # Number of backward packets in a sub-flow
            subflow_bwd_byts = 0  # Number of backward bytes in a sub-flow
            init_bwd_win_byts = 0  # Initial number of backward window bytes
            fwd_act_data_pkts = 1  # Number of forward packets with active data
            fwd_seg_size_min = len(packet)  # Minimum size of forward segments
            active_mean = 0  # Mean time a flow was active
            active_std = 0  # Standard deviation of active time
            active_max = 0  # Maximum active time
            active_min = 0  # Minimum active time
            idle_mean = 0  # Mean time a flow was idle
            idle_std = 0  # Standard deviation of idle time
            idle_max = 0  # Maximum idle time
            idle_min = 0  # Minimum idle time

            return {
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'flags': flags,
                'window': window,
                'packet_len': len(packet),
                'flow_duration': flow_duration,
                'tot_fwd_pkts': tot_fwd_pkts,
                'tot_bwd_pkts': tot_bwd_pkts,
                'totlen_fwd_pkts': totlen_fwd_pkts,
                'totlen_bwd_pkts': totlen_bwd_pkts,
                'fwd_pkt_len_max': fwd_pkt_len_max,
                'fwd_pkt_len_min': fwd_pkt_len_min,
                'fwd_pkt_len_mean': fwd_pkt_len_mean,
                'fwd_pkt_len_std': fwd_pkt_len_std,
                'bwd_pkt_len_max': bwd_pkt_len_max,
                'bwd_pkt_len_min': bwd_pkt_len_min,
                'bwd_pkt_len_mean': bwd_pkt_len_mean,
                'bwd_pkt_len_std': bwd_pkt_len_std,
                'flow_iat_mean': flow_iat_mean,
                'flow_iat_std': flow_iat_std,
                'flow_iat_max': flow_iat_max,
                'flow_iat_min': flow_iat_min,
                'fwd_iat_tot': fwd_iat_tot,
                'fwd_iat_mean': fwd_iat_mean,
                'fwd_iat_std': fwd_iat_std,
                'fwd_iat_max': fwd_iat_max,
                'fwd_iat_min': fwd_iat_min,
                'bwd_iat_tot': bwd_iat_tot,
                'bwd_iat_mean': bwd_iat_mean,
                'bwd_iat_std': bwd_iat_std,
                'bwd_iat_max': bwd_iat_max,
                'bwd_iat_min': bwd_iat_min,
                'fwd_psh_flags': fwd_psh_flags,
                'bwd_psh_flags': bwd_psh_flags,
                'fwd_urg_flags': fwd_urg_flags,
                'bwd_urg_flags': bwd_urg_flags,
                'fwd_header_len': fwd_header_len,
                'bwd_header_len': bwd_header_len,
                'fwd_pkts_s': fwd_pkts_s,
                'bwd_pkts_s': bwd_pkts_s,
                'pkt_len_min': pkt_len_min,
                'pkt_len_max': pkt_len_max,
                'pkt_len_mean': pkt_len_mean,
                'pkt_len_std': pkt_len_std,
                'pkt_len_var': pkt_len_var,
                'fin_flag_cnt': fin_flag_cnt,
                'syn_flag_cnt': syn_flag_cnt,
                'rst_flag_cnt': rst_flag_cnt,
                'ack_flag_cnt': ack_flag_cnt,
                'urg_flag_cnt': urg_flag_cnt,
                'cwe_flag_count': cwe_flag_count,
                'ece_flag_cnt': ece_flag_cnt,
                'down_up_ratio': down_up_ratio,
                'pkt_size_avg': pkt_size_avg,
                'fwd_seg_size_avg': fwd_seg_size_avg,
                'bwd_seg_size_avg': bwd_seg_size_avg,
                'fwd_byts_b_avg': fwd_byts_b_avg,
                'fwd_pkts_b_avg': fwd_pkts_b_avg,
                'fwd_blk_rate_avg': fwd_blk_rate_avg,
                'bwd_byts_b_avg': bwd_byts_b_avg,
                'bwd_pkts_b_avg': bwd_pkts_b_avg,
                'bwd_blk_rate_avg': bwd_blk_rate_avg,
                'subflow_fwd_pkts': subflow_fwd_pkts,
                'subflow_fwd_byts': subflow_fwd_byts,
                'subflow_bwd_pkts': subflow_bwd_pkts,
                'subflow_bwd_byts': subflow_bwd_byts,
                'init_bwd_win_byts': init_bwd_win_byts,
                'fwd_act_data_pkts': fwd_act_data_pkts,
                'fwd_seg_size_min': fwd_seg_size_min,
                'active_mean': active_mean,
                'active_std': active_std,
                'active_max': active_max,
                'active_min': active_min,
                'idle_mean': idle_mean,
                'idle_std': idle_std,
                'idle_max': idle_max,
                'idle_min': idle_min,
                'FIRST_SWITCHED': int(time.time()),
                'LAST_SWITCHED': int(time.time()),
                'ANALYSIS_TIMESTAMP': int(time.time()),
                'TOTAL_PKTS_EXP': 1,
                'TOTAL_BYTES_EXP': len(packet)
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
            # Update the flow information
            flow['flow_duration'] = (time.time() - flow.get('FIRST_SWITCHED', 0)) * 1000
            flow['tot_fwd_pkts'] = flow.get('tot_fwd_pkts', 0) + 1  # Update total forward packets
            flow['totlen_fwd_pkts'] = flow.get('totlen_fwd_pkts', 0) + parsed_packet['packet_len']
            flow['fwd_pkt_len_max'] = max(flow['fwd_pkt_len_max'], parsed_packet['packet_len'])  # Update max forward packet length
            flow['fwd_pkt_len_min'] = min(flow['fwd_pkt_len_min'], parsed_packet['packet_len'])  # Update min forward packet length
            flow['fwd_pkt_len_mean'] = (flow['fwd_pkt_len_mean'] * (flow['tot_fwd_pkts'] - 1) + parsed_packet['packet_len']) / flow['tot_fwd_pkts']  # Update mean forward packet length
            flow['fwd_pkt_len_std'] = np.sqrt(
                (flow['fwd_pkt_len_std'] ** 2 * (flow['tot_fwd_pkts'] - 2) + (parsed_packet['packet_len'] - flow['fwd_pkt_len_mean']) ** 2) / (flow['tot_fwd_pkts'] - 1)
            )  # Update standard deviation of forward packet lengths

            # Update other features in a similar manner
            flow['bwd_pkt_len_max'] = max(flow['bwd_pkt_len_max'], parsed_packet['packet_len'])
            flow['bwd_pkt_len_min'] = min(flow['bwd_pkt_len_min'], parsed_packet['packet_len'])
            if flow['tot_bwd_pkts'] > 0:
                flow['bwd_pkt_len_mean'] = (flow['bwd_pkt_len_mean'] * (flow['tot_bwd_pkts']) + parsed_packet['packet_len']) / (flow['tot_bwd_pkts'] + 1)
                flow['bwd_pkt_len_std'] = np.sqrt(
                    (flow['bwd_pkt_len_std'] ** 2 * (flow['tot_bwd_pkts'] - 1) + (parsed_packet['packet_len'] - flow['bwd_pkt_len_mean']) ** 2) / (flow['tot_bwd_pkts'])
                )
            else:
                flow['bwd_pkt_len_mean'] = parsed_packet['packet_len']
                flow['bwd_pkt_len_std'] = 0

            flow['flow_iat_mean'] = (flow.get('flow_iat_mean', 0) * (flow.get('TOTAL_PKTS_EXP', 1) - 1) + (time.time() - flow.get('LAST_SWITCHED', 0))) / flow.get('TOTAL_PKTS_EXP', 1)
            if flow['TOTAL_PKTS_EXP'] > 1:
                flow['flow_iat_std'] = np.sqrt(
                    (flow['flow_iat_std'] ** 2 * (flow['TOTAL_PKTS_EXP'] - 2) + (time.time() - flow['LAST_SWITCHED'] - flow['flow_iat_mean']) ** 2) / (flow['TOTAL_PKTS_EXP'] - 1)
                )
            else:
                flow['flow_iat_std'] = 0

            flow['flow_iat_max'] = max(flow['flow_iat_max'], time.time() - flow['LAST_SWITCHED'])
            flow['flow_iat_min'] = min(flow['flow_iat_min'], time.time() - flow['LAST_SWITCHED'])

            flow['fwd_iat_tot'] += time.time() - flow['LAST_SWITCHED']
            flow['fwd_iat_mean'] = flow['fwd_iat_tot'] / flow['tot_fwd_pkts']
            flow['fwd_iat_std'] = np.sqrt(
                (flow['fwd_iat_std'] ** 2 * (flow['tot_fwd_pkts'] - 2) + (time.time() - flow['LAST_SWITCHED'] - flow['fwd_iat_mean']) ** 2) / (flow['tot_fwd_pkts'] - 1)
            )
            flow['fwd_iat_max'] = max(flow['fwd_iat_max'], time.time() - flow['LAST_SWITCHED'])
            flow['fwd_iat_min'] = min(flow['fwd_iat_min'], time.time() - flow['LAST_SWITCHED'])

            flow['bwd_iat_tot'] += time.time() - flow['LAST_SWITCHED']
            if flow['tot_bwd_pkts'] > 0:
                flow['bwd_iat_mean'] = flow['bwd_iat_tot'] / flow['tot_bwd_pkts']
                flow['bwd_iat_std'] = np.sqrt(
                    (flow['bwd_iat_std'] ** 2 * (flow['tot_bwd_pkts'] - 2) + (time.time() - flow['LAST_SWITCHED'] - flow['bwd_iat_mean']) ** 2) / (flow['tot_bwd_pkts'] - 1)
                )
            else:
                flow['bwd_iat_mean'] = 0
                flow['bwd_iat_std'] = 0
            flow['bwd_iat_max'] = max(flow['bwd_iat_max'], time.time() - flow['LAST_SWITCHED'])
            flow['bwd_iat_min'] = min(flow['bwd_iat_min'], time.time() - flow['LAST_SWITCHED'])
            if isinstance(flags, int) and flags & 0x08:
                flow['fwd_psh_flags'] += 1
            if isinstance(flags, int) and flags & 0x20:
                flow['bwd_psh_flags'] += 1
            if isinstance(flags, int) and flags & 0x20:
                flow['fwd_urg_flags'] += 1
            if isinstance(flags, int) and flags & 0x20:
                flow['bwd_urg_flags'] += 1
            flow['fwd_header_len'] = 0
            flow['bwd_header_len'] = 0

            flow['fwd_pkts_s'] = flow['tot_fwd_pkts'] / ((flow['LAST_SWITCHED'] - flow['FIRST_SWITCHED']) or 1)
            flow['bwd_pkts_s'] = flow['tot_bwd_pkts'] / ((flow['LAST_SWITCHED'] - flow['FIRST_SWITCHED']) or 1)

            flow['pkt_len_min'] = min(flow['pkt_len_min'], parsed_packet['packet_len'])
            flow['pkt_len_max'] = max(flow['pkt_len_max'], parsed_packet['packet_len'])
            flow['pkt_len_mean'] = (flow['pkt_len_mean'] * (flow['TOTAL_PKTS_EXP'] - 1) + parsed_packet['packet_len']) / flow['TOTAL_PKTS_EXP']
            if flow['TOTAL_PKTS_EXP'] > 1:
                flow['pkt_len_std'] = np.sqrt(
                    (flow['pkt_len_std'] ** 2 * (flow['TOTAL_PKTS_EXP'] - 2) + (parsed_packet['packet_len'] - flow['pkt_len_mean']) ** 2) / (flow['TOTAL_PKTS_EXP'] - 1)
                )
            else:
                flow['pkt_len_std'] = 0
            flow['pkt_len_var'] = flow['pkt_len_std'] ** 2

            flow['down_up_ratio'] = flow['tot_bwd_pkts'] / (flow['tot_fwd_pkts'] or 1)

            flow['pkt_size_avg'] = flow['TOTAL_BYTES_EXP'] / flow['TOTAL_PKTS_EXP']
            flow['fwd_seg_size_avg'] = flow['totlen_fwd_pkts'] / flow['tot_fwd_pkts']
            if flow['tot_bwd_pkts'] > 0:
                flow['bwd_seg_size_avg'] = flow['totlen_bwd_pkts'] / flow['tot_bwd_pkts']
            else:
                flow['bwd_seg_size_avg'] = 0
            flow['fwd_byts_b_avg'] = flow['totlen_fwd_pkts'] / (flow['tot_fwd_pkts'] or 1)
            flow['fwd_pkts_b_avg'] = flow['tot_fwd_pkts'] / (flow['TOTAL_PKTS_EXP'] or 1)
            flow['fwd_blk_rate_avg'] = flow['fwd_pkts_s'] / (flow['bwd_pkts_s'] or 1)
            flow['bwd_byts_b_avg'] = flow['totlen_bwd_pkts'] / (flow['tot_bwd_pkts'] or 1)
            flow['bwd_pkts_b_avg'] = flow['tot_bwd_pkts'] / (flow['TOTAL_PKTS_EXP'] or 1)
            flow['bwd_blk_rate_avg'] = flow['bwd_pkts_s'] / (flow['fwd_pkts_s'] or 1)

            flow['subflow_fwd_pkts'] = flow['tot_fwd_pkts']
            flow['subflow_fwd_byts'] = flow['totlen_fwd_pkts']
            flow['subflow_bwd_pkts'] = flow['tot_bwd_pkts']
            flow['subflow_bwd_byts'] = flow['totlen_bwd_pkts']

            flow['fwd_act_data_pkts'] = flow['tot_fwd_pkts']
            flow['fwd_seg_size_min'] = flow['fwd_pkt_len_min']

            flow['active_mean'] = (flow['active_mean'] * (flow['TOTAL_PKTS_EXP'] - 1) + (time.time() - flow['FIRST_SWITCHED'])) / flow['TOTAL_PKTS_EXP']
            if flow['TOTAL_PKTS_EXP'] > 1:
                flow['active_std'] = np.sqrt(
                    (flow['active_std'] ** 2 * (flow['TOTAL_PKTS_EXP'] - 2) + (time.time() - flow['FIRST_SWITCHED'] - flow['active_mean']) ** 2) / (flow['TOTAL_PKTS_EXP'] - 1)
                )
            else:
                flow['active_std'] = 0
            flow['active_max'] = max(flow['active_max'], time.time() - flow['FIRST_SWITCHED'])
            flow['active_min'] = min(flow['active_min'], time.time() - flow['FIRST_SWITCHED'])

            flow['idle_mean'] = (flow['idle_mean'] * (flow['TOTAL_PKTS_EXP'] - 1) + (time.time() - flow['LAST_SWITCHED'])) / flow['TOTAL_PKTS_EXP']
            if flow['TOTAL_PKTS_EXP'] > 1:
                flow['idle_std'] = np.sqrt(
                    (flow['idle_std'] ** 2 * (flow['TOTAL_PKTS_EXP'] - 2) + (time.time() - flow['LAST_SWITCHED'] - flow['idle_mean']) ** 2) / (flow['TOTAL_PKTS_EXP'] - 1)
                )
            else:
                flow['idle_std'] = 0
            flow['idle_max'] = max(flow['idle_max'], time.time() - flow['LAST_SWITCHED'])
            flow['idle_min'] = min(flow['idle_min'], time.time() - flow['LAST_SWITCHED'])

            flow['LAST_SWITCHED'] = int(time.time())
            flow['ANALYSIS_TIMESTAMP'] = int(time.time())
            print(f"Flow Updated: {flow}")
            import csv
            with open(filename, 'a') as f:
                writer = csv.DictWriter(f, fieldnames=flow.keys())
                if os.stat(filename).st_size == 0:  # check if file is empty
                    writer.writeheader()

                writer.writerows([flow])
            
            



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
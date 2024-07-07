import React, { useEffect, useState } from 'react';

interface PacketInfo {
  src_addr: string;
  dst_addr: string;
  src_port: number;
  dst_port: number;
  protocol: number;
  flags: number;
  window: number;
  packet_len: number;
  flow_duration: number;
  tot_fwd_pkts: number;
  tot_bwd_pkts: number;
  totlen_fwd_pkts: number;
  totlen_bwd_pkts: number;
  fwd_pkt_len_max: number;
  fwd_pkt_len_min: number;
  fwd_pkt_len_mean: number;
  fwd_pkt_len_std: number;
  bwd_pkt_len_max: number;
  bwd_pkt_len_min: number;
  bwd_pkt_len_mean: number;
  bwd_pkt_len_std: number;
  flow_iat_mean: number;
  flow_iat_std: number;
  flow_iat_max: number;
  flow_iat_min: number;
  fwd_iat_tot: number;
  fwd_iat_mean: number;
  fwd_iat_std: number;
  fwd_iat_max: number;
  fwd_iat_min: number;
  bwd_iat_tot: number;
  bwd_iat_mean: number;
  bwd_iat_std: number;
  bwd_iat_max: number;
  bwd_iat_min: number;
  fwd_psh_flags: number;
  bwd_psh_flags: number;
  fwd_urg_flags: number;
  bwd_urg_flags: number;
  fwd_header_len: number;
  bwd_header_len: number;
  fwd_pkts_s: number;
  bwd_pkts_s: number;
  pkt_len_min: number;
  pkt_len_max: number;
  pkt_len_mean: number;
  pkt_len_std: number;
  pkt_len_var: number;
  fin_flag_cnt: number;
  syn_flag_cnt: number;
  rst_flag_cnt: number;
  ack_flag_cnt: number;
  urg_flag_cnt: number;
  cwe_flag_count: number;
  ece_flag_cnt: number;
  down_up_ratio: number;
  pkt_size_avg: number;
  fwd_seg_size_avg: number;
  bwd_seg_size_avg: number;
  fwd_byts_b_avg: number;
  fwd_pkts_b_avg: number;
  fwd_blk_rate_avg: number;
  bwd_byts_b_avg: number;
  bwd_pkts_b_avg: number;
  bwd_blk_rate_avg: number;
  subflow_fwd_pkts: number;
  subflow_fwd_byts: number;
  subflow_bwd_pkts: number;
  subflow_bwd_byts: number;
  init_bwd_win_byts: number;
  fwd_act_data_pkts: number;
  fwd_seg_size_min: number;
  active_mean: number;
  active_std: number;
  active_max: number;
  active_min: number;
  idle_mean: number;
  idle_std: number;
  idle_max: number;
  idle_min: number;
  FIRST_SWITCHED: number;
  LAST_SWITCHED: number;
  ANALYSIS_TIMESTAMP: number;
  TOTAL_PKTS_EXP: number;
  TOTAL_BYTES_EXP: number;
}

const Sniffer: React.FC = () => {
  const [packets, setPackets] = useState<PacketInfo[]>([]);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws');

    ws.onopen = () => {
      console.log('Connected to WebSocket');
    };

    ws.onmessage = (event) => {
      const packetInfo: PacketInfo[] = JSON.parse(event.data);
      console.log('Received packet:', packetInfo);
      setPackets(packetInfo);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
      console.log('WebSocket connection closed');
    };

    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center p-4">
      <h1 className="text-3xl font-bold mb-4">Packet Sniffer</h1>
      <div className="overflow-x-auto w-full">
        <table className="min-w-full bg-white shadow-md rounded">
          <thead>
            <tr>
              <th className="py-2 px-4 border-b">Source IP</th>
              <th className="py-2 px-4 border-b">Source Port</th>
              <th className="py-2 px-4 border-b">Destination IP</th>
              <th className="py-2 px-4 border-b">Destination Port</th>
              <th className="py-2 px-4 border-b">Protocol</th>
              <th className="py-2 px-4 border-b">Packets</th>
              <th className="py-2 px-4 border-b">Bytes</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((packet, index) => (
              <tr key={index} className="hover:bg-gray-100">
                <td className="py-2 px-4 border-b">{packet.src_addr}</td>
                <td className="py-2 px-4 border-b">{packet.src_port}</td>
                <td className="py-2 px-4 border-b">{packet.dst_addr}</td>
                <td className="py-2 px-4 border-b">{packet.dst_port}</td>
                <td className="py-2 px-4 border-b">{packet.protocol}</td>
                <td className="py-2 px-4 border-b">{packet.tot_fwd_pkts}</td>
                <td className="py-2 px-4 border-b">{packet.totlen_fwd_pkts}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Sniffer;

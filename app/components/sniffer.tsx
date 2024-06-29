import React, { useEffect, useState } from 'react';

interface PacketInfo {
  FLOW_ID: string;
  PROTOCOL_MAP: string;
  L4_SRC_PORT: number | null;
  IPV4_SRC_ADDR: string;
  L4_DST_PORT: number | null;
  IPV4_DST_ADDR: string;
  FIRST_SWITCHED: number;
  FLOW_DURATION_MILLISECONDS: number;
  LAST_SWITCHED: number;
  PROTOCOL: number;
  TCP_FLAGS: number | null;
  TCP_WIN_MAX_IN: number | null;
  TCP_WIN_MAX_OUT: number | null;
  TCP_WIN_MIN_IN: number | null;
  TCP_WIN_MIN_OUT: number | null;
  TCP_WIN_MSS_IN: number | null;
  TCP_WIN_SCALE_IN: number | null;
  TCP_WIN_SCALE_OUT: number | null;
  SRC_TOS: number | null;
  DST_TOS: number | null;
  TOTAL_FLOWS_EXP: number;
  MIN_IP_PKT_LEN: number;
  MAX_IP_PKT_LEN: number;
  TOTAL_PKTS_EXP: number;
  TOTAL_BYTES_EXP: number;
  IN_BYTES: number;
  IN_PKTS: number;
  OUT_BYTES: number;
  OUT_PKTS: number;
  ANALYSIS_TIMESTAMP: number;
  ANOMALY: number;
  ALERT: string;
  ID: number;
}

const Sniffer: React.FC = () => {
  const [packets, setPackets] = useState<PacketInfo[]>([]);

  useEffect(() => {
    const ws = new WebSocket('ws://127.0.0.1:8000/ws');

    ws.onopen = () => {
      console.log('Connected to WebSocket');
    };

    ws.onmessage = (event) => {
      const packetInfo: PacketInfo = JSON.parse(event.data);
      console.log('Received packet:', packetInfo);
      setPackets((prevPackets) => [packetInfo, ...prevPackets]);
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
              <th className="py-2 px-4 border-b">Flow ID</th>
              <th className="py-2 px-4 border-b">Protocol</th>
              <th className="py-2 px-4 border-b">Source IP</th>
              <th className="py-2 px-4 border-b">Source Port</th>
              <th className="py-2 px-4 border-b">Destination IP</th>
              <th className="py-2 px-4 border-b">Destination Port</th>
              <th className="py-2 px-4 border-b">Packets</th>
              <th className="py-2 px-4 border-b">Bytes</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((packet) => (
              <tr key={packet.FLOW_ID} className="hover:bg-gray-100">
                <td className="py-2 px-4 border-b">{packet.FLOW_ID}</td>
                <td className="py-2 px-4 border-b">{packet.PROTOCOL_MAP}</td>
                <td className="py-2 px-4 border-b">{packet.IPV4_SRC_ADDR}</td>
                <td className="py-2 px-4 border-b">{packet.L4_SRC_PORT}</td>
                <td className="py-2 px-4 border-b">{packet.IPV4_DST_ADDR}</td>
                <td className="py-2 px-4 border-b">{packet.L4_DST_PORT}</td>
                <td className="py-2 px-4 border-b">{packet.TOTAL_PKTS_EXP}</td>
                <td className="py-2 px-4 border-b">{packet.TOTAL_BYTES_EXP}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Sniffer;

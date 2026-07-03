"""
Packet parser for extracting features from network packets
"""

import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class PacketParser:
    """Parse network packets and extract features for ML analysis"""
    
    def __init__(self):
        self.features = []
        
    def parse_pcap(self, pcap_file: str) -> pd.DataFrame:
        """
        Parse PCAP file and extract features
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Parsing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"Loaded {len(packets)} packets")
            
            features_list = []
            for i, packet in enumerate(packets):
                features = self._extract_packet_features(packet)
                if features:
                    features_list.append(features)
            
            df = pd.DataFrame(features_list)
            logger.info(f"Extracted features for {len(df)} packets")
            
            return df
            
        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            raise
    
    def _extract_packet_features(self, packet) -> Optional[Dict]:
        """Extract features from a single packet"""
        features = {}
        
        try:
            if IP in packet:
                features['src_ip'] = packet[IP].src
                features['dst_ip'] = packet[IP].dst
                features['protocol'] = packet[IP].proto
                features['packet_size'] = len(packet)
                
                # TCP specific features
                if TCP in packet:
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    features['flags'] = str(packet[TCP].flags)
                    features['protocol_type'] = 'tcp'
                
                # UDP specific features
                elif UDP in packet:
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
                    features['flags'] = ''
                    features['protocol_type'] = 'udp'
                
                # ICMP specific features
                elif ICMP in packet:
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    features['flags'] = ''
                    features['protocol_type'] = 'icmp'
                
                else:
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    features['flags'] = ''
                    features['protocol_type'] = 'other'
                
                features['timestamp'] = float(packet.time)
                
                return features
            
            return None
            
        except Exception as e:
            logger.warning(f"Error extracting features from packet: {e}")
            return None
    
    def calculate_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate flow-based features from packet data
        
        Args:
            df: DataFrame with packet-level features
            
        Returns:
            DataFrame with flow-based features
        """
        logger.info("Calculating flow features")
        
        if df.empty:
            return df
        
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        # Group by flow (src_ip, dst_ip, src_port, dst_port, protocol)
        df['flow_key'] = (
            df['src_ip'].astype(str) + '_' +
            df['dst_ip'].astype(str) + '_' +
            df['src_port'].astype(str) + '_' +
            df['dst_port'].astype(str) + '_' +
            df['protocol_type']
        )
        
        flow_features = []
        
        for flow_key, flow_df in df.groupby('flow_key'):
            flow_data = {}
            
            flow_data['flow_key'] = flow_key
            flow_data['src_ip'] = flow_df['src_ip'].iloc[0]
            flow_data['dst_ip'] = flow_df['dst_ip'].iloc[0]
            flow_data['src_port'] = flow_df['src_port'].iloc[0]
            flow_data['dst_port'] = flow_df['dst_port'].iloc[0]
            flow_data['protocol_type'] = flow_df['protocol_type'].iloc[0]
            
            # Calculate flow statistics
            flow_data['packet_count'] = len(flow_df)
            flow_data['byte_count'] = flow_df['packet_size'].sum()
            flow_data['flow_duration'] = flow_df['timestamp'].max() - flow_df['timestamp'].min()
            
            if flow_data['flow_duration'] > 0:
                flow_data['packet_rate'] = flow_data['packet_count'] / flow_data['flow_duration']
                flow_data['byte_rate'] = flow_data['byte_count'] / flow_data['flow_duration']
            else:
                flow_data['packet_rate'] = flow_data['packet_count']
                flow_data['byte_rate'] = flow_data['byte_count']
            
            flow_data['avg_packet_size'] = flow_df['packet_size'].mean()
            flow_data['std_packet_size'] = flow_df['packet_size'].std()
            flow_data['min_packet_size'] = flow_df['packet_size'].min()
            flow_data['max_packet_size'] = flow_df['packet_size'].max()
            
            # TCP flags analysis
            if flow_data['protocol_type'] == 'tcp':
                syn_count = flow_df['flags'].str.contains('S').sum()
                ack_count = flow_df['flags'].str.contains('A').sum()
                fin_count = flow_df['flags'].str.contains('F').sum()
                rst_count = flow_df['flags'].str.contains('R').sum()
                
                flow_data['syn_count'] = syn_count
                flow_data['ack_count'] = ack_count
                flow_data['fin_count'] = fin_count
                flow_data['rst_count'] = rst_count
            else:
                flow_data['syn_count'] = 0
                flow_data['ack_count'] = 0
                flow_data['fin_count'] = 0
                flow_data['rst_count'] = 0
            
            flow_features.append(flow_data)
        
        flow_df = pd.DataFrame(flow_features)
        logger.info(f"Calculated features for {len(flow_df)} flows")
        
        return flow_df
    
    def normalize_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize numerical features
        
        Args:
            df: DataFrame with features
            
        Returns:
            DataFrame with normalized features
        """
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        
        logger.info("Normalizing features")
        
        df_normalized = df.copy()
        
        # Numerical columns to normalize
        numerical_cols = [
            'packet_count', 'byte_count', 'flow_duration',
            'packet_rate', 'byte_rate', 'avg_packet_size',
            'std_packet_size', 'min_packet_size', 'max_packet_size',
            'src_port', 'dst_port', 'syn_count', 'ack_count',
            'fin_count', 'rst_count'
        ]
        
        # Normalize numerical features
        scaler = StandardScaler()
        for col in numerical_cols:
            if col in df_normalized.columns:
                df_normalized[col] = scaler.fit_transform(
                    df_normalized[[col]].values.reshape(-1, 1)
                )
        
        # Encode categorical features
        if 'protocol_type' in df_normalized.columns:
            le = LabelEncoder()
            df_normalized['protocol_type_encoded'] = le.fit_transform(
                df_normalized['protocol_type']
            )
        
        return df_normalized
    
    def save_features(self, df: pd.DataFrame, output_file: str):
        """
        Save extracted features to CSV
        
        Args:
            df: DataFrame with features
            output_file: Output CSV file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        df.to_csv(output_path, index=False)
        logger.info(f"Saved features to {output_path}")

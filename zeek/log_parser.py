"""
Zeek log parser for extracting features from Zeek logs
"""

import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ZeekLogParser:
    """Parse Zeek log files and extract features"""
    
    def __init__(self):
        self.log_data = {}
        
    def parse_log(self, log_file: str) -> pd.DataFrame:
        """
        Parse a single Zeek log file
        
        Args:
            log_file: Path to Zeek log file
            
        Returns:
            DataFrame with parsed log data
        """
        log_path = Path(log_file)
        
        if not log_path.exists():
            logger.warning(f"Log file not found: {log_file}")
            return pd.DataFrame()
        
        try:
            # Zeek logs are tab-separated with header comments
            # Skip lines starting with #
            df = pd.read_csv(
                log_file,
                sep='\t',
                comment='#',
                skip_blank_lines=True,
                low_memory=False
            )
            
            # Clean column names (remove leading/trailing whitespace)
            df.columns = df.columns.str.strip()
            
            logger.info(f"Parsed {len(df)} records from {log_file}")
            return df
            
        except Exception as e:
            logger.error(f"Error parsing log file {log_file}: {e}")
            return pd.DataFrame()
    
    def parse_all_logs(self, log_files: Dict[str, str]) -> Dict[str, pd.DataFrame]:
        """
        Parse multiple Zeek log files
        
        Args:
            log_files: Dictionary mapping log types to file paths
            
        Returns:
            Dictionary mapping log types to DataFrames
        """
        parsed_logs = {}
        
        for log_type, log_file in log_files.items():
            df = self.parse_log(log_file)
            if not df.empty:
                parsed_logs[log_type] = df
        
        logger.info(f"Parsed {len(parsed_logs)} log files")
        return parsed_logs
    
    def extract_conn_features(self, conn_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from connection log
        
        Args:
            conn_df: DataFrame from conn.log
            
        Returns:
            DataFrame with extracted features
        """
        if conn_df.empty:
            return pd.DataFrame()
        
        features = pd.DataFrame()
        
        # Basic connection features
        features['id.orig_h'] = conn_df.get('id.orig_h', '')
        features['id.orig_p'] = conn_df.get('id.orig_p', 0)
        features['id.resp_h'] = conn_df.get('id.resp_h', '')
        features['id.resp_p'] = conn_df.get('id.resp_p', 0)
        features['proto'] = conn_df.get('proto', '')
        
        # Duration and size features
        features['duration'] = pd.to_numeric(conn_df.get('duration', 0), errors='coerce').fillna(0)
        features['orig_bytes'] = pd.to_numeric(conn_df.get('orig_bytes', 0), errors='coerce').fillna(0)
        features['resp_bytes'] = pd.to_numeric(conn_df.get('resp_bytes', 0), errors='coerce').fillna(0)
        
        # Packet counts
        features['orig_pkts'] = pd.to_numeric(conn_df.get('orig_pkts', 0), errors='coerce').fillna(0)
        features['resp_pkts'] = pd.to_numeric(conn_df.get('resp_pkts', 0), errors='coerce').fillna(0)
        
        # Calculate derived features
        features['total_bytes'] = features['orig_bytes'] + features['resp_bytes']
        features['total_pkts'] = features['orig_pkts'] + features['resp_pkts']
        
        # Packet sizes
        features['avg_orig_pkt_size'] = features.apply(
            lambda x: x['orig_bytes'] / x['orig_pkts'] if x['orig_pkts'] > 0 else 0,
            axis=1
        )
        features['avg_resp_pkt_size'] = features.apply(
            lambda x: x['resp_bytes'] / x['resp_pkts'] if x['resp_pkts'] > 0 else 0,
            axis=1
        )
        
        # Connection state
        features['conn_state'] = conn_df.get('conn_state', '')
        
        # Calculate byte/packet rates
        features['orig_byte_rate'] = features.apply(
            lambda x: x['orig_bytes'] / x['duration'] if x['duration'] > 0 else 0,
            axis=1
        )
        features['resp_byte_rate'] = features.apply(
            lambda x: x['resp_bytes'] / x['duration'] if x['duration'] > 0 else 0,
            axis=1
        )
        
        return features
    
    def extract_dns_features(self, dns_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from DNS log
        
        Args:
            dns_df: DataFrame from dns.log
            
        Returns:
            DataFrame with extracted features
        """
        if dns_df.empty:
            return pd.DataFrame()
        
        features = pd.DataFrame()
        
        features['id.orig_h'] = dns_df.get('id.orig_h', '')
        features['id.orig_p'] = dns_df.get('id.orig_p', 0)
        features['id.resp_h'] = dns_df.get('id.resp_h', '')
        features['id.resp_p'] = dns_df.get('id.resp_p', 0)
        features['query'] = dns_df.get('query', '')
        features['qclass'] = dns_df.get('qclass', '')
        features['qclass_name'] = dns_df.get('qclass_name', '')
        features['qtype'] = dns_df.get('qtype', '')
        features['qtype_name'] = dns_df.get('qtype_name', '')
        features['rcode'] = dns_df.get('rcode', 0)
        features['rcode_name'] = dns_df.get('rcode_name', '')
        
        # Calculate query length
        features['query_length'] = features['query'].str.len()
        
        # Response time
        features['rtt'] = pd.to_numeric(dns_df.get('rtt', 0), errors='coerce').fillna(0)
        
        return features
    
    def extract_http_features(self, http_df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from HTTP log
        
        Args:
            http_df: DataFrame from http.log
            
        Returns:
            DataFrame with extracted features
        """
        if http_df.empty:
            return pd.DataFrame()
        
        features = pd.DataFrame()
        
        features['id.orig_h'] = http_df.get('id.orig_h', '')
        features['id.orig_p'] = http_df.get('id.orig_p', 0)
        features['id.resp_h'] = http_df.get('id.resp_h', '')
        features['id.resp_p'] = http_df.get('id.resp_p', 0)
        features['method'] = http_df.get('method', '')
        features['host'] = http_df.get('host', '')
        features['uri'] = http_df.get('uri', '')
        features['version'] = http_df.get('version', '')
        features['user_agent'] = http_df.get('user_agent', '')
        features['request_body_len'] = pd.to_numeric(http_df.get('request_body_len', 0), errors='coerce').fillna(0)
        features['response_body_len'] = pd.to_numeric(http_df.get('response_body_len', 0), errors='coerce').fillna(0)
        features['status_code'] = pd.to_numeric(http_df.get('status_code', 0), errors='coerce').fillna(0)
        
        # Calculate URI length
        features['uri_length'] = features['uri'].str.len()
        
        # Calculate total transfer size
        features['total_transfer'] = features['request_body_len'] + features['response_body_len']
        
        return features
    
    def merge_logs(self, parsed_logs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """
        Merge multiple log types into a single DataFrame
        
        Args:
            parsed_logs: Dictionary of parsed log DataFrames
            
        Returns:
            Merged DataFrame
        """
        if not parsed_logs:
            return pd.DataFrame()
        
        # Start with connection log as base
        if 'conn' in parsed_logs:
            merged = self.extract_conn_features(parsed_logs['conn'])
        else:
            # Use first available log as base
            first_log = next(iter(parsed_logs.values()))
            merged = first_log.copy()
        
        # Merge other logs on connection identifiers
        for log_type, df in parsed_logs.items():
            if log_type == 'conn':
                continue
            
            try:
                if log_type == 'dns':
                    dns_features = self.extract_dns_features(df)
                    merged = pd.merge(
                        merged,
                        dns_features,
                        on=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
                        how='left',
                        suffixes=('', f'_{log_type}')
                    )
                elif log_type == 'http':
                    http_features = self.extract_http_features(df)
                    merged = pd.merge(
                        merged,
                        http_features,
                        on=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
                        how='left',
                        suffixes=('', f'_{log_type}')
                    )
                else:
                    # Generic merge
                    merged = pd.merge(
                        merged,
                        df,
                        on=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
                        how='left',
                        suffixes=('', f'_{log_type}')
                    )
            except Exception as e:
                logger.warning(f"Could not merge {log_type} log: {e}")
        
        logger.info(f"Merged logs into DataFrame with {len(merged)} rows")
        return merged
    
    def save_merged_logs(self, df: pd.DataFrame, output_file: str):
        """
        Save merged logs to CSV
        
        Args:
            df: Merged DataFrame
            output_file: Output CSV file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        df.to_csv(output_path, index=False)
        logger.info(f"Saved merged logs to {output_path}")

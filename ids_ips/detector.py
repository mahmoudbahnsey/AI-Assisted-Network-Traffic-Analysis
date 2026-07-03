"""
Attack detection system using ML models and rule-based detection
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
from typing import Dict, List, Optional, Tuple
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class AttackDetector:
    """Detect network attacks using ML models and statistical analysis"""
    
    def __init__(self, model=None, threshold: float = 0.7):
        """
        Initialize attack detector
        
        Args:
            model: Trained ML model for prediction
            threshold: Confidence threshold for attack detection
        """
        self.model = model
        self.threshold = threshold
        self.detection_history = deque(maxlen=1000)
        self.blocked_ips = {}
        self.attack_counts = defaultdict(int)
        self.connection_tracker = defaultdict(list)
        
    def detect_with_model(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Detect attack using ML model
        
        Args:
            features: Feature vector for prediction
            
        Returns:
            Tuple of (prediction, confidence)
        """
        if self.model is None:
            logger.warning("No model loaded, using default detection")
            return 0, 0.0
        
        try:
            # Get prediction
            prediction = self.model.predict(features.reshape(1, -1))[0]
            
            # Get confidence if available
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(features.reshape(1, -1))[0]
                confidence = max(probabilities)
            else:
                confidence = 1.0 if prediction == 1 else 0.0
            
            return prediction, confidence
            
        except Exception as e:
            logger.error(f"Error in model prediction: {e}")
            return 0, 0.0
    
    def detect_statistical(self, flow_data: pd.DataFrame) -> List[Dict]:
        """
        Detect attacks using statistical analysis
        
        Args:
            flow_data: DataFrame with flow data
            
        Returns:
            List of detected attacks
        """
        attacks = []
        
        if flow_data.empty:
            return attacks
        
        # Check for high packet rate (potential DDoS)
        if 'packet_rate' in flow_data.columns:
            high_rate_flows = flow_data[flow_data['packet_rate'] > flow_data['packet_rate'].quantile(0.95)]
            for _, flow in high_rate_flows.iterrows():
                attacks.append({
                    'type': 'high_packet_rate',
                    'confidence': 0.8,
                    'src_ip': flow.get('src_ip', 'unknown'),
                    'dst_ip': flow.get('dst_ip', 'unknown'),
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Packet rate: {flow['packet_rate']:.2f}"
                })
        
        # Check for high byte rate
        if 'byte_rate' in flow_data.columns:
            high_byte_flows = flow_data[flow_data['byte_rate'] > flow_data['byte_rate'].quantile(0.95)]
            for _, flow in high_byte_flows.iterrows():
                attacks.append({
                    'type': 'high_byte_rate',
                    'confidence': 0.75,
                    'src_ip': flow.get('src_ip', 'unknown'),
                    'dst_ip': flow.get('dst_ip', 'unknown'),
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Byte rate: {flow['byte_rate']:.2f}"
                })
        
        # Check for SYN flood patterns
        if 'syn_count' in flow_data.columns:
            syn_flows = flow_data[flow_data['syn_count'] > flow_data['syn_count'].quantile(0.90)]
            for _, flow in syn_flows.iterrows():
                if flow['syn_count'] > 10:  # Threshold for suspicious SYN count
                    attacks.append({
                        'type': 'syn_flood',
                        'confidence': 0.85,
                        'src_ip': flow.get('src_ip', 'unknown'),
                        'dst_ip': flow.get('dst_ip', 'unknown'),
                        'timestamp': datetime.now().isoformat(),
                        'details': f"SYN count: {flow['syn_count']}"
                    })
        
        # Check for port scanning (many connections to different ports)
        if 'src_ip' in flow_data.columns and 'dst_port' in flow_data.columns:
            for src_ip in flow_data['src_ip'].unique():
                src_flows = flow_data[flow_data['src_ip'] == src_ip]
                unique_ports = src_flows['dst_port'].nunique()
                if unique_ports > 50:  # Threshold for port scanning
                    attacks.append({
                        'type': 'port_scan',
                        'confidence': 0.9,
                        'src_ip': src_ip,
                        'dst_ip': 'multiple',
                        'timestamp': datetime.now().isoformat(),
                        'details': f"Unique ports: {unique_ports}"
                    })
        
        return attacks
    
    def detect_anomaly(self, features: np.ndarray, baseline_stats: Dict) -> Dict:
        """
        Detect anomalies based on baseline statistics
        
        Args:
            features: Feature vector
            baseline_stats: Dictionary with baseline statistics
            
        Returns:
            Dictionary with anomaly detection results
        """
        anomalies = []
        
        for i, feature_value in enumerate(features):
            feature_name = f"feature_{i}"
            if feature_name in baseline_stats:
                mean = baseline_stats[feature_name]['mean']
                std = baseline_stats[feature_name]['std']
                
                # Check if value is outside 3 standard deviations
                if abs(feature_value - mean) > 3 * std:
                    anomalies.append({
                        'feature': feature_name,
                        'value': feature_value,
                        'mean': mean,
                        'std': std,
                        'z_score': abs(feature_value - mean) / std
                    })
        
        return {
            'is_anomaly': len(anomalies) > 0,
            'anomaly_count': len(anomalies),
            'anomalies': anomalies
        }
    
    def track_connections(self, src_ip: str, dst_ip: str, dst_port: int):
        """
        Track connections for rate limiting
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
        """
        key = f"{src_ip}_{dst_ip}_{dst_port}"
        now = datetime.now()
        
        # Clean old connections (older than 1 minute)
        self.connection_tracker[key] = [
            t for t in self.connection_tracker[key]
            if now - t < timedelta(minutes=1)
        ]
        
        # Add new connection
        self.connection_tracker[key].append(now)
    
    def check_rate_limit(self, src_ip: str, dst_ip: str, dst_port: int, threshold: int = 100) -> bool:
        """
        Check if connection rate exceeds threshold
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            threshold: Maximum allowed connections per minute
            
        Returns:
            True if rate limit exceeded
        """
        key = f"{src_ip}_{dst_ip}_{dst_port}"
        
        # Clean old connections
        now = datetime.now()
        self.connection_tracker[key] = [
            t for t in self.connection_tracker[key]
            if now - t < timedelta(minutes=1)
        ]
        
        connection_count = len(self.connection_tracker[key])
        
        if connection_count > threshold:
            logger.warning(f"Rate limit exceeded for {key}: {connection_count} connections/min")
            return True
        
        return False
    
    def log_detection(self, attack: Dict):
        """
        Log attack detection
        
        Args:
            attack: Attack information dictionary
        """
        self.detection_history.append(attack)
        self.attack_counts[attack['type']] += 1
        
        logger.info(f"Attack detected: {attack['type']} from {attack.get('src_ip', 'unknown')}")
    
    def get_detection_stats(self) -> Dict:
        """
        Get detection statistics
        
        Returns:
            Dictionary with detection statistics
        """
        return {
            'total_detections': len(self.detection_history),
            'attack_counts': dict(self.attack_counts),
            'blocked_ips_count': len(self.blocked_ips),
            'recent_detections': list(self.detection_history)[-10:]
        }
    
    def save_detection_history(self, output_path: str):
        """
        Save detection history to file
        
        Args:
            output_path: Path to save the history
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        history = list(self.detection_history)
        
        with open(output_path, 'w') as f:
            json.dump(history, f, indent=2)
        
        logger.info(f"Saved detection history to {output_path}")
    
    def load_detection_history(self, input_path: str):
        """
        Load detection history from file
        
        Args:
            input_path: Path to load the history from
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Detection history file not found: {input_path}")
        
        with open(input_path, 'r') as f:
            history = json.load(f)
        
        self.detection_history = deque(history, maxlen=1000)
        
        # Reconstruct attack counts
        self.attack_counts = defaultdict(int)
        for attack in history:
            self.attack_counts[attack['type']] += 1
        
        logger.info(f"Loaded detection history from {input_path}")

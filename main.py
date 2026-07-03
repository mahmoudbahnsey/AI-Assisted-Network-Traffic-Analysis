"""
Main pipeline orchestrator for AI-Assisted Network Traffic Analysis System
Integrates capture, Zeek analysis, ML models, IDS/IPS, and attack simulation
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd

# Import project modules
from config import *
from capture import WiresharkCapture, PacketParser
from zeek import ZeekAnalyzer, ZeekLogParser
from ml import MLModels, ModelEvaluator, DataPreprocessor
from ids_ips import AttackDetector, AttackBlocker
from attacks import DDoSSimulator

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOGS_DIR / 'main.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class NetworkTrafficAnalysisPipeline:
    """Main pipeline for network traffic analysis"""
    
    def __init__(self):
        """Initialize the pipeline with all components"""
        self.capture = WiresharkCapture(interface=CAPTURE_INTERFACE, output_dir=str(RAW_DATA_DIR))
        self.parser = PacketParser()
        self.zeek = ZeekAnalyzer(zeek_path=ZEEK_PATH, output_dir=str(ZEEK_LOG_DIR))
        self.zeek_parser = ZeekLogParser()
        self.preprocessor = DataPreprocessor(test_size=TEST_SIZE, random_state=RANDOM_STATE)
        self.ml_models = MLModels(model_params=MODEL_PARAMS)
        self.evaluator = ModelEvaluator()
        self.detector = AttackDetector(threshold=IDS_THRESHOLD)
        self.blocker = AttackBlocker(block_duration=BLOCK_DURATION)
        self.ddos_simulator = DDoSSimulator(target_ip=DDOS_TARGET_IP, target_port=DDOS_TARGET_PORT)
        
    def capture_traffic(self, duration: int = None, interface: str = None, filter: str = None) -> str:
        """
        Capture network traffic using Wireshark/tshark
        
        Args:
            duration: Capture duration in seconds
            interface: Network interface to capture from
            filter: BPF filter for packet capture
            
        Returns:
            Path to captured PCAP file
        """
        logger.info("="*60)
        logger.info("STARTING NETWORK TRAFFIC CAPTURE")
        logger.info("="*60)
        
        if interface:
            self.capture.interface = interface
        if duration is None:
            duration = CAPTURE_DURATION
        
        try:
            pcap_file = self.capture.start_capture(
                duration=duration,
                packet_count=PACKET_COUNT,
                filter=filter or CAPTURE_FILTER
            )
            logger.info(f"Capture completed: {pcap_file}")
            return pcap_file
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            raise
    
    def analyze_with_zeek(self, pcap_file: str) -> dict:
        """
        Analyze PCAP file with Zeek
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary of generated log files
        """
        logger.info("="*60)
        logger.info("ANALYZING TRAFFIC WITH ZEEK")
        logger.info("="*60)
        
        try:
            log_files = self.zeek.analyze_pcap(pcap_file)
            logger.info(f"Zeek analysis completed. Generated {len(log_files)} log files")
            return log_files
        except Exception as e:
            logger.error(f"Zeek analysis failed: {e}")
            raise
    
    def parse_zeek_logs(self, log_files: dict) -> pd.DataFrame:
        """
        Parse Zeek logs and extract features
        
        Args:
            log_files: Dictionary of log file paths
            
        Returns:
            DataFrame with extracted features
        """
        logger.info("="*60)
        logger.info("PARSING ZEEK LOGS")
        logger.info("="*60)
        
        try:
            parsed_logs = self.zeek_parser.parse_all_logs(log_files)
            merged_df = self.zeek_parser.merge_logs(parsed_logs)
            
            # Save merged logs
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = PROCESSED_DATA_DIR / f"zeek_features_{timestamp}.csv"
            self.zeek_parser.save_merged_logs(merged_df, str(output_file))
            
            logger.info(f"Zeek logs parsed and saved to {output_file}")
            return merged_df
        except Exception as e:
            logger.error(f"Failed to parse Zeek logs: {e}")
            raise
    
    def parse_pcap_directly(self, pcap_file: str) -> pd.DataFrame:
        """
        Parse PCAP file directly using Scapy
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            DataFrame with extracted features
        """
        logger.info("="*60)
        logger.info("PARSING PCAP DIRECTLY")
        logger.info("="*60)
        
        try:
            packet_df = self.parser.parse_pcap(pcap_file)
            flow_df = self.parser.calculate_flow_features(packet_df)
            
            # Save features
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = PROCESSED_DATA_DIR / f"flow_features_{timestamp}.csv"
            self.parser.save_features(flow_df, str(output_file))
            
            logger.info(f"PCAP parsed and features saved to {output_file}")
            return flow_df
        except Exception as e:
            logger.error(f"Failed to parse PCAP: {e}")
            raise
    
    def train_models(self, data_path: str, target_column: str = 'label') -> dict:
        """
        Train ML models on network traffic data
        
        Args:
            data_path: Path to training data CSV
            target_column: Name of target column
            
        Returns:
            Dictionary of trained models
        """
        logger.info("="*60)
        logger.info("TRAINING ML MODELS")
        logger.info("="*60)
        
        try:
            # Preprocess data
            processed_data = self.preprocessor.preprocess_pipeline(
                data_path=data_path,
                target_column=target_column,
                apply_smote=True,
                scale=True
            )
            
            # Train all models
            trained_models = self.ml_models.train_all_models(
                processed_data['X_train'],
                processed_data['y_train']
            )
            
            # Save models
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            for model_name, model in trained_models.items():
                model_path = MODELS_DIR / f"{model_name}_{timestamp}.pkl"
                self.ml_models.save_model(model_name, str(model_path))
            
            logger.info(f"Trained {len(trained_models)} models successfully")
            return trained_models
            
        except Exception as e:
            logger.error(f"Failed to train models: {e}")
            raise
    
    def evaluate_models(self, trained_models: dict, data_path: str, target_column: str = 'label') -> dict:
        """
        Evaluate trained models
        
        Args:
            trained_models: Dictionary of trained models
            data_path: Path to test data
            target_column: Name of target column
            
        Returns:
            Dictionary of evaluation results
        """
        logger.info("="*60)
        logger.info("EVALUATING ML MODELS")
        logger.info("="*60)
        
        try:
            # Load and preprocess test data
            processed_data = self.preprocessor.preprocess_pipeline(
                data_path=data_path,
                target_column=target_column,
                apply_smote=False,
                scale=True
            )
            
            # Evaluate all models
            evaluation_results = self.evaluator.evaluate_all_models(
                trained_models,
                processed_data['X_test'],
                processed_data['y_test']
            )
            
            # Select best model
            best_model = self.evaluator.select_best_model(metric='f1_score')
            
            # Save evaluation results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = LOGS_DIR / f"evaluation_results_{timestamp}.json"
            self.evaluator.save_evaluation_results(str(results_file))
            
            # Print summary
            self.evaluator.print_summary()
            
            # Generate comparison plot
            plot_file = LOGS_DIR / f"model_comparison_{timestamp}.png"
            self.evaluator.plot_model_comparison(str(plot_file))
            
            logger.info(f"Model evaluation completed. Best model: {best_model}")
            return evaluation_results
            
        except Exception as e:
            logger.error(f"Failed to evaluate models: {e}")
            raise
    
    def detect_attacks(self, features_df: pd.DataFrame, model_name: str = None) -> list:
        """
        Detect attacks using ML model and statistical analysis
        
        Args:
            features_df: DataFrame with traffic features
            model_name: Name of model to use for detection
            
        Returns:
            List of detected attacks
        """
        logger.info("="*60)
        logger.info("DETECTING ATTACKS")
        logger.info("="*60)
        
        all_attacks = []
        
        # Statistical detection
        statistical_attacks = self.detector.detect_statistical(features_df)
        all_attacks.extend(statistical_attacks)
        
        # ML-based detection if model is available
        if model_name and model_name in self.ml_models.trained_models:
            model = self.ml_models.trained_models[model_name]
            self.detector.model = model
            
            # Prepare features for prediction
            feature_cols = [col for col in features_df.columns if col not in ['src_ip', 'dst_ip', 'protocol_type', 'flow_key']]
            if feature_cols:
                X = features_df[feature_cols].fillna(0).values
                
                for i in range(len(X)):
                    prediction, confidence = self.detector.detect_with_model(X[i])
                    if prediction == 1 and confidence > self.detector.threshold:
                        attack = {
                            'type': 'ml_detected_attack',
                            'confidence': confidence,
                            'src_ip': features_df.iloc[i].get('src_ip', 'unknown'),
                            'dst_ip': features_df.iloc[i].get('dst_ip', 'unknown'),
                            'timestamp': datetime.now().isoformat(),
                            'details': f'ML prediction: attack (confidence: {confidence:.2f})'
                        }
                        all_attacks.append(attack)
        
        # Log all detections
        for attack in all_attacks:
            self.detector.log_detection(attack)
        
        logger.info(f"Detected {len(all_attacks)} potential attacks")
        return all_attacks
    
    def block_attackers(self, attacks: list, auto_block: bool = True) -> list:
        """
        Block detected attackers using IPS
        
        Args:
            attacks: List of detected attacks
            auto_block: Whether to automatically block IPs
            
        Returns:
            List of blocked IPs
        """
        logger.info("="*60)
        logger.info("BLOCKING ATTACKERS (IPS)")
        logger.info("="*60)
        
        blocked_ips = []
        
        for attack in attacks:
            src_ip = attack.get('src_ip')
            if src_ip and src_ip != 'unknown':
                # Check if already blocked
                if not self.blocker.is_blocked(src_ip):
                    if auto_block and attack.get('confidence', 0) > IDS_THRESHOLD:
                        success = self.blocker.block_ip(src_ip, reason=attack.get('type', 'Attack detected'))
                        if success:
                            blocked_ips.append(src_ip)
        
        # Cleanup expired blocks
        self.blocker.cleanup_expired_blocks()
        
        # Save blocked IPs
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        blocked_file = LOGS_DIR / f"blocked_ips_{timestamp}.json"
        self.blocker.save_blocked_ips(str(blocked_file))
        
        logger.info(f"Blocked {len(blocked_ips)} IP addresses")
        return blocked_ips
    
    def simulate_ddos_attack(self, 
                           attack_type: str = 'syn_flood',
                           packet_count: int = 1000,
                           duration: int = 30,
                           save_pcap: bool = True) -> str:
        """
        Simulate DDoS attack for testing
        
        Args:
            attack_type: Type of DDoS attack
            packet_count: Number of packets
            duration: Duration in seconds
            save_pcap: Whether to save attack traffic to PCAP
            
        Returns:
            Path to generated PCAP file (if save_pcap=True)
        """
        logger.info("="*60)
        logger.info(f"SIMULATING DDoS ATTACK: {attack_type}")
        logger.info("="*60)
        
        try:
            if save_pcap:
                pcap_file = self.ddos_simulator.generate_attack_traffic(
                    attack_type=attack_type,
                    packet_count=packet_count
                )
                logger.info(f"Attack traffic saved to {pcap_file}")
                return pcap_file
            else:
                # Run live attack simulation
                if attack_type == 'syn_flood':
                    self.ddos_simulator.syn_flood(packet_count, duration)
                elif attack_type == 'udp_flood':
                    self.ddos_simulator.udp_flood(packet_count, duration)
                elif attack_type == 'icmp_flood':
                    self.ddos_simulator.icmp_flood(packet_count, duration)
                elif attack_type == 'mixed':
                    self.ddos_simulator.mixed_attack(packet_count, duration)
                else:
                    logger.error(f"Unknown attack type: {attack_type}")
                
                return None
                
        except Exception as e:
            logger.error(f"DDoS simulation failed: {e}")
            raise
    
    def full_pipeline(self, 
                     capture_duration: int = 60,
                     interface: str = None,
                     train_model: bool = False,
                     training_data: str = None) -> dict:
        """
        Run the complete analysis pipeline
        
        Args:
            capture_duration: Duration for traffic capture
            interface: Network interface to use
            train_model: Whether to train ML models
            training_data: Path to training data
            
        Returns:
            Dictionary with pipeline results
        """
        logger.info("="*60)
        logger.info("STARTING FULL ANALYSIS PIPELINE")
        logger.info("="*60)
        
        results = {}
        
        try:
            # Step 1: Capture traffic
            pcap_file = self.capture_traffic(duration=capture_duration, interface=interface)
            results['pcap_file'] = pcap_file
            
            # Step 2: Analyze with Zeek
            log_files = self.analyze_with_zeek(pcap_file)
            results['zeek_logs'] = log_files
            
            # Step 3: Parse Zeek logs
            zeek_features = self.parse_zeek_logs(log_files)
            results['zeek_features'] = str(zeek_features.shape)
            
            # Step 4: Parse PCAP directly for additional features
            pcap_features = self.parse_pcap_directly(pcap_file)
            results['pcap_features'] = str(pcap_features.shape)
            
            # Step 5: Detect attacks
            attacks = self.detect_attacks(pcap_features)
            results['detected_attacks'] = len(attacks)
            
            # Step 6: Block attackers
            blocked_ips = self.block_attackers(attacks)
            results['blocked_ips'] = blocked_ips
            
            # Step 7: Train models if requested
            if train_model and training_data:
                trained_models = self.train_models(training_data)
                results['trained_models'] = list(trained_models.keys())
                
                # Evaluate models
                evaluation_results = self.evaluate_models(trained_models, training_data)
                results['best_model'] = self.evaluator.best_model
            
            logger.info("="*60)
            logger.info("PIPELINE COMPLETED SUCCESSFULLY")
            logger.info("="*60)
            
            return results
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            raise


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Assisted Network Traffic Analysis System'
    )
    
    parser.add_argument(
        '--mode',
        choices=['capture', 'analyze', 'train', 'detect', 'simulate-ddos', 'full'],
        required=True,
        help='Operation mode'
    )
    
    parser.add_argument(
        '--interface',
        default=CAPTURE_INTERFACE,
        help='Network interface to capture from'
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        default=CAPTURE_DURATION,
        help='Capture duration in seconds'
    )
    
    parser.add_argument(
        '--input',
        help='Input file (PCAP or CSV)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path'
    )
    
    parser.add_argument(
        '--model',
        default=DEFAULT_MODEL,
        help='ML model to use'
    )
    
    parser.add_argument(
        '--attack-type',
        choices=['syn_flood', 'udp_flood', 'icmp_flood', 'mixed'],
        default='syn_flood',
        help='Type of DDoS attack to simulate'
    )
    
    parser.add_argument(
        '--target',
        default=DDOS_TARGET_IP,
        help='Target IP for attack simulation'
    )
    
    parser.add_argument(
        '--train',
        action='store_true',
        help='Train ML models'
    )
    
    parser.add_argument(
        '--training-data',
        help='Path to training data CSV'
    )
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = NetworkTrafficAnalysisPipeline()
    
    try:
        if args.mode == 'capture':
            pcap_file = pipeline.capture_traffic(
                duration=args.duration,
                interface=args.interface
            )
            print(f"Capture completed: {pcap_file}")
        
        elif args.mode == 'analyze':
            if not args.input:
                print("Error: --input required for analyze mode")
                sys.exit(1)
            
            log_files = pipeline.analyze_with_zeek(args.input)
            features_df = pipeline.parse_zeek_logs(log_files)
            print(f"Analysis completed. Features shape: {features_df.shape}")
        
        elif args.mode == 'train':
            if not args.training_data:
                print("Error: --training-data required for train mode")
                sys.exit(1)
            
            trained_models = pipeline.train_models(args.training_data)
            evaluation_results = pipeline.evaluate_models(trained_models, args.training_data)
            print(f"Training completed. Best model: {pipeline.evaluator.best_model}")
        
        elif args.mode == 'detect':
            if not args.input:
                print("Error: --input required for detect mode")
                sys.exit(1)
            
            # Load features from CSV
            features_df = pd.read_csv(args.input)
            attacks = pipeline.detect_attacks(features_df, model_name=args.model)
            blocked_ips = pipeline.block_attackers(attacks)
            
            print(f"Detected {len(attacks)} attacks")
            print(f"Blocked {len(blocked_ips)} IPs")
        
        elif args.mode == 'simulate-ddos':
            pipeline.ddos_simulator.target_ip = args.target
            pcap_file = pipeline.simulate_ddos_attack(
                attack_type=args.attack_type,
                save_pcap=True
            )
            print(f"DDoS simulation completed: {pcap_file}")
        
        elif args.mode == 'full':
            results = pipeline.full_pipeline(
                capture_duration=args.duration,
                interface=args.interface,
                train_model=args.train,
                training_data=args.training_data
            )
            print("Full pipeline completed:")
            for key, value in results.items():
                print(f"  {key}: {value}")
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

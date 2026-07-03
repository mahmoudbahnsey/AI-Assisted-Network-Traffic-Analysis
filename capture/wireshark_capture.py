"""
Wireshark/tshark based network packet capture
"""

import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class WiresharkCapture:
    """Handles network packet capture using tshark (Wireshark command-line)"""
    
    def __init__(self, interface: str = "eth0", output_dir: str = None):
        """
        Initialize Wireshark capture
        
        Args:
            interface: Network interface to capture from
            output_dir: Directory to save capture files
        """
        self.interface = interface
        self.output_dir = Path(output_dir) if output_dir else Path("./data/raw")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.capture_process = None
        
    def check_tshark_available(self) -> bool:
        """Check if tshark is available in the system"""
        try:
            result = subprocess.run(["tshark", "--version"], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("tshark not found. Please install Wireshark.")
            return False
    
    def start_capture(self, 
                     duration: int = 60,
                     packet_count: int = 10000,
                     filter: str = "",
                     output_file: Optional[str] = None) -> str:
        """
        Start packet capture using tshark
        
        Args:
            duration: Capture duration in seconds
            packet_count: Maximum number of packets to capture
            filter: BPF filter for packet capture
            output_file: Output PCAP file path
            
        Returns:
            Path to the captured PCAP file
        """
        if not self.check_tshark_available():
            raise RuntimeError("tshark is not available")
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"capture_{timestamp}.pcap"
        else:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Build tshark command
        cmd = [
            "tshark",
            "-i", self.interface,
            "-a", f"duration:{duration}",
            "-c", str(packet_count),
            "-w", str(output_file)
        ]
        
        if filter:
            cmd.extend(["-f", filter])
        
        logger.info(f"Starting capture on interface {self.interface}")
        logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for capture to complete
            stdout, stderr = self.capture_process.communicate()
            
            if self.capture_process.returncode != 0:
                logger.error(f"Capture failed: {stderr.decode()}")
                raise RuntimeError(f"Capture failed: {stderr.decode()}")
            
            logger.info(f"Capture completed successfully: {output_file}")
            return str(output_file)
            
        except subprocess.TimeoutExpired:
            self.capture_process.kill()
            logger.error("Capture timed out")
            raise
        except Exception as e:
            logger.error(f"Error during capture: {e}")
            raise
    
    def start_live_capture(self,
                          filter: str = "",
                          callback=None) -> subprocess.Popen:
        """
        Start live packet capture with real-time processing
        
        Args:
            filter: BPF filter for packet capture
            callback: Optional callback function for processing packets
            
        Returns:
            Subprocess object for the capture
        """
        if not self.check_tshark_available():
            raise RuntimeError("tshark is not available")
        
        cmd = [
            "tshark",
            "-i", self.interface,
            "-l",  # Line buffered output
            "-T", "fields",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "frame.len"
        ]
        
        if filter:
            cmd.extend(["-f", filter])
        
        logger.info(f"Starting live capture on interface {self.interface}")
        
        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            return self.capture_process
        except Exception as e:
            logger.error(f"Error starting live capture: {e}")
            raise
    
    def stop_capture(self):
        """Stop the ongoing capture"""
        if self.capture_process:
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
            logger.info("Capture stopped")
    
    def convert_to_json(self, pcap_file: str, output_file: str = None) -> str:
        """
        Convert PCAP file to JSON format for easier processing
        
        Args:
            pcap_file: Path to PCAP file
            output_file: Output JSON file path
            
        Returns:
            Path to the JSON file
        """
        if output_file is None:
            output_file = Path(pcap_file).with_suffix('.json')
        else:
            output_file = Path(output_file)
        
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-T", "json",
            "-o", "json.output_file:" + str(output_file)
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"Converted {pcap_file} to JSON: {output_file}")
            return str(output_file)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to convert PCAP to JSON: {e}")
            raise
    
    def get_packet_statistics(self, pcap_file: str) -> dict:
        """
        Get statistics from PCAP file
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary with packet statistics
        """
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-q",
            "-z", "io,phs"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            stats = self._parse_statistics(result.stdout)
            return stats
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _parse_statistics(self, stats_output: str) -> dict:
        """Parse tshark statistics output"""
        stats = {}
        lines = stats_output.split('\n')
        for line in lines:
            if 'packets' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        stats['total_packets'] = int(parts[0])
                    except ValueError:
                        pass
        return stats

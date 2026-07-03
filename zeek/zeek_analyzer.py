"""
Zeek analyzer for deep packet inspection and protocol analysis
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, List, Dict
import logging
import shutil

logger = logging.getLogger(__name__)


class ZeekAnalyzer:
    """Handles Zeek execution and log generation"""
    
    def __init__(self, zeek_path: str = "zeek", output_dir: str = None):
        """
        Initialize Zeek analyzer
        
        Args:
            zeek_path: Path to zeek executable
            output_dir: Directory to save Zeek logs
        """
        self.zeek_path = zeek_path
        self.output_dir = Path(output_dir) if output_dir else Path("./data/zeek_logs")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def check_zeek_available(self) -> bool:
        """Check if Zeek is available in the system"""
        try:
            result = subprocess.run([self.zeek_path, "--version"], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                logger.info(f"Zeek version: {result.stdout.strip()}")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("Zeek not found. Please install Zeek.")
            return False
    
    def analyze_pcap(self, pcap_file: str, scripts: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Analyze PCAP file using Zeek
        
        Args:
            pcap_file: Path to PCAP file
            scripts: Optional list of Zeek scripts to load
            
        Returns:
            Dictionary mapping log types to their file paths
        """
        if not self.check_zeek_available():
            raise RuntimeError("Zeek is not available")
        
        if not Path(pcap_file).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        # Create output directory for this analysis
        timestamp = Path(pcap_file).stem
        analysis_dir = self.output_dir / timestamp
        analysis_dir.mkdir(parents=True, exist_ok=True)
        
        # Build Zeek command
        cmd = [self.zeek_path, "-r", pcap_file]
        
        # Add custom scripts if provided
        if scripts:
            for script in scripts:
                cmd.extend(["-e", f'@load {script}'])
        
        # Set output directory
        cmd.extend(["Log::default_logdir", f'"{analysis_dir}"'])
        
        logger.info(f"Running Zeek analysis on {pcap_file}")
        logger.info(f"Output directory: {analysis_dir}")
        
        try:
            # Run Zeek
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(analysis_dir),
                timeout=300  # 5 minute timeout
            )
            
            if process.returncode != 0:
                logger.error(f"Zeek analysis failed: {process.stderr}")
                raise RuntimeError(f"Zeek analysis failed: {process.stderr}")
            
            # Collect generated log files
            log_files = self._collect_log_files(analysis_dir)
            logger.info(f"Zeek analysis completed. Generated {len(log_files)} log files")
            
            return log_files
            
        except subprocess.TimeoutExpired:
            logger.error("Zeek analysis timed out")
            raise
        except Exception as e:
            logger.error(f"Error during Zeek analysis: {e}")
            raise
    
    def analyze_live_traffic(self, interface: str = "eth0", duration: int = 60) -> Dict[str, str]:
        """
        Analyze live network traffic using Zeek
        
        Args:
            interface: Network interface to monitor
            duration: Duration of capture in seconds
            
        Returns:
            Dictionary mapping log types to their file paths
        """
        if not self.check_zeek_available():
            raise RuntimeError("Zeek is not available")
        
        # Create output directory
        timestamp = Path(pcap_file).stem if 'pcap_file' in locals() else "live"
        analysis_dir = self.output_dir / f"live_{timestamp}"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        
        # Build Zeek command for live capture
        cmd = [
            self.zeek_path,
            "-i", interface,
            "-e", f'@load protocols/ssh/detect-bruteforce',
            "-e", f'@load protocols/http/detect-sqli',
            "-e", f'@load frameworks/files/detect-MHR'
        ]
        
        logger.info(f"Starting live Zeek analysis on interface {interface}")
        
        try:
            # Run Zeek in background
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(analysis_dir)
            )
            
            # Wait for specified duration
            import time
            time.sleep(duration)
            
            # Stop Zeek
            process.terminate()
            process.wait(timeout=10)
            
            # Collect generated log files
            log_files = self._collect_log_files(analysis_dir)
            logger.info(f"Live analysis completed. Generated {len(log_files)} log files")
            
            return log_files
            
        except Exception as e:
            logger.error(f"Error during live analysis: {e}")
            if process:
                process.kill()
            raise
    
    def _collect_log_files(self, analysis_dir: Path) -> Dict[str, str]:
        """Collect all log files from analysis directory"""
        log_files = {}
        
        # Standard Zeek log files
        log_types = [
            "conn", "dns", "http", "ssl", "ssh", "smtp",
            "ftp", "sip", "icmp", "arp", "weird", "notice"
        ]
        
        for log_type in log_types:
            log_file = analysis_dir / f"{log_type}.log"
            if log_file.exists():
                log_files[log_type] = str(log_file)
        
        # Also collect any other .log files
        for log_file in analysis_dir.glob("*.log"):
            log_name = log_file.stem
            if log_name not in log_files:
                log_files[log_name] = str(log_file)
        
        return log_files
    
    def load_custom_script(self, script_path: str):
        """
        Load a custom Zeek script
        
        Args:
            script_path: Path to the Zeek script
        """
        if not Path(script_path).exists():
            raise FileNotFoundError(f"Script not found: {script_path}")
        
        logger.info(f"Loading custom Zeek script: {script_path}")
        # This would be used when calling analyze_pcap with scripts parameter
        return script_path
    
    def create_detection_script(self, output_path: str, detection_rules: List[Dict]):
        """
        Create a custom Zeek detection script
        
        Args:
            output_path: Path to save the script
            detection_rules: List of detection rule dictionaries
        """
        script_content = """
# Custom detection script generated by AI-Assisted Network Traffic Analysis

@load base/frameworks/notice
@load base/protocols/conn

"""
        
        for rule in detection_rules:
            script_content += f"# {rule.get('description', 'Custom rule')}\n"
            script_content += f"event {rule.get('event', 'connection_state_remove')}(c: connection)\n"
            script_content += "{\n"
            
            if 'condition' in rule:
                script_content += f"    if ({rule['condition']}) {{\n"
                script_content += f"        NOTICE([$note={rule.get('notice_type', 'Custom::Attack')},\n"
                script_content += f"                $msg={rule.get('message', 'Potential attack detected')},\n"
                script_content += f"                $conn=c]);\n"
                script_content += "    }\n"
            
            script_content += "}\n\n"
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(script_content)
        
        logger.info(f"Created custom detection script: {output_path}")

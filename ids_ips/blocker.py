"""
Attack blocking system for IPS functionality
"""

import subprocess
from datetime import datetime, timedelta
from typing import Dict, List
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class AttackBlocker:
    """Block malicious network traffic"""
    
    def __init__(self, block_duration: int = 300):
        """
        Initialize attack blocker
        
        Args:
            block_duration: Duration to block IP in seconds (default: 5 minutes)
        """
        self.block_duration = block_duration
        self.blocked_ips = {}  # IP -> (block_time, reason)
        self.block_rules = []
        
    def block_ip(self, ip_address: str, reason: str = "Attack detected") -> bool:
        """
        Block an IP address using firewall rules
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            
        Returns:
            True if blocking was successful
        """
        logger.info(f"Blocking IP: {ip_address} (Reason: {reason})")
        
        # Record the block
        self.blocked_ips[ip_address] = {
            'block_time': datetime.now(),
            'reason': reason,
            'duration': self.block_duration
        }
        
        # Try to block using different methods
        success = False
        
        # Method 1: Windows Firewall (netsh)
        if self._block_with_windows_firewall(ip_address, reason):
            success = True
        
        # Method 2: iptables (Linux)
        elif self._block_with_iptables(ip_address):
            success = True
        
        # Method 3: pf (macOS/BSD)
        elif self._block_with_pf(ip_address):
            success = True
        
        if success:
            logger.info(f"Successfully blocked IP: {ip_address}")
        else:
            logger.warning(f"Could not block IP: {ip_address} (no suitable method available)")
        
        return success
    
    def _block_with_windows_firewall(self, ip_address: str, reason: str) -> bool:
        """
        Block IP using Windows Firewall
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            
        Returns:
            True if successful
        """
        try:
            # Check if running on Windows
            try:
                subprocess.run(["cmd", "/c", "ver"], capture_output=True, check=True)
            except:
                return False
            
            # Create firewall rule name
            rule_name = f"Block_{ip_address.replace('.', '_')}"
            
            # Delete existing rule if it exists
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ], capture_output=True)
            
            # Add new blocking rule
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}",
                f"description={reason}"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Added Windows Firewall rule for {ip_address}")
                return True
            else:
                logger.error(f"Failed to add Windows Firewall rule: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking with Windows Firewall: {e}")
            return False
    
    def _block_with_iptables(self, ip_address: str) -> bool:
        """
        Block IP using iptables (Linux)
        
        Args:
            ip_address: IP address to block
            
        Returns:
            True if successful
        """
        try:
            # Check if iptables is available
            result = subprocess.run(["which", "iptables"], capture_output=True)
            if result.returncode != 0:
                return False
            
            # Add iptables rule
            result = subprocess.run([
                "sudo", "iptables",
                "-A", "INPUT",
                "-s", ip_address,
                "-j", "DROP"
            ], capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"Added iptables rule for {ip_address}")
                return True
            else:
                logger.error(f"Failed to add iptables rule: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking with iptables: {e}")
            return False
    
    def _block_with_pf(self, ip_address: str) -> bool:
        """
        Block IP using pf (macOS/BSD)
        
        Args:
            ip_address: IP address to block
            
        Returns:
            True if successful
        """
        try:
            # Check if pf is available
            result = subprocess.run(["which", "pfctl"], capture_output=True)
            if result.returncode != 0:
                return False
            
            # Add pf rule
            result = subprocess.run([
                "sudo", "pfctl",
                "-t", "blocked_ips",
                "-T", "add",
                ip_address
            ], capture_output=True)
            
            if result.returncode == 0:
                logger.info(f"Added pf rule for {ip_address}")
                return True
            else:
                logger.error(f"Failed to add pf rule: {result.stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking with pf: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            True if unblocking was successful
        """
        logger.info(f"Unblocking IP: {ip_address}")
        
        # Remove from blocked list
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
        
        success = False
        
        # Try different unblock methods
        if self._unblock_with_windows_firewall(ip_address):
            success = True
        elif self._unblock_with_iptables(ip_address):
            success = True
        elif self._unblock_with_pf(ip_address):
            success = True
        
        if success:
            logger.info(f"Successfully unblocked IP: {ip_address}")
        else:
            logger.warning(f"Could not unblock IP: {ip_address}")
        
        return success
    
    def _unblock_with_windows_firewall(self, ip_address: str) -> bool:
        """Unblock IP using Windows Firewall"""
        try:
            rule_name = f"Block_{ip_address.replace('.', '_')}"
            
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ], capture_output=True)
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error unblocking with Windows Firewall: {e}")
            return False
    
    def _unblock_with_iptables(self, ip_address: str) -> bool:
        """Unblock IP using iptables"""
        try:
            result = subprocess.run([
                "sudo", "iptables",
                "-D", "INPUT",
                "-s", ip_address,
                "-j", "DROP"
            ], capture_output=True)
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error unblocking with iptables: {e}")
            return False
    
    def _unblock_with_pf(self, ip_address: str) -> bool:
        """Unblock IP using pf"""
        try:
            result = subprocess.run([
                "sudo", "pfctl",
                "-t", "blocked_ips",
                "-T", "delete",
                ip_address
            ], capture_output=True)
            
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error unblocking with pf: {e}")
            return False
    
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        now = datetime.now()
        expired_ips = []
        
        for ip, block_info in self.blocked_ips.items():
            block_time = block_info['block_time']
            duration = timedelta(seconds=block_info['duration'])
            
            if now - block_time > duration:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            logger.info(f"Block expired for {ip}, unblocking...")
            self.unblock_ip(ip)
    
    def get_blocked_ips(self) -> List[Dict]:
        """
        Get list of currently blocked IPs
        
        Returns:
            List of blocked IP information
        """
        blocked_list = []
        
        for ip, block_info in self.blocked_ips.items():
            blocked_list.append({
                'ip': ip,
                'block_time': block_info['block_time'].isoformat(),
                'reason': block_info['reason'],
                'duration': block_info['duration'],
                'remaining_seconds': int(block_info['duration'] - 
                                       (datetime.now() - block_info['block_time']).total_seconds())
            })
        
        return blocked_list
    
    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP is currently blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is blocked
        """
        if ip_address not in self.blocked_ips:
            return False
        
        # Check if block has expired
        block_info = self.blocked_ips[ip_address]
        block_time = block_info['block_time']
        duration = timedelta(seconds=block_info['duration'])
        
        if datetime.now() - block_time > duration:
            # Block expired, remove it
            self.unblock_ip(ip_address)
            return False
        
        return True
    
    def save_blocked_ips(self, output_path: str):
        """
        Save blocked IPs to file
        
        Args:
            output_path: Path to save the blocked IPs
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert datetime objects to strings for JSON serialization
        blocked_data = []
        for ip, block_info in self.blocked_ips.items():
            blocked_data.append({
                'ip': ip,
                'block_time': block_info['block_time'].isoformat(),
                'reason': block_info['reason'],
                'duration': block_info['duration']
            })
        
        with open(output_path, 'w') as f:
            json.dump(blocked_data, f, indent=2)
        
        logger.info(f"Saved blocked IPs to {output_path}")
    
    def load_blocked_ips(self, input_path: str):
        """
        Load blocked IPs from file
        
        Args:
            input_path: Path to load the blocked IPs from
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Blocked IPs file not found: {input_path}")
        
        with open(input_path, 'r') as f:
            blocked_data = json.load(f)
        
        for item in blocked_data:
            ip = item['ip']
            self.blocked_ips[ip] = {
                'block_time': datetime.fromisoformat(item['block_time']),
                'reason': item['reason'],
                'duration': item['duration']
            }
        
        logger.info(f"Loaded {len(blocked_data)} blocked IPs from {input_path}")

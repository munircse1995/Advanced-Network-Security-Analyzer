#!/usr/bin/env python3
"""
Advanced Network Packet Analyzer - Enterprise Edition
Professional-grade network security monitoring tool

All Rights Reserved. Developed by Shirajam Munir Fahad.
Licensed for educational and professional use.
"""

import socket
import struct
import threading
import time
import json
import csv
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import queue
import logging
import hashlib
import sqlite3
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Set
import argparse
import sys
import os
import psutil
import ipaddress
import re
from pathlib import Path

# Configure logging with enhanced security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('network_analyzer_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class PacketInfo:
    """Enhanced packet information structure"""
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_size: int = 0
    flags: str = ""
    payload_preview: str = ""
    ttl: int = 0
    packet_id: str = ""
    geo_location: str = ""
    threat_level: str = "LOW"
    service_name: str = ""
    asn: str = ""

@dataclass
class ThreatIndicator:
    """Threat intelligence data structure"""
    ip_address: str
    threat_type: str
    severity: str
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1

class EnhancedNetworkAnalyzer:
    """Enterprise-grade network packet analyzer with advanced security features"""
    
    def __init__(self):
        self.is_capturing = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packets = deque(maxlen=50000)  # Memory-efficient storage
        self.stats = defaultdict(int)
        self.protocol_stats = Counter()
        self.capture_thread = None
        self.start_time = None
        
        # Enhanced Security Monitoring
        self.threat_indicators = {}
        self.suspicious_ips = set()
        self.port_scan_tracker = defaultdict(lambda: {"ports": set(), "timestamps": deque(maxlen=100)})
        self.connection_tracker = defaultdict(int)
        self.ddos_detector = defaultdict(lambda: deque(maxlen=1000))
        self.malware_signatures = self.load_malware_signatures()
        self.geo_ip_cache = {}
        self.asn_cache = {}
        
        # Performance monitoring
        self.performance_stats = {
            "packets_per_second": 0,
            "bytes_per_second": 0,
            "dropped_packets": 0,
            "cpu_usage": 0,
            "memory_usage": 0
        }
        
        # Known service ports for better analysis
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
            110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT"
        }
        
        # Advanced filters
        self.filters = {
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'port': None,
            'threat_level': None,
            'payload_contains': None,
            'service': None
        }
        
        # Database for persistent storage
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for storing analysis results"""
        try:
            db_path = Path("network_analysis.db")
            self.db_conn = sqlite3.connect(str(db_path), check_same_thread=False)
            
            # Create tables
            cursor = self.db_conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    packet_size INTEGER,
                    flags TEXT,
                    threat_level TEXT,
                    service_name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    threat_type TEXT,
                    severity TEXT,
                    description TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    count INTEGER DEFAULT 1
                )
            ''')
            
            self.db_conn.commit()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            self.db_conn = None
    
    def load_malware_signatures(self) -> Set[str]:
        """Load known malware signatures and suspicious patterns"""
        signatures = {
            # Common malware patterns
            b'cmd.exe', b'powershell', b'rundll32', b'wscript.shell',
            # Exploit patterns
            b'../../', b'/etc/passwd', b'win.ini',
            # SQL injection patterns
            b'union select', b'drop table', b'insert into', b';--',
            # XSS patterns
            b'<script>', b'javascript:', b'onerror=', b'alert(',
            # Suspicious file extensions in HTTP
            b'.exe', b'.bat', b'.cmd', b'.scr', b'.pif', b'.dll',
            # Crypto mining patterns
            b'stratum+tcp', b'xmrpool', b'cryptonight',
            # Ransomware patterns
            b'encryption_key', b'decrypt_instructions', b'ransom_note'
        }
        return signatures
    
    def get_local_ip(self):
        """Get local IP address for socket binding"""
        try:
            # Create a temporary socket to get local IP
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to a public DNS server
                temp_sock.connect(("8.8.8.8", 80))
                local_ip = temp_sock.getsockname()[0]
                return local_ip
            finally:
                temp_sock.close()
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    def create_socket(self) -> socket.socket:
        """Create optimized raw socket for packet capture"""
        try:
            if os.name == 'nt':  # Windows
                # Get local IP for binding
                local_ip = self.get_local_ip()
                logger.info(f"Binding to local IP: {local_ip}")
                
                # Create raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                
                # Bind to the specific interface
                sock.bind((local_ip, 0))
                
                # Enable promiscuous mode
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                
                # Set buffer size for better performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**24)  # 16MB buffer
            else:  # Linux/Unix
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**24)
            
            return sock
        except PermissionError:
            logger.error("Permission denied. Run as administrator/root.")
            raise
        except Exception as e:
            logger.error(f"Socket creation failed: {e}")
            raise
    
    def analyze_packet(self, packet: bytes) -> Optional[PacketInfo]:
        """Enhanced packet analysis with security assessment"""
        try:
            # Handle different OS packet formats
            if os.name != 'nt':  # Linux - strip Ethernet header
                packet, eth_type = self.parse_ethernet_header(packet)
                if eth_type != "IPv4":
                    return None
            
            # Parse IP header
            ip_info, payload = self.parse_ip_header(packet)
            if not ip_info:
                return None
            
            # Generate unique packet ID
            packet_id = hashlib.sha256(packet[:100]).hexdigest()[:16]
            
            packet_info = PacketInfo(
                timestamp=datetime.now().strftime('%H:%M:%S.%f')[:-3],
                src_ip=ip_info['src_ip'],
                dst_ip=ip_info['dst_ip'],
                protocol=ip_info['protocol'],
                packet_size=len(packet),
                ttl=ip_info.get('ttl', 0),
                packet_id=packet_id
            )
            
            # Parse transport layer headers
            if ip_info['protocol'] == 'TCP':
                tcp_info = self.parse_tcp_header(payload)
                if tcp_info:
                    packet_info.src_port = tcp_info.get('src_port')
                    packet_info.dst_port = tcp_info.get('dst_port')
                    packet_info.flags = tcp_info.get('flags', '')
                    packet_info.service_name = self.get_service_name(packet_info.dst_port)
                    
            elif ip_info['protocol'] == 'UDP':
                udp_info = self.parse_udp_header(payload)
                if udp_info:
                    packet_info.src_port = udp_info.get('src_port')
                    packet_info.dst_port = udp_info.get('dst_port')
                    packet_info.service_name = self.get_service_name(packet_info.dst_port)
            
            # Enhanced payload analysis
            if len(payload) > 0:
                packet_info.payload_preview = self.analyze_payload(payload)
            
            # Security assessment
            packet_info.threat_level = self.assess_threat_level(packet_info, payload)
            
            # Geolocation and ASN (simplified)
            packet_info.geo_location, packet_info.asn = self.get_ip_info(packet_info.src_ip)
            
            # Advanced security analysis
            self.perform_security_analysis(packet_info, payload)
            
            # Update statistics
            self.update_enhanced_stats(packet_info)
            
            return packet_info
            
        except Exception as e:
            logger.debug(f"Packet analysis error: {e}")
            self.performance_stats["dropped_packets"] += 1
            return None
    
    def get_service_name(self, port: int) -> str:
        """Get service name for a given port"""
        return self.common_ports.get(port, f"Port-{port}" if port else "Unknown")
    
    def analyze_payload(self, payload: bytes) -> str:
        """Enhanced payload analysis with security checks"""
        try:
            # Check for malware signatures
            for signature in self.malware_signatures:
                if signature in payload.lower():
                    logger.warning(f"Malware signature detected: {signature}")
                    return f"[MALWARE] {signature.decode('utf-8', errors='ignore')[:50]}"
            
            # Extract readable text
            if len(payload) > 20:
                text = payload[20:100].decode('utf-8', errors='ignore')
                # Filter printable characters
                readable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    'select * from', 'drop table', '<script', 
                    'eval(', 'document.cookie', 'base64_decode',
                    '<?php', 'system(', 'exec(', 'shell_exec('
                ]
                if any(pattern in readable.lower() for pattern in suspicious_patterns):
                    return f"[SUSPICIOUS] {readable[:50]}"
                
                return readable[:50] if readable.strip() else "Binary data"
            
            return "No payload"
            
        except Exception:
            return "Binary data"
    
    def assess_threat_level(self, packet_info: PacketInfo, payload: bytes) -> str:
        """Assess threat level based on multiple factors"""
        threat_score = 0
        
        # Check source IP reputation
        if packet_info.src_ip in self.suspicious_ips:
            threat_score += 50
        
        # Check for suspicious ports
        suspicious_ports = {1337, 31337, 12345, 54321, 9999, 666, 4444, 5555}
        if packet_info.src_port in suspicious_ports or packet_info.dst_port in suspicious_ports:
            threat_score += 30
        
        # Check for private IP communicating with external
        try:
            src_private = ipaddress.ip_address(packet_info.src_ip).is_private
            dst_private = ipaddress.ip_address(packet_info.dst_ip).is_private
            if src_private and not dst_private:  # Internal to external
                threat_score += 20
        except:
            pass
        
        # Check payload for suspicious content
        suspicious_payload_indicators = [
            b'malware', b'trojan', b'exploit', b'ransom', 
            b'backdoor', b'keylogger', b'rootkit'
        ]
        if any(indicator in payload.lower() for indicator in suspicious_payload_indicators):
            threat_score += 40
        
        # Check for large ICMP packets (possible ping flood)
        if packet_info.protocol == "ICMP" and packet_info.packet_size > 1000:
            threat_score += 20
        
        # Determine threat level
        if threat_score >= 70:
            return "CRITICAL"
        elif threat_score >= 40:
            return "HIGH"
        elif threat_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_ip_info(self, ip: str) -> Tuple[str, str]:
        """Get geolocation and ASN for IP (simplified implementation)"""
        if ip in self.geo_ip_cache and ip in self.asn_cache:
            return self.geo_ip_cache[ip], self.asn_cache[ip]
        
        try:
            # Check if private IP
            if ipaddress.ip_address(ip).is_private:
                location = "Private Network"
                asn = "N/A"
            else:
                # In production, use a real GeoIP service
                location = "Unknown"
                asn = "AS???"
            
            self.geo_ip_cache[ip] = location
            self.asn_cache[ip] = asn
            return location, asn
        except:
            return "Invalid IP", "N/A"
    
    def perform_security_analysis(self, packet_info: PacketInfo, payload: bytes):
        """Perform comprehensive security analysis"""
        # Port scan detection
        if packet_info.dst_port:
            self.detect_advanced_port_scan(packet_info.src_ip, packet_info.dst_port)
        
        # DDoS detection
        self.detect_ddos_attempt(packet_info.src_ip, packet_info.packet_size)
        
        # Suspicious activity detection
        self.detect_suspicious_activity(packet_info, payload)
    
    def detect_advanced_port_scan(self, src_ip: str, dst_port: int):
        """Advanced port scan detection with time-based analysis"""
        current_time = datetime.now()
        scan_data = self.port_scan_tracker[src_ip]
        
        scan_data["ports"].add(dst_port)
        scan_data["timestamps"].append(current_time)
        
        # Check for rapid port scanning (more than 10 ports in 30 seconds)
        recent_scans = [t for t in scan_data["timestamps"] 
                       if (current_time - t).total_seconds() < 30]
        
        if len(scan_data["ports"]) > 15 or len(recent_scans) > 20:
            self.add_threat_indicator(src_ip, "PORT_SCAN", "HIGH", 
                                    f"Scanned {len(scan_data['ports'])} ports")
            self.suspicious_ips.add(src_ip)
    
    def detect_ddos_attempt(self, src_ip: str, packet_size: int):
        """Detect potential DDoS attacks"""
        current_time = datetime.now()
        self.ddos_detector[src_ip].append((current_time, packet_size))
        
        # Check for high packet rate in last 10 seconds
        recent_packets = [(t, s) for t, s in self.ddos_detector[src_ip] 
                         if (current_time - t).total_seconds() < 10]
        
        if len(recent_packets) > 100:  # More than 100 packets in 10 seconds
            total_bytes = sum(s for _, s in recent_packets)
            if total_bytes > 1024 * 1024:  # More than 1MB
                self.add_threat_indicator(src_ip, "DDOS_ATTEMPT", "CRITICAL", 
                                        f"{len(recent_packets)} packets, {total_bytes} bytes")
    
    def detect_suspicious_activity(self, packet_info: PacketInfo, payload: bytes):
        """Detect various suspicious activities"""
        # Check for data exfiltration patterns
        if packet_info.packet_size > 1400 and packet_info.protocol == "UDP":
            self.add_threat_indicator(packet_info.src_ip, "LARGE_UDP", "MEDIUM", 
                                    "Unusually large UDP packet")
        
        # Check for suspicious protocols on unusual ports
        if packet_info.dst_port and packet_info.dst_port > 49152:  # Dynamic ports
            if packet_info.protocol == "TCP" and "SYN" in packet_info.flags:
                self.add_threat_indicator(packet_info.src_ip, "HIGH_PORT_ACCESS", "LOW", 
                                        f"Access to high port {packet_info.dst_port}")
        
        # Detect potential DNS tunneling
        if packet_info.dst_port == 53 and len(payload) > 200:
            self.add_threat_indicator(packet_info.src_ip, "DNS_TUNNEL_SUSPECT", "MEDIUM", 
                                    "Large DNS request, possible DNS tunneling")
    
    def add_threat_indicator(self, ip: str, threat_type: str, severity: str, description: str):
        """Add or update threat indicator"""
        current_time = datetime.now()
        
        if ip in self.threat_indicators:
            indicator = self.threat_indicators[ip]
            indicator.last_seen = current_time
            indicator.count += 1
            if severity == "CRITICAL":
                indicator.severity = severity
        else:
            self.threat_indicators[ip] = ThreatIndicator(
                ip_address=ip,
                threat_type=threat_type,
                severity=severity,
                description=description,
                first_seen=current_time,
                last_seen=current_time
            )
        
        # Log threat
        logger.warning(f"THREAT DETECTED: {threat_type} from {ip} - {description}")
        
        # Store in database
        if self.db_conn:
            try:
                cursor = self.db_conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO threats 
                    (ip_address, threat_type, severity, description, first_seen, last_seen, count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (ip, threat_type, severity, description, 
                     current_time.isoformat(), current_time.isoformat(), 
                     self.threat_indicators[ip].count))
                self.db_conn.commit()
            except Exception as e:
                logger.error(f"Database insert failed: {e}")
    
    def parse_ethernet_header(self, packet: bytes) -> Tuple[bytes, str]:
        """Parse Ethernet header (Linux only)"""
        if len(packet) < 14:
            return packet, "UNKNOWN"
        
        eth_header = struct.unpack('!6s6sH', packet[:14])
        eth_protocol = socket.ntohs(eth_header[2])
        
        if eth_protocol == 8:  # IPv4
            return packet[14:], "IPv4"
        elif eth_protocol == 1544:  # ARP
            return packet[14:], "ARP"
        else:
            return packet[14:], f"ETH_{eth_protocol}"
    
    def parse_ip_header(self, packet: bytes) -> Tuple[Dict, bytes]:
        """Enhanced IPv4 header parsing"""
        if len(packet) < 20:
            return {}, packet
        
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        
        if version != 4:
            return {}, packet
        
        protocol = ip_header[6]
        src_addr = socket.inet_ntoa(ip_header[8])
        dst_addr = socket.inet_ntoa(ip_header[9])
        
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 
                       47: 'GRE', 50: 'ESP', 51: 'AH'}
        protocol_name = protocol_map.get(protocol, f'PROTO_{protocol}')
        
        return {
            'version': version,
            'header_length': iph_length,
            'ttl': ip_header[5],
            'protocol': protocol_name,
            'src_ip': src_addr,
            'dst_ip': dst_addr,
            'total_length': ip_header[2],
            'identification': ip_header[3],
            'flags': ip_header[4]
        }, packet[iph_length:]
    
    def parse_tcp_header(self, packet: bytes) -> Dict:
        """Enhanced TCP header parsing"""
        if len(packet) < 20:
            return {}
        
        tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
        
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        flags = tcp_header[5]
        window_size = tcp_header[6]
        
        # TCP flags
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        if flags & 0x40: flag_names.append('ECE')
        if flags & 0x80: flag_names.append('CWR')
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'flags': '|'.join(flag_names) if flag_names else 'NONE',
            'window_size': window_size
        }
    
    def parse_udp_header(self, packet: bytes) -> Dict:
        """Enhanced UDP header parsing"""
        if len(packet) < 8:
            return {}
        
        udp_header = struct.unpack('!HHHH', packet[:8])
        
        return {
            'src_port': udp_header[0],
            'dst_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3]
        }
    
    def update_enhanced_stats(self, packet_info: PacketInfo):
        """Update enhanced statistics"""
        current_time = time.time()
        
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += packet_info.packet_size
        self.protocol_stats[packet_info.protocol] += 1
        
        # Update threat level statistics
        threat_key = f"threat_{packet_info.threat_level.lower()}"
        self.stats[threat_key] += 1
        
        # Performance metrics
        if not hasattr(self, '_last_stats_update'):
            self._last_stats_update = current_time
            self._packets_in_interval = 0
            self._bytes_in_interval = 0
        
        self._packets_in_interval += 1
        self._bytes_in_interval += packet_info.packet_size
        
        # Update performance stats every second
        if current_time - self._last_stats_update >= 1.0:
            interval = current_time - self._last_stats_update
            self.performance_stats["packets_per_second"] = int(self._packets_in_interval / interval)
            self.performance_stats["bytes_per_second"] = int(self._bytes_in_interval / interval)
            
            # Add system performance metrics
            self.performance_stats["cpu_usage"] = psutil.cpu_percent()
            self.performance_stats["memory_usage"] = psutil.virtual_memory().percent
            
            self._last_stats_update = current_time
            self._packets_in_interval = 0
            self._bytes_in_interval = 0
        
        # Track connections
        conn_key = f"{packet_info.src_ip} -> {packet_info.dst_ip}"
        if packet_info.src_port and packet_info.dst_port:
            conn_key += f":{packet_info.src_port}-{packet_info.dst_port}"
        self.connection_tracker[conn_key] += 1
    
    def apply_enhanced_filters(self, packet_info: PacketInfo) -> bool:
        """Apply enhanced filters including threat level and payload content"""
        if self.filters['protocol'] and packet_info.protocol != self.filters['protocol']:
            return False
        
        if self.filters['src_ip'] and self.filters['src_ip'] not in packet_info.src_ip:
            return False
        
        if self.filters['dst_ip'] and self.filters['dst_ip'] not in packet_info.dst_ip:
            return False
        
        if self.filters['port']:
            if (packet_info.src_port != self.filters['port'] and 
                packet_info.dst_port != self.filters['port']):
                return False
        
        if self.filters['threat_level'] and packet_info.threat_level != self.filters['threat_level']:
            return False
        
        if self.filters['service'] and self.filters['service'] not in packet_info.service_name:
            return False
        
        if self.filters['payload_contains']:
            if self.filters['payload_contains'].lower() not in packet_info.payload_preview.lower():
                return False
        
        return True
    
    def capture_packets(self):
        """Enhanced packet capture loop with performance monitoring"""
        try:
            sock = self.create_socket()
            sock.settimeout(0.1)  # Reduced timeout for better responsiveness
            logger.info("Enhanced packet capture started with security monitoring")
            
            while self.is_capturing:
                try:
                    packet = sock.recv(65565)
                    if not packet:
                        continue
                    
                    packet_info = self.analyze_packet(packet)
                    
                    if packet_info and self.apply_enhanced_filters(packet_info):
                        try:
                            self.packet_queue.put_nowait(packet_info)
                            self.packets.append(packet_info)
                        except queue.Full:
                            # Drop oldest packets if queue is full
                            try:
                                self.packet_queue.get_nowait()
                                self.packet_queue.put_nowait(packet_info)
                                self.performance_stats["dropped_packets"] += 1
                            except queue.Empty:
                                pass
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_capturing:
                        logger.error(f"Packet capture error: {e}")
                        
        except Exception as e:
            logger.error(f"Capture initialization failed: {e}")
        finally:
            try:
                if os.name == 'nt':
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sock.close()
            except:
                pass
    
    def start_capture(self):
        """Start enhanced packet capture"""
        if not self.is_capturing:
            self.is_capturing = True
            self.start_time = datetime.now()
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            logger.info("Enhanced network analysis started")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=3.0)
        logger.info("Network analysis stopped")
    
    def export_enhanced_data(self, filename: str, format: str = 'csv', include_threats: bool = True):
        """Export enhanced data with threat intelligence"""
        try:
            if not self.packets:
                logger.warning("No packets to export")
                return False
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format.lower() == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=asdict(list(self.packets)[0]).keys())
                    writer.writeheader()
                    for packet in self.packets:
                        writer.writerow(asdict(packet))
                
                # Export threats separately
                if include_threats and self.threat_indicators:
                    threat_file = filename.replace('.csv', '_threats.csv')
                    with open(threat_file, 'w', newline='', encoding='utf-8') as f:
                        fieldnames = ['ip_address', 'threat_type', 'severity', 'description', 
                                    'first_seen', 'last_seen', 'count']
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        for threat in self.threat_indicators.values():
                            writer.writerow({
                                'ip_address': threat.ip_address,
                                'threat_type': threat.threat_type,
                                'severity': threat.severity,
                                'description': threat.description,
                                'first_seen': threat.first_seen.isoformat(),
                                'last_seen': threat.last_seen.isoformat(),
                                'count': threat.count
                            })
            
            elif format.lower() == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    data = {
                        'metadata': {
                            'analyzer_version': '3.0 Enterprise',
                            'capture_start': self.start_time.isoformat() if self.start_time else None,
                            'export_time': datetime.now().isoformat(),
                            'total_packets': len(self.packets),
                            'total_bytes': self.stats.get('total_bytes', 0),
                            'developer': 'Shirajam Munir Fahad',
                            'performance_stats': self.performance_stats
                        },
                        'statistics': {
                            'protocol_distribution': dict(self.protocol_stats),
                            'threat_levels': {
                                'critical': self.stats.get('threat_critical', 0),
                                'high': self.stats.get('threat_high', 0),
                                'medium': self.stats.get('threat_medium', 0),
                                'low': self.stats.get('threat_low', 0)
                            }
                        },
                        'packets': [asdict(packet) for packet in list(self.packets)],
                        'threat_indicators': {
                            ip: {
                                'threat_type': threat.threat_type,
                                'severity': threat.severity,
                                'description': threat.description,
                                'first_seen': threat.first_seen.isoformat(),
                                'last_seen': threat.last_seen.isoformat(),
                                'count': threat.count
                            } for ip, threat in self.threat_indicators.items()
                        } if include_threats else {}
                    }
                    json.dump(data, f, indent=2)
            
            logger.info(f"Enhanced data exported to {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

class ModernNetworkAnalyzerGUI:
    """Modern, professional GUI with dark theme and advanced features"""
    
    def __init__(self):
        self.analyzer = EnhancedNetworkAnalyzer()
        self.root = tk.Tk()
        self.setup_modern_theme()
        self.setup_window()
        self.setup_modern_ui()
        self.update_id = None
        
        # Performance monitoring
        self.last_update_time = time.time()
        self.ui_update_interval = 250  # milliseconds
        self.packet_store = {}  # packet_id: PacketInfo
        
    def setup_modern_theme(self):
        """Setup modern dark theme"""
        # Configure modern dark theme colors
        self.colors = {
            'bg_primary': '#121212',      # Deep dark background
            'bg_secondary': '#1f1f1f',    # Secondary dark
            'bg_tertiary': '#2d2d2d',     # Tertiary dark
            'fg_primary': '#ffffff',      # White text
            'fg_secondary': '#b0b0b0',    # Light gray text
            'accent_blue': '#2962ff',     # Modern blue
            'accent_green': '#00c853',    # Success green
            'accent_red': '#ff5252',      # Error red
            'accent_orange': '#ffab40',   # Warning orange
            'accent_purple': '#7c4dff',   # Purple accent
            'accent_cyan': '#18ffff',     # Cyan accent
            'border': '#424242'           # Border color
        }
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure modern styles
        style.configure('Modern.TFrame', 
                       background=self.colors['bg_primary'],
                       borderwidth=0)
        
        style.configure('Modern.TLabel', 
                       background=self.colors['bg_primary'],
                       foreground=self.colors['fg_primary'],
                       font=('Segoe UI', 9))
        
        style.configure('Modern.TButton',
                       background=self.colors['accent_blue'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 9, 'bold'),
                       padding=5)
        
        style.map('Modern.TButton',
                 background=[('active', '#0039cb')])
        
        style.configure('Modern.TEntry',
                       fieldbackground=self.colors['bg_tertiary'],
                       foreground=self.colors['fg_primary'],
                       bordercolor=self.colors['border'],
                       insertcolor=self.colors['fg_primary'],
                       padding=5)
        
        style.configure('Modern.Treeview',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['fg_primary'],
                       fieldbackground=self.colors['bg_secondary'],
                       borderwidth=0,
                       rowheight=25)
        
        style.configure('Modern.Treeview.Heading',
                       background=self.colors['bg_tertiary'],
                       foreground=self.colors['fg_primary'],
                       borderwidth=1,
                       relief='solid',
                       font=('Segoe UI', 9, 'bold'))
        
        style.configure('Modern.TCombobox',
                       fieldbackground=self.colors['bg_tertiary'],
                       foreground=self.colors['fg_primary'],
                       arrowcolor=self.colors['fg_primary'])
        
        style.configure('Modern.Vertical.TScrollbar',
                       background=self.colors['bg_tertiary'],
                       troughcolor=self.colors['bg_primary'])
        
        style.configure('Modern.Horizontal.TScrollbar',
                       background=self.colors['bg_tertiary'],
                       troughcolor=self.colors['bg_primary'])
    
    def setup_window(self):
        """Setup main window with modern styling"""
        self.root.title("🛡️ Advanced Network Security Analyzer - Enterprise Edition")
        self.root.geometry("1600x900")
        self.root.minsize(1200, 700)
        self.root.configure(bg=self.colors['bg_primary'])
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Set window icon (if available)
        try:
            # You can add an icon file here
            # self.root.iconbitmap('icon.ico')
            pass
        except:
            pass
    
    def setup_modern_ui(self):
        """Setup modern user interface"""
        # Header frame with branding
        self.create_header()
        
        # Main toolbar
        self.create_toolbar()
        
        # Status bar
        self.create_status_bar()
        
        # Main content area with tabs
        self.create_main_content()
        
        # Footer with developer info
        self.create_footer()
    
    def create_header(self):
        """Create modern header with branding"""
        header_frame = tk.Frame(self.root, bg=self.colors['bg_tertiary'], height=70)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Logo and title
        title_frame = tk.Frame(header_frame, bg=self.colors['bg_tertiary'])
        title_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        title_label = tk.Label(title_frame, 
                              text="🛡️ NETWORK SECURITY ANALYZER",
                              font=('Segoe UI', 18, 'bold'),
                              bg=self.colors['bg_tertiary'],
                              fg=self.colors['accent_cyan'])
        title_label.pack(side=tk.LEFT, padx=5)
        
        version_label = tk.Label(title_frame,
                                text="v3.0 Enterprise",
                                font=('Segoe UI', 10),
                                bg=self.colors['bg_tertiary'],
                                fg=self.colors['fg_secondary'])
        version_label.pack(side=tk.LEFT, padx=10, pady=8)
        
        # Real-time clock and performance
        stats_frame = tk.Frame(header_frame, bg=self.colors['bg_tertiary'])
        stats_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        self.clock_label = tk.Label(stats_frame,
                                   font=('Segoe UI', 10, 'bold'),
                                   bg=self.colors['bg_tertiary'],
                                   fg=self.colors['accent_green'])
        self.clock_label.pack(side=tk.TOP, padx=5)
        
        self.cpu_label = tk.Label(stats_frame,
                                 text="CPU: 0%",
                                 font=('Segoe UI', 9),
                                 bg=self.colors['bg_tertiary'],
                                 fg=self.colors['fg_secondary'])
        self.cpu_label.pack(side=tk.RIGHT, padx=5)
        
        self.mem_label = tk.Label(stats_frame,
                                 text="MEM: 0%",
                                 font=('Segoe UI', 9),
                                 bg=self.colors['bg_tertiary'],
                                 fg=self.colors['fg_secondary'])
        self.mem_label.pack(side=tk.RIGHT, padx=5)
        
        self.update_clock()
    
    def create_toolbar(self):
        """Create modern toolbar with professional controls"""
        toolbar_frame = tk.Frame(self.root, bg=self.colors['bg_secondary'], height=50)
        toolbar_frame.pack(fill=tk.X, padx=0, pady=0)
        toolbar_frame.pack_propagate(False)
        
        # Control buttons
        btn_frame = tk.Frame(toolbar_frame, bg=self.colors['bg_secondary'])
        btn_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.start_btn = tk.Button(btn_frame, text="▶ START CAPTURE",
                                  font=('Segoe UI', 10, 'bold'),
                                  bg=self.colors['accent_green'],
                                  fg='white',
                                  activebackground='#009624',
                                  border=0,
                                  padx=20,
                                  pady=5,
                                  command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹ STOP",
                                 font=('Segoe UI', 10, 'bold'),
                                 bg=self.colors['accent_red'],
                                 fg='white',
                                 activebackground='#c50e29',
                                 border=0,
                                 padx=20,
                                 pady=5,
                                 state=tk.DISABLED,
                                 command=self.stop_capture)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🗑 CLEAR",
                 font=('Segoe UI', 10, 'bold'),
                 bg=self.colors['accent_orange'],
                 fg='white',
                 activebackground='#c67c00',
                 border=0,
                 padx=15,
                 pady=5,
                 command=self.clear_data).pack(side=tk.LEFT, padx=5)
        
        # Export buttons
        export_frame = tk.Frame(toolbar_frame, bg=self.colors['bg_secondary'])
        export_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        tk.Button(export_frame, text="📊 EXPORT CSV",
                 font=('Segoe UI', 9, 'bold'),
                 bg=self.colors['accent_blue'],
                 fg='white',
                 border=0,
                 padx=15,
                 pady=3,
                 command=self.export_csv).pack(side=tk.RIGHT, padx=2)
        
        tk.Button(export_frame, text="📋 EXPORT JSON",
                 font=('Segoe UI', 9, 'bold'),
                 bg=self.colors['accent_purple'],
                 fg='white',
                 border=0,
                 padx=15,
                 pady=3,
                 command=self.export_json).pack(side=tk.RIGHT, padx=2)
    
    def create_status_bar(self):
        """Create professional status bar"""
        status_frame = tk.Frame(self.root, bg=self.colors['bg_tertiary'], height=30)
        status_frame.pack(fill=tk.X, padx=0, pady=0)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame,
                                    text="🟢 Ready - Waiting for capture to start",
                                    font=('Segoe UI', 10),
                                    bg=self.colors['bg_tertiary'],
                                    fg=self.colors['accent_green'])
        self.status_label.pack(side=tk.LEFT, padx=20, pady=5)
        
        # Performance indicators
        self.perf_label = tk.Label(status_frame,
                                  text="Performance: 0 pps | 0 Bps | Drops: 0",
                                  font=('Segoe UI', 9),
                                  bg=self.colors['bg_tertiary'],
                                  fg=self.colors['fg_secondary'])
        self.perf_label.pack(side=tk.RIGHT, padx=20, pady=5)
    
    def create_main_content(self):
        """Create main content area with modern tabs"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root, style='Modern.TFrame')
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Packet Monitor Tab
        self.create_packet_monitor_tab(notebook)
        
        # Security Dashboard Tab
        self.create_security_dashboard_tab(notebook)
        
        # Analytics Tab
        self.create_analytics_tab(notebook)
        
        # Settings Tab
        self.create_settings_tab(notebook)
    
    def create_packet_monitor_tab(self, parent):
        """Create packet monitoring tab"""
        packet_frame = ttk.Frame(parent, style='Modern.TFrame')
        parent.add(packet_frame, text='📡 Live Packets')
        
        # Filters section
        filters_frame = tk.LabelFrame(packet_frame,
                                     text="🔍 Advanced Filters",
                                     font=('Segoe UI', 10, 'bold'),
                                     bg=self.colors['bg_primary'],
                                     fg=self.colors['fg_primary'],
                                     bd=1,
                                     relief='solid')
        filters_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Filter controls in grid
        filter_grid = tk.Frame(filters_frame, bg=self.colors['bg_primary'])
        filter_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Protocol filter
        tk.Label(filter_grid, text="Protocol:",
                font=('Segoe UI', 9),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).grid(row=0, column=0, padx=5, sticky='w')
        
        self.protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(filter_grid, textvariable=self.protocol_var,
                                     values=['', 'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'HTTPS'],
                                     style='Modern.TCombobox',
                                     width=10)
        protocol_combo.grid(row=0, column=1, padx=5)
        protocol_combo.bind('<<ComboboxSelected>>', self.update_filters)
        
        # Service filter
        tk.Label(filter_grid, text="Service:",
                font=('Segoe UI', 9),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).grid(row=0, column=2, padx=5, sticky='w')
        
        self.service_var = tk.StringVar()
        service_combo = ttk.Combobox(filter_grid, textvariable=self.service_var,
                                     values=['', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'RDP', 'SMTP', 'FTP'],
                                     style='Modern.TCombobox',
                                     width=10)
        service_combo.grid(row=0, column=3, padx=5)
        service_combo.bind('<<ComboboxSelected>>', self.update_filters)
        
        # IP filters
        tk.Label(filter_grid, text="Source IP:",
                font=('Segoe UI', 9),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        
        self.src_ip_var = tk.StringVar()
        src_ip_entry = tk.Entry(filter_grid, textvariable=self.src_ip_var,
                               bg=self.colors['bg_tertiary'],
                               fg=self.colors['fg_primary'],
                               insertbackground=self.colors['fg_primary'],
                               width=15)
        src_ip_entry.grid(row=1, column=1, padx=5, pady=5)
        src_ip_entry.bind('<KeyRelease>', self.update_filters)
        
        tk.Label(filter_grid, text="Dest IP:",
                font=('Segoe UI', 9),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).grid(row=1, column=2, padx=5, pady=5, sticky='w')
        
        self.dst_ip_var = tk.StringVar()
        dst_ip_entry = tk.Entry(filter_grid, textvariable=self.dst_ip_var,
                               bg=self.colors['bg_tertiary'],
                               fg=self.colors['fg_primary'],
                               insertbackground=self.colors['fg_primary'],
                               width=15)
        dst_ip_entry.grid(row=1, column=3, padx=5, pady=5)
        dst_ip_entry.bind('<KeyRelease>', self.update_filters)
        
        # Port and threat level filters
        tk.Label(filter_grid, text="Port:",
                font=('Segoe UI', 9),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).grid(row=2, column=0, padx=5, pady=5, sticky='w')
        
        self.port_var = tk.StringVar()
        port_entry = tk.Entry(filter_grid, textvariable=self.port_var,
                             bg=self.colors['bg_tertiary'],
                             fg=self.colors['fg_primary'],
                             insertbackground=self.colors['fg_primary'],
                             width=10)
        port_entry.grid(row=2, column=1, padx=5, pady=5)
        port_entry.bind('<KeyRelease>', self.update_filters)
        
        tk.Label(filter_grid, text="Threat Level:",
                font=('Segoe UI', 9),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).grid(row=2, column=2, padx=5, pady=5, sticky='w')
        
        self.threat_var = tk.StringVar()
        threat_combo = ttk.Combobox(filter_grid, textvariable=self.threat_var,
                                   values=['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                                   style='Modern.TCombobox',
                                   width=10)
        threat_combo.grid(row=2, column=3, padx=5, pady=5)
        threat_combo.bind('<<ComboboxSelected>>', self.update_filters)
        
        # Packet display
        packet_display_frame = tk.Frame(packet_frame, bg=self.colors['bg_primary'])
        packet_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Enhanced packet treeview
        columns = ('Time', 'Source', 'Destination', 'Protocol', 'Service', 
                  'Src Port', 'Dst Port', 'Size', 'Threat', 'Location', 'ASN', 'Info')
        
        self.packet_tree = ttk.Treeview(packet_display_frame, columns=columns,
                                       show='headings', style='Modern.Treeview',
                                       selectmode='browse')
        
        # Configure columns
        column_widths = {
            'Time': 120, 'Source': 150, 'Destination': 150, 'Protocol': 80,
            'Service': 100, 'Src Port': 80, 'Dst Port': 80, 'Size': 60,
            'Threat': 80, 'Location': 120, 'ASN': 80, 'Info': 250
        }
        
        for col in columns:
            self.packet_tree.heading(col, text=col, anchor='w')
            self.packet_tree.column(col, width=column_widths.get(col, 100), anchor='w')
        
        # Add threat level color coding
        self.packet_tree.tag_configure('CRITICAL', background='#b71c1c', foreground='white')
        self.packet_tree.tag_configure('HIGH', background='#ff5722', foreground='white')
        self.packet_tree.tag_configure('MEDIUM', background='#ff9800', foreground='black')
        self.packet_tree.tag_configure('LOW', background=self.colors['bg_secondary'])
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(packet_display_frame, orient=tk.VERTICAL,
                                command=self.packet_tree.yview,
                                style='Modern.Vertical.TScrollbar')
        h_scroll = ttk.Scrollbar(packet_display_frame, orient=tk.HORIZONTAL,
                                command=self.packet_tree.xview,
                                style='Modern.Horizontal.TScrollbar')
        
        self.packet_tree.configure(yscrollcommand=v_scroll.set,
                                  xscrollcommand=h_scroll.set)
        
        # Grid layout for treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        packet_display_frame.grid_rowconfigure(0, weight=1)
        packet_display_frame.grid_columnconfigure(0, weight=1)
        
        # Bind selection event
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Packet details panel
        details_frame = tk.LabelFrame(packet_frame,
                                     text="📄 Packet Details",
                                     font=('Segoe UI', 10, 'bold'),
                                     bg=self.colors['bg_primary'],
                                     fg=self.colors['fg_primary'])
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame,
                                                     bg=self.colors['bg_secondary'],
                                                     fg=self.colors['fg_primary'],
                                                     font=('Consolas', 9),
                                                     height=8)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.insert(tk.END, "Select a packet to view details")
        self.details_text.configure(state='disabled')
    
    def create_security_dashboard_tab(self, parent):
        """Create security monitoring dashboard"""
        security_frame = ttk.Frame(parent, style='Modern.TFrame')
        parent.add(security_frame, text='🛡️ Security Dashboard')
        
        # Top metrics row
        metrics_frame = tk.Frame(security_frame, bg=self.colors['bg_primary'])
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Metric cards
        self.create_metric_card(metrics_frame, "🚨 Critical Threats", "0", '#b71c1c')
        self.create_metric_card(metrics_frame, "⚠️ High Threats", "0", '#ff5722')
        self.create_metric_card(metrics_frame, "📊 Total Packets", "0", '#2962ff')
        self.create_metric_card(metrics_frame, "🔍 Port Scans", "0", '#7c4dff')
        self.create_metric_card(metrics_frame, "💥 DDoS Attempts", "0", '#ff5252')
        
        # Main dashboard content
        dashboard_content = tk.Frame(security_frame, bg=self.colors['bg_primary'])
        dashboard_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Threat indicators panel
        threats_frame = tk.LabelFrame(dashboard_content,
                                     text="🚨 Active Threat Indicators",
                                     font=('Segoe UI', 10, 'bold'),
                                     bg=self.colors['bg_primary'],
                                     fg=self.colors['fg_primary'])
        threats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        columns = ('IP', 'Type', 'Severity', 'Count', 'Last Seen', 'Description')
        self.threats_tree = ttk.Treeview(threats_frame,
                                        columns=columns,
                                        show='headings',
                                        style='Modern.Treeview')
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=120)
        
        self.threats_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Activity log panel
        log_frame = tk.LabelFrame(dashboard_content,
                                 text="📋 Security Activity Log",
                                 font=('Segoe UI', 10, 'bold'),
                                 bg=self.colors['bg_primary'],
                                 fg=self.colors['fg_primary'])
        log_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.security_log = scrolledtext.ScrolledText(log_frame,
                                                     bg=self.colors['bg_secondary'],
                                                     fg=self.colors['fg_primary'],
                                                     font=('Consolas', 9))
        self.security_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_metric_card(self, parent, title, value, color):
        """Create metric display card"""
        card = tk.Frame(parent, bg=color, relief='solid', bd=1)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        title_label = tk.Label(card, text=title, font=('Segoe UI', 10, 'bold'),
                              bg=color, fg='white')
        title_label.pack(pady=(10, 5))
        
        value_label = tk.Label(card, text=value, font=('Segoe UI', 20, 'bold'),
                              bg=color, fg='white')
        value_label.pack(pady=(0, 10))
        
        # Store reference for updates
        if not hasattr(self, 'metric_labels'):
            self.metric_labels = {}
        self.metric_labels[title] = value_label
    
    def create_analytics_tab(self, parent):
        """Create analytics and statistics tab"""
        analytics_frame = ttk.Frame(parent, style='Modern.TFrame')
        parent.add(analytics_frame, text='📊 Analytics')
        
        # Statistics display
        stats_content = tk.Frame(analytics_frame, bg=self.colors['bg_primary'])
        stats_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Protocol statistics
        protocol_frame = tk.LabelFrame(stats_content,
                                      text="📈 Protocol Distribution",
                                      font=('Segoe UI', 10, 'bold'),
                                      bg=self.colors['bg_primary'],
                                      fg=self.colors['fg_primary'])
        protocol_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.protocol_stats_text = scrolledtext.ScrolledText(protocol_frame,
                                                            bg=self.colors['bg_secondary'],
                                                            fg=self.colors['fg_primary'],
                                                            font=('Consolas', 10))
        self.protocol_stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Connection statistics
        conn_frame = tk.LabelFrame(stats_content,
                                  text="🔗 Top Connections",
                                  font=('Segoe UI', 10, 'bold'),
                                  bg=self.colors['bg_primary'],
                                  fg=self.colors['fg_primary'])
        conn_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.connection_stats_text = scrolledtext.ScrolledText(conn_frame,
                                                              bg=self.colors['bg_secondary'],
                                                              fg=self.colors['fg_primary'],
                                                              font=('Consolas', 10))
        self.connection_stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_settings_tab(self, parent):
        """Create settings and configuration tab"""
        settings_frame = ttk.Frame(parent, style='Modern.TFrame')
        parent.add(settings_frame, text='⚙️ Settings')
        
        # Settings content
        settings_content = tk.Frame(settings_frame, bg=self.colors['bg_primary'])
        settings_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Capture settings
        capture_frame = tk.LabelFrame(settings_content,
                                     text="🎯 Capture Settings",
                                     font=('Segoe UI', 12, 'bold'),
                                     bg=self.colors['bg_primary'],
                                     fg=self.colors['fg_primary'])
        capture_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Buffer size setting
        tk.Label(capture_frame, text="Buffer Size (packets):",
                font=('Segoe UI', 10),
                bg=self.colors['bg_primary'],
                fg=self.colors['fg_primary']).pack(anchor='w', padx=10, pady=5)
        
        self.buffer_size_var = tk.StringVar(value="50000")
        tk.Entry(capture_frame, textvariable=self.buffer_size_var,
                bg=self.colors['bg_tertiary'],
                fg=self.colors['fg_primary'],
                width=20).pack(anchor='w', padx=10, pady=5)
        
        # About section
        about_frame = tk.LabelFrame(settings_content,
                                   text="ℹ️ About",
                                   font=('Segoe UI', 12, 'bold'),
                                   bg=self.colors['bg_primary'],
                                   fg=self.colors['fg_primary'])
        about_frame.pack(fill=tk.X, pady=(20, 0))
        
        about_text = """
Advanced Network Security Analyzer - Enterprise Edition v3.0

🔒 Professional-grade network packet analysis and security monitoring
📊 Real-time threat detection and analysis
🛡️ Advanced security dashboard with threat intelligence
📈 Comprehensive analytics and reporting

All Rights Reserved.
Developed by: Shirajam Munir Fahad
Licensed for educational and professional use.

Features:
• Real-time packet capture and analysis
• Advanced threat detection algorithms
• Port scan and DDoS detection
• Malware signature detection
• Geolocation and ASN tracking
• Professional reporting
• SQLite database storage
        """
        
        about_label = tk.Label(about_frame, text=about_text,
                              font=('Segoe UI', 9),
                              bg=self.colors['bg_primary'],
                              fg=self.colors['fg_primary'],
                              justify=tk.LEFT)
        about_label.pack(padx=20, pady=20)
    
    def create_footer(self):
        """Create footer with developer information"""
        footer_frame = tk.Frame(self.root, bg=self.colors['bg_tertiary'], height=25)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        footer_frame.pack_propagate(False)
        
        footer_text = "© 2024 Advanced Network Security Analyzer - All Rights Reserved | Developed by Shirajam Munir Fahad"
        footer_label = tk.Label(footer_frame, text=footer_text,
                               font=('Segoe UI', 8),
                               bg=self.colors['bg_tertiary'],
                               fg=self.colors['fg_secondary'])
        footer_label.pack(pady=5)
    
    def update_clock(self):
        """Update real-time clock and system stats"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.clock_label.config(text=current_time)
        
        # Update system stats
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.cpu_label.config(text=f"CPU: {cpu}%")
        self.mem_label.config(text=f"MEM: {mem}%")
        
        self.root.after(1000, self.update_clock)
    
    def on_close(self):
        """Handle window close event"""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?\nThis will stop packet capture."):
            self.analyzer.stop_capture()
            if self.update_id:
                self.root.after_cancel(self.update_id)
            self.root.destroy()
    
    def update_filters(self, event=None):
        """Update analyzer filters based on GUI input"""
        try:
            self.analyzer.filters['protocol'] = self.protocol_var.get() or None
            self.analyzer.filters['src_ip'] = self.src_ip_var.get() or None
            self.analyzer.filters['dst_ip'] = self.dst_ip_var.get() or None
            self.analyzer.filters['threat_level'] = self.threat_var.get() or None
            self.analyzer.filters['service'] = self.service_var.get() or None
            
            port_text = self.port_var.get()
            self.analyzer.filters['port'] = int(port_text) if port_text.isdigit() else None
        except ValueError:
            pass
    
    def start_capture(self):
        """Start packet capture with modern UI updates"""
        try:
            self.analyzer.start_capture()
            self.start_btn.config(state=tk.DISABLED, bg=self.colors['bg_secondary'])
            self.stop_btn.config(state=tk.NORMAL, bg=self.colors['accent_red'])
            self.status_label.config(text="🔴 Live Capture Active - Monitoring network traffic",
                                   fg=self.colors['accent_red'])
            
            # Start UI updates
            self.schedule_ui_update()
            
        except Exception as e:
            messagebox.showerror("Capture Error", 
                               f"Failed to start packet capture:\n{str(e)}\n\nEnsure you're running as administrator.")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.analyzer.stop_capture()
        self.start_btn.config(state=tk.NORMAL, bg=self.colors['accent_green'])
        self.stop_btn.config(state=tk.DISABLED, bg=self.colors['bg_secondary'])
        self.status_label.config(text="🟡 Capture Stopped - Ready to analyze data",
                               fg=self.colors['accent_orange'])
        
        # Cancel UI updates
        if self.update_id:
            self.root.after_cancel(self.update_id)
            self.update_id = None
    
    def schedule_ui_update(self):
        """Schedule periodic UI updates for better performance"""
        self.update_display()
        if self.analyzer.is_capturing:
            self.update_id = self.root.after(self.ui_update_interval, self.schedule_ui_update)
    
    def update_display(self):
        """Enhanced display update with performance optimization"""
        try:
            current_time = time.time()
            
            # Limit update frequency for better performance
            if current_time - self.last_update_time < 0.1:  # Max 10 updates per second
                return
            
            packets_processed = 0
            max_packets_per_update = 25  # Process max 25 packets per update
            
            # Process queued packets
            while not self.analyzer.packet_queue.empty() and packets_processed < max_packets_per_update:
                try:
                    packet = self.analyzer.packet_queue.get_nowait()
                    
                    # Add to packet display
                    values = (
                        packet.timestamp,
                        packet.src_ip,
                        packet.dst_ip,
                        packet.protocol,
                        packet.service_name,
                        packet.src_port or '',
                        packet.dst_port or '',
                        packet.packet_size,
                        packet.threat_level,
                        packet.geo_location,
                        packet.asn,
                        packet.payload_preview
                    )
                    
                    # Store packet for details view
                    self.packet_store[packet.packet_id] = packet
                    
                    # Insert with threat level color coding
                    item_id = self.packet_tree.insert('', tk.END, values=values,
                                                     tags=(packet.threat_level, packet.packet_id))
                    packets_processed += 1
                    
                except queue.Empty:
                    break
            
            # Auto-scroll to show latest packets
            if packets_processed > 0:
                children = self.packet_tree.get_children()
                if children:
                    self.packet_tree.see(children[-1])
                    
                    # Limit displayed packets for performance
                    if len(children) > 1000:
                        for item in children[:100]:  # Remove oldest 100 items
                            self.packet_tree.delete(item)
            
            # Update all displays
            self.update_metrics()
            self.update_security_dashboard()
            self.update_analytics()
            self.update_performance_indicators()
            
            self.last_update_time = current_time
            
        except Exception as e:
            logger.error(f"Display update error: {e}")
    
    def on_packet_select(self, event):
        """Handle packet selection event"""
        selected = self.packet_tree.selection()
        if selected:
            item = selected[0]
            tags = self.packet_tree.item(item, 'tags')
            if len(tags) > 1:
                packet_id = tags[1]
                packet = self.packet_store.get(packet_id)
                if packet:
                    self.display_packet_details(packet)
    
    def display_packet_details(self, packet: PacketInfo):
        """Display detailed packet information"""
        details = f"""
        ⏱️ Timestamp: {packet.timestamp}
        🌐 Protocol: {packet.protocol}
        🛡️ Threat Level: {packet.threat_level}
        
        🔹 Source:
          IP: {packet.src_ip}
          Port: {packet.src_port or 'N/A'}
          Location: {packet.geo_location}
          ASN: {packet.asn}
        
        🔹 Destination:
          IP: {packet.dst_ip}
          Port: {packet.dst_port or 'N/A'}
          Service: {packet.service_name}
        
        🔹 Packet Info:
          Size: {packet.packet_size} bytes
          TTL: {packet.ttl}
          Flags: {packet.flags or 'N/A'}
        
        🔹 Payload Preview:
        {packet.payload_preview}
        """
        
        self.details_text.configure(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.configure(state='disabled')
    
    def update_metrics(self):
        """Update metric cards"""
        if hasattr(self, 'metric_labels'):
            # Critical threats
            critical_count = self.analyzer.stats.get('threat_critical', 0)
            if '🚨 Critical Threats' in self.metric_labels:
                self.metric_labels['🚨 Critical Threats'].config(text=str(critical_count))
            
            # High threats
            high_count = self.analyzer.stats.get('threat_high', 0)
            if '⚠️ High Threats' in self.metric_labels:
                self.metric_labels['⚠️ High Threats'].config(text=str(high_count))
            
            # Total packets
            total_packets = self.analyzer.stats.get('total_packets', 0)
            if '📊 Total Packets' in self.metric_labels:
                self.metric_labels['📊 Total Packets'].config(text=f"{total_packets:,}")
            
            # Port scans
            port_scan_count = len(self.analyzer.suspicious_ips)
            if '🔍 Port Scans' in self.metric_labels:
                self.metric_labels['🔍 Port Scans'].config(text=str(port_scan_count))
            
            # DDoS attempts
            ddos_count = sum(1 for t in self.analyzer.threat_indicators.values() 
                            if t.threat_type == "DDOS_ATTEMPT")
            if '💥 DDoS Attempts' in self.metric_labels:
                self.metric_labels['💥 DDoS Attempts'].config(text=str(ddos_count))
    
    def update_security_dashboard(self):
        """Update security dashboard with threat information"""
        try:
            # Clear current items
            for item in self.threats_tree.get_children():
                self.threats_tree.delete(item)
            
            # Add threat indicators
            for ip, threat in list(self.analyzer.threat_indicators.items())[-20:]:  # Show latest 20
                values = (
                    ip,
                    threat.threat_type,
                    threat.severity,
                    threat.count,
                    threat.last_seen.strftime('%H:%M:%S'),
                    threat.description[:50] + "..." if len(threat.description) > 50 else threat.description
                )
                self.threats_tree.insert('', tk.END, values=values)
            
            # Update security log
            self.update_security_log()
            
        except Exception as e:
            logger.error(f"Security dashboard update error: {e}")
    
    def update_security_log(self):
        """Update security activity log"""
        try:
            # Get recent log entries
            log_entries = []
            
            # Add threat indicators to log
            for ip, threat in list(self.analyzer.threat_indicators.items())[-10:]:
                timestamp = threat.last_seen.strftime('%H:%M:%S')
                log_entry = f"[{timestamp}] {threat.severity} - {threat.threat_type} from {ip}\n"
                log_entries.append(log_entry)
            
            # Add suspicious activity
            if self.analyzer.suspicious_ips:
                for ip in list(self.analyzer.suspicious_ips)[-5:]:
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    log_entries.append(f"[{timestamp}] SUSPICIOUS - Port scanning activity from {ip}\n")
            
            # Update log display
            if log_entries:
                current_content = self.security_log.get(1.0, tk.END)
                new_content = ''.join(log_entries[-20:])  # Show last 20 entries
                
                if new_content != current_content:
                    self.security_log.delete(1.0, tk.END)
                    self.security_log.insert(tk.END, new_content)
                    self.security_log.see(tk.END)
            
        except Exception as e:
            logger.error(f"Security log update error: {e}")
    
    def update_analytics(self):
        """Update analytics displays"""
        try:
            # Protocol statistics
            protocol_stats = self.analyzer.protocol_stats
            total_packets = max(self.analyzer.stats.get('total_packets', 1), 1)
            
            protocol_text = "Protocol Distribution:\n" + "="*50 + "\n"
            for protocol, count in protocol_stats.most_common(10):
                percentage = (count / total_packets) * 100
                bar = "█" * min(int(percentage / 2), 25)
                protocol_text += f"{protocol:<8} {count:>6} ({percentage:>5.1f}%) {bar}\n"
            
            # Add total statistics
            protocol_text += "\n" + "="*50 + "\n"
            protocol_text += f"Total Packets: {total_packets:,}\n"
            protocol_text += f"Total Bytes: {self.analyzer.stats.get('total_bytes', 0):,}\n"
            
            if self.analyzer.start_time:
                duration = datetime.now() - self.analyzer.start_time
                protocol_text += f"Duration: {str(duration).split('.')[0]}\n"
            
            self.protocol_stats_text.delete(1.0, tk.END)
            self.protocol_stats_text.insert(1.0, protocol_text)
            
            # Connection statistics
            conn_stats = self.analyzer.connection_tracker
            conn_text = "Top Connections:\n" + "="*50 + "\n"
            
            for conn, count in Counter(conn_stats).most_common(15):
                conn_text += f"{conn:<45} {count:>6}\n"
            
            self.connection_stats_text.delete(1.0, tk.END)
            self.connection_stats_text.insert(1.0, conn_text)
            
        except Exception as e:
            logger.error(f"Analytics update error: {e}")
    
    def update_performance_indicators(self):
        """Update performance indicators"""
        try:
            perf_stats = self.analyzer.performance_stats
            perf_text = (f"Performance: {perf_stats['packets_per_second']} pps | "
                        f"{perf_stats['bytes_per_second']:,} Bps | "
                        f"Drops: {perf_stats['dropped_packets']}")
            
            self.perf_label.config(text=perf_text)
            
        except Exception as e:
            logger.error(f"Performance indicator update error: {e}")
    
    def clear_data(self):
        """Clear all captured data with confirmation"""
        if messagebox.askyesno("Clear Data", "Are you sure you want to clear all captured data?"):
            # Clear analyzer data
            self.analyzer.packets.clear()
            self.analyzer.stats.clear()
            self.analyzer.protocol_stats.clear()
            self.analyzer.suspicious_ips.clear()
            self.analyzer.port_scan_tracker.clear()
            self.analyzer.connection_tracker.clear()
            self.analyzer.threat_indicators.clear()
            self.packet_store.clear()
            
            # Clear GUI displays
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            
            for item in self.threats_tree.get_children():
                self.threats_tree.delete(item)
            
            self.security_log.delete(1.0, tk.END)
            self.protocol_stats_text.delete(1.0, tk.END)
            self.connection_stats_text.delete(1.0, tk.END)
            
            self.details_text.configure(state='normal')
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, "Select a packet to view details")
            self.details_text.configure(state='disabled')
            
            # Reset metrics
            if hasattr(self, 'metric_labels'):
                for label in self.metric_labels.values():
                    label.config(text="0")
            
            self.status_label.config(text="🟢 Data Cleared - Ready for new capture",
                                   fg=self.colors['accent_green'])
    
    def export_csv(self):
        """Export data to CSV with enhanced features"""
        if not self.analyzer.packets:
            messagebox.showinfo("Export Info", "No packets captured to export")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"network_analysis_{timestamp}.csv"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialname=default_filename,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Packet Data to CSV"
        )
        
        if filename:
            try:
                if self.analyzer.export_enhanced_data(filename, 'csv', include_threats=True):
                    messagebox.showinfo("Export Success", 
                                      f"Data successfully exported to:\n{filename}\n\n"
                                      f"Packets exported: {len(self.analyzer.packets)}\n"
                                      f"Threats exported: {len(self.analyzer.threat_indicators)}")
                else:
                    messagebox.showerror("Export Error", "Failed to export data")
            except Exception as e:
                messagebox.showerror("Export Error", f"Export failed:\n{str(e)}")
    
    def export_json(self):
        """Export data to JSON with enhanced features"""
        if not self.analyzer.packets:
            messagebox.showinfo("Export Info", "No packets captured to export")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"network_analysis_{timestamp}.json"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialname=default_filename,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Analysis Data to JSON"
        )
        
        if filename:
            try:
                if self.analyzer.export_enhanced_data(filename, 'json', include_threats=True):
                    messagebox.showinfo("Export Success", 
                                      f"Complete analysis exported to:\n{filename}\n\n"
                                      f"Includes:\n"
                                      f"• {len(self.analyzer.packets)} packets\n"
                                      f"• {len(self.analyzer.threat_indicators)} threat indicators\n"
                                      f"• Performance statistics\n"
                                      f"• Protocol analysis")
                else:
                    messagebox.showerror("Export Error", "Failed to export data")
            except Exception as e:
                messagebox.showerror("Export Error", f"Export failed:\n{str(e)}")
    
    def run(self):
        """Start the modern GUI application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_close()

def check_requirements():
    """Check system requirements and permissions"""
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher required")
        return False
    
    # Check admin privileges
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("❌ Error: Administrator privileges required on Windows")
                print("💡 Solution: Run as administrator (Right-click → Run as administrator)")
                return False
        except ImportError:
            print("⚠️  Warning: Cannot check admin privileges")
    else:  # Linux/Unix
        if os.geteuid() != 0:
            print("❌ Error: Root privileges required on Unix systems")
            print("💡 Solution: Run with sudo (sudo python network_analyzer.py)")
            return False
    
    print("✅ System requirements check passed")
    return True

def create_desktop_shortcut():
    """Create desktop shortcut (Windows only)"""
    if os.name == 'nt':
        try:
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            path = os.path.join(desktop, "Network Security Analyzer.lnk")
            target = sys.executable
            wDir = os.path.dirname(os.path.abspath(__file__))
            icon = sys.executable
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(path)
            shortcut.Targetpath = target
            shortcut.Arguments = f'"{os.path.abspath(__file__)}"'
            shortcut.WorkingDirectory = wDir
            shortcut.IconLocation = icon
            shortcut.save()
            
            print(f"✅ Desktop shortcut created: {path}")
        except ImportError:
            print("⚠️  Could not create desktop shortcut (winshell not available)")
        except Exception as e:
            print(f"⚠️  Could not create desktop shortcut: {e}")

def main():
    """Enhanced main entry point with better error handling"""
    print("🛡️  Advanced Network Security Analyzer - Enterprise Edition v3.0")
    print("="*60)
    print("All Rights Reserved. Developed by Shirajam Munir Fahad")
    print("="*60)
    
    parser = argparse.ArgumentParser(
        description='Advanced Network Security Analyzer - Enterprise Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_analyzer.py                    # Run GUI mode
  python network_analyzer.py --cli              # Run CLI mode
  python network_analyzer.py --cli -o data.json # CLI with JSON export
  python network_analyzer.py --create-shortcut  # Create desktop shortcut

Security Features:
  • Real-time threat detection and analysis
  • Advanced port scan detection
  • DDoS attack detection
  • Malware signature detection
  • Geolocation and ASN tracking
  • Professional security reporting
        """)
    
    parser.add_argument('--cli', action='store_true', 
                       help='Run in CLI mode (no GUI)')
    parser.add_argument('--interface', '-i', 
                       help='Network interface to monitor')
    parser.add_argument('--filter', '-f', 
                       help='Capture filter expression')
    parser.add_argument('--output', '-o', 
                       help='Output file for analysis data')
    parser.add_argument('--create-shortcut', action='store_true',
                       help='Create desktop shortcut (Windows only)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        print("🔍 Verbose logging enabled")
    
    # Create desktop shortcut
    if args.create_shortcut:
        create_desktop_shortcut()
        return
    
    # Check system requirements
    if not check_requirements():
        input("Press Enter to exit...")
        sys.exit(1)
    
    try:
        if args.cli:
            # CLI mode
            print("\n🖥️  Starting Network Analyzer in CLI mode...")
            analyzer = EnhancedNetworkAnalyzer()
            
            print("📡 Initializing packet capture...")
            analyzer.start_capture()
            print("✅ Packet capture started successfully")
            print("⏹️  Press Ctrl+C to stop capture\n")
            
            # Display periodic updates
            last_update = time.time()
            try:
                while True:
                    time.sleep(1)
                    
                    # Update stats every 5 seconds
                    if time.time() - last_update > 5:
                        stats = analyzer.stats
                        perf = analyzer.performance_stats
                        threats = len(analyzer.threat_indicators)
                        
                        print(f"📊 Packets: {stats.get('total_packets', 0):,} | "
                              f"Rate: {perf['packets_per_second']} pps | "
                              f"Threats: {threats} | "
                              f"Suspicious IPs: {len(analyzer.suspicious_ips)}")
                        
                        last_update = time.time()
                        
            except KeyboardInterrupt:
                print("\n\n🛑 Stopping packet capture...")
                analyzer.stop_capture()
                
                # Export data if requested
                if args.output:
                    print(f"📤 Exporting analysis data to {args.output}...")
                    format_type = 'json' if args.output.endswith('.json') else 'csv'
                    
                    if analyzer.export_enhanced_data(args.output, format_type, include_threats=True):
                        print(f"✅ Data exported successfully")
                    else:
                        print(f"❌ Export failed")
                
                # Display final statistics
                print("\n📈 Final Statistics:")
                print(f"   Total packets captured: {len(analyzer.packets):,}")
                print(f"   Threat indicators: {len(analyzer.threat_indicators)}")
                print(f"   Suspicious IPs detected: {len(analyzer.suspicious_ips)}")
                print(f"   Protocols detected: {len(analyzer.protocol_stats)}")
                
                if analyzer.threat_indicators:
                    print(f"\n🚨 Security Summary:")
                    for ip, threat in list(analyzer.threat_indicators.items())[:5]:
                        print(f"   {threat.severity}: {threat.threat_type} from {ip}")
        
        else:
            # GUI mode
            print("\n🖥️  Starting Advanced Network Security Analyzer GUI...")
            print("🎨 Loading modern interface...")
            
            try:
                app = ModernNetworkAnalyzerGUI()
                print("✅ GUI initialized successfully")
                print("🚀 Application ready - starting main interface...")
                app.run()
                
            except ImportError as e:
                print(f"❌ GUI initialization failed - missing dependency: {e}")
                print("💡 Try running: pip install tkinter")
                sys.exit(1)
            except Exception as e:
                print(f"❌ GUI initialization failed: {e}")
                print("💡 Try running in CLI mode: python network_analyzer.py --cli")
                sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n👋 Application terminated by user")
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        logger.error(f"Critical error: {e}", exc_info=True)
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
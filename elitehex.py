#!/data/data/com.termux/files/usr/bin/env python3
# hex_netmap_pro.py
# Advanced LAN Scanner with Ultimate Banner + Real-time Monitoring
# Features: Port Scanning, OS Detection, Vulnerability Assessment
# Usage: python3 hex_netmap_pro.py

import os
import sys
import socket
import subprocess
import concurrent.futures
import time
import csv
import json
import threading
from datetime import datetime
import ipaddress
import random

# Optional imports
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ---------------- CONFIG ----------------
SAVE_DIR = os.path.expanduser('~/storage/downloads')
CSV_PATH = os.path.join(SAVE_DIR, 'hex_netmap_advanced.csv')
JSON_PATH = os.path.join(SAVE_DIR, 'hex_netmap_advanced.json')
TIMEOUT_PING = 1
THREADS = 150
SCAN_PORTS = [21, 22, 23, 53, 80, 443, 8080, 8443]  # Common ports to scan
# ----------------------------------------

# Ultimate ASCII Banner
BANNER = r"""
\033[1;35m
    ╔═╗┬  ┬┌─┐┌─┐  ╔╗ ┌─┐┌─┐┬┌─  ╔╦╗┌─┐┌─┐┌┬┐┌─┐┌┐┌┌┬┐
    ║ ║└┐┌┘├┤ ├┤   ╠╩╗├┤ ├─┤├┴┐  ║║║├┤ └─┐ │ │ ││││ │ 
    ╚═╝ └┘ └─┘└─┘  ╚═╝└─┘┴ ┴┴ ┴  ╩ ╩└─┘└─┘ ┴ └─┘┘└┘ ┴ 
\033[0m
\033[1;36m
    ╦ ╦┌─┐┬  ┌─┐┌─┐┌┬┐┌─┐  ╔╗ ┬ ┬┌─┐┌─┐┌─┐┬┌─┐
    ╠═╣├┤ │  │  │ ││││├┤   ╠╩╗└┬┘├─┘│ │├─┘│└─┐
    ╩ ╩└─┘┴─┘└─┘└─┘┴ ┴└─┘  ╚═╝ ┴ ┴  └─┘┴  ┴└─┘
\033[0m
\033[1;33m
    ┌─────────────────────────────────────────────────────┐
    │  ██╗  ██╗███████╗██╗  ██╗    ███╗   ██╗███████╗████████╗███╗   ███╗ █████╗ ██████╗  │
    │  ██║  ██║██╔════╝╚██╗██╔╝    ████╗  ██║██╔════╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗ │
    │  ███████║█████╗   ╚███╔╝     ██╔██╗ ██║█████╗     ██║   ██╔████╔██║███████║██████╔╝ │
    │  ██╔══██║██╔══╝   ██╔██╗     ██║╚██╗██║██╔══╝     ██║   ██║╚██╔╝██║██╔══██║██╔═══╝  │
    │  ██║  ██║███████╗██╔╝ ██╗    ██║ ╚████║███████╗   ██║   ██║ ╚═╝ ██║██║  ██║██║      │
    │  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝      │
    └─────────────────────────────────────────────────────┘
\033[0m
\033[1;32m
                    ═══════════════════════════════
                     VERSION 4.0 | Elite-Hex
                    ═══════════════════════════════
\033[0m
"""

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    os.system('clear')
    print(BANNER)

def animate_loading(text, duration=2):
    """Animated loading effect"""
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    start_time = time.time()
    i = 0
    
    while time.time() - start_time < duration:
        sys.stdout.write(f'\r{Colors.CYAN}{chars[i % len(chars)]} {text}{Colors.END}')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write(f'\r{Colors.GREEN}✓ {text} Complete!{Colors.END}\n')

def get_local_ip():
    """Get local IP with multiple fallback methods"""
    methods = [
        # Method 1: UDP connection
        lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).connect(('8.8.8.8', 53)).getsockname()[0],
        # Method 2: Hostname resolution
        lambda: socket.gethostbyname(socket.gethostname()),
        # Method 3: Network interfaces
        lambda: [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][0]
    ]
    
    for method in methods:
        try:
            ip = method()
            if ip and ip != '127.0.0.1':
                return ip
        except:
            continue
    
    return '127.0.0.1'

def get_network_range(ip):
    """Detect network range automatically"""
    try:
        # Try to get netmask from system
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if ip in line and 'src' in line:
                parts = line.split()
                if len(parts) > 0:
                    network = parts[0]
                    return list(ipaddress.ip_network(network, strict=False).hosts())
    except:
        pass
    
    # Fallback to /24
    base = '.'.join(ip.split('.')[:3])
    return [f"{base}.{i}" for i in range(1, 255)]

def advanced_ping_scan(ip):
    """Advanced ping with multiple detection methods"""
    methods = [
        # ICMP Ping
        lambda: subprocess.run(['ping', '-c', '1', '-W', str(TIMEOUT_PING), ip],
                             capture_output=True, text=True).returncode == 0,
        # TCP Connect
        lambda: socket.create_connection((ip, 80), timeout=TIMEOUT_PING).close() or True,
        # ARP Ping
        lambda: 'REACHABLE' in subprocess.run(['arping', '-c', '1', ip],
                                            capture_output=True, text=True).stdout
    ]
    
    for method in methods:
        try:
            if method():
                return True
        except:
            continue
    
    return False

def port_scan(ip, ports=SCAN_PORTS):
    """Scan common ports on alive hosts"""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def os_fingerprint(ip, ttl):
    """Basic OS fingerprinting based on TTL and port responses"""
    os_guess = "Unknown"
    
    if ttl:
        if ttl <= 64:
            os_guess = "Linux/Unix"
        elif ttl <= 128:
            os_guess = "Windows"
        else:
            os_guess = "Network Device"
    
    return os_guess

def get_mac_vendor(mac):
    """Get vendor information from MAC address"""
    if not REQUESTS_AVAILABLE:
        return "Install requests for vendor lookup"
    
    try:
        response = requests.get(f'https://api.macvendors.com/{mac}', timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    
    return "Unknown"

def vulnerability_check(ip, open_ports):
    """Basic vulnerability assessment"""
    vulnerabilities = []
    
    # Common vulnerability checks
    if 21 in open_ports:
        vulnerabilities.append("FTP Service - Check for anonymous login")
    if 22 in open_ports:
        vulnerabilities.append("SSH Service - Check for weak authentication")
    if 23 in open_ports:
        vulnerabilities.append("Telnet Service - Unencrypted communication")
    if 80 in open_ports or 443 in open_ports:
        vulnerabilities.append("Web Service - Check for common web vulnerabilities")
    if 3389 in open_ports:
        vulnerabilities.append("RDP Service - Check for BlueKeep vulnerability")
    
    return vulnerabilities

class ProgressTracker:
    """Advanced progress tracking with multiple bars"""
    def __init__(self):
        self.lock = threading.Lock()
        self.completed = 0
        self.total = 0
        self.current_phase = ""
        
    def update(self, completed, total, phase=""):
        with self.lock:
            self.completed = completed
            self.total = total
            if phase:
                self.current_phase = phase
            self.display()
    
    def display(self):
        bar_length = 40
        percent = self.completed / self.total if self.total > 0 else 0
        filled = int(bar_length * percent)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        sys.stdout.write(f'\r{Colors.CYAN}{self.current_phase}: [{bar}] {int(percent*100)}% ({self.completed}/{self.total}){Colors.END}')
        sys.stdout.flush()

def comprehensive_scan():
    """Main comprehensive scanning function"""
    print_banner()
    
    # Initialization phase
    animate_loading("Initializing Hex Netmap System", 1)
    
    local_ip = get_local_ip()
    print(f"{Colors.GREEN}📍 Local IP Detected: {Colors.BOLD}{local_ip}{Colors.END}\n")
    
    network_hosts = get_network_range(local_ip)
    total_hosts = len(network_hosts)
    
    print(f"{Colors.YELLOW}🎯 Scan Target: {total_hosts} hosts in network range{Colors.END}")
    print(f"{Colors.BLUE}⚡ Threads: {THREADS} | Timeout: {TIMEOUT_PING}s{Colors.END}\n")
    
    # Phase 1: Host Discovery
    progress = ProgressTracker()
    alive_hosts = []
    
    print(f"{Colors.MAGENTA}🚀 Phase 1: Host Discovery{Colors.END}")
    
    def scan_host(ip):
        if advanced_ping_scan(ip):
            alive_hosts.append(ip)
        progress.update(len(alive_hosts) + network_hosts.index(ip) - len([h for h in alive_hosts if network_hosts.index(h) < network_hosts.index(ip)]), 
                       total_hosts, "Discovering hosts")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        list(executor.map(scan_host, network_hosts))
    
    print(f"\n{Colors.GREEN}✅ Host Discovery Complete: {len(alive_hosts)} alive hosts found{Colors.END}\n")
    
    # Phase 2: Port Scanning & Analysis
    print(f"{Colors.MAGENTA}🔍 Phase 2: Service Discovery{Colors.END}")
    
    detailed_hosts = []
    progress = ProgressTracker()
    
    def analyze_host(ip):
        # Get MAC address
        mac = get_mac_address(ip)
        
        # Port scan
        open_ports = port_scan(ip)
        
        # OS detection
        os_info = detect_os(ip)
        
        # Hostname resolution
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        
        # Vendor info
        vendor = get_mac_vendor(mac) if mac else "Unknown"
        
        # Vulnerability assessment
        vulnerabilities = vulnerability_check(ip, open_ports)
        
        host_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'os': os_info,
            'open_ports': ', '.join(map(str, open_ports)) if open_ports else 'None',
            'vendor': vendor,
            'vulnerabilities': ', '.join(vulnerabilities) if vulnerabilities else 'None',
            'risk_level': 'High' if vulnerabilities else 'Low'
        }
        
        detailed_hosts.append(host_info)
        progress.update(len(detailed_hosts), len(alive_hosts), "Analyzing services")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(analyze_host, alive_hosts))
    
    print(f"\n{Colors.GREEN}✅ Service Analysis Complete{Colors.END}\n")
    
    return detailed_hosts

def get_mac_address(ip):
    """Get MAC address from ARP table"""
    try:
        # Try ip neigh command
        result = subprocess.run(['ip', 'neigh', 'show', 'to', ip], 
                              capture_output=True, text=True)
        if result.returncode == 0 and 'lladdr' in result.stdout:
            return result.stdout.split('lladdr ')[1].split()[0]
    except:
        pass
    
    try:
        # Try arp command
        result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return parts[3]
    except:
        pass
    
    return "Unknown"

def detect_os(ip):
    """Enhanced OS detection"""
    try:
        # TTL-based detection
        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                              capture_output=True, text=True)
        if 'ttl=' in result.stdout.lower():
            ttl_line = [line for line in result.stdout.split('\n') if 'ttl=' in line.lower()][0]
            ttl = int(ttl_line.split('ttl=')[1].split()[0])
            
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"
    except:
        pass
    
    return "Unknown"

def display_results(hosts):
    """Display results in a beautiful format"""
    if not hosts:
        print(f"{Colors.RED}❌ No hosts found or all hosts are offline.{Colors.END}")
        return
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}📊 SCAN RESULTS SUMMARY{Colors.END}")
    print(f"{Colors.YELLOW}═" * 120 + Colors.END)
    
    # Summary statistics
    total_hosts = len(hosts)
    hosts_with_ports = len([h for h in hosts if h['open_ports'] != 'None'])
    high_risk = len([h for h in hosts if h['risk_level'] == 'High'])
    
    print(f"{Colors.GREEN}• Total Hosts Found: {total_hosts}")
    print(f"• Hosts with Open Ports: {hosts_with_ports}")
    print(f"• High Risk Systems: {high_risk}{Colors.END}\n")
    
    if TABULATE_AVAILABLE:
        # Prepare table data
        table_data = []
        for host in sorted(hosts, key=lambda x: [int(i) for i in x['ip'].split('.')]):
            risk_color = Colors.RED if host['risk_level'] == 'High' else Colors.GREEN
            table_data.append([
                host['ip'],
                host['mac'][:17] if host['mac'] != 'Unknown' else 'Unknown',
                host['hostname'][:20],
                host['os'],
                host['open_ports'],
                risk_color + host['risk_level'] + Colors.END
            ])
        
        headers = [f"{Colors.BOLD}IP{Colors.END}", f"{Colors.BOLD}MAC{Colors.END}", 
                  f"{Colors.BOLD}Hostname{Colors.END}", f"{Colors.BOLD}OS{Colors.END}", 
                  f"{Colors.BOLD}Open Ports{Colors.END}", f"{Colors.BOLD}Risk{Colors.END}"]
        
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
    else:
        # Simple display
        for host in sorted(hosts, key=lambda x: [int(i) for i in x['ip'].split('.')]):
            risk_color = Colors.RED if host['risk_level'] == 'High' else Colors.GREEN
            print(f"{Colors.WHITE}{host['ip']:15} {host['mac'][:17]:18} {host['hostname'][:20]:20} {host['os']:15} {host['open_ports']:20} {risk_color}{host['risk_level']}{Colors.END}")

def save_results(hosts):
    """Save results to CSV and JSON"""
    os.makedirs(SAVE_DIR, exist_ok=True)
    
    # Save CSV
    try:
        with open(CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'hostname', 'os', 'open_ports', 'vendor', 'vulnerabilities', 'risk_level'])
            writer.writeheader()
            for host in hosts:
                writer.writerow(host)
        print(f"\n{Colors.GREEN}💾 CSV Report Saved: {CSV_PATH}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error saving CSV: {e}{Colors.END}")
    
    # Save JSON
    try:
        report_data = {
            'scan_date': datetime.now().isoformat(),
            'scan_type': 'Comprehensive Network Scan',
            'total_hosts_found': len(hosts),
            'high_risk_hosts': len([h for h in hosts if h['risk_level'] == 'High']),
            'hosts': hosts
        }
        
        with open(JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"{Colors.GREEN}💾 JSON Report Saved: {JSON_PATH}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error saving JSON: {e}{Colors.END}")

def print_security_notice():
    """Print security and legal notice"""
    print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  SECURITY & LEGAL NOTICE{Colors.END}")
    print(f"{Colors.YELLOW}═" * 80 + Colors.END)
    print(f"{Colors.WHITE}• This tool is for educational and authorized testing purposes only")
    print(f"• Only scan networks you own or have explicit permission to test")
    print(f"• Unauthorized scanning may be illegal in your jurisdiction")
    print(f"• The developers are not responsible for misuse of this tool")
    print(f"• Always follow responsible disclosure practices{Colors.END}\n")

def main():
    try:
        start_time = time.time()
        
        # Perform comprehensive scan
        hosts = comprehensive_scan()
        
        # Display results
        display_results(hosts)
        
        # Save results
        save_results(hosts)
        
        # Calculate and display scan duration
        duration = time.time() - start_time
        print(f"\n{Colors.CYAN}⏱️  Scan completed in {duration:.2f} seconds{Colors.END}")
        
        # Security notice
        print_security_notice()
        
        print(f"{Colors.BOLD}{Colors.GREEN}🎯 Hex Netmap Advanced - Scan Complete!{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}❌ Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}💥 Unexpected error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == '__main__':
    main()
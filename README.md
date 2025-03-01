# WIFI-JAMMER

A Python-based Wi-Fi deauthentication tool for educational purposes. This tool allows you to scan for Wi-Fi networks and perform deauthentication attacks on targeted networks.

**Disclaimer**: This tool is for educational purposes only. Unauthorized use of this tool is illegal and unethical. Always ensure you have permission before performing any network testing or attacks.

---

## Features
- Scan for nearby Wi-Fi networks.
- Perform deauthentication attacks on all networks or a specific network.
- Set wireless interfaces to monitor mode automatically or manually.

---

## Prerequisites

### 1. Set Interface to Monitor Mode
Before using this tool, you need to set your wireless interface to monitor mode. You can do this manually using `airmon-ng`:

```bash
sudo airmon-ng start <interface>


Also library used is scapy 

Useful tools airmon-ng  

Have fun

 ### also u would be required to run this tool in a virtual environment###


### 3. Install `toilet` (for ASCII Art)
`toilet` is required for generating the ASCII art in the script. Install it using your system's package manager:

#### For Debian-based systems (e.g., Ubuntu):
```bash
sudo apt update
sudo apt install toilet

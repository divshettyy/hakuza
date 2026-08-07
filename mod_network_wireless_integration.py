#!/usr/bin/env python3
"""
Integration wrapper for mod_network_wireless into hakuza CLI
Provides high-level orchestration and engagement context
"""

import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

try:
    from mod_network_wireless import (
        Logger, ScopeValidator, Layer2Attacks, CredentialCapture,
        KerberosAttacks, WirelessAttacks, NetworkRecon, AttackChains
    )
    MOD_AVAILABLE = True
except ImportError as e:
    MOD_AVAILABLE = False
    IMPORT_ERROR = str(e)


def cmd_wireless(args, console: Console) -> None:
    """
    hakuza wireless [--scan|--capture|--crack|--chain] [--interface wlan0] [--target-ap BSSID]

    Deep wireless attack module: WPA2 cracking, evil twin, deauth, Bluetooth, RF exploitation
    """
    if not MOD_AVAILABLE:
        console.print(f"[red][!] mod_network_wireless not available: {IMPORT_ERROR}[/red]")
        return

    # Initialize logger and scope
    logger = Logger()
    scope = ScopeValidator()
    wireless = WirelessAttacks(logger, scope)

    # --- WiFi Scan ---
    if hasattr(args, 'scan') and args.scan:
        console.print(Panel(
            "[bold]WiFi Network Scan[/bold]",
            title="HAKUZA Wireless",
            border_style="cyan"
        ))

        interface = getattr(args, 'interface', None)
        networks = wireless.wifi_scan(interface)

        if networks:
            table = Table(
                title=f"Found {len(networks)} WiFi Networks",
                box=box.DOUBLE,
                show_header=True,
                header_style="bold blue"
            )
            table.add_column("SSID", style="bold white", width=30)
            table.add_column("BSSID", width=20)
            table.add_column("Channel", width=8, justify="center")
            table.add_column("Signal", width=10, justify="center")
            table.add_column("Encryption", width=15)

            for net in networks:
                table.add_row(
                    net.ssid[:30] if net.ssid else "(hidden)",
                    net.bssid,
                    str(net.channel),
                    f"{net.signal_strength} dBm",
                    net.encryption
                )

            console.print(table)
        else:
            console.print("[yellow][!] No WiFi networks found[/yellow]")

    # --- Handshake Capture ---
    elif hasattr(args, 'capture') and args.capture:
        ssid = getattr(args, 'ssid', None)
        bssid = getattr(args, 'bssid', None)
        interface = getattr(args, 'interface', 'wlan0')

        if not ssid or not bssid:
            console.print("[red][!] --ssid and --bssid required for capture[/red]")
            return

        console.print(Panel(
            f"[bold]Capturing WPA2 Handshake[/bold]\n"
            f"SSID: {ssid}\n"
            f"BSSID: {bssid}\n"
            f"Interface: {interface}",
            title="HAKUZA Wireless",
            border_style="cyan"
        ))

        success = wireless.capture_handshake(ssid, bssid, interface)
        if success:
            console.print("[green][+] Handshake captured successfully[/green]")
        else:
            console.print("[red][!] Handshake capture failed[/red]")

    # --- WPA2 Crack ---
    elif hasattr(args, 'crack') and args.crack:
        pcap_file = args.crack
        wordlist = getattr(args, 'wordlist', None)

        if not os.path.exists(pcap_file):
            console.print(f"[red][!] File not found: {pcap_file}[/red]")
            return

        console.print(Panel(
            f"[bold]Cracking WPA2 Handshake[/bold]\n"
            f"PCAP: {pcap_file}\n"
            f"Wordlist: {wordlist or 'rockyou.txt (default)'}",
            title="HAKUZA Wireless",
            border_style="cyan"
        ))

        password = wireless.crack_wpa2(pcap_file, wordlist)
        if password:
            console.print(f"[green][+] Password found:[/green] {password}")
        else:
            console.print("[yellow][!] No password found[/yellow]")

    # --- Evil Twin ---
    elif hasattr(args, 'evil_twin') and args.evil_twin:
        ssid = getattr(args, 'ssid', None)
        channel = getattr(args, 'channel', 6)
        interface = getattr(args, 'interface', 'wlan0')

        if not ssid:
            console.print("[red][!] --ssid required for evil twin[/red]")
            return

        console.print(Panel(
            f"[bold]Creating Evil Twin AP[/bold]\n"
            f"SSID: {ssid}\n"
            f"Channel: {channel}\n"
            f"Interface: {interface}",
            title="HAKUZA Wireless",
            border_style="cyan"
        ))

        success = wireless.evil_twin(ssid, channel, interface)
        if success:
            console.print(f"[green][+] Evil twin running - connect to access portal[/green]")
        else:
            console.print("[red][!] Evil twin setup failed[/red]")

    # --- Deauth Attack ---
    elif hasattr(args, 'deauth') and args.deauth:
        bssid = getattr(args, 'bssid', None)
        interface = getattr(args, 'interface', 'wlan0')

        if not bssid:
            console.print("[red][!] --bssid required for deauth[/red]")
            return

        console.print(Panel(
            f"[bold]Deauthentication Attack[/bold]\n"
            f"Target BSSID: {bssid}\n"
            f"Interface: {interface}",
            title="HAKUZA Wireless",
            border_style="cyan"
        ))

        success = wireless.deauth_attack(bssid, interface)
        if success:
            console.print("[green][+] Deauth packets sent[/green]")
        else:
            console.print("[red][!] Deauth attack failed[/red]")

    # --- Bluetooth Scan ---
    elif hasattr(args, 'bluetooth') and args.bluetooth:
        console.print(Panel(
            "[bold]Bluetooth Device Scan[/bold]",
            title="HAKUZA Wireless",
            border_style="cyan"
        ))

        devices = wireless.bluetooth_scan()

        if devices:
            table = Table(
                title=f"Found {len(devices)} Bluetooth Devices",
                box=box.DOUBLE,
                show_header=True,
                header_style="bold blue"
            )
            table.add_column("MAC Address", width=20)
            table.add_column("Device Name", style="bold white")

            for dev in devices:
                table.add_row(dev['mac'], dev['name'])

            console.print(table)
        else:
            console.print("[yellow][!] No Bluetooth devices found[/yellow]")

    else:
        console.print("[yellow][*] Use --scan, --capture, --crack, --evil-twin, --deauth, or --bluetooth[/yellow]")


def cmd_network_deep(args, console: Console) -> None:
    """
    hakuza network-deep [--scan|--mitm|--creds|--kerberos] [--range CIDR] [--interface eth0]

    Deep network attack module: ARP spoofing, MITM, LLMNR/NBT-NS poisoning,
    NTLM relay, Kerberos attacks, VLAN hopping
    """
    if not MOD_AVAILABLE:
        console.print(f"[red][!] mod_network_wireless not available: {IMPORT_ERROR}[/red]")
        return

    # Initialize modules
    logger = Logger()
    scope = ScopeValidator()
    recon = NetworkRecon(logger, scope)
    l2 = Layer2Attacks(logger, scope)
    creds = CredentialCapture(logger, scope)
    krb = KerberosAttacks(logger, scope)

    # --- ARP Network Scan ---
    if hasattr(args, 'scan') and args.scan:
        network_range = getattr(args, 'range', '192.168.1.0/24')
        interface = getattr(args, 'interface', None)

        console.print(Panel(
            f"[bold]Network Reconnaissance[/bold]\n"
            f"Range: {network_range}",
            title="HAKUZA Network Deep",
            border_style="blue"
        ))

        hosts = recon.arp_scan(network_range, interface)

        if hosts:
            table = Table(
                title=f"Discovered {len(hosts)} Hosts",
                box=box.DOUBLE,
                show_header=True,
                header_style="bold blue"
            )
            table.add_column("IP Address", style="bold white", width=18)
            table.add_column("MAC Address", width=20)
            table.add_column("Hostname", width=25)
            table.add_column("Services", width=20)

            for host in hosts:
                table.add_row(
                    host.ip,
                    host.mac,
                    host.hostname or "unknown",
                    ", ".join(host.services[:2]) if host.services else "unknown"
                )

            console.print(table)
        else:
            console.print("[yellow][!] No hosts discovered[/yellow]")

    # --- ARP MITM ---
    elif hasattr(args, 'mitm') and args.mitm:
        target1 = getattr(args, 'target1', None)
        target2 = getattr(args, 'target2', None)
        interface = getattr(args, 'interface', None)

        if not target1 or not target2:
            console.print("[red][!] --target1 and --target2 required for MITM[/red]")
            return

        console.print(Panel(
            f"[bold]ARP MITM Setup[/bold]\n"
            f"Host 1: {target1}\n"
            f"Host 2: {target2}",
            title="HAKUZA Network Deep",
            border_style="blue"
        ))

        try:
            success = l2.arp_mitm(target1, target2, interface)
            if success:
                console.print(f"[green][+] MITM active between {target1} and {target2}[/green]")
                console.print("[yellow][*] Press Ctrl+C to stop[/yellow]")
                import time
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    console.print("[*] MITM stopped")
            else:
                console.print("[red][!] MITM setup failed[/red]")
        except Exception as e:
            console.print(f"[red][!] Error: {e}[/red]")

    # --- Credential Capture ---
    elif hasattr(args, 'creds') and args.creds:
        interface = getattr(args, 'interface', None)
        spoof_ip = getattr(args, 'spoof_ip', '0.0.0.0')
        llmnr = getattr(args, 'llmnr', True)
        nbt_ns = getattr(args, 'nbt_ns', True)

        console.print(Panel(
            f"[bold]Credential Capture Setup[/bold]\n"
            f"LLMNR: {llmnr}\n"
            f"NBT-NS: {nbt_ns}",
            title="HAKUZA Network Deep",
            border_style="blue"
        ))

        if llmnr:
            creds.llmnr_poison(interface, spoof_ip)
            console.print("[green][+] LLMNR poisoning active[/green]")

        if nbt_ns:
            creds.nbt_ns_poison(interface, spoof_ip)
            console.print("[green][+] NBT-NS poisoning active[/green]")

        console.print("[yellow][*] Waiting for credential captures - Press Ctrl+C to stop[/yellow]")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("[*] Credential capture stopped")

    # --- Kerberos Attacks ---
    elif hasattr(args, 'kerberos') and args.kerberos:
        dc_ip = getattr(args, 'dc', None)
        domain = getattr(args, 'domain', None)

        if not dc_ip or not domain:
            console.print("[red][!] --dc and --domain required[/red]")
            return

        console.print(Panel(
            f"[bold]Kerberos Attack Options[/bold]\n"
            f"Domain Controller: {dc_ip}\n"
            f"Domain: {domain}",
            title="HAKUZA Network Deep",
            border_style="blue"
        ))

        console.print("[cyan][*] Kerberos attack options:[/cyan]")
        console.print("    1. AS-REP Roasting (users with pre-auth disabled)")
        console.print("    2. Kerberoasting (crack service account tickets)")
        console.print("    3. Golden Ticket (forge TGT as any user)")
        console.print("    4. Silver Ticket (forge TGS for specific service)")

    else:
        console.print("[yellow][*] Use --scan, --mitm, --creds, or --kerberos[/yellow]")


def cmd_attack_chain(args, console: Console) -> None:
    """
    hakuza chain [--wifi-domain|--arp-creds] [--options...]

    Pre-built attack chains: WiFi → Domain Admin, ARP MITM → Credential Capture
    """
    if not MOD_AVAILABLE:
        console.print(f"[red][!] mod_network_wireless not available: {IMPORT_ERROR}[/red]")
        return

    logger = Logger()
    scope = ScopeValidator()
    chains = AttackChains(logger, scope)

    # --- WiFi to Domain Admin Chain ---
    if hasattr(args, 'wifi_domain') and args.wifi_domain:
        ssid = getattr(args, 'ssid', None)
        bssid = getattr(args, 'bssid', None)
        interface = getattr(args, 'interface', 'wlan0')
        network_range = getattr(args, 'range', '192.168.1.0/24')

        if not ssid or not bssid:
            console.print("[red][!] --ssid and --bssid required[/red]")
            return

        console.print(Panel(
            f"[bold]WiFi → Domain Admin Attack Chain[/bold]\n"
            f"SSID: {ssid}\n"
            f"BSSID: {bssid}\n"
            f"Network: {network_range}",
            title="HAKUZA Attack Chains",
            border_style="magenta"
        ))

        chains.wifi_to_domain_admin(ssid, bssid, interface, network_range)

    # --- ARP MITM → Credential Capture Chain ---
    elif hasattr(args, 'arp_creds') and args.arp_creds:
        target1 = getattr(args, 'target1', None)
        target2 = getattr(args, 'target2', None)
        interface = getattr(args, 'interface', None)

        if not target1 or not target2:
            console.print("[red][!] --target1 and --target2 required[/red]")
            return

        console.print(Panel(
            f"[bold]ARP MITM → Credential Capture Chain[/bold]\n"
            f"Target 1: {target1}\n"
            f"Target 2: {target2}",
            title="HAKUZA Attack Chains",
            border_style="magenta"
        ))

        chains.arp_mitm_credential_capture(target1, target2, interface)

    else:
        console.print("[yellow][*] Use --wifi-domain or --arp-creds[/yellow]")

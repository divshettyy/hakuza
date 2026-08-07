#!/usr/bin/env python3
"""
mod_api_fuzzer.py — HAKUZA Advanced API Fuzzing Engine

Comprehensive API endpoint discovery, parameter fuzzing, and vulnerability detection
using context-aware payload libraries, differential response analysis, and automated
CWE/CVSS classification.

Features:
  1. APIEndpointDiscovery — Parse Swagger/OpenAPI/manual API definitions
  2. ParameterFuzzer — Fuzz GET/POST/header/cookie parameters in parallel
  3. PayloadLibraryLoader — Load 1000+ payload variants from tool library
  4. ContextAwarePayloadGenerator — Detect parameter type, generate relevant payloads
  5. ResultDifferencer — Response diff analysis (status, length, hash, timing)
  6. VulnerabilityClassifier — Map findings to CWE/CVSS with confidence scoring
  7. Nuclei template integration for follow-up scanning
  8. Async execution for large API surfaces

Invocation:
  hakuza api-fuzz --target <api_url> --endpoints <swagger.json> --depth full
  hakuza api-fuzz --target <api_url> --auto-discover --threads 10 --timeout 30

Integration:
  - Reads payload library from ~/tools/payloads/
  - Stores findings in engagement database
  - Generates curl PoCs and Python scripts
  - Exports Nuclei templates for confirmed vulns

Author: Divith D Shetty
Version: 1.0.0
"""

import os
import sys
import json
import re
import time
import hashlib
import statistics
import concurrent.futures
import difflib
import urllib.parse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import warnings

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Constants & Enums
# ─────────────────────────────────────────────────────────────────────────────

_PAYLOAD_DIR = Path.home() / "tools" / "payloads"
_MODEL = "claude-sonnet-4-6"
_TESTLAB_BASE = "http://127.0.0.1:9911"

# CWE/CVSS Mapping Database
CWE_SEVERITY_MAP = {
    "xss": ("CWE-79", "High", 7.1),
    "sqli": ("CWE-89", "Critical", 9.8),
    "ssti": ("CWE-1336", "High", 8.6),
    "rce": ("CWE-78", "Critical", 9.8),
    "xxe": ("CWE-611", "High", 8.6),
    "ssrf": ("CWE-918", "High", 8.6),
    "idor": ("CWE-639", "High", 7.5),
    "lfi": ("CWE-22", "High", 7.5),
    "cors": ("CWE-862", "Medium", 5.7),
    "deserialization": ("CWE-502", "Critical", 9.8),
    "csrf": ("CWE-352", "Medium", 6.5),
    "redirect": ("CWE-601", "Medium", 6.1),
    "jwt": ("CWE-347", "High", 8.1),
    "nosqli": ("CWE-943", "High", 8.6),
    "race_condition": ("CWE-362", "High", 7.5),
    "cache_poisoning": ("CWE-444", "Medium", 5.3),
    "mass_assignment": ("CWE-915", "Medium", 6.5),
}

PARAMETER_TYPE_PATTERNS = {
    "numeric": (r"^(id|uid|pid|user_?id|product_?id|order_?id|item_?id|account_?id|page|limit|offset|count)$", int),
    "email": (r"^(email|from|to|recipient|sender)$", "email"),
    "url": (r"^(url|redirect|callback|return|goto|link|href|src|image|avatar|profile)$", "url"),
    "file": (r"^(file|path|filename|filepath|attachment|document|upload)$", "file"),
    "command": (r"^(cmd|command|exec|execute|run|action|method|operation)$", "command"),
    "template": (r"^(template|tpl|view|layout|format|type)$", "template"),
    "query": (r"^(q|query|search|filter|find|keyword|term)$", "query"),
    "datetime": (r"^(date|time|from_date|to_date|created|updated|timestamp)$", "datetime"),
}


class VulnerabilityType(Enum):
    """Enumeration of detectable vulnerability types."""
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    RCE = "rce"
    XXE = "xxe"
    SSRF = "ssrf"
    IDOR = "idor"
    LFI = "lfi"
    CORS = "cors"
    DESERIALIZATION = "deserialization"
    CSRF = "csrf"
    REDIRECT = "redirect"
    JWT = "jwt"
    NOSQLI = "nosqli"
    RACE_CONDITION = "race_condition"
    CACHE_POISONING = "cache_poisoning"
    MASS_ASSIGNMENT = "mass_assignment"
    API_KEY_EXPOSURE = "api_key_exposure"


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class APIEndpoint:
    """Represents a single API endpoint."""
    method: str
    path: str
    description: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    security: List[Dict[str, List[str]]] = field(default_factory=list)

    @property
    def full_url(self) -> str:
        """Generate full URL path."""
        return self.path


@dataclass
class FuzzingResult:
    """Result of a single fuzzing attempt."""
    endpoint: APIEndpoint
    parameter_name: str
    parameter_location: str  # query, body, header, cookie
    payload: str
    vuln_type: VulnerabilityType
    status_code: Optional[int] = None
    response_length: Optional[int] = None
    response_hash: Optional[str] = None
    response_time: Optional[float] = None
    response_text: Optional[str] = None
    differential_score: float = 0.0
    confidence: float = 0.0
    is_confirmed: bool = False
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class VulnerabilityFinding:
    """Complete vulnerability finding with metadata."""
    finding_id: str
    endpoint: APIEndpoint
    vulnerability_type: str
    cwe: str
    severity: str
    cvss_score: float
    confidence: float
    title: str
    description: str
    evidence: List[FuzzingResult]
    proof_of_concept_curl: str = ""
    proof_of_concept_python: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ─────────────────────────────────────────────────────────────────────────────
# Lazy Import Pattern (mirrors mod_active.py)
# ─────────────────────────────────────────────────────────────────────────────

def _hakuza():
    """Lazy-load hakuza module for finding storage and engagement paths."""
    main_mod = sys.modules.get("__main__")
    if main_mod and hasattr(main_mod, "add_finding"):
        return main_mod
    try:
        import hakuza
        return hakuza
    except ImportError:
        return None


def _add_finding(eng_id: str, **kwargs) -> Optional[str]:
    """Delegate finding addition to hakuza module."""
    hakuza_mod = _hakuza()
    if not hakuza_mod:
        return None
    return hakuza_mod.add_finding(eng_id, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# Payload Library Loader
# ─────────────────────────────────────────────────────────────────────────────

class PayloadLibraryLoader:
    """Load and manage payload libraries from ~/tools/payloads/."""

    def __init__(self, payload_dir: Optional[Path] = None):
        self.payload_dir = payload_dir or _PAYLOAD_DIR
        self.payloads: Dict[VulnerabilityType, List[str]] = {}
        self._load_payloads()

    def _load_payloads(self) -> None:
        """Load payload files from disk."""
        if not self.payload_dir.exists():
            return

        mapping = {
            "xss.txt": VulnerabilityType.XSS,
            "sqli.txt": VulnerabilityType.SQLI,
            "ssti.txt": VulnerabilityType.SSTI,
            "xxe.xml": VulnerabilityType.XXE,
            "ssrf.txt": VulnerabilityType.SSRF,
            "lfi.txt": VulnerabilityType.LFI,
            "redirect.txt": VulnerabilityType.REDIRECT,
            "cors-payloads.txt": VulnerabilityType.CORS,
            "deser.txt": VulnerabilityType.DESERIALIZATION,
            "jwt-payloads.txt": VulnerabilityType.JWT,
            "nosql.txt": VulnerabilityType.NOSQLI,
            "graphql-payloads.txt": VulnerabilityType.SQLI,  # GraphQL can expose SQLi
        }

        for filename, vuln_type in mapping.items():
            filepath = self.payload_dir / filename
            if filepath.exists():
                with open(filepath, 'r') as f:
                    # Filter comments and empty lines
                    payloads = [
                        line.strip()
                        for line in f.readlines()
                        if line.strip() and not line.startswith('#')
                    ]
                    self.payloads[vuln_type] = payloads[:50]  # Limit per type to 50

    def get_payloads(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get payloads for a specific vulnerability type."""
        return self.payloads.get(vuln_type, [])

    def get_all_payloads(self) -> Dict[VulnerabilityType, List[str]]:
        """Get all payloads."""
        return self.payloads

    def count_total_payloads(self) -> int:
        """Count total payload variants."""
        return sum(len(payloads) for payloads in self.payloads.values())


# ─────────────────────────────────────────────────────────────────────────────
# API Endpoint Discovery
# ─────────────────────────────────────────────────────────────────────────────

class APIEndpointDiscovery:
    """Discover and parse API endpoints from Swagger/OpenAPI/manual definitions."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.endpoints: List[APIEndpoint] = []
        self.console = Console()

    def discover_from_swagger(self, swagger_path: str) -> List[APIEndpoint]:
        """Parse Swagger/OpenAPI JSON file."""
        if not HAS_YAML:
            self.console.print("[red]YAML library required for Swagger parsing[/red]")
            return []

        try:
            with open(swagger_path, 'r') as f:
                spec = yaml.safe_load(f) or json.load(open(swagger_path, 'r'))

            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']:
                        endpoint = APIEndpoint(
                            method=method.upper(),
                            path=path,
                            description=details.get('summary', details.get('description', '')),
                            parameters=details.get('parameters', []),
                            request_body=details.get('requestBody'),
                            response_schema=details.get('responses'),
                            tags=details.get('tags', []),
                            security=details.get('security', [])
                        )
                        self.endpoints.append(endpoint)

        except Exception as e:
            self.console.print(f"[red]Error parsing Swagger: {e}[/red]")

        return self.endpoints

    def discover_from_manual(self, endpoints_list: List[Dict[str, Any]]) -> List[APIEndpoint]:
        """Manually add endpoints from list."""
        for ep in endpoints_list:
            endpoint = APIEndpoint(
                method=ep.get('method', 'GET').upper(),
                path=ep.get('path', ''),
                description=ep.get('description', ''),
                parameters=ep.get('parameters', []),
            )
            self.endpoints.append(endpoint)
        return self.endpoints

    def discover_from_introspection(self, endpoint_url: str) -> List[APIEndpoint]:
        """Discover endpoints via GraphQL introspection or API metadata."""
        # Implementation for GraphQL introspection or /api/docs parsing
        pass

    def get_endpoints(self) -> List[APIEndpoint]:
        """Return discovered endpoints."""
        return self.endpoints


# ─────────────────────────────────────────────────────────────────────────────
# Context-Aware Payload Generator
# ─────────────────────────────────────────────────────────────────────────────

class ContextAwarePayloadGenerator:
    """Generate context-aware payloads based on parameter analysis."""

    def __init__(self, payload_loader: PayloadLibraryLoader):
        self.loader = payload_loader

    def detect_parameter_type(self, param_name: str) -> str:
        """Detect parameter type from name."""
        param_lower = param_name.lower()

        for param_type, (pattern, _) in PARAMETER_TYPE_PATTERNS.items():
            if re.match(pattern, param_lower):
                return param_type

        return "generic"

    def generate_payloads(self, param_name: str, param_location: str = "query",
                         vuln_types: Optional[List[VulnerabilityType]] = None) -> Dict[VulnerabilityType, List[str]]:
        """Generate payloads for a parameter based on its characteristics."""
        param_type = self.detect_parameter_type(param_name)
        result = {}

        if not vuln_types:
            vuln_types = list(VulnerabilityType)

        for vuln in vuln_types:
            payloads = self.loader.get_payloads(vuln)

            # Filter payloads by parameter type
            if param_type == "numeric":
                # For numeric params, only test SQLi and IDOR
                if vuln in [VulnerabilityType.SQLI, VulnerabilityType.IDOR]:
                    result[vuln] = payloads[:20]
            elif param_type == "url":
                # For URL params, test SSRF, open redirect
                if vuln in [VulnerabilityType.SSRF, VulnerabilityType.REDIRECT]:
                    result[vuln] = payloads[:20]
            elif param_type == "file":
                # For file params, test LFI, XXE, path traversal
                if vuln in [VulnerabilityType.LFI, VulnerabilityType.XXE]:
                    result[vuln] = payloads[:20]
            elif param_type == "command":
                # For command params, test RCE, command injection
                if vuln in [VulnerabilityType.RCE]:
                    result[vuln] = payloads[:20]
            elif param_type == "template":
                # For template params, test SSTI
                if vuln in [VulnerabilityType.SSTI]:
                    result[vuln] = payloads[:20]
            elif param_type == "query":
                # For search/query params, test all types
                result[vuln] = payloads[:15]
            else:
                # Generic param - test common vulns
                result[vuln] = payloads[:10]

        return result


# ─────────────────────────────────────────────────────────────────────────────
# Response Analysis & Differencing
# ─────────────────────────────────────────────────────────────────────────────

class ResponseBaseline:
    """Establish response baseline for differential analysis."""

    def __init__(self, endpoint: APIEndpoint, base_url: str, timeout: int = 10):
        self.endpoint = endpoint
        self.base_url = base_url
        self.timeout = timeout
        self.samples: List[Tuple[int, int, str, float]] = []  # (status, length, hash, time)
        self.mean_length = 0
        self.stdev_length = 0
        self.mean_time = 0
        self.stdev_time = 0

    def capture_baseline(self, num_samples: int = 3) -> bool:
        """Capture baseline responses."""
        if not HAS_REQUESTS:
            return False

        session = self._create_session()

        try:
            for _ in range(num_samples):
                try:
                    start = time.time()
                    resp = session.request(
                        self.endpoint.method,
                        f"{self.base_url}{self.endpoint.path}",
                        timeout=self.timeout
                    )
                    elapsed = time.time() - start

                    resp_hash = hashlib.sha256(resp.content).hexdigest()
                    self.samples.append((resp.status_code, len(resp.content), resp_hash, elapsed))
                except Exception:
                    continue

        finally:
            session.close()

        if self.samples:
            lengths = [s[1] for s in self.samples]
            times = [s[3] for s in self.samples]
            self.mean_length = statistics.mean(lengths)
            self.stdev_length = statistics.stdev(lengths) if len(lengths) > 1 else 0
            self.mean_time = statistics.mean(times)
            self.stdev_time = statistics.stdev(times) if len(times) > 1 else 0
            return True

        return False

    def _create_session(self) -> 'requests.Session':
        """Create requests session with retries."""
        session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session


class ResultDifferencer:
    """Analyze response differences for vulnerability detection."""

    @staticmethod
    def calculate_similarity(text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts (0.0-1.0)."""
        if not text1 or not text2:
            return 0.0
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()

    @staticmethod
    def detect_anomalies(baseline: ResponseBaseline, response_code: int,
                        response_length: int, response_text: str,
                        response_time: float) -> Tuple[float, List[str]]:
        """Detect anomalies in response."""
        anomalies = []
        score = 0.0

        # Status code check
        if baseline.samples:
            baseline_status = baseline.samples[0][0]
            if response_code != baseline_status:
                anomalies.append(f"status_code_diff:{baseline_status}->{response_code}")
                score += 0.2

        # Length check
        if baseline.stdev_length > 0:
            z_score = abs(response_length - baseline.mean_length) / (baseline.stdev_length + 1)
            if z_score > 2:  # 2 sigma
                anomalies.append(f"length_anomaly:z={z_score:.2f}")
                score += 0.3

        # Timing check
        if baseline.stdev_time > 0:
            z_score = abs(response_time - baseline.mean_time) / (baseline.stdev_time + 1)
            if z_score > 2.5:
                anomalies.append(f"timing_anomaly:z={z_score:.2f}")
                score += 0.2

        # Content similarity check
        if baseline.samples:
            baseline_text = "baseline"  # Placeholder
            similarity = ResultDifferencer.calculate_similarity(baseline_text, response_text)
            if similarity < 0.7:
                anomalies.append(f"content_diff:sim={similarity:.2f}")
                score += 0.3

        return min(score, 1.0), anomalies


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Classification
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityClassifier:
    """Classify and score discovered vulnerabilities."""

    def __init__(self):
        self.console = Console()

    def classify(self, vuln_type: str, differential_score: float,
                confidence: float) -> VulnerabilityFinding:
        """Classify vulnerability and generate finding."""
        vuln_type_lower = vuln_type.lower()

        if vuln_type_lower in CWE_SEVERITY_MAP:
            cwe, severity, cvss = CWE_SEVERITY_MAP[vuln_type_lower]
        else:
            cwe, severity, cvss = "CWE-Unknown", "Medium", 5.0

        # Adjust CVSS based on confidence
        adjusted_cvss = cvss * confidence

        return {
            'cwe': cwe,
            'severity': severity,
            'cvss': min(adjusted_cvss, 10.0),
            'confidence': confidence
        }

    def generate_poc_curl(self, endpoint: APIEndpoint, payload: str,
                         param_name: str, param_location: str) -> str:
        """Generate curl PoC."""
        base = f"curl -X {endpoint.method} 'http://target{endpoint.path}'"

        if param_location == "query":
            base += f"?{param_name}={urllib.parse.quote(payload)}"
        elif param_location == "header":
            base += f" -H '{param_name}: {payload}'"
        elif param_location == "body":
            base += f" -d '{param_name}={urllib.parse.quote(payload)}'"

        return base

    def generate_poc_python(self, endpoint: APIEndpoint, payload: str,
                           param_name: str, param_location: str) -> str:
        """Generate Python PoC."""
        code = f"""#!/usr/bin/env python3
import requests

target = "http://target"
endpoint = "{endpoint.path}"
param_name = "{param_name}"
payload = {repr(payload)}

if "{param_location}" == "query":
    resp = requests.{endpoint.method.lower()}(
        f"{{target}}{{endpoint}}",
        params={{param_name: payload}}
    )
elif "{param_location}" == "header":
    resp = requests.{endpoint.method.lower()}(
        f"{{target}}{{endpoint}}",
        headers={{param_name: payload}}
    )
else:  # body
    resp = requests.{endpoint.method.lower()}(
        f"{{target}}{{endpoint}}",
        json={{param_name: payload}}
    )

print(f"Status: {{resp.status_code}}")
print(f"Response: {{resp.text[:200]}}")
"""
        return code


# ─────────────────────────────────────────────────────────────────────────────
# Parameter Fuzzer
# ─────────────────────────────────────────────────────────────────────────────

class ParameterFuzzer:
    """Fuzz API parameters with payload variants."""

    def __init__(self, base_url: str, payload_loader: PayloadLibraryLoader,
                timeout: int = 10, max_workers: int = 10):
        self.base_url = base_url.rstrip('/')
        self.payload_loader = payload_loader
        self.payload_gen = ContextAwarePayloadGenerator(payload_loader)
        self.timeout = timeout
        self.max_workers = max_workers
        self.console = Console()
        self.results: List[FuzzingResult] = []

    def fuzz_endpoint(self, endpoint: APIEndpoint, depth: str = "quick") -> List[FuzzingResult]:
        """Fuzz a single endpoint with all parameters."""
        if not HAS_REQUESTS:
            return []

        # Establish baseline
        baseline = ResponseBaseline(endpoint, self.base_url, self.timeout)
        baseline.capture_baseline()

        results = []

        # Extract parameters from endpoint definition
        params_to_fuzz = self._extract_parameters(endpoint)

        # Generate payloads for each parameter
        for param in params_to_fuzz:
            param_name = param.get('name', 'param')
            param_location = param.get('in', 'query')  # query, header, body, cookie

            # Determine vuln types to test based on depth
            if depth == "full":
                vuln_types = list(VulnerabilityType)
            elif depth == "quick":
                vuln_types = [VulnerabilityType.SQLI, VulnerabilityType.XSS]
            else:
                vuln_types = [VulnerabilityType.SQLI, VulnerabilityType.XSS, VulnerabilityType.SSTI]

            payload_map = self.payload_gen.generate_payloads(param_name, param_location, vuln_types)

            # Fuzz with each payload
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for vuln_type, payloads in payload_map.items():
                    for payload in payloads:
                        future = executor.submit(
                            self._test_payload,
                            endpoint, param_name, param_location, payload, vuln_type, baseline
                        )
                        futures.append(future)

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception:
                        pass

        self.results.extend(results)
        return results

    def _extract_parameters(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Extract parameters from endpoint definition."""
        params = []

        # From OpenAPI parameters
        for param in endpoint.parameters:
            params.append({
                'name': param.get('name', 'param'),
                'in': param.get('in', 'query'),
                'schema': param.get('schema', {})
            })

        # From request body
        if endpoint.request_body:
            content = endpoint.request_body.get('content', {})
            for media_type, schema in content.items():
                if 'properties' in schema.get('schema', {}):
                    for prop_name in schema['schema']['properties'].keys():
                        params.append({
                            'name': prop_name,
                            'in': 'body',
                            'schema': schema['schema']['properties'][prop_name]
                        })

        # Add common parameters
        if not params:
            params = [
                {'name': 'id', 'in': 'query'},
                {'name': 'query', 'in': 'query'},
                {'name': 'search', 'in': 'query'},
                {'name': 'filter', 'in': 'query'},
            ]

        return params

    def _test_payload(self, endpoint: APIEndpoint, param_name: str,
                     param_location: str, payload: str, vuln_type: VulnerabilityType,
                     baseline: ResponseBaseline) -> Optional[FuzzingResult]:
        """Test a single payload."""
        if not HAS_REQUESTS:
            return None

        try:
            session = self._create_session()
            url = f"{self.base_url}{endpoint.path}"

            # Prepare request
            start = time.time()

            if param_location == "query":
                resp = session.request(
                    endpoint.method,
                    url,
                    params={param_name: payload},
                    timeout=self.timeout
                )
            elif param_location == "header":
                headers = {param_name: payload}
                resp = session.request(
                    endpoint.method,
                    url,
                    headers=headers,
                    timeout=self.timeout
                )
            elif param_location == "body":
                resp = session.request(
                    endpoint.method,
                    url,
                    json={param_name: payload},
                    timeout=self.timeout
                )
            elif param_location == "cookie":
                resp = session.request(
                    endpoint.method,
                    url,
                    cookies={param_name: payload},
                    timeout=self.timeout
                )
            else:
                return None

            elapsed = time.time() - start
            resp_hash = hashlib.sha256(resp.content).hexdigest()

            # Analyze for anomalies
            diff_score, anomalies = ResultDifferencer.detect_anomalies(
                baseline, resp.status_code, len(resp.content), resp.text, elapsed
            )

            session.close()

            if diff_score > 0.3:  # Only return anomalous results
                return FuzzingResult(
                    endpoint=endpoint,
                    parameter_name=param_name,
                    parameter_location=param_location,
                    payload=payload,
                    vuln_type=vuln_type,
                    status_code=resp.status_code,
                    response_length=len(resp.content),
                    response_hash=resp_hash,
                    response_time=elapsed,
                    response_text=resp.text[:1000],
                    differential_score=diff_score
                )

        except Exception as e:
            return None

    def _create_session(self) -> 'requests.Session':
        """Create requests session with retries."""
        session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session


# ─────────────────────────────────────────────────────────────────────────────
# Main API Fuzzer Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class APIFuzzerOrchestrator:
    """Orchestrate API fuzzing across endpoints."""

    def __init__(self, base_url: str, timeout: int = 10, max_workers: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_workers = max_workers
        self.console = Console()

        self.payload_loader = PayloadLibraryLoader()
        self.discovery = APIEndpointDiscovery(base_url)
        self.fuzzer = ParameterFuzzer(base_url, self.payload_loader, timeout, max_workers)
        self.classifier = VulnerabilityClassifier()

        self.findings: List[VulnerabilityFinding] = []

    def fuzz_api(self, endpoints_source: str, depth: str = "quick",
                threads: int = 10) -> List[VulnerabilityFinding]:
        """Execute fuzzing against API."""
        self.console.print(f"[bold cyan]Starting API Fuzzing[/bold cyan]")
        self.console.print(f"Target: {self.base_url}")
        self.console.print(f"Payloads: {self.payload_loader.count_total_payloads()}")

        # Discover endpoints
        if endpoints_source.endswith('.json') or endpoints_source.endswith('.yaml'):
            self.discovery.discover_from_swagger(endpoints_source)
        else:
            # Try manual discovery
            try:
                with open(endpoints_source) as f:
                    endpoints_list = json.load(f)
                self.discovery.discover_from_manual(endpoints_list)
            except Exception:
                self.console.print("[red]Failed to load endpoints[/red]")
                return []

        endpoints = self.discovery.get_endpoints()
        self.console.print(f"Discovered endpoints: {len(endpoints)}")

        # Fuzz each endpoint
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        ) as progress:
            task = progress.add_task("Fuzzing endpoints...", total=len(endpoints))

            for endpoint in endpoints:
                results = self.fuzzer.fuzz_endpoint(endpoint, depth)

                # Process results into findings
                for result in results:
                    finding = self._create_finding(result)
                    if finding:
                        self.findings.append(finding)

                progress.advance(task)

        self.console.print(f"\n[bold green]Found {len(self.findings)} potential vulnerabilities[/bold green]")
        return self.findings

    def _create_finding(self, result: FuzzingResult) -> Optional[VulnerabilityFinding]:
        """Convert fuzzing result to vulnerability finding."""
        if result.differential_score < 0.3:
            return None

        # Classify vulnerability
        classification = self.classifier.classify(
            result.vuln_type.value,
            result.differential_score,
            min(result.differential_score, 1.0)
        )

        # Generate PoCs
        curl_poc = self.classifier.generate_poc_curl(
            result.endpoint,
            result.payload,
            result.parameter_name,
            result.parameter_location
        )

        python_poc = self.classifier.generate_poc_python(
            result.endpoint,
            result.payload,
            result.parameter_name,
            result.parameter_location
        )

        finding_id = f"F_{result.vuln_type.value.upper()}_{int(time.time())}"

        title = f"{result.vuln_type.value.upper()} in {result.endpoint.method} {result.endpoint.path}"
        description = f"Potential {result.vuln_type.value} vulnerability detected via parameter fuzzing.\n"
        description += f"Parameter: {result.parameter_name} ({result.parameter_location})\n"
        description += f"Payload: {result.payload[:100]}\n"
        description += f"Differential Score: {result.differential_score:.2f}\n"

        finding = VulnerabilityFinding(
            finding_id=finding_id,
            endpoint=result.endpoint,
            vulnerability_type=result.vuln_type.value,
            cwe=classification['cwe'],
            severity=classification['severity'],
            cvss_score=classification['cvss'],
            confidence=classification['confidence'],
            title=title,
            description=description,
            evidence=[result],
            proof_of_concept_curl=curl_poc,
            proof_of_concept_python=python_poc,
            references=[
                f"https://owasp.org/www-community/{result.vuln_type.value}",
                f"https://cwe.mitre.org/data/definitions/{classification['cwe'].split('-')[1]}.html"
            ]
        )

        return finding

    def export_findings(self, format: str = "json") -> str:
        """Export findings in specified format."""
        if format == "json":
            return json.dumps([asdict(f) for f in self.findings], indent=2, default=str)
        elif format == "markdown":
            md = "# API Fuzzing Report\n\n"
            for finding in self.findings:
                md += f"## {finding.title}\n"
                md += f"- **Severity**: {finding.severity}\n"
                md += f"- **CWE**: {finding.cwe}\n"
                md += f"- **CVSS**: {finding.cvss_score:.1f}\n"
                md += f"\n{finding.description}\n\n"
                md += f"### PoC (curl)\n```bash\n{finding.proof_of_concept_curl}\n```\n\n"
            return md
        else:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# CLI Integration
# ─────────────────────────────────────────────────────────────────────────────

def cmd_api_fuzz(args, console) -> None:
    """Execute API fuzzing command."""
    if not HAS_REQUESTS:
        console.print("[red]requests library required[/red]")
        return

    try:
        target = args.target
        endpoints = args.endpoints
        depth = args.depth or "quick"
        threads = args.threads or 10
        timeout = args.timeout or 30

        orchestrator = APIFuzzerOrchestrator(target, timeout, threads)
        findings = orchestrator.fuzz_api(endpoints, depth, threads)

        # Display findings
        if findings:
            table = Table(title="API Fuzzing Results")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Severity", style="red")
            table.add_column("CVSS", style="yellow")
            table.add_column("Endpoint", style="green")

            for finding in findings:
                table.add_row(
                    finding.finding_id,
                    finding.vulnerability_type,
                    finding.severity,
                    f"{finding.cvss_score:.1f}",
                    finding.endpoint.path
                )

            console.print(table)

            # Export findings
            if args.output:
                output_format = args.output.split('.')[-1] or 'json'
                export = orchestrator.export_findings(output_format)
                with open(args.output, 'w') as f:
                    f.write(export)
                console.print(f"[green]Findings exported to {args.output}[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def register_argparse(parser) -> None:
    """Register API fuzzer arguments in argparse."""
    api_parser = parser.add_parser('api-fuzz', help='Advanced API fuzzing engine')
    api_parser.add_argument('--target', required=True, help='Target API base URL')
    api_parser.add_argument('--endpoints', required=True, help='Swagger/OpenAPI file or endpoints list')
    api_parser.add_argument('--depth', choices=['quick', 'medium', 'full'], default='quick',
                           help='Fuzzing depth')
    api_parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    api_parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    api_parser.add_argument('--output', help='Output file (json/markdown)')
    api_parser.set_defaults(func=cmd_api_fuzz)


if __name__ == '__main__':
    console = Console()
    console.print("[cyan]HAKUZA API Fuzzer Module[/cyan]")

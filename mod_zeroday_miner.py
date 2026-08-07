#!/usr/bin/env python3
"""
mod_zeroday_miner.py — HAKUZA AI-Powered Vulnerability Pattern Discovery Engine

Discovers UNDOCUMENTED vulnerability patterns not yet in MITRE/OWASP/CWE by mining:
  1. GitHub trending exploits (GitHubExploitScanner)
  2. CVE descriptions & NVD data (CVEPatternMatcher)
  3. Shodan honeypot trends (ShodanTrendAnalyzer)
  4. PoC code patterns via AST analysis (PoC CodeAnalyzer)
  5. Pattern generalization: 1 exploit → 100 variants (VulnerabilityPatternExtractor)
  6. Novel technique detection against HAKUZA's 250+ (NovelVulnDetector)
  7. Auto-generation of YAML technique definitions (AutomaticTechniqueCreation)

Target: discover 20-50 new vulnerability patterns monthly, 10-50x amplify finding rate.

Key principles:
  - Real-world exploit data from production sources
  - AST+semantic analysis of PoC code for pattern extraction
  - AI-powered generalization to identify related variants
  - Automatic technique YAML generation
  - Cross-source correlation to identify emerging trends
  - Integration with hakuza's technique database

Author: Divith D Shetty | CEH · CRTP · CAISP
Integration: hakuza zeroday --scan-github --scan-shodan --output techniques.yaml
"""

import os
import sys
import json
import re
import ast
import subprocess
import tempfile
import hashlib
import base64
from typing import Optional, Dict, Any, List, Tuple, Set
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
import textwrap
import urllib.parse

# Optional dependencies with graceful degradation
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


# ─────────────────────────────────────────────────────────────────────────────
# Constants & Configuration
# ─────────────────────────────────────────────────────────────────────────────

_MODEL = "claude-sonnet-4-6"
ZERODAY_CACHE_DIR = Path.home() / ".hakuza" / "zeroday_cache"
ZERODAY_OUTPUT_DIR = Path.home() / ".hakuza" / "zeroday_patterns"
ZERODAY_DB = ZERODAY_CACHE_DIR / "patterns.json"

# Pattern confidence thresholds
MIN_CONFIDENCE = 0.65
HIGH_CONFIDENCE = 0.85
CRITICAL_CONFIDENCE = 0.95

# Exploit mining limits
GITHUB_STARS_MIN = 50
GITHUB_FETCH_LIMIT = 100
CVE_LOOKBACK_DAYS = 30
SHODAN_RESULTS_MAX = 500

# CVSS severity mappings
CVSS_TO_SEVERITY = {
    (0.0, 3.9): "low",
    (4.0, 6.9): "medium",
    (7.0, 8.9): "high",
    (9.0, 10.0): "critical",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnerabilityPattern:
    """Represents a discovered vulnerability pattern."""

    pattern_id: str
    name: str
    description: str
    vuln_type: str
    cvss_score: float = 0.0
    severity: str = "medium"

    # Detection artifacts
    indicators: List[str] = field(default_factory=list)
    detection_code: str = ""
    false_positive_rate: float = 0.0

    # Sources and evidence
    sources: List[str] = field(default_factory=list)
    cve_refs: List[str] = field(default_factory=list)
    github_repos: List[str] = field(default_factory=list)

    # Generalized variants
    variants: List[Dict[str, Any]] = field(default_factory=list)
    affected_frameworks: List[str] = field(default_factory=list)

    # Novelty assessment
    novelty_score: float = 0.0  # 0-1: how new/unknown
    matches_existing_cwe: Optional[str] = None
    matches_existing_mitre: Optional[str] = None

    # Confidence & reliability
    confidence: float = 0.0  # 0-1
    validation_count: int = 0

    # Timestamps
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Exploitation metadata
    exploitation_difficulty: str = "medium"  # easy, medium, hard
    exploit_availability: bool = False
    exploit_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_yaml_technique(self) -> Dict[str, Any]:
        """Convert to HAKUZA technique YAML format."""
        return {
            "id": f"zeroday_{self.pattern_id}",
            "name": self.name,
            "mitre": [self.matches_existing_mitre] if self.matches_existing_mitre else [],
            "cwe": [self.matches_existing_cwe] if self.matches_existing_cwe else [],
            "cvss": self.cvss_score,
            "severity": self.severity,
            "description": self.description,
            "applicability_tags": [self.vuln_type.lower()] + self.affected_frameworks,
            "indicators": self.indicators,
            "prerequisites": ["target_url"],
            "procedure": f"Test for {self.name} using indicators: {'; '.join(self.indicators[:3])}",
            "expected_artifacts": ["exploit_proof", "evidence"],
            "novelty_score": self.novelty_score,
            "confidence": self.confidence,
            "variants": self.variants,
            "sources": self.sources,
        }


@dataclass
class ExploitRepo:
    """GitHub exploit repository."""

    url: str
    name: str
    stars: int
    language: str
    updated_at: str
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def vuln_type(self) -> str:
        """Infer vulnerability type from repo metadata."""
        keywords = {
            "sqli": ["sql", "injection"],
            "xss": ["xss", "cross-site"],
            "rce": ["rce", "remote code", "command injection"],
            "ssrf": ["ssrf", "request forgery"],
            "csrf": ["csrf", "cross-site request"],
            "lfi": ["lfi", "local file", "traversal"],
            "xxe": ["xxe", "xml external"],
            "idor": ["idor", "insecure direct"],
            "ssti": ["ssti", "template injection"],
            "oauth": ["oauth", "oidc"],
        }

        combined = f"{self.name} {self.description}".lower()
        for vuln_type, kws in keywords.items():
            if any(kw in combined for kw in kws):
                return vuln_type
        return "unknown"


@dataclass
class CVEPattern:
    """Pattern extracted from CVE data."""

    cve_id: str
    title: str
    description: str
    cvss_score: float
    published_date: str
    vuln_type: str
    affected_products: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None



# ─────────────────────────────────────────────────────────────────────────────
# 1. GitHub Exploit Scanner
# ─────────────────────────────────────────────────────────────────────────────

class GitHubExploitScanner:
    """Mine trending exploit repositories from GitHub."""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN", "")
        self.api_base = "https://api.github.com"
        self.session = None

    def _ensure_session(self):
        """Create HTTP session with auth if available."""
        if not HAS_REQUESTS:
            return None
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"Authorization": f"token {self.token}"})
        return self.session

    def search_exploits(self, query: str, days_back: int = 7) -> List[ExploitRepo]:
        """Search GitHub for exploit repositories matching query."""
        if not HAS_REQUESTS:
            return []

        session = self._ensure_session()
        if not session:
            return []

        repos = []
        cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat()

        # Build search query with filters
        search_query = f"{query} stars:>={GITHUB_STARS_MIN} pushed:>{cutoff_date}"

        try:
            url = f"{self.api_base}/search/repositories"
            params = {
                "q": search_query,
                "sort": "stars",
                "order": "desc",
                "per_page": min(GITHUB_FETCH_LIMIT, 100),
            }

            resp = session.get(url, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("items", [])[:GITHUB_FETCH_LIMIT]:
                repo = ExploitRepo(
                    url=item["html_url"],
                    name=item["name"],
                    stars=item["stargazers_count"],
                    language=item["language"] or "unknown",
                    updated_at=item["updated_at"],
                    description=item["description"] or "",
                )
                repos.append(repo)

        except Exception as e:
            print(f"[!] GitHub search error: {e}")

        return repos

    def fetch_trending_exploits(self, keywords: Optional[List[str]] = None) -> List[ExploitRepo]:
        """Fetch trending exploit repositories across common vuln types."""
        if keywords is None:
            keywords = [
                "exploit", "vulnerability", "poc", "rce", "sqli",
                "xss", "ssrf", "idor", "csrf", "lfi", "ssti",
            ]

        all_repos = []
        for keyword in keywords:
            repos = self.search_exploits(keyword)
            all_repos.extend(repos)

        # Deduplicate by URL
        seen_urls = set()
        unique_repos = []
        for repo in sorted(all_repos, key=lambda r: r.stars, reverse=True):
            if repo.url not in seen_urls:
                seen_urls.add(repo.url)
                unique_repos.append(repo)

        return unique_repos


# ─────────────────────────────────────────────────────────────────────────────
# 2. CVE Pattern Matcher
# ─────────────────────────────────────────────────────────────────────────────

class CVEPatternMatcher:
    """Extract patterns from CVE descriptions and NVD data."""

    def __init__(self):
        self.nvd_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = None

    def _ensure_session(self):
        """Create HTTP session."""
        if not HAS_REQUESTS:
            return None
        if not self.session:
            self.session = requests.Session()
        return self.session

    def fetch_recent_cves(self, days_back: int = CVE_LOOKBACK_DAYS) -> List[CVEPattern]:
        """Fetch recent CVEs from NVD."""
        if not HAS_REQUESTS:
            return []

        session = self._ensure_session()
        if not session:
            return []

        cves = []
        cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat()

        try:
            # NVD API v2.0 limit: 5 requests/30 seconds without API key
            params = {
                "lastModStartDate": f"{cutoff_date}Z",
                "resultsPerPage": 100,
            }

            resp = session.get(
                f"{self.nvd_base}",
                params=params,
                timeout=15,
                headers={"Accept": "application/json"}
            )
            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", [])[:100]:
                cve = vuln.get("cve", {})
                cves.append(CVEPattern(
                    cve_id=cve.get("id", ""),
                    title=cve.get("descriptions", [{}])[0].get("value", ""),
                    description=cve.get("descriptions", [{}])[0].get("value", ""),
                    cvss_score=cve.get("metrics", {}).get("cvssV31", {}).get("baseScore", 0.0),
                    published_date=cve.get("published", ""),
                    vuln_type=self._infer_vuln_type(cve.get("descriptions", [{}])[0].get("value", "")),
                ))

        except Exception as e:
            print(f"[!] CVE fetch error: {e}")

        return cves

    def _infer_vuln_type(self, description: str) -> str:
        """Infer vulnerability type from CVE description."""
        keywords = {
            "sqli": ["sql injection", "sql"],
            "xss": ["cross-site scripting", "xss"],
            "rce": ["remote code execution", "arbitrary code", "command injection"],
            "ssrf": ["server-side request forgery", "ssrf"],
            "lfi": ["local file inclusion", "path traversal"],
            "xxe": ["xml external entity", "xxe"],
            "idor": ["insecure direct object", "idor"],
            "csrf": ["cross-site request forgery", "csrf"],
            "auth": ["authentication bypass", "authorization"],
            "crypto": ["cryptographic", "weak cipher", "weak algorithm"],
        }

        desc_lower = description.lower()
        for vuln_type, kws in keywords.items():
            if any(kw in desc_lower for kw in kws):
                return vuln_type

        return "unknown"

    def extract_patterns(self, cves: List[CVEPattern]) -> List[Dict[str, Any]]:
        """Extract attack patterns from CVE data."""
        patterns = []

        for cve in cves:
            # Extract keywords and attack vectors
            keywords = self._extract_keywords(cve.description)
            pattern = {
                "cve_id": cve.cve_id,
                "vuln_type": cve.vuln_type,
                "keywords": keywords,
                "cvss": cve.cvss_score,
                "attack_complexity": cve.attack_complexity,
                "requires_auth": "authentication" in cve.description.lower(),
            }
            patterns.append(pattern)

        return patterns

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract significant keywords from description."""
        # Remove common words
        stopwords = {
            "the", "a", "an", "and", "or", "but", "in", "of", "to", "for",
            "is", "was", "been", "be", "have", "has", "do", "does", "did",
            "will", "would", "could", "should", "may", "might", "must",
        }

        words = re.findall(r'\b[a-z_]+\b', text.lower())
        return [w for w in words if len(w) > 3 and w not in stopwords]


# ─────────────────────────────────────────────────────────────────────────────
# 3. Shodan Trend Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class ShodanTrendAnalyzer:
    """Identify emerging attack vectors via Shodan honeypot trends."""

    def __init__(self):
        self.api_key = os.getenv("SHODAN_API_KEY", "")
        self.api_base = "https://api.shodan.io"

    def search_trends(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search Shodan for attack patterns."""
        if not HAS_REQUESTS or not self.api_key:
            return []

        results = []
        try:
            url = f"{self.api_base}/shodan/query/search"
            params = {
                "query": query,
                "key": self.api_key,
                "size": min(limit, SHODAN_RESULTS_MAX),
            }

            resp = requests.get(url, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            for match in data.get("matches", []):
                results.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "data": match.get("data", ""),
                    "os": match.get("os"),
                    "timestamp": match.get("timestamp"),
                })

        except Exception as e:
            print(f"[!] Shodan search error: {e}")

        return results

    def analyze_attack_vectors(self) -> List[Dict[str, Any]]:
        """Analyze emerging attack vectors from Shodan data."""
        queries = [
            "http.title:admin",
            "http.title:login",
            "device:webcam",
            "port:5900",  # VNC
            "port:3389",  # RDP
            "port:22",    # SSH
        ]

        vectors = []
        for query in queries:
            results = self.search_trends(query)
            if results:
                vectors.append({
                    "query": query,
                    "count": len(results),
                    "samples": results[:5],
                })

        return vectors


# ─────────────────────────────────────────────────────────────────────────────
# 4. PoC Code Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class PoCCodeAnalyzer:
    """AST-based pattern extraction from exploit code."""

    def extract_patterns_from_python(self, code: str) -> Dict[str, Any]:
        """Analyze Python PoC code for patterns."""
        patterns = {
            "imports": [],
            "functions": [],
            "network_calls": [],
            "file_operations": [],
            "string_patterns": [],
            "dangerous_calls": [],
        }

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                # Extract imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        patterns["imports"].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        patterns["imports"].append(node.module)

                # Extract function definitions
                elif isinstance(node, ast.FunctionDef):
                    patterns["functions"].append(node.name)

                # Extract string literals (potential payloads)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if len(node.value) > 10:  # Meaningful strings
                        patterns["string_patterns"].append(node.value[:100])

                # Detect network calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ["get", "post", "request"]:
                            patterns["network_calls"].append(node.func.attr)
                        elif node.func.attr in ["open", "write", "read"]:
                            patterns["file_operations"].append(node.func.attr)
                    elif isinstance(node.func, ast.Name):
                        if node.func.id in ["eval", "exec", "system", "popen"]:
                            patterns["dangerous_calls"].append(node.func.id)

        except SyntaxError:
            pass

        return patterns

    def analyze_javascript(self, code: str) -> Dict[str, Any]:
        """Analyze JavaScript PoC code for patterns."""
        patterns = {
            "dom_sinks": [],
            "network_calls": [],
            "eval_calls": [],
            "payload_indicators": [],
        }

        # Simple regex-based analysis (full JS parsing would require external libs)
        patterns["dom_sinks"] = re.findall(
            r'\.(innerHTML|textContent|appendChild|insertBefore)\s*=',
            code,
            re.IGNORECASE
        )

        patterns["network_calls"] = re.findall(
            r'(fetch|XMLHttpRequest|axios\.get|\.post)\s*\(',
            code,
            re.IGNORECASE
        )

        patterns["eval_calls"] = re.findall(
            r'\b(eval|Function|setTimeout|setInterval)\s*\(',
            code,
            re.IGNORECASE
        )

        # Look for payload-like strings
        patterns["payload_indicators"] = re.findall(
            r'["\'].*?(?:alert|payload|inject|exploit)["\']',
            code,
            re.IGNORECASE
        )

        return patterns


# ─────────────────────────────────────────────────────────────────────────────
# 5. Vulnerability Pattern Extractor
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityPatternExtractor:
    """Generalize exploit patterns to identify variants."""

    def __init__(self, client: Optional[Any] = None):
        self.client = client

    def generalize_pattern(self, exploit_sample: str, vuln_type: str) -> List[Dict[str, Any]]:
        """Use AI to generalize one exploit into many variants."""
        if not HAS_ANTHROPIC or not self.client:
            return self._generalize_heuristic(exploit_sample, vuln_type)

        try:
            prompt = f"""Analyze this {vuln_type} exploit and generate 5-10 related attack variants:

```
{exploit_sample[:1000]}
```

For each variant, provide:
1. Attack pattern (high-level description)
2. Payload template
3. Detection indicators
4. Target frameworks/languages affected

Format as JSON array with objects: {{
  "variant_id": "v1",
  "pattern": "...",
  "payload_template": "...",
  "indicators": ["...", "..."],
  "targets": ["framework1", "framework2"]
}}"""

            msg = self.client.messages.create(
                model=_MODEL,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            # Extract JSON from response
            response_text = msg.content[0].text
            json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
            if json_match:
                variants = json.loads(json_match.group())
                return variants

        except Exception as e:
            print(f"[!] Generalization error: {e}")

        return self._generalize_heuristic(exploit_sample, vuln_type)

    def _generalize_heuristic(self, exploit: str, vuln_type: str) -> List[Dict[str, Any]]:
        """Heuristic-based generalization without AI."""
        variants = []

        # Extract patterns
        strings = re.findall(r"['\"]([^'\"]{20,})['\"]", exploit)
        functions = re.findall(r'\b([a-z_]+)\s*\(', exploit.lower())

        # Generate variants by parameterizing
        base_pattern = {
            "variant_id": "v1",
            "pattern": f"{vuln_type} via parameter injection",
            "indicators": strings[:3] if strings else [],
            "targets": [f"framework_{i}" for i in range(3)],
        }

        variants.append(base_pattern)
        return variants

    def identify_affected_frameworks(self, pattern: Dict[str, Any]) -> List[str]:
        """Identify frameworks affected by pattern."""
        frameworks = []

        # Map indicators to known vulnerable frameworks
        framework_map = {
            "wordpress": ["wordpress", "wp-", "wpdb"],
            "django": ["django", "settings.py", "views.py"],
            "rails": ["rails", "activerecord", "erb"],
            "laravel": ["laravel", "blade", "eloquent"],
            "nodejs": ["node", "express", "req.query"],
            "php": ["php", "serialize", "$_"],
            "aspnet": ["asp.net", "web.config", "viewstate"],
            "jsp": ["jsp", "request.getParameter"],
        }

        indicators = pattern.get("indicators", [])
        for framework, keywords in framework_map.items():
            if any(kw.lower() in str(ind).lower() for ind in indicators for kw in keywords):
                frameworks.append(framework)

        return frameworks if frameworks else ["generic"]


# ─────────────────────────────────────────────────────────────────────────────
# 6. Novel Vulnerability Detector
# ─────────────────────────────────────────────────────────────────────────────

class NovelVulnDetector:
    """Identify techniques not yet in HAKUZA's 250+ vulnerabilities."""

    def __init__(self, existing_techniques: Optional[List[Dict[str, Any]]] = None):
        self.existing = existing_techniques or []
        self.existing_ids = {t.get("id") for t in self.existing}
        self.existing_keywords = self._extract_keywords(self.existing)

    def _extract_keywords(self, techniques: List[Dict[str, Any]]) -> Set[str]:
        """Extract keywords from existing techniques."""
        keywords = set()
        for tech in techniques:
            name = tech.get("name", "").lower()
            desc = tech.get("description", "").lower()
            keywords.update(re.findall(r'\b\w{4,}\b', f"{name} {desc}"))
        return keywords

    def compute_novelty_score(self, pattern: VulnerabilityPattern) -> float:
        """Compute novelty score 0-1 (0=known, 1=completely novel)."""
        score = 0.0

        # Check for direct CWE/MITRE matches
        if pattern.matches_existing_cwe or pattern.matches_existing_mitre:
            return 0.1  # Very low novelty if directly matches

        # Check keyword overlap with existing techniques
        pattern_keywords = set(re.findall(r'\b\w{4,}\b', pattern.name.lower()))
        overlap = len(pattern_keywords & self.existing_keywords)
        keyword_similarity = overlap / len(pattern_keywords) if pattern_keywords else 0.0

        # High novelty if minimal keyword overlap
        score += (1.0 - keyword_similarity) * 0.5

        # Check for novel combinations
        if self._is_novel_combination(pattern):
            score += 0.3

        # Confidence adjustment
        score *= pattern.confidence

        return min(score, 1.0)

    def _is_novel_combination(self, pattern: VulnerabilityPattern) -> bool:
        """Check if pattern is a novel combination of known techniques."""
        # Simple heuristic: if affects multiple frameworks or combines multiple indicators
        return len(pattern.affected_frameworks) > 2 or len(pattern.indicators) > 5

    def filter_novel_patterns(self, patterns: List[VulnerabilityPattern]) -> List[VulnerabilityPattern]:
        """Filter and rank patterns by novelty."""
        novel = []
        for pattern in patterns:
            novelty = self.compute_novelty_score(pattern)
            pattern.novelty_score = novelty
            if novelty > 0.5:  # Only keep reasonably novel patterns
                novel.append(pattern)

        # Sort by novelty descending
        return sorted(novel, key=lambda p: p.novelty_score, reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Automatic Technique Creation
# ─────────────────────────────────────────────────────────────────────────────

class AutomaticTechniqueCreation:
    """Generate YAML technique definitions from vulnerability patterns."""

    def __init__(self, client: Optional[Any] = None):
        self.client = client

    def create_technique(self, pattern: VulnerabilityPattern) -> Dict[str, Any]:
        """Create HAKUZA technique YAML from pattern."""
        return pattern.to_yaml_technique()

    def create_procedure_description(self, pattern: VulnerabilityPattern) -> str:
        """Generate detailed procedure description."""
        if not HAS_ANTHROPIC or not self.client:
            return self._default_procedure(pattern)

        try:
            prompt = f"""Generate a detailed penetration testing procedure for detecting:

Name: {pattern.name}
Type: {pattern.vuln_type}
Indicators: {', '.join(pattern.indicators[:5])}
Frameworks: {', '.join(pattern.affected_frameworks[:3])}

Provide step-by-step procedure (2-3 sentences) suitable for a pentest playbook."""

            msg = self.client.messages.create(
                model=_MODEL,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )

            return msg.content[0].text

        except Exception:
            return self._default_procedure(pattern)

    def _default_procedure(self, pattern: VulnerabilityPattern) -> str:
        """Default procedure template."""
        indicators_str = "; ".join(pattern.indicators[:3])
        frameworks_str = ", ".join(pattern.affected_frameworks[:2])
        return (
            f"Test parameters using indicators ({indicators_str}). "
            f"Verify exploitation on {frameworks_str}. "
            f"Confirm via out-of-band callback or response observation."
        )

    def generate_yaml_file(self, patterns: List[VulnerabilityPattern], output_path: Optional[Path] = None) -> str:
        """Generate complete YAML technique file."""
        if output_path is None:
            output_path = ZERODAY_OUTPUT_DIR / "zeroday_techniques.yaml"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        techniques = {
            "techniques": [p.to_yaml_technique() for p in patterns]
        }

        if HAS_YAML:
            with open(output_path, 'w') as f:
                yaml.dump(techniques, f, default_flow_style=False, sort_keys=False)
        else:
            # Fallback: JSON output if PyYAML not available
            with open(output_path.with_suffix('.json'), 'w') as f:
                json.dump(techniques, f, indent=2)

        return str(output_path)


# ─────────────────────────────────────────────────────────────────────────────
# Zeroday Miner Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class ZerodayMiner:
    """Main orchestrator for vulnerability pattern discovery."""

    def __init__(self, client: Optional[Any] = None):
        self.client = client
        self.github_scanner = GitHubExploitScanner()
        self.cve_matcher = CVEPatternMatcher()
        self.shodan_analyzer = ShodanTrendAnalyzer()
        self.poc_analyzer = PoCCodeAnalyzer()
        self.pattern_extractor = VulnerabilityPatternExtractor(client)
        self.novel_detector = NovelVulnDetector()
        self.technique_creator = AutomaticTechniqueCreation(client)

        self.discovered_patterns: List[VulnerabilityPattern] = []

    def run_full_scan(
        self,
        scan_github: bool = True,
        scan_cve: bool = True,
        scan_shodan: bool = False,
        output_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Execute complete zeroday discovery pipeline."""

        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "patterns_discovered": 0,
            "novel_patterns": 0,
            "patterns": [],
            "sources": [],
        }

        # Phase 1: GitHub exploit mining
        if scan_github:
            print("[*] Phase 1: Mining GitHub exploits...")
            github_repos = self.github_scanner.fetch_trending_exploits()
            results["sources"].extend([r.url for r in github_repos[:20]])

            for repo in github_repos[:20]:
                pattern = self._pattern_from_github(repo)
                if pattern:
                    self.discovered_patterns.append(pattern)

        # Phase 2: CVE pattern extraction
        if scan_cve:
            print("[*] Phase 2: Extracting CVE patterns...")
            cves = self.cve_matcher.fetch_recent_cves()
            results["sources"].extend([c.cve_id for c in cves[:10]])

            for cve in cves[:20]:
                pattern = self._pattern_from_cve(cve)
                if pattern:
                    self.discovered_patterns.append(pattern)

        # Phase 3: Shodan trend analysis
        if scan_shodan:
            print("[*] Phase 3: Analyzing Shodan trends...")
            vectors = self.shodan_analyzer.analyze_attack_vectors()
            for vector in vectors:
                pattern = self._pattern_from_shodan(vector)
                if pattern:
                    self.discovered_patterns.append(pattern)

        # Phase 4: Pattern generalization
        print(f"[*] Phase 4: Generalizing {len(self.discovered_patterns)} patterns...")
        self._generalize_patterns()

        # Phase 5: Novelty detection
        print("[*] Phase 5: Assessing novelty...")
        novel_patterns = self.novel_detector.filter_novel_patterns(self.discovered_patterns)

        # Phase 6: Technique generation
        print(f"[*] Phase 6: Generating {len(novel_patterns)} technique definitions...")
        output_file = self.technique_creator.generate_yaml_file(novel_patterns, output_path)

        results["patterns_discovered"] = len(self.discovered_patterns)
        results["novel_patterns"] = len(novel_patterns)
        results["patterns"] = [p.to_dict() for p in novel_patterns[:50]]
        results["output_file"] = output_file

        return results

    def _pattern_from_github(self, repo: ExploitRepo) -> Optional[VulnerabilityPattern]:
        """Extract pattern from GitHub repository."""
        try:
            pattern = VulnerabilityPattern(
                pattern_id=hashlib.sha256(repo.url.encode()).hexdigest()[:12],
                name=f"{repo.vuln_type().upper()} - {repo.name}",
                description=repo.description or f"Exploit for {repo.name}",
                vuln_type=repo.vuln_type(),
                sources=[repo.url],
                github_repos=[repo.url],
                indicators=[repo.name.lower()],
                affected_frameworks=[repo.language.lower()] if repo.language else [],
                confidence=min(0.7 + (repo.stars / 1000), 0.95),
                exploit_availability=True,
                exploit_url=repo.url,
            )
            return pattern
        except Exception:
            return None

    def _pattern_from_cve(self, cve: CVEPattern) -> Optional[VulnerabilityPattern]:
        """Extract pattern from CVE data."""
        try:
            pattern = VulnerabilityPattern(
                pattern_id=hashlib.sha256(cve.cve_id.encode()).hexdigest()[:12],
                name=cve.title,
                description=cve.description[:500],
                vuln_type=cve.vuln_type,
                cvss_score=cve.cvss_score,
                severity=self._cvss_to_severity(cve.cvss_score),
                sources=[cve.cve_id],
                cve_refs=[cve.cve_id],
                indicators=self.cve_matcher._extract_keywords(cve.description),
                affected_frameworks=cve.affected_products[:3],
                confidence=0.8 + (cve.cvss_score / 100),
            )
            return pattern
        except Exception:
            return None

    def _pattern_from_shodan(self, vector: Dict[str, Any]) -> Optional[VulnerabilityPattern]:
        """Extract pattern from Shodan data."""
        try:
            pattern = VulnerabilityPattern(
                pattern_id=hashlib.sha256(str(vector).encode()).hexdigest()[:12],
                name=f"Shodan Vector - {vector.get('query', 'unknown')}",
                description=f"Attack vector detected by Shodan: {vector.get('query')}",
                vuln_type="reconnaissance",
                sources=[f"shodan:{vector.get('query')}"],
                indicators=[vector.get('query')],
                confidence=0.6,
            )
            return pattern
        except Exception:
            return None

    def _generalize_patterns(self):
        """Generalize patterns to identify variants."""
        for pattern in self.discovered_patterns:
            if pattern.github_repos:
                # Try to generalize from exploit URL
                variants = self.pattern_extractor.generalize_pattern(
                    pattern.description, pattern.vuln_type
                )
                pattern.variants = variants[:5]  # Keep top 5 variants
                pattern.affected_frameworks.extend(
                    self.pattern_extractor.identify_affected_frameworks(
                        {"indicators": pattern.indicators}
                    )
                )

    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity."""
        for (min_s, max_s), severity in CVSS_TO_SEVERITY.items():
            if min_s <= score <= max_s:
                return severity
        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# CLI Command Handler
# ─────────────────────────────────────────────────────────────────────────────

def cmd_zeroday(args, console):
    """CLI handler for hakuza zeroday command."""

    console.print(
        "[bold cyan]HAKUZA Zeroday Miner[/bold cyan] — "
        "AI-Powered Vulnerability Pattern Discovery"
    )

    # Initialize paths
    ZERODAY_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ZERODAY_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Create miner instance
    client = None
    if HAS_ANTHROPIC:
        try:
            client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        except Exception as e:
            console.print(f"[yellow]Warning: Claude client unavailable: {e}[/yellow]")

    miner = ZerodayMiner(client=client)

    # Execute scan
    console.print("\n[bold]Scanning for novel vulnerability patterns...[/bold]")
    console.print(f"  GitHub mining: {args.scan_github}")
    console.print(f"  CVE analysis: {args.scan_cve}")
    console.print(f"  Shodan trends: {args.scan_shodan}")

    results = miner.run_full_scan(
        scan_github=args.scan_github,
        scan_cve=args.scan_cve,
        scan_shodan=args.scan_shodan,
        output_path=Path(args.output) if args.output else None,
    )

    # Display results
    console.print("\n[bold]═══ DISCOVERY RESULTS ═══[/bold]")
    console.print(f"  Total patterns discovered: {results['patterns_discovered']}")
    console.print(f"  Novel patterns (novelty > 0.5): {results['novel_patterns']}")
    console.print(f"  Technique YAML: {results.get('output_file', 'N/A')}")

    if results.get("patterns"):
        console.print("\n[bold]Top Novel Patterns:[/bold]")
        for i, pattern in enumerate(results["patterns"][:10], 1):
            console.print(
                f"\n  [{i}] {pattern['name']} ({pattern['vuln_type'].upper()})"
                f"\n      Novelty: {pattern['novelty_score']:.2%} | "
                f"Confidence: {pattern['confidence']:.2%} | "
                f"Severity: {pattern['severity'].upper()}"
            )

    console.print(f"\n[green]✓ Scan complete. Results saved to {results.get('output_file')}[/green]")


# ─────────────────────────────────────────────────────────────────────────────
# Integration with hakuza CLI (at end of hakuza.py)
# ─────────────────────────────────────────────────────────────────────────────

def register_zeroday_command(parser):
    """Register zeroday command with hakuza argument parser."""
    p_zeroday = parser.add_parser(
        "zeroday",
        help="AI-powered vulnerability pattern discovery from GitHub/CVE/Shodan"
    )
    p_zeroday.add_argument(
        "--scan-github",
        action="store_true",
        default=True,
        help="Mine trending exploit repositories from GitHub"
    )
    p_zeroday.add_argument(
        "--scan-cve",
        action="store_true",
        default=True,
        help="Extract patterns from recent CVE descriptions"
    )
    p_zeroday.add_argument(
        "--scan-shodan",
        action="store_true",
        default=False,
        help="Analyze emerging attack vectors from Shodan"
    )
    p_zeroday.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output YAML file path (default: ~/.hakuza/zeroday_patterns/zeroday_techniques.yaml)"
    )
    p_zeroday.add_argument(
        "--deep-scan",
        action="store_true",
        default=False,
        help="Extended scan with more sources and longer processing"
    )


if __name__ == "__main__":
    print("mod_zeroday_miner.py — Use via hakuza zeroday command")
    print("or import as a Python module")

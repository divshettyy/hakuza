#!/usr/bin/env python3
"""
HAKUZA Fireteam Module — Parallel agent coordination for concurrent investigation
Multi-angle reconnaissance and exploitation with sync gates
"""

import threading
import queue
import json
from typing import List, Dict, Any, Callable, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class WaveSpec:
    """Specification for one Fireteam wave (batch of parallel agents)."""
    wave_id: str
    num_agents: int
    investigation_angles: List[str]  # e.g. ["subdomain_enum", "web_recon", "cloud_enum", "api_scan"]
    timeout_seconds: int = 300
    approval_gate: bool = False  # Require approval before executing findings from this wave


@dataclass
class AgentResult:
    """Result from one agent in a Fireteam wave."""
    agent_id: str
    angle: str
    status: str  # "success", "blocked", "timeout", "error"
    findings: List[Dict[str, Any]]
    logs: str
    duration_seconds: float


class FireteamCoordinator:
    """
    Coordinates parallel investigation agents for concurrent offense.

    Pattern (from RedAmon):
    - Fan out N agents, each investigating different angles (recon, web, cloud, api, etc.)
    - Each agent runs independently with timeout + resource limits
    - Sync gate: wait for all agents in wave → consolidate results → apply filter
    - Approval gate: human reviews discoveries before auto-exploitation
    - Next wave: orchestrator plans next set of angles based on findings so far
    """

    def __init__(self, engagement_id: str, db_conn, engagement_name: str):
        self.engagement_id = engagement_id
        self.engagement_name = engagement_name
        self.db = db_conn
        self.result_queue = queue.Queue()
        self.wave_results = []
        self.thread_pool = []
        self.total_findings = 0

    def run_wave(self, wave: WaveSpec) -> List[AgentResult]:
        """
        Execute one Fireteam wave: fan out agents, sync, consolidate results.

        Returns list of AgentResult from all agents in this wave.
        """
        console.print(f"\n[bold cyan]Fireteam Wave: {wave.wave_id}[/bold cyan]")
        console.print(f"  Agents: {wave.num_agents}")
        console.print(f"  Angles: {', '.join(wave.investigation_angles)}")
        console.print(f"  Timeout: {wave.timeout_seconds}s")
        console.print("─" * 80)

        # 1. Fan out: spawn N agents for N angles
        threads = []
        for i, angle in enumerate(wave.investigation_angles):
            agent_id = f"{wave.wave_id}-agent-{i}"
            t = threading.Thread(
                target=self._run_agent,
                args=(agent_id, angle, wave.timeout_seconds),
                daemon=True
            )
            t.start()
            threads.append(t)
            console.print(f"  [dim]Spawned agent {agent_id}: {angle}[/dim]")

        # 2. Sync gate: wait for all to complete (with timeout)
        for t in threads:
            t.join(timeout=wave.timeout_seconds + 10)

        # 3. Collect results
        wave_results = []
        while not self.result_queue.empty():
            try:
                result = self.result_queue.get_nowait()
                wave_results.append(result)
            except queue.Empty:
                break

        # 4. Consolidate
        total_wave_findings = sum(len(r.findings) for r in wave_results)
        self.total_findings += total_wave_findings

        console.print(f"\n[bold]Wave Results:[/bold]")
        for result in wave_results:
            status_color = "green" if result.status == "success" else "yellow"
            console.print(f"  [{status_color}]{result.agent_id}[/{status_color}]: {result.angle} → {len(result.findings)} findings ({result.duration_seconds:.1f}s)")

        # 5. Approval gate (if configured)
        if wave.approval_gate and total_wave_findings > 0:
            if not Confirm.ask(f"    Approve {total_wave_findings} findings from this wave?"):
                console.print("  [yellow]Wave findings rejected by user[/yellow]")
                return wave_results

        # 6. Persist findings to DB
        for result in wave_results:
            for finding in result.findings:
                add_finding(
                    engagement_id=self.engagement_id,
                    title=finding.get("title", "Unknown"),
                    severity=finding.get("severity", "low"),
                    description=finding.get("description"),
                    evidence=finding.get("evidence"),
                    tool=f"fireteam-{result.angle}",
                    technique_id=finding.get("technique_id"),
                    cve_id=finding.get("cve_id"),
                    curl_poc=finding.get("curl_poc"),
                )

        self.wave_results.append(wave_results)
        return wave_results

    def _run_agent(self, agent_id: str, angle: str, timeout: int) -> None:
        """Execute one investigation angle in a dedicated thread."""
        start = datetime.now()
        results = []
        logs = ""
        status = "success"

        try:
            # Dispatch to angle-specific handler
            results, logs = self._execute_angle(angle, timeout)

        except Exception as e:
            status = "error"
            logs = f"Error: {str(e)}"

        duration = (datetime.now() - start).total_seconds()

        result = AgentResult(
            agent_id=agent_id,
            angle=angle,
            status=status,
            findings=results,
            logs=logs,
            duration_seconds=duration,
        )

        self.result_queue.put(result)

    def _execute_angle(self, angle: str, timeout: int) -> tuple:
        """Execute an investigation angle. Returns (findings_list, logs_str)."""

        handlers = {
            "subdomain_enum": self._angle_subdomain_enum,
            "web_recon": self._angle_web_recon,
            "api_scan": self._angle_api_scan,
            "cloud_enum": self._angle_cloud_enum,
            "network_scan": self._angle_network_scan,
            "vulnerability_scan": self._angle_vulnerability_scan,
            "secret_hunting": self._angle_secret_hunting,
            "supply_chain": self._angle_supply_chain,
        }

        handler = handlers.get(angle)
        if not handler:
            return [], f"Unknown angle: {angle}"

        return handler(timeout)

    def _angle_subdomain_enum(self, timeout: int) -> tuple:
        """Enumerate subdomains in parallel (crt.sh, subfinder, hackertarget, etc.)"""
        # Placeholder: actual implementation would call subfinder, amass, etc.
        return [
            {
                "title": "Subdomain Discovered: api.example.com",
                "severity": "low",
                "description": "New subdomain discovered via CT log",
                "evidence": "api.example.com resolves to 203.0.113.45",
            }
        ], "Subdomain enumeration completed"

    def _angle_web_recon(self, timeout: int) -> tuple:
        """Web application reconnaissance: tech fingerprint, headers, paths"""
        return [], "Web recon placeholder"

    def _angle_api_scan(self, timeout: int) -> tuple:
        """API discovery and testing: GraphQL, REST, SOAP"""
        return [], "API scan placeholder"

    def _angle_cloud_enum(self, timeout: int) -> tuple:
        """Cloud asset enumeration: S3, GCP storage, Azure blobs"""
        return [], "Cloud enum placeholder"

    def _angle_network_scan(self, timeout: int) -> tuple:
        """Network reconnaissance: Nmap, service fingerprint"""
        return [], "Network scan placeholder"

    def _angle_vulnerability_scan(self, timeout: int) -> tuple:
        """Vulnerability scanning: Nuclei, Nessus integration"""
        return [], "Vulnerability scan placeholder"

    def _angle_secret_hunting(self, timeout: int) -> tuple:
        """Secret/credential exposure detection: JS files, git repos, env files"""
        return [], "Secret hunting placeholder"

    def _angle_supply_chain(self, timeout: int) -> tuple:
        """Supply chain attack surface: dependencies, 3rd-party services"""
        return [], "Supply chain analysis placeholder"

    def summary(self) -> Dict[str, Any]:
        """Return summary of all waves."""
        return {
            "engagement_id": self.engagement_id,
            "total_waves": len(self.wave_results),
            "total_findings": self.total_findings,
            "findings_by_severity": self._count_by_severity(),
            "timestamp": datetime.now().isoformat(),
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity across all waves."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for wave_results in self.wave_results:
            for result in wave_results:
                for finding in result.findings:
                    sev = finding.get("severity", "info")
                    if sev in counts:
                        counts[sev] += 1
        return counts


def cmd_fireteam(args) -> None:
    """Run Fireteam parallel investigation."""
    engagement_name = args.engagement or get_config_value("current_engagement")
    if not engagement_name:
        console.print("[red]No engagement selected[/red]")
        return

    engagement = get_engagement(engagement_name)
    if not engagement:
        console.print(f"[red]Engagement not found: {engagement_name}[/red]")
        return

    console.print(f"\n[bold cyan]HAKUZA Fireteam — Parallel Investigation[/bold cyan]")
    console.print(f"Target: {engagement['target']}")
    console.print()

    coordinator = FireteamCoordinator(engagement["id"], get_db(), engagement_name)

    # Define waves of investigation
    waves = [
        WaveSpec(
            wave_id="wave-1-recon",
            num_agents=3,
            investigation_angles=["subdomain_enum", "web_recon", "cloud_enum"],
            timeout_seconds=120,
            approval_gate=False,
        ),
        WaveSpec(
            wave_id="wave-2-scanning",
            num_agents=3,
            investigation_angles=["api_scan", "vulnerability_scan", "secret_hunting"],
            timeout_seconds=180,
            approval_gate=True,
        ),
        WaveSpec(
            wave_id="wave-3-depth",
            num_agents=2,
            investigation_angles=["supply_chain", "network_scan"],
            timeout_seconds=150,
            approval_gate=True,
        ),
    ]

    # Execute waves sequentially (with internal parallelism)
    for wave in waves:
        coordinator.run_wave(wave)

    # Summary
    summary = coordinator.summary()
    console.print(f"\n[bold cyan]Fireteam Summary[/bold cyan]")
    console.print(f"  Waves: {summary['total_waves']}")
    console.print(f"  Total Findings: {summary['total_findings']}")
    console.print(f"  Severity Breakdown: {summary['findings_by_severity']}")


# ─────────────────────────────────────────────────────────────────────────────
# ARGPARSE ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In build_parser(), inside the sub-commands block, add:

#   p_ft = sub.add_parser("fireteam",
#       help="Run parallel Fireteam investigation (N agents, multiple angles)",
#       description="Fan out parallel agents investigating: recon, web, cloud, api, network, vulns, secrets"
#   )
#   p_ft.add_argument("--engagement", "-e", help="Engagement name (default: current)")
#   p_ft.add_argument("--waves", type=int, default=3, help="Number of waves (default: 3)")
#   p_ft.set_defaults(func=cmd_fireteam)

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In main(), in the dispatch dict, add:

#   "fireteam": cmd_fireteam,

#!/usr/bin/env python3
"""
HAKUZA Master Orchestrator — Central coordinator for autonomous red-team operations
Orchestrates: ReAct planning, Fireteam waves, technique execution, PoC generation, attack-graph enrichment
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import anthropic


class MasterOrchestrator:
    """
    Central orchestrator for full autonomous red-team engagement.

    Flow:
    1. **Planning Phase**: LLM reads engagement state, formulates comprehensive strategy
    2. **Wave Orchestration**: Fan out Fireteam parallel investigation waves
    3. **Technique Execution**: Execute planned techniques via handlers
    4. **PoC Generation**: Generate reproducible exploits for each finding
    5. **Graph Enrichment**: Populate attack-surface graph with discovered topology
    6. **Reporting**: Compile findings, attack paths, remediation prioritization
    """

    def __init__(self, engagement_id: str, engagement_name: str, db_conn, client: anthropic.Anthropic):
        self.engagement_id = engagement_id
        self.engagement_name = engagement_name
        self.db = db_conn
        self.client = client
        self.state = {
            "current_phase": "planning",
            "total_findings": 0,
            "total_fireteam_waves": 0,
            "techniques_executed": [],
            "pocs_generated": 0,
            "graph_nodes": 0,
            "start_time": datetime.now().isoformat(),
        }

    def execute_full_engagement(self, max_waves: int = 5, autonomous: bool = True) -> Dict[str, Any]:
        """
        Execute full autonomous red-team engagement:
        Plan → Fireteam Waves → Technique Execution → PoC Gen → Graph → Report

        Args:
            max_waves: Maximum Fireteam waves to execute
            autonomous: If True, run without approval gates; if False, get human approval

        Returns:
            Engagement summary with findings, attack paths, remediation prioritization
        """

        console.print("\n" + "=" * 80)
        console.print("[bold cyan]HAKUZA Master Orchestrator — Full Autonomous Engagement[/bold cyan]")
        console.print("=" * 80)

        engagement = get_engagement(self.engagement_name)
        console.print(f"Target: {engagement['target']}")
        console.print(f"Type: {engagement['type']}")
        console.print(f"Autonomous Mode: {'Yes' if autonomous else 'No (approval gates enabled)'}")
        console.print()

        # Phase 1: Strategic Planning
        console.print("[bold]Phase 1: Strategic Planning[/bold]")
        strategy = self._generate_strategy(engagement, max_waves)
        console.print(f"  Strategy: {strategy.get('name', 'Custom')}")
        console.print(f"  Planned Waves: {strategy.get('num_waves', 0)}")
        console.print(f"  Planned Techniques: {len(strategy.get('techniques', []))}")

        if not autonomous and not Confirm.ask("  Approve strategy and begin execution?"):
            console.print("[yellow]Execution cancelled by user[/yellow]")
            return self.state

        # Phase 2: Fireteam Parallel Reconnaissance
        console.print("\n[bold]Phase 2: Fireteam Parallel Reconnaissance[/bold]")
        fireteam_coordinator = FireteamCoordinator(self.engagement_id, self.db, self.engagement_name)
        for i in range(min(strategy.get("num_waves", 3), max_waves)):
            wave = strategy.get("waves", [])[i] if i < len(strategy.get("waves", [])) else None
            if not wave:
                break
            wave_results = fireteam_coordinator.run_wave(wave)
            self.state["total_fireteam_waves"] += 1
            self.state["total_findings"] += sum(len(r.findings) for r in wave_results)

        # Phase 3: Technique Execution
        console.print("\n[bold]Phase 3: Technique-Driven Exploitation[/bold]")
        findings = list_findings(self.engagement_id)
        techniques_to_test = strategy.get("techniques", [])
        for technique_id in techniques_to_test:
            console.print(f"  Testing: {technique_id}")
            # Call execution handler
            # result = execute_technique(technique_id, engagement['target'], ..., self.db)
            self.state["techniques_executed"].append(technique_id)

        # Phase 4: PoC Generation
        console.print("\n[bold]Phase 4: Automated PoC Generation[/bold]")
        new_findings = list_findings(self.engagement_id)
        for finding in new_findings:
            if finding.get("cve_id") and not finding.get("curl_poc"):
                console.print(f"  Generating PoC for {finding['title']}...")
                # poc = generate_poc_for_finding(finding, test_enabled=True)
                # if poc:
                #     update_finding(finding['id'], curl_poc=poc)
                #     self.state["pocs_generated"] += 1

        # Phase 5: Attack-Surface Graph Enrichment
        console.print("\n[bold]Phase 5: Attack-Surface Graph Analysis[/bold]")
        # for finding in new_findings:
        #     url = finding.get('url', '')
        #     if url:
        #         host, port = parse_url(url)
        #         add_service(host, port, ...)
        #         add_vulnerability(host_id, service_id, finding['cve_id'], finding['severity'], finding['technique_id'])
        #     self.state["graph_nodes"] += 1

        # Phase 6: Attack-Path Analysis
        console.print("\n[bold]Phase 6: Attack-Path Discovery[/bold]")
        attack_paths = self._discover_attack_paths()
        console.print(f"  Discovered {len(attack_paths)} potential attack chains")

        # Phase 7: Reporting
        console.print("\n[bold]Phase 7: Comprehensive Reporting[/bold]")
        report = self._generate_report(findings, attack_paths)
        console.print(f"  Report: {len(report.get('findings', []))} findings")
        console.print(f"  Attack Paths: {len(report.get('attack_paths', []))}")
        console.print(f"  Severity: {report.get('severity_breakdown', {})}")

        self.state["current_phase"] = "complete"
        self.state["end_time"] = datetime.now().isoformat()

        return self._build_summary(report)

    def _generate_strategy(self, engagement: Dict[str, Any], max_waves: int) -> Dict[str, Any]:
        """
        Use LLM to generate comprehensive attack strategy based on target type and scope.
        """

        prompt = f"""
        Generate a comprehensive attack strategy for a {engagement['type']} penetration test.

        Target: {engagement['target']}
        Scope: {engagement.get('scope', 'Unknown')}

        Respond in JSON format:
        {{
            "name": "Strategy Name",
            "num_waves": 3,
            "waves": [
                {{"wave_id": "wave-1", "angles": ["subdomain_enum", "web_recon"]}},
                {{"wave_id": "wave-2", "angles": ["api_scan", "vulnerability_scan"]}}
            ],
            "techniques": ["xss_reflected", "sqli_error", "ssrf_cloud_metadata", ...],
            "risk_level": "high",
            "estimated_time_minutes": 120
        }}
        """

        message = self.client.messages.create(
            model="claude-opus-4-1-20250805",
            max_tokens=1024,
            system="You are a red-team strategist. Generate aggressive but systematic attack strategies.",
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            strategy_text = message.content[0].text
            strategy = json.loads(strategy_text)
            return strategy
        except:
            # Fallback strategy
            return {
                "name": "Default Web Pentest",
                "num_waves": 3,
                "waves": [
                    WaveSpec("wave-1", 3, ["subdomain_enum", "web_recon", "cloud_enum"], 120),
                    WaveSpec("wave-2", 3, ["api_scan", "vulnerability_scan", "secret_hunting"], 180),
                ],
                "techniques": ["xss_reflected", "sqli_error", "ssrf_cloud_metadata"],
            }

    def _discover_attack_paths(self) -> List[Dict[str, Any]]:
        """
        Query attack-surface graph to find attack chains.
        Returns list of {start: "host1", path: ["vuln1", "vuln2"], end: "host2", risk: "critical"}
        """
        # TODO: Query attack_graph tables for chains
        return []

    def _generate_report(self, findings: List[Dict], attack_paths: List[Dict]) -> Dict[str, Any]:
        """
        Generate comprehensive penetration test report with findings, chains, remediation.
        """
        return {
            "findings": findings,
            "attack_paths": attack_paths,
            "severity_breakdown": self._count_severity(findings),
            "techniques_used": self.state["techniques_executed"],
            "pocs_included": self.state["pocs_generated"],
        }

    def _count_severity(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _build_summary(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Build final engagement summary."""
        self.state["report"] = report
        return self.state


def cmd_master_orchestrate(args) -> None:
    """
    Run full Master Orchestrator autonomous engagement.
    Entry point: `hakuza master-orchestrate [--autonomous] [--max-waves N]`
    """

    engagement_name = args.engagement or get_config_value("current_engagement")
    if not engagement_name:
        console.print("[red]No engagement selected[/red]")
        return

    engagement = get_engagement(engagement_name)
    if not engagement:
        console.print(f"[red]Engagement not found: {engagement_name}[/red]")
        return

    client = anthropic.Anthropic()
    orchestrator = MasterOrchestrator(engagement["id"], engagement_name, get_db(), client)

    summary = orchestrator.execute_full_engagement(
        max_waves=args.max_waves or 5,
        autonomous=args.autonomous or False,
    )

    console.print("\n" + "=" * 80)
    console.print("[bold cyan]Engagement Complete[/bold cyan]")
    console.print(f"  Findings: {summary['total_findings']}")
    console.print(f"  Fireteam Waves: {summary['total_fireteam_waves']}")
    console.print(f"  Techniques: {len(summary['techniques_executed'])}")
    console.print(f"  PoCs Generated: {summary['pocs_generated']}")
    console.print(f"  Attack-Surface Nodes: {summary['graph_nodes']}")
    console.print("=" * 80)


# ─────────────────────────────────────────────────────────────────────────────
# ARGPARSE ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In build_parser(), inside the sub-commands block, add:

#   p_master = sub.add_parser("master-orchestrate",
#       help="Run full autonomous red-team engagement (all phases)",
#       description="Orchestrates planning, Fireteam waves, technique execution, PoC generation, attack-graph enrichment, and reporting"
#   )
#   p_master.add_argument("--engagement", "-e", help="Engagement name (default: current)")
#   p_master.add_argument("--max-waves", type=int, default=5, help="Max Fireteam waves (default: 5)")
#   p_master.add_argument("--autonomous", action="store_true", help="Run fully autonomous (no approval gates)")
#   p_master.set_defaults(func=cmd_master_orchestrate)

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In main(), in the dispatch dict, add:

#   "master-orchestrate": cmd_master_orchestrate,

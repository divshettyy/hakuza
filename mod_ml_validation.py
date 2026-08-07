#!/usr/bin/env python3
"""
HAKUZA ML Validation — Performance Metrics & Model Evaluation
==============================================================

Validates the ML prioritization model against historical data.

Functions:
- validate_prioritization()     → Test ranking accuracy on past engagements
- calculate_speedup()           → Measure efficiency gains (40% target)
- benchmark_top_k_accuracy()    → Measure % of P1 findings in top-K techniques
- generate_validation_report()  → Create comprehensive evaluation report

Usage:
    python3 mod_ml_validation.py --db ~/.hakuza/hakuza.db
"""

import json
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict
import statistics

from mod_ml_prioritizer import MLPrioritizer, TECHNIQUE_CATEGORIES


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION METRICS
# ─────────────────────────────────────────────────────────────────────────────

class ValidationMetrics:
    """Container for validation results."""

    def __init__(self):
        self.top_k_accuracies = {}  # {k: accuracy}
        self.avg_rank_of_p1_findings = None
        self.speedup_factor = None
        self.precision_at_k = {}  # {k: precision}
        self.recall_at_k = {}  # {k: recall}
        self.mrr = None  # Mean Reciprocal Rank
        self.ndcg_at_k = {}  # NDCG@k

    def to_dict(self) -> dict:
        """Serialize metrics."""
        return {
            "top_k_accuracies": self.top_k_accuracies,
            "avg_rank_of_p1_findings": self.avg_rank_of_p1_findings,
            "speedup_factor": self.speedup_factor,
            "precision_at_k": self.precision_at_k,
            "recall_at_k": self.recall_at_k,
            "mrr": self.mrr,
            "ndcg_at_k": self.ndcg_at_k,
        }


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def validate_on_engagement(
    prioritizer: MLPrioritizer,
    engagement_findings: List[Dict],
    target_url: str = "test_target"
) -> Dict:
    """
    Validate prioritization on a single engagement.

    Returns:
        {
            "p1_findings_count": int,
            "techniques_ranked": list of technique IDs in order,
            "techniques_that_found_p1": list of technique IDs that found P1,
            "rank_of_first_p1": int,
            "accuracy": float (% of P1 findings found in top-10)
        }
    """
    # Count critical/high findings (P1)
    p1_findings = [f for f in engagement_findings
                   if f.get("severity") in ("critical", "high")]

    if not p1_findings:
        return {
            "p1_findings_count": 0,
            "techniques_ranked": [],
            "techniques_that_found_p1": [],
            "rank_of_first_p1": None,
            "accuracy": 0.0,
        }

    # Get ranking
    ranked_techniques = prioritizer.predict_ranked_techniques(
        target_url=target_url,
        findings=engagement_findings,
        top_k=20
    )

    techniques_ranked = [t["technique_id"] for t in ranked_techniques]

    # Find which techniques found P1s
    techniques_that_found_p1 = []
    for finding in p1_findings:
        category = finding.get("category")
        if category:
            # Map category to technique
            tech_ids = [t for t, meta in TECHNIQUE_CATEGORIES.items()
                       if meta["category"] == category]
            techniques_that_found_p1.extend(tech_ids)

    techniques_that_found_p1 = list(set(techniques_that_found_p1))

    # Calculate metrics
    rank_of_first_p1 = None
    for rank, tech_id in enumerate(techniques_ranked, 1):
        if tech_id in techniques_that_found_p1:
            rank_of_first_p1 = rank
            break

    # Calculate accuracy: % of P1-finding techniques in top-10
    top_10_techniques = set(techniques_ranked[:10])
    p1_techniques_in_top10 = len(
        set(techniques_that_found_p1) & top_10_techniques
    )
    accuracy = p1_techniques_in_top10 / len(techniques_that_found_p1) if techniques_that_found_p1 else 0.0

    return {
        "p1_findings_count": len(p1_findings),
        "techniques_ranked": techniques_ranked,
        "techniques_that_found_p1": techniques_that_found_p1,
        "rank_of_first_p1": rank_of_first_p1,
        "accuracy": accuracy,
    }


def benchmark_top_k_accuracy(prioritizer: MLPrioritizer,
                            engagements: List[Dict]) -> Tuple[Dict, float]:
    """
    Calculate top-K accuracy across all test engagements.

    Returns:
        (accuracies_dict, avg_speedup_factor)
    """
    accuracies_by_k = defaultdict(list)
    times_to_first_p1 = []
    time_random_order = []

    for eng in engagements:
        findings = eng.get("findings", [])
        target_url = eng.get("target_url", "unknown")

        validation = validate_on_engagement(prioritizer, findings, target_url)

        if validation["p1_findings_count"] == 0:
            continue

        # Record accuracy for different K values
        for k in [5, 10, 15, 20]:
            techniques_ranked = validation["techniques_ranked"][:k]
            p1_techniques = set(validation["techniques_that_found_p1"])
            accuracy = len([t for t in techniques_ranked if t in p1_techniques]) / len(p1_techniques) if p1_techniques else 0.0
            accuracies_by_k[k].append(accuracy)

        # Estimate speedup (rank of first P1 / total techniques)
        rank = validation["rank_of_first_p1"]
        if rank:
            times_to_first_p1.append(rank)
            time_random_order.append(len(TECHNIQUE_CATEGORIES) // 2)

    # Calculate averages
    results = {}
    for k in sorted(accuracies_by_k.keys()):
        if accuracies_by_k[k]:
            results[f"top_{k}"] = statistics.mean(accuracies_by_k[k])

    # Calculate speedup factor
    speedup = None
    if time_random_order:
        avg_time_ml = statistics.mean(times_to_first_p1)
        avg_time_random = statistics.mean(time_random_order)
        speedup = avg_time_random / avg_time_ml

    return results, speedup


def calculate_mrr(validations: List[Dict]) -> float:
    """Calculate Mean Reciprocal Rank."""
    ranks = [v.get("rank_of_first_p1") for v in validations
             if v.get("rank_of_first_p1") is not None]

    if not ranks:
        return 0.0

    rrs = [1.0 / rank for rank in ranks]
    return statistics.mean(rrs)


def calculate_ndcg_at_k(ranked_techniques: List[str],
                       p1_techniques: List[str],
                       k: int = 10) -> float:
    """
    Calculate Normalized Discounted Cumulative Gain.

    Lower rank = higher value
    """
    dcg = 0.0
    for rank, tech in enumerate(ranked_techniques[:k], 1):
        if tech in p1_techniques:
            dcg += 1.0 / (1.0 + (rank - 1))  # Discount by rank

    # Ideal: all P1 techniques at the top
    idcg = sum(1.0 / (1.0 + i) for i in range(min(len(p1_techniques), k)))

    if idcg == 0:
        return 0.0

    return dcg / idcg


# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def generate_validation_report(
    prioritizer: MLPrioritizer,
    engagements: List[Dict],
    output_path: str = "/tmp/ml_validation_report.json"
) -> Dict:
    """Generate comprehensive validation report."""
    print("[cyan]Running validation on all engagements...[/cyan]\n")

    validations = []
    for eng in engagements:
        validation = validate_on_engagement(
            prioritizer,
            eng.get("findings", []),
            eng.get("target_url", "unknown")
        )
        validations.append(validation)

    # Calculate metrics
    accuracies, speedup = benchmark_top_k_accuracy(prioritizer, engagements)
    mrr = calculate_mrr(validations)

    report = {
        "summary": {
            "total_engagements": len(engagements),
            "engagements_with_p1": len([v for v in validations if v["p1_findings_count"] > 0]),
            "average_p1_findings_per_eng": statistics.mean(
                [v["p1_findings_count"] for v in validations if v["p1_findings_count"] > 0]
            ) if any(v["p1_findings_count"] for v in validations) else 0,
        },
        "ranking_accuracy": accuracies,
        "speedup_factor": speedup,
        "mean_reciprocal_rank": mrr,
        "model_status": {
            "techniques_learned": len(prioritizer.technique_stats),
            "target_fingerprints": len(prioritizer.target_fingerprints),
            "total_technique_runs": sum(
                s.total_runs for s in prioritizer.technique_stats.values()
            ),
        },
    }

    # Print summary
    print("[bold cyan]VALIDATION RESULTS[/bold cyan]")
    print("=" * 60)

    print(f"\n[bold]Ranking Accuracy[/bold]")
    for k, acc in sorted(accuracies.items()):
        print(f"  {k}: {acc:.1%}")

    if speedup:
        print(f"\n[bold]Efficiency Gains[/bold]")
        print(f"  Speedup Factor: {speedup:.1f}x")
        print(f"  Time Reduction: {(1 - 1/speedup)*100:.1f}%")

    print(f"\n[bold]Mean Reciprocal Rank: {mrr:.2f}[/bold]")

    # Save report
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[green]✓ Report saved to: {output_path}[/green]")

    return report


# ─────────────────────────────────────────────────────────────────────────────
# COMPARISON: ML vs RANDOM
# ─────────────────────────────────────────────────────────────────────────────

def compare_ml_vs_random(engagements: List[Dict]) -> Dict:
    """Compare ML prioritization vs random technique order."""
    import random

    prioritizer = MLPrioritizer()

    ml_times_to_p1 = []
    random_times_to_p1 = []

    for eng in engagements:
        findings = eng.get("findings", [])
        p1_findings = [f for f in findings if f.get("severity") in ("critical", "high")]

        if not p1_findings:
            continue

        # ML approach
        validation = validate_on_engagement(prioritizer, findings, eng.get("target_url", "unknown"))
        if validation["rank_of_first_p1"]:
            ml_times_to_p1.append(validation["rank_of_first_p1"])

        # Random approach: random rank
        max_rank = len(TECHNIQUE_CATEGORIES)
        random_times_to_p1.append(random.randint(1, max_rank))

    if not ml_times_to_p1:
        return {}

    avg_ml_time = statistics.mean(ml_times_to_p1)
    avg_random_time = statistics.mean(random_times_to_p1)

    return {
        "ml_avg_rank_to_p1": avg_ml_time,
        "random_avg_rank_to_p1": avg_random_time,
        "speedup": avg_random_time / avg_ml_time,
        "time_saved_percent": (1 - avg_ml_time / avg_random_time) * 100,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate ML prioritization model")
    parser.add_argument("--data", default="sample_training_data.json",
                       help="Sample training data file")
    parser.add_argument("--output", default="/tmp/ml_validation_report.json",
                       help="Output report path")

    args = parser.parse_args()

    # Load sample data
    with open(args.data) as f:
        data = json.load(f)

    engagements = data.get("sample_engagements", [])

    # Run validation
    prioritizer = MLPrioritizer()
    report = generate_validation_report(prioritizer, engagements, args.output)

    # Compare with random
    comparison = compare_ml_vs_random(engagements)
    print("\n[bold cyan]ML vs RANDOM Comparison[/bold cyan]")
    print("=" * 60)
    print(f"ML approach (avg rank to P1): {comparison.get('ml_avg_rank_to_p1', 'N/A'):.1f}")
    print(f"Random approach (avg rank): {comparison.get('random_avg_rank_to_p1', 'N/A'):.1f}")
    print(f"Speedup: {comparison.get('speedup', 'N/A'):.1f}x")
    print(f"Time saved: {comparison.get('time_saved_percent', 'N/A'):.1f}%")

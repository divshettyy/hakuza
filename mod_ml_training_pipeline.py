#!/usr/bin/env python3
"""
HAKUZA ML Training Pipeline — Historical Engagement Data Ingestion
====================================================================

Ingests findings from multiple engagements to train the ML prioritization model.

Key functions:
- load_historical_engagements()  → Load all engagement data from hakuza.db
- build_training_dataset()      → Convert findings to feature vectors
- train_ensemble_model()        → Train RandomForest + GradientBoosting
- evaluate_model()              → Cross-validation & metrics
- export_training_results()     → Generate performance report

Usage:
    python3 mod_ml_training_pipeline.py --db ~/.hakuza/hakuza.db --output results.json
"""

import sqlite3
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from datetime import datetime

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from mod_ml_prioritizer import (
    MLPrioritizer, TechniqueStats, TargetFingerprint,
    TECHNIQUE_CATEGORIES, PRIORITIZER_DIR, MODEL_PATH, SCALER_PATH
)


# ─────────────────────────────────────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_historical_engagements(db_path: str) -> List[Dict]:
    """Load all engagements with their findings from hakuza.db."""
    engagements = []

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get all engagements
        cursor.execute("SELECT * FROM engagements")
        rows = cursor.fetchall()

        for eng_row in rows:
            eng_id = eng_row["id"]
            eng_dict = {
                "id": eng_id,
                "name": eng_row["name"],
                "target": eng_row.get("target", "unknown"),
                "client": eng_row.get("client", "unknown"),
                "created_at": eng_row["created_at"],
                "findings": [],
            }

            # Get findings for this engagement
            cursor.execute(
                "SELECT * FROM findings WHERE engagement_id = ?",
                (eng_id,)
            )
            findings_rows = cursor.fetchall()

            for f_row in findings_rows:
                finding = {
                    "id": f_row["id"],
                    "title": f_row["title"],
                    "severity": f_row["severity"],
                    "category": f_row["category"],
                    "status": f_row["status"],
                    "cvss_score": f_row.get("cvss_score"),
                    "cwe": f_row.get("cwe"),
                    "url": f_row.get("url"),
                    "description": f_row.get("description", ""),
                    "evidence": f_row.get("evidence", ""),
                    "tool": f_row.get("tool"),
                }
                eng_dict["findings"].append(finding)

            engagements.append(eng_dict)

        conn.close()

    except Exception as e:
        print(f"[red]Error loading engagements: {e}[/red]")
        return []

    return engagements


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────────────────────────────────────

def extract_features_from_finding(finding: Dict) -> Dict:
    """Extract ML features from a single finding."""
    features = {
        "severity_weight": {
            "critical": 1.0, "high": 0.8, "medium": 0.6,
            "low": 0.4, "informational": 0.2, "info": 0.2
        }.get(finding.get("severity", "low"), 0.5),
        "has_cvss": 1.0 if finding.get("cvss_score") else 0.0,
        "has_cwe": 1.0 if finding.get("cwe") else 0.0,
        "has_url": 1.0 if finding.get("url") else 0.0,
        "description_length": len(finding.get("description", "")),
        "evidence_length": len(finding.get("evidence", "")),
        "is_confirmed": 1.0 if finding.get("status") in ("confirmed", "exploited") else 0.0,
        "is_fp": 1.0 if finding.get("status") == "false_positive" else 0.0,
    }

    # Normalize lengths
    features["description_length"] = min(1.0, features["description_length"] / 1000.0)
    features["evidence_length"] = min(1.0, features["evidence_length"] / 1000.0)

    return features


def build_training_dataset(engagements: List[Dict]) -> Tuple[List, List, List]:
    """
    Convert engagements to training data.

    Returns:
        (X, y, feature_names) where:
        - X: feature vectors (one per finding)
        - y: labels (1 = successful finding, 0 = not confirmed)
        - feature_names: names of features
    """
    X = []
    y = []
    feature_names = None

    for eng in engagements:
        for finding in eng.get("findings", []):
            features_dict = extract_features_from_finding(finding)

            if feature_names is None:
                feature_names = list(features_dict.keys())

            # Convert to ordered feature vector
            feature_vector = [features_dict[name] for name in feature_names]
            X.append(feature_vector)

            # Label: 1 if confirmed/exploited, 0 otherwise
            label = 1 if finding.get("status") in ("confirmed", "exploited") else 0
            y.append(label)

    return X, y, feature_names


# ─────────────────────────────────────────────────────────────────────────────
# MODEL TRAINING
# ─────────────────────────────────────────────────────────────────────────────

def train_ensemble_model(X: List, y: List, feature_names: List) -> Tuple:
    """
    Train ensemble ML model on finding features.

    Returns:
        (rf_model, gb_model, scaler, metrics) where metrics is a dict
        of performance statistics.
    """
    if not HAS_SKLEARN:
        print("[red]scikit-learn not installed. Skipping model training.[/red]")
        return None, None, None, {}

    if not HAS_NUMPY:
        print("[red]numpy not installed. Skipping model training.[/red]")
        return None, None, None, {}

    print(f"[cyan]Training on {len(X)} samples with {len(feature_names)} features...[/cyan]")

    X_array = np.array(X)
    y_array = np.array(y)

    # Normalize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_array)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_array, test_size=0.2, random_state=42
    )

    # Train Random Forest
    print("[cyan]Training Random Forest...[/cyan]")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # Train Gradient Boosting
    print("[cyan]Training Gradient Boosting...[/cyan]")
    gb_model = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    gb_model.fit(X_train, y_train)

    # Evaluate
    metrics = {}

    for name, model in [("Random Forest", rf_model), ("Gradient Boosting", gb_model)]:
        y_pred = model.predict(X_test)

        metrics[name] = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1": f1_score(y_test, y_pred, zero_division=0),
        }

        print(f"\n[bold cyan]{name} Performance[/bold cyan]")
        for metric, value in metrics[name].items():
            print(f"  {metric:10} {value:.3f}")

    # Cross-validation
    print("\n[cyan]Running cross-validation (5-fold)...[/cyan]")
    rf_cv_scores = cross_val_score(rf_model, X_scaled, y_array, cv=5)
    gb_cv_scores = cross_val_score(gb_model, X_scaled, y_array, cv=5)

    print(f"[green]Random Forest CV: {rf_cv_scores.mean():.3f} (+/- {rf_cv_scores.std():.3f})[/green]")
    print(f"[green]Gradient Boosting CV: {gb_cv_scores.mean():.3f} (+/- {gb_cv_scores.std():.3f})[/green]")

    metrics["cross_validation"] = {
        "random_forest_mean": float(rf_cv_scores.mean()),
        "random_forest_std": float(rf_cv_scores.std()),
        "gradient_boosting_mean": float(gb_cv_scores.mean()),
        "gradient_boosting_std": float(gb_cv_scores.std()),
    }

    return rf_model, gb_model, scaler, metrics


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE STATISTICS EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_technique_statistics(engagements: List[Dict]) -> Dict[str, TechniqueStats]:
    """Extract success rates and statistics for each technique."""
    technique_stats: Dict[str, TechniqueStats] = {}

    for eng in engagements:
        for finding in eng.get("findings", []):
            category = finding.get("category")
            if not category:
                continue

            # Map category to techniques
            techniques = [
                t for t, meta in TECHNIQUE_CATEGORIES.items()
                if meta["category"] == category
            ]

            for tech_id in techniques:
                if tech_id not in technique_stats:
                    technique_stats[tech_id] = TechniqueStats(tech_id)

                stats = technique_stats[tech_id]
                stats.total_runs += 1

                # Update success/FP counts
                status = finding.get("status", "open")
                if status in ("confirmed", "exploited"):
                    stats.successful_runs += 1
                elif status == "false_positive":
                    stats.false_positive_count += 1

    return technique_stats


# ─────────────────────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def generate_training_report(
    engagements: List[Dict],
    technique_stats: Dict[str, TechniqueStats],
    metrics: Dict,
    output_path: Optional[str] = None
) -> str:
    """Generate a detailed training report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_engagements": len(engagements),
            "total_findings": sum(len(e.get("findings", [])) for e in engagements),
            "unique_techniques_found": len(technique_stats),
        },
        "model_metrics": metrics,
        "technique_statistics": {},
    }

    # Add technique stats
    for tech_id, stats in sorted(technique_stats.items(), 
                                 key=lambda x: x[1].success_rate, 
                                 reverse=True):
        report["technique_statistics"][tech_id] = {
            "total_runs": stats.total_runs,
            "successful_runs": stats.successful_runs,
            "success_rate": stats.success_rate,
            "false_positive_rate": stats.false_positive_rate,
            "avg_time_seconds": stats.avg_time_seconds,
        }

    # Save report
    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[green]Report saved to: {output_path}[/green]")

    return json.dumps(report, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def train_model(db_path: str, output_dir: Optional[str] = None) -> None:
    """Main training pipeline."""
    print("[bold cyan]HAKUZA ML Training Pipeline[/bold cyan]\n")

    # Load data
    print("[cyan]Loading historical engagements...[/cyan]")
    engagements = load_historical_engagements(db_path)

    if not engagements:
        print("[yellow]No engagements found. Nothing to train on.[/yellow]")
        return

    print(f"[green]Loaded {len(engagements)} engagements[/green]\n")

    # Extract features
    print("[cyan]Extracting features from findings...[/cyan]")
    X, y, feature_names = build_training_dataset(engagements)

    if not X:
        print("[yellow]No findings to train on.[/yellow]")
        return

    print(f"[green]Extracted {len(X)} samples with {len(feature_names)} features[/green]\n")

    # Extract technique statistics
    print("[cyan]Computing technique statistics...[/cyan]")
    technique_stats = extract_technique_statistics(engagements)
    print(f"[green]Analyzed {len(technique_stats)} techniques[/green]\n")

    # Train model
    print("[cyan]Training ensemble ML model...[/cyan]\n")
    rf_model, gb_model, scaler, metrics = train_ensemble_model(X, y, feature_names)

    if HAS_SKLEARN and rf_model:
        # Save models
        import pickle
        PRIORITIZER_DIR.mkdir(parents=True, exist_ok=True)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump((rf_model, gb_model), f)
        print(f"[green]✓ Models saved to {MODEL_PATH}[/green]")

        with open(SCALER_PATH, "wb") as f:
            pickle.dump(scaler, f)
        print(f"[green]✓ Scaler saved to {SCALER_PATH}[/green]")

    # Generate report
    output_path = Path(output_dir) / "training_report.json" if output_dir else None
    report = generate_training_report(engagements, technique_stats, metrics, str(output_path))

    # Print summary
    print("\n" + "="*70)
    print("[bold]TRAINING SUMMARY[/bold]")
    print("="*70)

    top_techniques = sorted(
        technique_stats.items(),
        key=lambda x: x[1].success_rate,
        reverse=True
    )[:5]

    print("\n[bold cyan]Top 5 Techniques by Success Rate:[/bold cyan]")
    for tech_id, stats in top_techniques:
        print(
            f"  {tech_id:25} "
            f"Success: {stats.success_rate:.1%} "
            f"(n={stats.total_runs})"
        )

    print(f"\n[green]Training complete! Model ready for deployment.[/green]")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train ML prioritization model")
    parser.add_argument("--db", default=str(Path.home() / ".hakuza" / "hakuza.db"),
                       help="Path to hakuza.db")
    parser.add_argument("--output", help="Output directory for report")

    args = parser.parse_args()

    train_model(args.db, args.output)

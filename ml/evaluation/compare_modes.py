"""
Benchmark script comparing:
1. Rules-only (DSA Security Engine)
2. Model-only (LogisticRegression v2.0.0)
3. Combined Ensemble (Option A: Fusion + Critical Overrides)
on the held-out test split of phishing_dataset_v2.csv (n=625, 440 unique unseen domains).
"""

from __future__ import annotations

import sys
import json
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.dsa import scan_url_dsa
from backend.app.services.ml_service import ml_service
from backend.app.services.pipeline import run_scan
from backend.app.services.feature_extractor import extract_features

DATASET_PATH = PROJECT_ROOT / "ml" / "datasets" / "phishing_dataset_v2.csv"


def benchmark_all_modes():
    df = pd.read_csv(DATASET_PATH)
    test_df = df[df["split"] == "test"].copy()
    print(f"Loaded held-out test set: {len(test_df)} URLs, {test_df['domain'].nunique()} domains")
    y_true = test_df["label"].values

    rules_preds = []
    rules_scores = []
    model_preds = []
    model_scores = []
    ensemble_preds = []
    ensemble_scores = []

    for idx, row in test_df.iterrows():
        url = row["url"]
        
        # 1. Rules-only
        dsa_res = scan_url_dsa(url, check_network=False)
        r_score = dsa_res.get("rule_score", dsa_res.get("risk_score", 0))
        rules_scores.append(r_score / 100.0)
        rules_preds.append(1 if r_score >= 45 else 0)

        # 2. Model-only
        feats = extract_features(url, check_network=False)
        feats.update(dsa_res.get("features", {}))
        prob, _ = ml_service.predict_probability(feats)
        model_scores.append(prob)
        model_preds.append(1 if prob >= 0.50 else 0)

        # 3. Combined Ensemble
        scan_res = run_scan(url, check_network=False)
        e_score = scan_res.risk_score
        ensemble_scores.append(e_score / 100.0)
        ensemble_preds.append(1 if e_score >= 45 else 0)

    modes = {
        "Rules-Only (DSA)": (rules_preds, rules_scores),
        "Model-Only (ML v2.0.0)": (model_preds, model_scores),
        "Combined Ensemble (Option A)": (ensemble_preds, ensemble_scores),
    }

    results = {}
    print("\n" + "=" * 80)
    print(f"{'Mode':<30} | {'Acc':<7} | {'Prec':<7} | {'Recall':<7} | {'F1':<7} | {'ROC-AUC':<8} | {'FP':<4} | {'FN':<4}")
    print("-" * 80)

    for name, (preds, scores) in modes.items():
        acc = accuracy_score(y_true, preds)
        prec = precision_score(y_true, preds, zero_division=0)
        rec = recall_score(y_true, preds, zero_division=0)
        f1 = f1_score(y_true, preds, zero_division=0)
        roc = roc_auc_score(y_true, scores)
        cm = confusion_matrix(y_true, preds)
        tn, fp, fn, tp = cm.ravel()

        results[name] = {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
            "roc_auc": float(roc),
            "cm": cm.tolist(),
            "fp": int(fp),
            "fn": int(fn)
        }
        print(f"{name:<30} | {acc*100:5.2f}% | {prec*100:5.2f}% | {rec*100:5.2f}% | {f1*100:5.2f}% | {roc:7.4f} | {fp:<4} | {fn:<4}")

    print("=" * 80)

    output_path = PROJECT_ROOT / "ml" / "evaluation" / "mode_comparison_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved benchmark results to {output_path}")


if __name__ == "__main__":
    benchmark_all_modes()


"""Evaluate the saved phishing model on the deterministic held-out test split."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import numpy.typing as npt
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.training.extract_features import FEATURE_COLUMNS, extract_features_from_url

DATASET_PATH = PROJECT_ROOT / "ml" / "datasets" / "phishing_dataset.csv"
MODEL_PATH = PROJECT_ROOT / "ml" / "models" / "phishing_model.joblib"
METADATA_PATH = PROJECT_ROOT / "ml" / "models" / "model_metadata.json"
METRICS_PATH = PROJECT_ROOT / "ml" / "evaluation" / "metrics.json"
TEST_SIZE = 0.15
RANDOM_STATE = 42


def validate_dataset(dataset: pd.DataFrame) -> None:
    """Reject invalid or duplicate examples so they cannot cross the split."""
    missing_columns = {"url", "label"} - set(dataset.columns)
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing_columns)}")
    if dataset.empty:
        raise ValueError("Dataset contains no rows.")
    if dataset[["url", "label"]].isna().any().any():
        raise ValueError("Dataset contains missing URLs or labels.")
    if not dataset["url"].map(lambda value: isinstance(value, str) and bool(value.strip())).all():
        raise ValueError("Every dataset URL must be a non-empty string.")
    if dataset["url"].duplicated().any():
        raise ValueError("Dataset contains duplicate URLs; remove duplicates before evaluation.")
    labels = set(dataset["label"].unique())
    if labels != {0, 1}:
        found_labels = sorted((repr(label) for label in labels))
        raise ValueError(
            f"Labels must contain both binary classes 0 and 1; found {found_labels}."
        )


def calculate_metrics(
    y_true: npt.ArrayLike,
    y_pred: npt.ArrayLike,
    y_score: npt.ArrayLike,
    *,
    model_version: str,
    model_type: str,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build the persisted metrics payload using phishing (label 1) as positive."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "test_set_size": int(np.asarray(y_true).size),
        "model_version": model_version,
        "model_type": model_type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
    }


def evaluate_artifacts(
    dataset_path: Path = DATASET_PATH,
    model_path: Path = MODEL_PATH,
    metadata_path: Path = METADATA_PATH,
) -> dict[str, Any]:
    """Load project artifacts and score the saved model on the original test split."""
    dataset = pd.read_csv(dataset_path)
    validate_dataset(dataset)

    labels = dataset["label"].to_numpy()
    _, test_indices = train_test_split(
        np.arange(len(dataset)),
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    feature_rows = [
        [extract_features_from_url(url)[column] for column in FEATURE_COLUMNS]
        for url in dataset["url"]
    ]
    test_features = np.asarray(feature_rows, dtype=np.float64)[test_indices]
    test_labels = labels[test_indices]

    model = joblib.load(model_path)
    predictions = model.predict(test_features)
    probabilities = model.predict_proba(test_features)
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("Loaded model does not expose phishing class 1.")
    phishing_scores = probabilities[:, classes.index(1)]

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("Model metadata must be a JSON object.")
    model_version = metadata.get("model_version")
    model_type = metadata.get("model_type")
    if not model_version or not model_type:
        raise ValueError("Model metadata must define model_version and model_type.")

    return calculate_metrics(
        test_labels,
        predictions,
        phishing_scores,
        model_version=model_version,
        model_type=model_type,
    )


def write_metrics(metrics: dict[str, Any], output_path: Path = METRICS_PATH) -> None:
    """Write the metrics file without leaving a partial JSON file on interruption."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    temporary_path.replace(output_path)


def print_report(metrics: dict[str, Any]) -> None:
    matrix = metrics["confusion_matrix"]
    print(f"Model:              {metrics['model_type']} ({metrics['model_version']})")
    print(f"Test set size:      {metrics['test_set_size']}")
    print(f"Accuracy:           {metrics['accuracy']:.2%}")
    print(f"Precision (phish):  {metrics['precision']:.2%}")
    print(f"Recall (phish):     {metrics['recall']:.2%}")
    print(f"F1 (phish):         {metrics['f1']:.2%}")
    print(f"ROC-AUC:            {metrics['roc_auc']:.6f}")
    print(f"Confusion matrix:   {matrix}  [[TN, FP], [FN, TP]]")
    print(f"Timestamp (UTC):    {metrics['timestamp']}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--metadata", type=Path, default=METADATA_PATH)
    parser.add_argument("--output", type=Path, default=METRICS_PATH)
    args = parser.parse_args(argv)

    for path, description in (
        (args.dataset, "Dataset"),
        (args.model, "Model"),
        (args.metadata, "Model metadata"),
    ):
        if not path.is_file():
            print(f"ERROR: {description} file not found: {path}", file=sys.stderr)
            return 2

    try:
        metrics = evaluate_artifacts(args.dataset, args.model, args.metadata)
        write_metrics(metrics, args.output)
    except (OSError, ValueError, json.JSONDecodeError, pd.errors.ParserError) as exc:
        print(f"ERROR: Evaluation failed: {exc}", file=sys.stderr)
        return 2

    print_report(metrics)
    print(f"Saved metrics:      {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

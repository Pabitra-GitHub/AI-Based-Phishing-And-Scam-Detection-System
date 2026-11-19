import pytest

from ml.evaluation.evaluate import calculate_metrics, validate_dataset
import pandas as pd


def test_calculate_metrics_reports_phishing_positive_class():
    metrics = calculate_metrics(
        [0, 0, 1, 1],
        [0, 1, 1, 1],
        [0.1, 0.7, 0.9, 0.8],
        model_version="test-v1",
        model_type="test-model",
        timestamp="2026-01-01T00:00:00+00:00",
    )

    assert metrics["accuracy"] == 0.75
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == pytest.approx(0.8)
    assert metrics["roc_auc"] == 1.0
    assert metrics["confusion_matrix"] == [[1, 1], [0, 2]]
    assert metrics["test_set_size"] == 4
    assert metrics["model_version"] == "test-v1"


def test_validate_dataset_rejects_duplicate_urls():
    dataset = pd.DataFrame({
        "url": ["https://example.com", "https://example.com"],
        "label": [0, 0],
    })

    with pytest.raises(ValueError, match="duplicate URLs"):
        validate_dataset(dataset)

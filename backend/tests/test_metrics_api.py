import json

from backend.app.api.v1.endpoints import metrics as metrics_endpoint


def test_metrics_endpoint_returns_saved_evaluation(client, tmp_path, monkeypatch):
    saved_metrics = {
        "accuracy": 0.95,
        "precision": 0.9,
        "recall": 1.0,
        "f1": 0.9473684210526316,
        "roc_auc": 0.98,
        "confusion_matrix": [[9, 1], [0, 10]],
        "test_set_size": 20,
        "model_version": "test-v1",
        "model_type": "LogisticRegression",
        "timestamp": "2026-01-01T00:00:00+00:00",
    }
    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(json.dumps(saved_metrics), encoding="utf-8")
    monkeypatch.setattr(metrics_endpoint, "METRICS_PATH", metrics_path)

    for path in ("/api/metrics", "/api/v1/metrics"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json() == saved_metrics


def test_metrics_endpoint_reports_missing_metrics(client, tmp_path, monkeypatch):
    monkeypatch.setattr(metrics_endpoint, "METRICS_PATH", tmp_path / "missing.json")

    response = client.get("/api/v1/metrics")

    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"].lower()

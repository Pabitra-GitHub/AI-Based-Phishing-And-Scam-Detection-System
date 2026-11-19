"""
Unit & Integration tests for 6-Layer Pipeline Orchestrator and Ensemble Scoring
"""

from backend.app.services.pipeline import run_scan


def test_clean_authentic_url_scan():
    # Clean authentic URL
    result = run_scan("https://www.google.com", check_network=False)
    assert result.classification == "SAFE"
    assert result.risk_score <= 25
    assert len(result.layer_results) >= 4
    assert "L1" in result.layers_executed
    assert "L2" in result.layers_executed
    assert "L6" in result.layers_executed


def test_typosquatting_phishing_url_scan():
    # Typosquatting impersonation URL
    result = run_scan(
        "http://paypa1-account-security-update.tk/login.php", check_network=False
    )
    assert result.classification in ("HIGH RISK", "CRITICAL", "SUSPICIOUS")
    assert result.risk_score >= 50
    assert len(result.all_findings) > 0
    assert any(f.layer in ("L1", "L2", "L3", "L4") for f in result.all_findings)


def test_pipeline_produces_all_layer_structures():
    result = run_scan("https://example.com", check_network=False)
    assert result.url == "https://example.com"
    assert len(result.layer_results) >= 5
    assert isinstance(result.features, dict)
    assert result.model_version is not None
    assert result.recommendation != ""

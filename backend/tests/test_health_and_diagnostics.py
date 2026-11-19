"""
Phase 8 Test Suite: Health & Diagnostics Endpoint.
Validates:
1. Health endpoint returns status 200 OK.
2. Reports database connection status as healthy.
3. Reports ML model status, version, and feature count.
4. Reports threat intelligence status and cache configuration.
"""

def test_health_check_endpoint(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "checks" in data

    # Database check
    db_check = data["checks"]["database"]
    assert db_check["status"] == "healthy"

    # ML model check
    ml_check = data["checks"]["machine_learning"]
    assert ml_check["status"] == "healthy"
    assert ml_check["model_version"] == "v2.0.0"
    assert ml_check["feature_count"] > 0

    # Threat intel check
    ti_check = data["checks"]["threat_intelligence"]
    assert ti_check["status"] == "operational"
    assert "configured_feeds" in ti_check


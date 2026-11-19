from backend.app.core.security import create_access_token
from backend.app.models.user import User


def test_public_and_authenticated_scan(client, db_session):
    # 1. Public scan without auth header
    pub_res = client.post("/api/v1/scans", json={
        "url": "https://www.google.com"
    })
    assert pub_res.status_code == 201
    pub_data = pub_res.json()
    assert pub_data["classification"] == "SAFE"
    assert pub_data["user_id"] is None
    assert "features" in pub_data

    # 2. Authenticated user token
    user = db_session.query(User).filter(User.email == "usertest@phishguard.local").first()
    token = create_access_token(subject=user.id, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Authenticated scan for phishing URL
    auth_scan_res = client.post("/api/v1/scans", json={
        "url": "http://paypal-security-update.account-verification.tk/login.php"
    }, headers=headers)
    assert auth_scan_res.status_code == 201
    scan_data = auth_scan_res.json()
    scan_id = scan_data["id"]
    assert scan_data["user_id"] is not None
    assert len(scan_data["detection_reasons"]) > 0

    # 4. View in user history
    history_res = client.get("/api/v1/scans", headers=headers)
    assert history_res.status_code == 200
    hist_data = history_res.json()
    assert hist_data["total"] >= 1
    assert any(item["id"] == scan_id for item in hist_data["items"])

    # 5. Fetch single scan detail
    detail_res = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == scan_id

    # 6. Delete scan
    del_res = client.delete(f"/api/v1/scans/{scan_id}", headers=headers)
    assert del_res.status_code == 204

    # 7. Invalid URL structure rejected with 422
    bad_res = client.post("/api/v1/scans", json={"url": "not_a_valid_url"})
    assert bad_res.status_code == 422
    assert "invalid domain structure" in bad_res.json()["detail"].lower()

    # 8. Unresolvable non-existent domain scan returns 201 with NXDOMAIN indicators
    nx_res = client.post("/api/v1/scans", json={"url": "https://nonexistent-fake-domain-123456789.com"})
    assert nx_res.status_code == 201
    nx_data = nx_res.json()
    assert nx_data["features"]["dns_resolvable"] == 0
    assert any(r["title"].startswith("Unresolvable") for r in nx_data["detection_reasons"])


def test_scan_endpoint_returns_intended_ml_model_and_fields(client):
    res = client.post("/api/v1/scans", json={"url": "https://www.google.com"})
    assert res.status_code == 201
    data = res.json()
    assert data["model_version"] == "v2.0.0"
    assert "ml_probability" in data
    assert isinstance(data["ml_probability"], float)
    assert 0.0 <= data["ml_probability"] <= 1.0
    assert "rule_score" in data
    assert isinstance(data["rule_score"], int)

    phish_res = client.post("/api/v1/scans", json={"url": "http://paypal-security-update.account-verification.tk/login.php"})
    assert phish_res.status_code == 201
    phish_data = phish_res.json()
    assert phish_data["model_version"] == "v2.0.0"
    assert phish_data["ml_probability"] > 0.8



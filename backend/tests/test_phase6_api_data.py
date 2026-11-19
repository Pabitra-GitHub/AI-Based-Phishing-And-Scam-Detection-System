"""
Phase 6 Test Suite: API, Accounts, Ownership, Retention & Data Security.
Verifies:
1. Strict Ownership Enforcement:
   - User A cannot view User B's scan history.
   - User A cannot delete User B's scan (403 Forbidden).
   - Guest cannot delete authenticated user's scan (403 Forbidden).
   - Guest A (with X-Session-ID A) cannot view or delete Guest B's scan (with X-Session-ID B).
   - Anonymous caller without session ID receives an empty list (prevents leaking all users' scans).
   - Admin user can view and delete any scan.
2. Data Leak Prevention on Scan Detail:
   - Public view of another user's scan masks the owner's user_id and session_id.
3. Retention Policy Cleanup:
   - purge_expired_scans removes scans older than 2 hours and preserves scans within the window.
4. Pagination Bounds & Schema Protection:
   - Invalid pagination parameters (page_size > 100, page < 1) are rejected or bounded.
5. Environment Secrets & Security Settings:
   - Production mode raises ValueError if weak development JWT keys are used.
"""

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.orm import Session

from backend.app.core.security import create_access_token, get_password_hash
from backend.app.core.config import Settings
from backend.app.models.user import User
from backend.app.models.scan import Scan
from backend.app.api.v1.endpoints.scans import purge_expired_scans


@pytest.fixture
def test_users(db_session: Session):
    """Create two regular test users and one admin user."""
    # User Alpha
    u_alpha = db_session.query(User).filter(User.email == "alpha@phishguard.test").first()
    if not u_alpha:
        u_alpha = User(
            name="User Alpha",
            email="alpha@phishguard.test",
            password_hash=get_password_hash("AlphaPass123!"),
            role="USER",
            is_active=True
        )
        db_session.add(u_alpha)

    # User Beta
    u_beta = db_session.query(User).filter(User.email == "beta@phishguard.test").first()
    if not u_beta:
        u_beta = User(
            name="User Beta",
            email="beta@phishguard.test",
            password_hash=get_password_hash("BetaPass123!"),
            role="USER",
            is_active=True
        )
        db_session.add(u_beta)

    # Admin User
    u_admin = db_session.query(User).filter(User.email == "admin@phishguard.test").first()
    if not u_admin:
        u_admin = User(
            name="Admin User",
            email="admin@phishguard.test",
            password_hash=get_password_hash("AdminPass123!"),
            role="ADMIN",
            is_active=True
        )
        db_session.add(u_admin)

    db_session.commit()
    db_session.refresh(u_alpha)
    db_session.refresh(u_beta)
    db_session.refresh(u_admin)

    token_alpha = create_access_token(subject=u_alpha.id, role=u_alpha.role)
    token_beta = create_access_token(subject=u_beta.id, role=u_beta.role)
    token_admin = create_access_token(subject=u_admin.id, role=u_admin.role)

    return {
        "alpha": (u_alpha, {"Authorization": f"Bearer {token_alpha}"}),
        "beta": (u_beta, {"Authorization": f"Bearer {token_beta}"}),
        "admin": (u_admin, {"Authorization": f"Bearer {token_admin}"}),
    }


def test_cross_user_scan_history_isolation(client, test_users):
    """User Alpha's history must never contain User Beta's scans."""
    _, headers_alpha = test_users["alpha"]
    _, headers_beta = test_users["beta"]

    # Alpha creates a scan
    res_a = client.post("/api/v1/scans", json={"url": "https://alpha-site.org"}, headers=headers_alpha)
    assert res_a.status_code == 201
    scan_a_id = res_a.json()["id"]

    # Beta creates a scan
    res_b = client.post("/api/v1/scans", json={"url": "https://beta-site.org"}, headers=headers_beta)
    assert res_b.status_code == 201
    scan_b_id = res_b.json()["id"]

    # Alpha gets history: must see scan_a but NOT scan_b
    hist_a = client.get("/api/v1/scans", headers=headers_alpha).json()
    scan_ids_in_a = [s["id"] for s in hist_a["items"]]
    assert scan_a_id in scan_ids_in_a
    assert scan_b_id not in scan_ids_in_a

    # Beta gets history: must see scan_b but NOT scan_a
    hist_b = client.get("/api/v1/scans", headers=headers_beta).json()
    scan_ids_in_b = [s["id"] for s in hist_b["items"]]
    assert scan_b_id in scan_ids_in_b
    assert scan_a_id not in scan_ids_in_b


def test_cross_user_and_guest_deletion_prevented(client, test_users):
    """User Alpha or guests cannot delete User Beta's scan."""
    _, headers_alpha = test_users["alpha"]
    u_beta, headers_beta = test_users["beta"]
    _, headers_admin = test_users["admin"]

    # Beta creates scan
    res_b = client.post("/api/v1/scans", json={"url": "https://beta-protected.com"}, headers=headers_beta)
    scan_b_id = res_b.json()["id"]

    # 1. User Alpha attempts to delete Beta's scan -> 403 Forbidden
    del_a = client.delete(f"/api/v1/scans/{scan_b_id}", headers=headers_alpha)
    assert del_a.status_code == 403
    assert "permission" in del_a.json()["detail"].lower()

    # 2. Guest without auth attempts to delete Beta's scan -> 403 Forbidden
    del_guest = client.delete(f"/api/v1/scans/{scan_b_id}")
    assert del_guest.status_code == 403

    # 3. Admin user can delete it
    del_admin = client.delete(f"/api/v1/scans/{scan_b_id}", headers=headers_admin)
    assert del_admin.status_code == 204


def test_guest_session_isolation(client):
    """Guest session A cannot view or delete guest session B's scan."""
    sess_a_headers = {"X-Session-ID": "session_guest_aaa_111"}
    sess_b_headers = {"X-Session-ID": "session_guest_bbb_222"}

    # Guest A creates scan
    res_a = client.post("/api/v1/scans", json={"url": "https://guest-a-page.com"}, headers=sess_a_headers)
    assert res_a.status_code == 201
    scan_a_id = res_a.json()["id"]

    # Guest B gets history -> must not see Guest A's scan
    hist_b = client.get("/api/v1/scans", headers=sess_b_headers).json()
    assert not any(s["id"] == scan_a_id for s in hist_b["items"])

    # Guest B attempts to delete Guest A's scan -> 403 Forbidden
    del_b = client.delete(f"/api/v1/scans/{scan_a_id}", headers=sess_b_headers)
    assert del_b.status_code == 403

    # Guest A can delete their own scan -> 204
    del_a = client.delete(f"/api/v1/scans/{scan_a_id}", headers=sess_a_headers)
    assert del_a.status_code == 204


def test_unauthenticated_request_without_session_returns_empty_list(client, test_users):
    """Anonymous callers without X-Session-ID receive empty list rather than exposing others' scans."""
    _, headers_alpha = test_users["alpha"]
    client.post("/api/v1/scans", json={"url": "https://secret-scan.com"}, headers=headers_alpha)

    # Calling GET /scans with no auth and no session header
    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    data = res.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_detail_endpoint_masks_owner_user_id_for_non_owners(client, test_users):
    """Viewing another user's scan masks the owner's user_id from public disclosure."""
    u_alpha, headers_alpha = test_users["alpha"]
    _, headers_beta = test_users["beta"]

    res = client.post("/api/v1/scans", json={"url": "https://example-mask.org"}, headers=headers_alpha)
    scan_id = res.json()["id"]

    # Owner views scan -> user_id is visible
    detail_owner = client.get(f"/api/v1/scans/{scan_id}", headers=headers_alpha).json()
    assert detail_owner["user_id"] == u_alpha.id

    # Non-owner views scan -> user_id is sanitized/masked to None
    detail_stranger = client.get(f"/api/v1/scans/{scan_id}", headers=headers_beta).json()
    assert detail_stranger["user_id"] is None

    # Anonymous guest views scan -> user_id is sanitized/masked to None
    detail_guest = client.get(f"/api/v1/scans/{scan_id}").json()
    assert detail_guest["user_id"] is None


def test_retention_policy_purges_only_expired_records(db_session: Session):
    """purge_expired_scans must delete records older than 2 hours and retain newer ones."""
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(hours=3)
    fresh_time = now - timedelta(minutes=30)

    # Create one expired scan and one fresh scan
    old_scan = Scan(
        input_type="URL",
        input_value="https://expired-url-123.com",
        risk_score=10,
        classification="SAFE",
        ml_probability=0.05,
        created_at=old_time
    )
    fresh_scan = Scan(
        input_type="URL",
        input_value="https://fresh-url-456.com",
        risk_score=20,
        classification="SAFE",
        ml_probability=0.10,
        created_at=fresh_time
    )
    db_session.add(old_scan)
    db_session.add(fresh_scan)
    db_session.commit()
    db_session.refresh(old_scan)
    db_session.refresh(fresh_scan)

    old_id = old_scan.id
    fresh_id = fresh_scan.id

    # Run retention cleanup
    purge_expired_scans(db_session)

    # Check database state
    assert db_session.query(Scan).filter(Scan.id == old_id).first() is None
    assert db_session.query(Scan).filter(Scan.id == fresh_id).first() is not None

    # Clean up
    db_session.query(Scan).filter(Scan.id == fresh_id).delete()
    db_session.commit()


def test_pagination_bounds_enforced(client, test_users):
    """Verify pagination validation prevents negative pages or excessive page_sizes."""
    _, headers = test_users["alpha"]

    # page_size > 100 rejected by FastAPI Query validator
    res_overflow = client.get("/api/v1/scans?page=1&page_size=500", headers=headers)
    assert res_overflow.status_code == 422

    # page < 1 rejected
    res_underflow = client.get("/api/v1/scans?page=0&page_size=10", headers=headers)
    assert res_underflow.status_code == 422


def test_production_environment_rejects_weak_dev_jwt_secret():
    """In production mode, Settings must reject default development secret keys."""
    with pytest.raises(ValueError, match="CRITICAL SECURITY RISK"):
        Settings(
            APP_ENV="production",
            JWT_SECRET_KEY="development-super-secret-key-change-in-production-32bytesmin"
        )


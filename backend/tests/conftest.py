"""
PhishGuard AI - Pytest Configuration & Test Fixtures
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.core.security import get_password_hash
from backend.app.models.user import User

# In-memory SQLite for fast, isolated testing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh in-memory database for each test."""
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()

    # Seed test users
    admin = User(
        name="Admin Test",
        email="admintest@phishguard.local",
        password_hash=get_password_hash("AdminPass123!"),
        role="ADMIN",
        is_active=True
    )
    user = User(
        name="User Test",
        email="usertest@phishguard.local",
        password_hash=get_password_hash("UserPass123!"),
        role="USER",
        is_active=True
    )
    session.add(admin)
    session.add(user)
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Test client overriding get_db with test in-memory session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

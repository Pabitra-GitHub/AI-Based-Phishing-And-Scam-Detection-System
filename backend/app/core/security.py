"""
PhishGuard AI - Security Core
Provides password hashing (PBKDF2-SHA256 / Bcrypt), JWT token management, and in-memory rate limiting.
"""

import hashlib
import hmac
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
import jwt
from fastapi import HTTPException, status
from backend.app.core.config import settings


# --- Password Hashing with PBKDF2-HMAC-SHA256 + Salt ---

def get_password_hash(password: str) -> str:
    """Hash password securely using PBKDF2-HMAC-SHA256 with a unique random salt."""
    salt = os.urandom(16).hex()
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()
    return f"pbkdf2:sha256:100000${salt}${key}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored hash safely."""
    try:
        if not hashed_password or "$" not in hashed_password:
            return False
        parts = hashed_password.split("$")
        if len(parts) == 3 and parts[0].startswith("pbkdf2"):
            iterations = int(parts[0].split(":")[2])
            salt = parts[1]
            expected_key = parts[2]
            key = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations
            ).hex()
            return hmac.compare_digest(key, expected_key)
        # Fallback for plain bcrypt if used
        return False
    except Exception:
        return False


# --- JWT Token Generation & Verification ---

def create_access_token(subject: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    payload = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    encoded_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        )


# --- In-Memory Sliding-Window Rate Limiter ---

class InMemoryRateLimiter:
    def __init__(self):
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(self, client_key: str, max_requests: int, window_seconds: int = 60) -> bool:
        """
        Check if client exceeds max_requests within window_seconds.
        Returns True if allowed, False if rate limited.
        """
        now = time.time()
        # Filter timestamps within window
        valid_timestamps = [t for t in self.requests[client_key] if now - t < window_seconds]
        if len(valid_timestamps) >= max_requests:
            self.requests[client_key] = valid_timestamps
            return False
        
        valid_timestamps.append(now)
        self.requests[client_key] = valid_timestamps
        return True


rate_limiter = InMemoryRateLimiter()

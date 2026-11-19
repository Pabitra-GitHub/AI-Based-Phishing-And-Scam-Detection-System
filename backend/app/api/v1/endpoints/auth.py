"""
PhishGuard AI - Authentication Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    rate_limiter
)
from backend.app.models.user import User
from backend.app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from backend.app.schemas.user import UserResponse, UserUpdate
from backend.app.services.audit_service import record_audit_log
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db)
):
    """Register a new user account."""
    client_ip = request.client.host if request.client else "unknown"

    # Normalize email
    email = payload.email.lower().strip()

    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists."
        )

    # First registered user can optionally be made ADMIN if no users exist, or default to USER
    total_users = db.query(User).count()
    role = "ADMIN" if total_users == 0 else "USER"

    user = User(
        name=payload.name.strip(),
        email=email,
        password_hash=get_password_hash(payload.password),
        role=role,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Record Audit
    record_audit_log(
        db=db,
        action="USER_REGISTERED",
        user_id=user.id,
        ip_address=client_ip,
        details=f"User registered with email {email} and role {role}"
    )

    token = create_access_token(subject=user.id, role=user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/login", response_model=TokenResponse)
def login_user(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db)
):
    """Authenticate with email and password to receive JWT token."""
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting on login attempts
    rate_limit_key = f"login:{client_ip}"
    if not rate_limiter.check_rate_limit(rate_limit_key, max_requests=settings.RATE_LIMIT_LOGIN_PER_MINUTE, window_seconds=60):
        record_audit_log(
            db=db,
            action="RATE_LIMIT_LOGIN_EXCEEDED",
            ip_address=client_ip,
            details="Exceeded login rate limit."
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait a minute and try again."
        )

    email = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()

    # Constant-time comparison / generic error message
    if not user or not verify_password(payload.password, user.password_hash):
        record_audit_log(
            db=db,
            action="USER_LOGIN_FAILED",
            ip_address=client_ip,
            details=f"Failed login attempt for {email}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact an administrator."
        )

    # Record successful login audit
    record_audit_log(
        db=db,
        action="USER_LOGIN_SUCCESS",
        user_id=user.id,
        ip_address=client_ip,
        details=f"User {email} logged in successfully."
    )

    token = create_access_token(subject=user.id, role=user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Return the profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)


@router.put("/me", response_model=UserResponse)
def update_user_profile(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update profile details or password."""
    if payload.name:
        current_user.name = payload.name.strip()

    if payload.new_password:
        if not payload.current_password or not verify_password(payload.current_password, current_user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is required and must match to set a new password."
            )
        current_user.password_hash = get_password_hash(payload.new_password)

    db.commit()
    db.refresh(current_user)
    return UserResponse.model_validate(current_user)

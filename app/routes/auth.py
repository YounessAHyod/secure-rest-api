from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.audit import write_audit_log
from app.db.database import get_db
from app.models.user import User
from app.security.auth import create_access_token, hash_password, verify_password
from app.security.rate_limit import login_ip_limiter, login_target_limiter

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class PublicUser(BaseModel):
    id: int
    email: EmailStr
    username: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username_or_email: Optional[str] = None
    username: Optional[str] = None
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/register", response_model=PublicUser, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        or_(User.email == payload.email, User.username == payload.username)
    ).first()

    if existing:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already exists",
        )

    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role="user",
        is_active=True,
        failed_login_attempts=0,
        locked_until=None,
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):

    ip = request.client.host if request.client else "unknown"

    identifier = (payload.username_or_email or payload.username or "").strip()
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="username or email required",
        )

    # Throttle ALL attempts (including valid user + wrong password)
    login_ip_limiter.check(ip)
    login_target_limiter.check(f"{ip}:{identifier.lower()}")

    write_audit_log("auth.login_attempt", request, username_or_email=identifier)

    invalid_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user = db.query(User).filter(
        or_(User.email == identifier, User.username == identifier)
    ).first()

    if not user:
        write_audit_log("auth.login_failed", request, reason="user_not_found")
        raise invalid_exc

    now = datetime.utcnow()

    if user.locked_until and user.locked_until > now:
        # You can choose to return invalid_exc here to reduce account-status leakage.
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account locked",
        )

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        if user.failed_login_attempts > 5:
            user.locked_until = now + timedelta(minutes=10)
            db.commit()

            write_audit_log("auth.account_locked", request, user_id=user.id)
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account locked",
            )

        db.commit()
        write_audit_log("auth.login_failed", request, reason="bad_password")
        raise invalid_exc

    # success
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role})
    write_audit_log("auth.login_success", request, user_id=user.id)

    return {"access_token": token, "token_type": "bearer"}

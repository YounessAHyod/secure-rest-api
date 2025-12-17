from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.security.auth import hash_password, verify_password, create_access_token
from app.security.rate_limit import login_limiter
from app.core.audit import write_audit_log

router = APIRouter(prefix="/auth", tags=["auth"])


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = (
        db.query(User)
        .filter((User.email == payload.email) | (User.username == payload.username))
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="User with that email/username already exists")

    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role="user",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit_log(
        event="auth.register_success",
        actor_user_id=user.id,
        target_user_id=user.id,
        details={"username": user.username, "email": user.email},
    )

    return {"message": "User created"}


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    now = datetime.utcnow()

    write_audit_log(
        event="auth.login_attempt",
        actor_user_id=None,
        target_user_id=None,
        details={"ip": ip, "username": payload.username},
    )

    user = db.query(User).filter(User.username == payload.username).first()


    if user and user.locked_until and user.locked_until > now:
        write_audit_log(
            event="auth.login_blocked_lockout",
            actor_user_id=None,
            target_user_id=user.id,
            details={"ip": ip, "username": payload.username},
        )
        raise HTTPException(status_code=423, detail="Account temporarily locked. Try again later.")


    if not login_limiter.is_allowed(ip):
        write_audit_log(
            event="auth.rate_limited",
            actor_user_id=None,
            target_user_id=user.id if user else None,
            details={"ip": ip, "username": payload.username},
        )
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")


    if not user or not verify_password(payload.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)

                write_audit_log(
                    event="auth.account_locked",
                    actor_user_id=None,
                    target_user_id=user.id,
                    details={"ip": ip, "username": payload.username},
                )

            db.commit()

        write_audit_log(
            event="auth.login_failed",
            actor_user_id=None,
            target_user_id=user.id if user else None,
            details={"ip": ip, "username": payload.username},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")


    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role})

    write_audit_log(
        event="auth.login_success",
        actor_user_id=user.id,
        target_user_id=user.id,
        details={"ip": ip, "username": payload.username},
    )

    return TokenResponse(access_token=token)


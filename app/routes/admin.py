from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.core.audit import write_audit_log
from app.db.database import get_db
from app.models.user import User
from app.security.auth import require_roles

router = APIRouter(prefix="/admin", tags=["admin"])

# Pydantic v1/v2 compatibility
try:
    from pydantic import ConfigDict  # v2

    class PublicUser(BaseModel):
        model_config = ConfigDict(from_attributes=True)
        id: int
        email: EmailStr
        username: str
        role: str
        is_active: bool
        failed_login_attempts: int
        locked_until: Optional[datetime] = None

except Exception:  # v1 fallback
    class PublicUser(BaseModel):
        id: int
        email: EmailStr
        username: str
        role: str
        is_active: bool
        failed_login_attempts: int
        locked_until: Optional[datetime] = None

        class Config:
            orm_mode = True


def _get_user_or_404(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/users", response_model=List[PublicUser])
def list_users(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles("admin")),
):
    users = db.query(User).all()
    write_audit_log(
        event="admin.list_users",
        actor_user_id=current_admin.id,
        target_user_id=None,
        details={"count": len(users)},
        request=request,
    )
    return users


@router.patch("/users/{user_id}/activate", response_model=PublicUser)
def activate_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles("admin")),
):
    user = _get_user_or_404(db, user_id)
    user.is_active = True
    db.commit()
    db.refresh(user)

    write_audit_log(
        event="admin.activate_user",
        actor_user_id=current_admin.id,
        target_user_id=user.id,
        details={},
        request=request,
    )
    return user


@router.patch("/users/{user_id}/deactivate", response_model=PublicUser)
def deactivate_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles("admin")),
):
    user = _get_user_or_404(db, user_id)
    user.is_active = False
    db.commit()
    db.refresh(user)

    write_audit_log(
        event="admin.deactivate_user",
        actor_user_id=current_admin.id,
        target_user_id=user.id,
        details={},
        request=request,
    )
    return user


@router.patch("/users/{user_id}/promote", response_model=PublicUser)
def promote_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles("admin")),
):
    user = _get_user_or_404(db, user_id)
    user.role = "admin"
    db.commit()
    db.refresh(user)

    write_audit_log(
        event="admin.promote_user",
        actor_user_id=current_admin.id,
        target_user_id=user.id,
        details={},
        request=request,
    )
    return user


@router.patch("/users/{user_id}/demote", response_model=PublicUser)
def demote_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_roles("admin")),
):
    if user_id == current_admin.id:
        raise HTTPException(status_code=400, detail="You cannot demote yourself")

    user = _get_user_or_404(db, user_id)
    user.role = "user"
    db.commit()
    db.refresh(user)

    write_audit_log(
        event="admin.demote_user",
        actor_user_id=current_admin.id,
        target_user_id=user.id,
        details={},
        request=request,
    )
    return user

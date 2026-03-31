# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — users.py (API v1)
# Purpose: User self-service endpoints (password, email, API key, account deletion).
# ─────────────────────────────────────────

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.core.security import get_current_user, get_password_hash, verify_password
from app.database.session import get_db
from app.models.scan import Scan
from app.models.user import User
from app.services.audit_service import log_event

logger = logging.getLogger("netrix")
router = APIRouter()


# ── Request schemas ───────────────────────────────────────────────

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    password: str


class DeleteAccountRequest(BaseModel):
    password: str


# ── Change Password ───────────────────────────────────────────────

@router.put("/me/password", status_code=status.HTTP_200_OK)
async def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters.")
    current_user.password_hash = get_password_hash(body.new_password)
    db.commit()
    log_event(db, "password_changed", current_user.id, details="User changed their password")
    return {"message": "Password updated successfully."}


# ── Change Email ──────────────────────────────────────────────────

@router.put("/me/email", status_code=status.HTTP_200_OK)
async def change_email(
    body: ChangeEmailRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Password is incorrect.")
    existing = db.query(User).filter(
        User.email == body.new_email, User.id != current_user.id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email is already in use.")
    current_user.email = body.new_email
    db.commit()
    log_event(db, "email_changed", current_user.id, details=f"Email changed to {body.new_email}")
    return {"message": "Email updated successfully.", "email": body.new_email}


# ── API Key ───────────────────────────────────────────────────────

@router.get("/me/api-key", status_code=status.HTTP_200_OK)
async def get_api_key(
    current_user: User = Depends(get_current_user),
):
    if not current_user.api_key:
        return {"api_key": None, "has_key": False}
    # Return masked key — show last 8 chars only
    masked = "netrix_" + ("*" * 24) + current_user.api_key[-8:]
    return {"api_key": masked, "has_key": True}


@router.post("/me/api-key", status_code=status.HTTP_201_CREATED)
async def generate_api_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_key = "netrix_" + secrets.token_urlsafe(32)
    current_user.api_key = new_key
    db.commit()
    log_event(db, "api_key_generated", current_user.id, details="User generated a new API key")
    return {"api_key": new_key, "message": "API key generated. Copy it now — it won't be shown again."}


@router.delete("/me/api-key", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user.api_key:
        raise HTTPException(status_code=404, detail="No API key to revoke.")
    current_user.api_key = None
    db.commit()
    log_event(db, "api_key_revoked", current_user.id, details="User revoked their API key")
    return {"message": "API key revoked successfully."}


# ── Delete All Scans ──────────────────────────────────────────────

@router.delete("/me/scans", status_code=status.HTTP_200_OK)
async def delete_all_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    count = db.query(Scan).filter(Scan.user_id == current_user.id).count()
    db.query(Scan).filter(Scan.user_id == current_user.id).delete(synchronize_session=False)
    db.commit()
    log_event(db, "all_scans_deleted", current_user.id, details=f"User deleted all {count} scans")
    return {"message": f"Deleted {count} scan(s) successfully.", "deleted_count": count}


# ── Delete Account ────────────────────────────────────────────────

@router.delete("/me", status_code=status.HTTP_200_OK)
async def delete_account(
    body: DeleteAccountRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Password is incorrect.")
    if current_user.role == "admin":
        admin_count = db.query(User).filter(User.role == "admin").count()
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last admin account."
            )
    log_event(db, "account_deleted", current_user.id, details=f"User {current_user.username} deleted their account")
    db.delete(current_user)
    db.commit()
    return {"message": "Account deleted successfully."}

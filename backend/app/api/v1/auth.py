# ─────────────────────────────────────────
# Netrix — auth.py (API v1)
# Purpose: Authentication endpoints (login, register, refresh, me, logout).
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.database.session import get_db
from app.schemas.user import Token, UserCreate, UserLogin, UserResponse
from app.services.audit_service import log_event
from app.services.auth_service import AuthService


class RefreshRequest(BaseModel):
    refresh_token: str

logger = logging.getLogger("netrix")

router = APIRouter()


@router.post(
    "/login",
    response_model=Token,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user",
)
async def login(
    credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Authenticate a user and return access + refresh tokens.

    Accepts a JSON body with ``username`` and ``password``.
    Returns a JWT access token and a refresh token on success.

    Raises:
        AuthenticationException: If credentials are invalid.
    """
    from app.core.exceptions import AuthenticationException
    from app.models.user import User

    auth_service = AuthService(db)
    try:
        token_data = auth_service.authenticate_user(
            username=credentials.username,
            password=credentials.password,
        )
    except AuthenticationException as exc:
        # Log the failed attempt before re-raising
        failed_user = db.query(User).filter(User.username == credentials.username).first()
        log_event(
            db, failed_user.id if failed_user else None, "login_failed",
            request, {"username": credentials.username},
        )
        raise

    # Update last_login timestamp
    user = db.query(User).filter(User.username == credentials.username).first()
    if user:
        user.last_login = datetime.now(timezone.utc)
        db.commit()

    log_event(db, user.id if user else None, "login", request)
    logger.info("[NETRIX] User '%s' logged in successfully.", credentials.username)

    return Token(
        access_token=token_data["access_token"],
        refresh_token=token_data["refresh_token"],
        token_type=token_data["token_type"],
        expires_in=15 * 60,  # ACCESS_TOKEN_EXPIRE_MINUTES in seconds
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    """
    Register a new user account.

    Password must be at least 8 characters with one uppercase letter,
    one digit, and one special character.

    Returns:
        UserResponse: The newly created user profile.

    Raises:
        AuthenticationException: If the username or email is already taken.
    """
    auth_service = AuthService(db)
    new_user = auth_service.register_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
    )
    logger.info("[NETRIX] New user registered: %s", user_data.username)
    return UserResponse.model_validate(new_user)


@router.post(
    "/refresh",
    response_model=Token,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
)
async def refresh_token(
    body: RefreshRequest,
    db: Session = Depends(get_db),
):
    """
    Exchange a valid refresh token for a new access token.

    Send the refresh token string in the request body as JSON:
    ``{"refresh_token": "<token>"}``

    Returns:
        Token: New access token with refreshed expiration.

    Raises:
        AuthenticationException: If the refresh token is invalid or expired.
    """
    auth_service = AuthService(db)
    result = auth_service.refresh_access_token(body.refresh_token)

    return Token(
        access_token=result["access_token"],
        refresh_token=body.refresh_token,
        token_type=result["token_type"],
        expires_in=15 * 60,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
)
async def get_me(
    current_user=Depends(get_current_user),
):
    """
    Return the profile of the currently authenticated user.

    Requires a valid JWT access token in the Authorization header.

    Returns:
        UserResponse: The authenticated user's profile data.
    """
    try:
        # Explicitly build the response to avoid ORM serialization edge cases
        return UserResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            role=current_user.role,
            is_active=current_user.is_active,
            created_at=current_user.created_at,
            updated_at=current_user.updated_at if current_user.updated_at else None,
            last_login=current_user.last_login if current_user.last_login else None,
        )
    except Exception as exc:
        logger.error("[NETRIX] Error serializing user profile: %s", str(exc))
        return JSONResponse(
            status_code=500,
            content={
                "error_code": "PROFILE_SERIALIZATION_ERROR",
                "message": "Failed to retrieve user profile.",
                "details": str(exc),
            },
        )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout current user",
)
async def logout(
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Invalidate the current session.

    In a stateless JWT setup this is a client-side operation —
    the server acknowledges the logout but the token remains valid
    until it expires. For true server-side invalidation, implement
    a token blacklist backed by Redis.

    Returns:
        dict: Confirmation message.
    """
    log_event(db, current_user.id, "logout", request)
    logger.info("[NETRIX] User '%s' logged out.", current_user.username)
    return {
        "message": "Logged out successfully.",
        "username": current_user.username,
    }

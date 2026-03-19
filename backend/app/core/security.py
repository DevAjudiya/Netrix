# ─────────────────────────────────────────
# Netrix — security.py
# Purpose: Authentication and authorization module providing JWT token
#          creation/verification and bcrypt password hashing.
# Author: Netrix Development Team
# ─────────────────────────────────────────

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import AuthenticationException
from app.database.session import get_db

# ─────────────────────────────────────────
# Password hashing context — bcrypt with 12 rounds
# ─────────────────────────────────────────
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)

# ─────────────────────────────────────────
# OAuth2 scheme for extracting Bearer tokens from the Authorization header
# ─────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a short-lived JWT access token.

    Encodes the provided data into a JWT with an expiration time.
    The token is signed using the SECRET_KEY and ALGORITHM from
    the application configuration.

    Args:
        data:          Dictionary containing claims to encode into the token.
                       Should include 'user_id', 'username', and 'role'.
        expires_delta: Optional custom expiration timedelta. If not provided,
                       defaults to ACCESS_TOKEN_EXPIRE_MINUTES from config.

    Returns:
        str: The encoded JWT access token string.
    """
    settings = get_settings()
    to_encode = data.copy()

    if expires_delta is not None:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a long-lived JWT refresh token.

    Refresh tokens are used to obtain new access tokens without
    requiring the user to re-authenticate. They have a longer
    lifetime (configured via REFRESH_TOKEN_EXPIRE_DAYS).

    Args:
        data: Dictionary containing claims to encode into the token.
              Should include 'user_id' and 'username'.

    Returns:
        str: The encoded JWT refresh token string.
    """
    settings = get_settings()
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a JWT token.

    Validates the token signature and expiration. Returns the full
    payload dictionary if the token is valid.

    Args:
        token: The JWT token string to verify.

    Returns:
        dict: The decoded payload containing user claims and metadata.

    Raises:
        AuthenticationException: If the token is expired, malformed,
                                 or has an invalid signature.
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError as decode_error:
        raise AuthenticationException(
            message="Invalid or expired authentication token.",
            details=str(decode_error),
        )

    # Ensure the token contains required claims
    if "user_id" not in payload:
        raise AuthenticationException(
            message="Token is missing required 'user_id' claim.",
            details="The token payload does not contain a user identifier.",
        )

    return payload


def verify_token_websocket(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify a JWT token for WebSocket connections.

    Unlike ``verify_token()``, this function does NOT raise an
    exception on failure — it returns ``None`` instead.  This is
    designed for WebSocket handlers where ``Depends()`` cannot be
    used and the handler must close the connection manually.

    Args:
        token: The JWT token string to verify.

    Returns:
        dict: The decoded payload if valid, or None on failure.
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        # Ensure the token contains required claims
        if "user_id" not in payload:
            return None
        return payload
    except JWTError:
        return None


def get_password_hash(password: str) -> str:
    """
    Hash a plain-text password using bcrypt with 12 rounds.

    Args:
        password: The plain-text password to hash.

    Returns:
        str: The bcrypt-hashed password string.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a bcrypt hash.

    Args:
        plain_password:  The plain-text password provided by the user.
        hashed_password: The bcrypt hash stored in the database.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    FastAPI dependency that extracts and validates the current user
    from the Authorization header.

    This function:
    1. Extracts the Bearer token from the request
    2. Verifies and decodes the JWT
    3. Looks up the user in the database
    4. Checks that the user account is active

    Args:
        token: The JWT Bearer token extracted from the Authorization header
               by the OAuth2PasswordBearer dependency.
        db:    The SQLAlchemy database session provided by the get_db dependency.

    Returns:
        User: The authenticated User ORM object.

    Raises:
        AuthenticationException: If the token is invalid, the user does not
                                 exist, or the user account is inactive.
    """
    # Import here to avoid circular imports between security and models
    from app.models.user import User

    # Verify the token and extract the payload
    payload = verify_token(token)
    user_id: Optional[int] = payload.get("user_id")

    if user_id is None:
        raise AuthenticationException(
            message="Token does not contain a valid user identifier.",
        )

    # Look up the user in the database
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise AuthenticationException(
            message="User account not found.",
            details=f"No user exists with ID {user_id}.",
        )

    # Ensure the user account is active
    if not user.is_active:
        raise AuthenticationException(
            message="User account is inactive.",
            details="Your account has been deactivated. Contact an administrator.",
        )

    # Ensure the user is not banned
    if user.is_banned:
        reason = user.ban_reason or "No reason provided."
        raise AuthenticationException(
            message="User account is banned.",
            details=f"Your account has been suspended. Reason: {reason}",
        )

    return user

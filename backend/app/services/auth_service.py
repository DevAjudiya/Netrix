# ─────────────────────────────────────────
# Netrix — services/auth_service.py
# Purpose: Business logic for user authentication and registration.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationException
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from app.models.user import User

logger = logging.getLogger("netrix")


class AuthService:
    """Service layer for authentication and user management."""

    def __init__(self, db: Session) -> None:
        """
        Initialize the auth service.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db

    def register_user(self, username: str, email: str, password: str) -> User:
        """
        Register a new user account.

        Args:
            username: The desired username.
            email:    The user's email address.
            password: The plain-text password to hash.

        Returns:
            User: The created User ORM object.

        Raises:
            AuthenticationException: If the username or email is already taken.
        """
        existing_user = self.db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            raise AuthenticationException(
                message="Username or email already registered.",
                details="Please choose a different username or email.",
            )

        new_user = User(
            username=username,
            email=email,
            password_hash=get_password_hash(password),
            role="analyst",
            is_active=True,
        )
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)

        logger.info("[NETRIX] New user registered: %s (ID: %d)", username, new_user.id)
        return new_user

    def authenticate_user(self, username: str, password: str) -> dict:
        """
        Authenticate a user and return JWT tokens.

        Args:
            username: The username to authenticate.
            password: The plain-text password to verify.

        Returns:
            dict: A dictionary containing access_token, refresh_token, and token_type.

        Raises:
            AuthenticationException: If credentials are invalid.
        """
        user = self.db.query(User).filter(User.username == username).first()

        if not user:
            logger.warning("[NETRIX] Login attempt with unknown username: %s", username)
            raise AuthenticationException(
                message="Invalid username or password.",
            )

        # Use password_hash — the correct field name on the User model
        if not verify_password(password, user.password_hash):
            logger.warning("[NETRIX] Invalid password for user: %s", username)
            raise AuthenticationException(
                message="Invalid username or password.",
            )

        if not user.is_active:
            logger.warning("[NETRIX] Login attempt by inactive user: %s", username)
            raise AuthenticationException(
                message="User account is inactive.",
            )

        token_data = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
        }

        access_token = create_access_token(data=token_data)
        refresh_token = create_refresh_token(data=token_data)

        logger.info("[NETRIX] User authenticated: %s (ID: %d)", username, user.id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    def get_current_user(self, user_id: int) -> Optional[User]:
        """
        Retrieve a user by ID for use with the /me endpoint.

        Args:
            user_id: The primary key of the user.

        Returns:
            User or None: The User ORM object if found; None otherwise.

        Raises:
            AuthenticationException: If user is not found or inactive.
        """
        user = self.db.query(User).filter(User.id == user_id).first()

        if not user:
            raise AuthenticationException(
                message="User account not found.",
                details=f"No user exists with ID {user_id}.",
            )

        if not user.is_active:
            raise AuthenticationException(
                message="User account is inactive.",
                details="Your account has been deactivated. Contact an administrator.",
            )

        return user

    def refresh_access_token(self, refresh_token_str: str) -> dict:
        """
        Exchange a valid refresh token for a new access token.

        Args:
            refresh_token_str: The refresh token string.

        Returns:
            dict: A dictionary containing the new access_token and token_type.

        Raises:
            AuthenticationException: If the refresh token is invalid or expired.
        """
        payload = verify_token(refresh_token_str)

        if payload.get("type") != "refresh":
            raise AuthenticationException(
                message="Invalid token type. Expected a refresh token.",
            )

        user_id = payload.get("user_id")
        user = self.db.query(User).filter(User.id == user_id).first()

        if not user or not user.is_active:
            raise AuthenticationException(
                message="User not found or inactive.",
            )

        token_data = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
        }

        new_access_token = create_access_token(data=token_data)

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
        }

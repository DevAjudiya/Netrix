# ─────────────────────────────────────────
# Netrix — User Schemas
# Purpose: Pydantic models for authentication, user CRUD,
#          and JWT token payloads.
# ─────────────────────────────────────────

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ─────────────────────────────────────────
# Base
# ─────────────────────────────────────────
class UserBase(BaseModel):
    """Fields shared by creation and response schemas."""

    username: str
    email: str

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, value: str) -> str:
        """Accept standard email format including internal .local domains."""
        stripped = value.strip().lower()
        if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", stripped):
            raise ValueError("Invalid email address format")
        return stripped


# ─────────────────────────────────────────
# Create (registration)
# ─────────────────────────────────────────
class UserCreate(UserBase):
    """
    Schema for new user registration.

    Password rules:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one digit
    - At least one special character (!@#$%^&*…)
    """

    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", value):
            raise ValueError("Password must contain at least one special character")
        return value

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if len(value) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if len(value) > 50:
            raise ValueError("Username must be 50 characters or fewer")
        if not re.match(r"^[a-zA-Z0-9_]+$", value):
            raise ValueError("Username may only contain letters, digits, and underscores")
        return value


# ─────────────────────────────────────────
# Response (read)
# ─────────────────────────────────────────
class UserResponse(UserBase):
    """
    Schema returned for user profile / list endpoints.

    .. warning::
        ``password_hash`` is **never** exposed.
    """

    id: int
    email: str  # override EmailStr — strict validation is for input only
    role: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────
# Login
# ─────────────────────────────────────────
class UserLogin(BaseModel):
    """Schema for login request body."""

    username: str
    password: str


# ─────────────────────────────────────────
# JWT Token Schemas
# ─────────────────────────────────────────
class Token(BaseModel):
    """Schema returned after successful authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    """Decoded JWT payload for internal use."""

    user_id: int
    username: str
    role: str

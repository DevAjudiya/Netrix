# ─────────────────────────────────────────
# Netrix — config.py
# Purpose: Centralized application configuration using pydantic-settings.
#          All values are loaded from environment variables / .env file.
# Author: Netrix Development Team
# ─────────────────────────────────────────

from functools import lru_cache
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    """
    Centralized configuration for the Netrix application.

    All settings are loaded from environment variables or a .env file.
    Required fields (no default) must be set in the environment or the app
    will refuse to start.
    """

    # ── Application ─────────────────────────────────────────────────────
    # Display name of the application, shown in the UI and API docs
    APP_NAME: str = "Netrix"
    # Semantic version string for the current release
    APP_VERSION: str = "1.0.0"
    # Enable debug mode — NEVER set to True in production
    DEBUG: bool = False

    # ── Security & Authentication ───────────────────────────────────────
    # Secret key used to sign JWT tokens — must be a strong random string
    JWT_SECRET_KEY: str
    # Cryptographic algorithm used for JWT signing (HS256, HS384, HS512)
    JWT_ALGORITHM: str = "HS256"
    # Lifetime of short-lived access tokens in minutes
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    # Lifetime of refresh tokens in days (used to obtain new access tokens)
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── MySQL Database ──────────────────────────────────────────────────
    # Hostname of the MySQL server (use 'mysql' inside Docker)
    MYSQL_HOST: str = "localhost"
    # Port the MySQL server listens on
    MYSQL_PORT: int = 3306
    # Database user with read/write access to MYSQL_DATABASE
    MYSQL_USER: str
    # Password for MYSQL_USER — must be kept secret
    MYSQL_PASSWORD: str
    # Name of the MySQL database to use
    MYSQL_DATABASE: str = "netrix_db"

    # ── Redis Cache ─────────────────────────────────────────────────────
    # Full Redis connection URL including protocol, host, and port
    REDIS_URL: str = "redis://localhost:6379"

    # ── Scanner Configuration ───────────────────────────────────────────
    # Absolute path to the nmap binary on the host system
    NMAP_PATH: str = "/usr/bin/nmap"
    # Maximum number of concurrent scan threads in the thread pool
    MAX_SCAN_THREADS: int = 10
    # Rate limit: maximum scans a single user can launch per hour
    MAX_SCANS_PER_USER_PER_HOUR: int = 5

    # ── CVE / Vulnerability Data ────────────────────────────────────────
    # Base URL for the NIST National Vulnerability Database REST API v2.0
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Optional NVD API key for higher rate limits (free at nvd.nist.gov)
    NVD_API_KEY: Optional[str] = None
    # Path to the offline CVE JSON database used as fallback
    OFFLINE_CVE_DB_PATH: str = "./data/cve_offline.json"

    # ── Reports ─────────────────────────────────────────────────────────
    # Directory where generated PDF/HTML/CSV/JSON reports are stored
    REPORTS_DIR: str = "./reports"

    # ── Network & CORS ──────────────────────────────────────────────────
    # Hostnames that the backend is allowed to serve (comma-separated in .env)
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    # Origins allowed for CORS requests — should include the frontend URL
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    @property
    def DATABASE_URL(self) -> str:
        from urllib.parse import quote_plus
        user = quote_plus(self.MYSQL_USER)
        password = quote_plus(self.MYSQL_PASSWORD)
        return (
            f"mysql+pymysql://{user}:{password}"
            f"@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DATABASE}"
            f"?charset=utf8mb4"
        )

    @field_validator("ALLOWED_HOSTS", "CORS_ORIGINS", mode="before")
    @classmethod
    def parse_comma_separated(cls, value: object) -> object:
        """
        Allow comma-separated strings in .env to be parsed into lists.

        Args:
            value: The raw value from the environment variable.

        Returns:
            list[str]: A list of trimmed strings.
        """
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Return a cached singleton instance of the application settings.

    The lru_cache decorator ensures the .env file is only parsed once
    during the lifetime of the process.

    Returns:
        Settings: The fully-loaded application configuration.
    """
    return Settings()

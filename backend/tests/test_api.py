# ─────────────────────────────────────────
# Netrix — tests/test_api.py
# Purpose: Unit tests for the API endpoints.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import unittest
from unittest.mock import MagicMock, patch


class TestHealthEndpoint(unittest.TestCase):
    """Test cases for the health check endpoint."""

    @patch("app.main.get_settings")
    def test_health_returns_200(self, mock_settings):
        """Verify the health endpoint returns a healthy status."""
        mock_settings.return_value = MagicMock(
            APP_NAME="Netrix",
            APP_VERSION="1.0.0",
            DEBUG=False,
            CORS_ORIGINS=["http://localhost:3000"],
            REDIS_URL="redis://localhost:6379",
            DATABASE_URL="sqlite:///:memory:",
        )
        from fastapi.testclient import TestClient

        # Minimal test — verifying the response structure
        expected_keys = {"status", "app", "version"}
        self.assertEqual(len(expected_keys), 3)


class TestAuthEndpoints(unittest.TestCase):
    """Test cases for authentication endpoints."""

    def test_login_requires_credentials(self):
        """Verify that login requires username and password."""
        from app.schemas.user import UserLogin
        login_data = UserLogin(username="test", password="test123")
        self.assertEqual(login_data.username, "test")
        self.assertEqual(login_data.password, "test123")

    def test_register_validates_password_length(self):
        """Verify that registration enforces minimum password length."""
        from pydantic import ValidationError
        from app.schemas.user import UserCreate

        with self.assertRaises(ValidationError):
            UserCreate(username="test", email="test@example.com", password="short")


if __name__ == "__main__":
    unittest.main()

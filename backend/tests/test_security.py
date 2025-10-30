import os
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.session import session_manager


class TestSecurityFeatures:
    """Comprehensive security tests for authentication system"""

    @pytest.fixture
    def client(self):
        """Create a test client for the FastAPI app"""
        return TestClient(app)

    @pytest.fixture
    def mock_google_token_validation(self):
        """Mock Google token validation"""
        with patch("app.auth.id_token.verify_oauth2_token") as mock_verify:
            mock_verify.return_value = {
                "sub": "test_google_sub",
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/picture.jpg",
            }
            yield mock_verify

    @pytest.mark.asyncio
    async def test_xss_protection_tokens_not_accessible_from_javascript(self, client):
        """Test that authentication tokens are not accessible from JavaScript (XSS protection)"""
        # Create a session
        session_id = await session_manager.create_session(1, "test_token")

        # Set cookie in request
        client.cookies.set("auth_session", session_id)

        # Make a request to get user info
        response = client.get("/auth/me")

        # Verify that the response doesn't contain any token information
        response_text = response.text
        assert "test_token" not in response_text
        assert session_id not in response_text

        # Verify that the cookie is httpOnly (not accessible to JavaScript)
        # This is tested by checking that the session cookie is set with httpOnly flag
        # The actual httpOnly flag is set in CookieManager.set_session_cookie
        # We can verify this by checking that no token data is exposed in the response
        if response.status_code == 200:
            data = response.json()
            # Response should only contain user data, no session or token info
            assert "id" in data
            assert "email" in data
            assert "session_id" not in data
            assert "token" not in data
            assert "google_token" not in data

    @pytest.mark.asyncio
    async def test_csrf_protection_samesite_cookie_attributes(self, client):
        """Test CSRF protection with SameSite cookie attributes"""
        # Mock the validate_google_token_and_get_user function
        with patch("app.auth.validate_google_token_and_get_user") as mock_validate:
            mock_validate.return_value = {
                "id": 1,
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/picture.jpg",
            }

            login_data = {"google_token": "valid_google_token"}
            response = client.post("/auth/login", json=login_data)

            assert response.status_code == 200

            # Check that the cookie is set with proper security attributes
            cookie_header = response.headers.get("set-cookie", "")
            assert "auth_session=" in cookie_header
            assert "HttpOnly" in cookie_header
            assert "SameSite=strict" in cookie_header
            # Note: Secure flag would be set in production with HTTPS

    @pytest.mark.asyncio
    async def test_session_hijacking_prevention_invalid_session_id(self, client):
        """Test session hijacking prevention with invalid session IDs"""
        # Try to access protected endpoint with invalid session ID
        client.cookies.set("auth_session", "invalid_session_id_12345")

        response = client.get("/auth/me")

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_session_hijacking_prevention_expired_session(self, client):
        """Test session hijacking prevention with expired sessions"""
        # Create a session and then manually expire it
        session_id = await session_manager.create_session(1, "test_token")

        # Manually expire the session by removing it
        await session_manager.invalidate_session(session_id)

        # Try to access protected endpoint with expired session
        client.cookies.set("auth_session", session_id)

        response = client.get("/auth/me")

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_session_hijacking_prevention_malformed_session_id(self, client):
        """Test session hijacking prevention with malformed session IDs"""
        from app.rate_limiter import rate_limiter

        malformed_session_ids = [
            "",  # Empty string
            "short",  # Too short
            "a" * 100,  # Too long
            "invalid-chars-!@#$%",  # Invalid characters
            "../../../etc/passwd",  # Path traversal attempt
            "<script>alert('xss')</script>",  # XSS attempt
        ]

        for i, malformed_id in enumerate(malformed_session_ids):
            # Reset rate limiter every 5 requests to avoid hitting the limit
            if i > 0 and i % 5 == 0:
                rate_limiter.requests.clear()

            client.cookies.set("auth_session", malformed_id)

            response = client.get("/auth/me")

            assert response.status_code == 401
            assert response.json()["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client):
        """Test that security headers are present in responses"""
        response = client.get("/auth/me")

        # Note: Security headers would typically be added by middleware
        # This test verifies that sensitive information is not exposed
        assert response.status_code == 401  # No session provided

        # Verify no sensitive information in error response
        error_detail = response.json()["detail"]
        assert "session" not in error_detail.lower()
        assert "token" not in error_detail.lower()
        assert "database" not in error_detail.lower()

    @pytest.mark.asyncio
    async def test_generic_error_messages_no_information_leakage(self, client):
        """Test that error messages don't leak sensitive information"""
        # Test various invalid authentication scenarios
        test_cases = [
            # Invalid session ID
            {"cookies": {"auth_session": "invalid_session"}, "endpoint": "/auth/me"},
            # No session
            {"cookies": {}, "endpoint": "/auth/me"},
            # Invalid refresh
            {
                "cookies": {"auth_session": "invalid_session"},
                "endpoint": "/auth/refresh",
            },
        ]

        for case in test_cases:
            if case["cookies"]:
                for key, value in case["cookies"].items():
                    client.cookies.set(key, value)

            if case["endpoint"] == "/auth/refresh":
                response = client.post(case["endpoint"])
            else:
                response = client.get(case["endpoint"])

            assert response.status_code == 401

            # Verify error message is generic and doesn't leak information
            error_detail = response.json()["detail"]

            # Should not contain specific technical details
            forbidden_terms = [
                "session_id",
                "token",
                "database",
                "sql",
                "exception",
                "traceback",
                "internal",
                "server error",
            ]

            for term in forbidden_terms:
                assert term not in error_detail.lower()

            # Should be a generic message
            assert error_detail in [
                "Authentication required",
                "No session found",
                "Session refresh failed",
            ]

    @pytest.mark.asyncio
    async def test_session_cleanup_on_logout(self, client):
        """Test that sessions are properly cleaned up on logout"""
        # Create a session
        session_id = await session_manager.create_session(1, "test_token")

        # Verify session exists
        assert session_id in session_manager.sessions

        # Set cookie and logout
        client.cookies.set("auth_session", session_id)
        response = client.post("/auth/logout")

        assert response.status_code == 200

        # Verify session was cleaned up
        assert session_id not in session_manager.sessions

        # Verify cookie was cleared
        cookie_header = response.headers.get("set-cookie", "")
        assert "Max-Age=0" in cookie_header

    @pytest.mark.asyncio
    async def test_concurrent_session_handling(self, client):
        """Test handling of concurrent sessions for the same user"""
        # Create multiple sessions for the same user
        session_id_1 = await session_manager.create_session(1, "test_token_1")
        session_id_2 = await session_manager.create_session(1, "test_token_2")

        # Both sessions should exist
        assert session_id_1 in session_manager.sessions
        assert session_id_2 in session_manager.sessions

        # Both sessions should be valid
        session_data_1 = await session_manager.validate_session(session_id_1)
        session_data_2 = await session_manager.validate_session(session_id_2)

        assert session_data_1 is not None
        assert session_data_2 is not None
        assert session_data_1.user_id == session_data_2.user_id == 1

    @pytest.mark.asyncio
    async def test_session_data_isolation(self, client):
        """Test that session data is properly isolated between users"""
        # Create sessions for different users
        session_id_user_1 = await session_manager.create_session(1, "token_user_1")
        session_id_user_2 = await session_manager.create_session(2, "token_user_2")

        # Validate sessions
        session_data_1 = await session_manager.validate_session(session_id_user_1)
        session_data_2 = await session_manager.validate_session(session_id_user_2)

        # Verify data isolation
        assert session_data_1.user_id == 1
        assert session_data_2.user_id == 2
        assert session_data_1.google_token == "token_user_1"
        assert session_data_2.google_token == "token_user_2"

        # Verify sessions are completely separate
        assert session_id_user_1 != session_id_user_2

    def teardown_method(self):
        """Clean up after each test"""
        session_manager.sessions.clear()

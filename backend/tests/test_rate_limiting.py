import os
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.rate_limiter import rate_limiter


class TestRateLimiting:
    """Tests for rate limiting functionality"""

    @pytest.fixture
    def client(self):
        """Create a test client for the FastAPI app"""
        return TestClient(app)

    def setup_method(self):
        """Clear rate limiter before each test"""
        rate_limiter.requests.clear()

    def test_login_rate_limiting(self, client):
        """Test rate limiting on login endpoint"""
        login_data = {"google_token": "test_token"}

        # Mock the validate_google_token_and_get_user function to fail
        with patch("app.auth.validate_google_token_and_get_user") as mock_validate:
            mock_validate.side_effect = Exception("Invalid token")

            # Make requests up to the limit (3 requests per minute for login)
            for i in range(3):
                response = client.post("/auth/login", json=login_data)
                # Should get 401 due to invalid token, not 429 (rate limit)
                assert response.status_code == 401

            # The 4th request should be rate limited
            response = client.post("/auth/login", json=login_data)
            assert response.status_code == 429
            assert "Too many requests" in response.json()["detail"]
            assert "Retry-After" in response.headers

    def test_refresh_rate_limiting(self, client):
        """Test rate limiting on refresh endpoint"""
        # Make requests up to the limit (10 requests per minute for refresh)
        for i in range(10):
            response = client.post("/auth/refresh")
            # Should get 401 due to no session, not 429 (rate limit)
            assert response.status_code == 401

        # The 11th request should be rate limited
        response = client.post("/auth/refresh")
        assert response.status_code == 429
        assert "Too many requests" in response.json()["detail"]
        assert "Retry-After" in response.headers

    def test_auth_me_rate_limiting(self, client):
        """Test rate limiting on /auth/me endpoint"""
        # Make requests up to the limit (5 requests per minute for auth endpoints)
        for i in range(5):
            response = client.get("/auth/me")
            # Should get 401 due to no session, not 429 (rate limit)
            assert response.status_code == 401

        # The 6th request should be rate limited
        response = client.get("/auth/me")
        assert response.status_code == 429
        assert "Too many requests" in response.json()["detail"]
        assert "Retry-After" in response.headers

    def test_rate_limiting_per_ip(self, client):
        """Test that rate limiting is applied per IP address"""
        login_data = {"google_token": "test_token"}

        with patch("app.auth.validate_google_token_and_get_user") as mock_validate:
            mock_validate.side_effect = Exception("Invalid token")

            # Simulate requests from different IPs by mocking the client host
            with patch.object(client, "request") as mock_request:
                # First IP makes 3 requests (hits limit)
                mock_request.return_value.client.host = "192.168.1.1"
                for i in range(3):
                    response = client.post("/auth/login", json=login_data)
                    assert response.status_code == 401

                # 4th request from same IP should be rate limited
                response = client.post("/auth/login", json=login_data)
                assert response.status_code == 429

                # But request from different IP should work
                mock_request.return_value.client.host = "192.168.1.2"
                response = client.post("/auth/login", json=login_data)
                assert (
                    response.status_code == 401
                )  # Not rate limited, just invalid token

    def test_rate_limiter_cleanup(self):
        """Test that rate limiter cleans up old entries"""
        import time

        from app.rate_limiter import RateLimiter

        limiter = RateLimiter()

        # Add some old requests
        old_time = time.time() - 7200  # 2 hours ago
        limiter.requests["192.168.1.1"].append(old_time)
        limiter.requests["192.168.1.2"].append(old_time)

        # Add some recent requests
        recent_time = time.time() - 30  # 30 seconds ago
        limiter.requests["192.168.1.1"].append(recent_time)

        # Cleanup old entries (older than 1 hour)
        limiter.cleanup_old_entries(max_age_seconds=3600)

        # IP with recent requests should still exist
        assert "192.168.1.1" in limiter.requests
        assert len(limiter.requests["192.168.1.1"]) == 1

        # IP with only old requests should be removed
        assert "192.168.1.2" not in limiter.requests

    def teardown_method(self):
        """Clean up after each test"""
        rate_limiter.requests.clear()

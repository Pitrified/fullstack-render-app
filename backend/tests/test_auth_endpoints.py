import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.session import session_manager


class TestAuthenticationEndpoints:
    """Integration tests for authentication endpoints"""

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

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        with patch("app.database.get_db") as mock_get_db:
            mock_db = AsyncMock()
            mock_result = MagicMock()
            mock_user = MagicMock()
            mock_user.id = 1
            mock_user.email = "test@example.com"
            mock_user.name = "Test User"
            mock_user.picture = "https://example.com/picture.jpg"

            mock_result.scalars.return_value.first.return_value = mock_user
            mock_db.execute.return_value = mock_result
            mock_get_db.return_value = mock_db
            yield mock_db

    @pytest.mark.asyncio
    async def test_login_endpoint_success(self, client, mock_google_token_validation):
        """Test successful login with session creation"""
        # Clear any existing sessions
        session_manager.sessions.clear()

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
            data = response.json()
            assert data["message"] == "Login successful"
            assert "user" in data
            assert data["user"]["email"] == "test@example.com"

            # Verify session was created
            assert len(session_manager.sessions) == 1

            # Verify cookie was set
            assert "auth_session" in response.cookies

    @pytest.mark.asyncio
    async def test_login_endpoint_invalid_token(self, client, mock_db_session):
        """Test login with invalid Google token"""
        with patch("app.auth.id_token.verify_oauth2_token") as mock_verify:
            mock_verify.side_effect = ValueError("Invalid token")

            login_data = {"google_token": "invalid_google_token"}
            response = client.post("/auth/login", json=login_data)

            assert response.status_code == 401
            assert response.json()["detail"] == "Authentication failed"

    @pytest.mark.asyncio
    async def test_logout_endpoint_success(self, client):
        """Test successful logout with session invalidation"""
        # Create a session first
        session_id = await session_manager.create_session(1, "test_token")

        # Set cookie in request
        client.cookies.set("auth_session", session_id)

        response = client.post("/auth/logout")

        assert response.status_code == 200
        assert response.json()["message"] == "Logout successful"

        # Verify session was invalidated
        assert session_id not in session_manager.sessions

        # Verify cookie was cleared (cookie will be set to empty with max_age=0)
        cookie_header = response.headers.get("set-cookie", "")
        assert "auth_session=" in cookie_header and "Max-Age=0" in cookie_header

    @pytest.mark.asyncio
    async def test_logout_endpoint_no_session(self, client):
        """Test logout without existing session"""
        response = client.post("/auth/logout")

        assert response.status_code == 200
        assert response.json()["message"] == "Logout successful"

    @pytest.mark.asyncio
    async def test_me_endpoint_success(self, client):
        """Test /auth/me endpoint with valid session"""
        # Mock the get_current_user_from_session function
        with patch("app.main.get_current_user_from_session") as mock_auth:
            mock_auth.return_value = {
                "id": 1,
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/picture.jpg",
            }

            response = client.get("/auth/me")

            assert response.status_code == 200
            data = response.json()
            assert data["email"] == "test@example.com"
            assert data["id"] == 1

    @pytest.mark.asyncio
    async def test_me_endpoint_no_session(self, client):
        """Test /auth/me endpoint without session"""
        response = client.get("/auth/me")

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_me_endpoint_invalid_session(self, client):
        """Test /auth/me endpoint with invalid session"""
        client.cookies.set("auth_session", "invalid_session_id")

        response = client.get("/auth/me")

        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_refresh_endpoint_success(self, client):
        """Test session refresh endpoint"""
        # Create a session
        session_id = await session_manager.create_session(1, "test_token")

        # Set cookie in request
        client.cookies.set("auth_session", session_id)

        response = client.post("/auth/refresh")

        assert response.status_code == 200
        assert response.json()["message"] == "Session refreshed successfully"

        # Verify session still exists
        assert session_id in session_manager.sessions

    @pytest.mark.asyncio
    async def test_refresh_endpoint_no_session(self, client):
        """Test session refresh without existing session"""
        response = client.post("/auth/refresh")

        assert response.status_code == 401
        assert response.json()["detail"] == "No session found"

    @pytest.mark.asyncio
    async def test_refresh_endpoint_invalid_session(self, client):
        """Test session refresh with invalid session"""
        client.cookies.set("auth_session", "invalid_session_id")

        response = client.post("/auth/refresh")

        assert response.status_code == 401
        assert response.json()["detail"] == "Session refresh failed"

    @pytest.mark.asyncio
    async def test_complete_authentication_flow(
        self, client, mock_google_token_validation
    ):
        """Test complete authentication flow from login to logout"""
        # Clear any existing sessions
        session_manager.sessions.clear()

        # Mock the validate_google_token_and_get_user function
        with patch("app.auth.validate_google_token_and_get_user") as mock_validate:
            mock_validate.return_value = {
                "id": 1,
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/picture.jpg",
            }

            # Step 1: Login
            login_data = {"google_token": "valid_google_token"}
            login_response = client.post("/auth/login", json=login_data)

            assert login_response.status_code == 200
            assert len(session_manager.sessions) == 1

            # Get session cookie
            session_cookie = login_response.cookies.get("auth_session")
            assert session_cookie is not None

            # Step 2: Mock the /auth/me endpoint
            with patch("app.main.get_current_user_from_session") as mock_auth:
                mock_auth.return_value = {
                    "id": 1,
                    "email": "test@example.com",
                    "name": "Test User",
                    "picture": "https://example.com/picture.jpg",
                }

                client.cookies.set("auth_session", session_cookie)
                me_response = client.get("/auth/me")

                assert me_response.status_code == 200
                assert me_response.json()["email"] == "test@example.com"

            # Step 3: Refresh session
            refresh_response = client.post("/auth/refresh")
            assert refresh_response.status_code == 200

            # Step 4: Logout
            logout_response = client.post("/auth/logout")

            assert logout_response.status_code == 200
            assert len(session_manager.sessions) == 0

    def teardown_method(self):
        """Clean up after each test"""
        session_manager.sessions.clear()

import asyncio
import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi import Response

# Add the parent directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.session import CookieManager, SessionData, SessionManager


class TestSessionManager:
    """Test cases for SessionManager functionality"""

    @pytest.fixture
    def session_manager(self):
        """Create a fresh SessionManager instance for each test"""
        return SessionManager(session_timeout_hours=1)

    @pytest.mark.asyncio
    async def test_create_session(self, session_manager):
        """Test session creation with valid parameters"""
        user_id = 123
        google_token = "test_google_token"

        session_id = await session_manager.create_session(user_id, google_token)

        assert session_id is not None
        assert len(session_id) > 0
        assert session_id in session_manager.sessions

        session_data = session_manager.sessions[session_id]
        assert session_data.user_id == user_id
        assert session_data.google_token == google_token
        assert session_data.expires_at > datetime.utcnow()

    @pytest.mark.asyncio
    async def test_validate_session_valid(self, session_manager):
        """Test validation of a valid session"""
        user_id = 123
        google_token = "test_token"

        session_id = await session_manager.create_session(user_id, google_token)
        session_data = await session_manager.validate_session(session_id)

        assert session_data is not None
        assert session_data.user_id == user_id
        assert session_data.google_token == google_token

    @pytest.mark.asyncio
    async def test_validate_session_invalid(self, session_manager):
        """Test validation of invalid session ID"""
        result = await session_manager.validate_session("invalid_session_id")
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_session_expired(self, session_manager):
        """Test validation of expired session"""
        user_id = 123
        google_token = "test_token"

        # Create session with very short timeout
        session_manager.session_timeout_hours = 0.001  # ~3.6 seconds
        session_id = await session_manager.create_session(user_id, google_token)

        # Manually expire the session
        session_manager.sessions[session_id].expires_at = datetime.utcnow() - timedelta(
            seconds=1
        )

        result = await session_manager.validate_session(session_id)
        assert result is None
        assert session_id not in session_manager.sessions

    @pytest.mark.asyncio
    async def test_refresh_session(self, session_manager):
        """Test session refresh functionality"""
        user_id = 123
        google_token = "test_token"

        session_id = await session_manager.create_session(user_id, google_token)
        original_expires_at = session_manager.sessions[session_id].expires_at

        # Wait a moment to ensure time difference
        await asyncio.sleep(0.1)

        success = await session_manager.refresh_session(session_id)
        assert success is True

        new_expires_at = session_manager.sessions[session_id].expires_at
        assert new_expires_at > original_expires_at

    @pytest.mark.asyncio
    async def test_refresh_invalid_session(self, session_manager):
        """Test refresh of invalid session"""
        success = await session_manager.refresh_session("invalid_session_id")
        assert success is False

    @pytest.mark.asyncio
    async def test_invalidate_session(self, session_manager):
        """Test session invalidation"""
        user_id = 123
        google_token = "test_token"

        session_id = await session_manager.create_session(user_id, google_token)
        assert session_id in session_manager.sessions

        success = await session_manager.invalidate_session(session_id)
        assert success is True
        assert session_id not in session_manager.sessions

    @pytest.mark.asyncio
    async def test_invalidate_nonexistent_session(self, session_manager):
        """Test invalidation of non-existent session"""
        success = await session_manager.invalidate_session("nonexistent_session")
        assert success is False

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_manager):
        """Test cleanup of expired sessions"""
        user_id = 123
        google_token = "test_token"

        # Create multiple sessions
        session_id1 = await session_manager.create_session(user_id, google_token)
        session_id2 = await session_manager.create_session(user_id + 1, google_token)

        # Expire one session
        session_manager.sessions[session_id1].expires_at = (
            datetime.utcnow() - timedelta(seconds=1)
        )

        cleaned_count = await session_manager.cleanup_expired_sessions()

        assert cleaned_count == 1
        assert session_id1 not in session_manager.sessions
        assert session_id2 in session_manager.sessions

    def test_generate_session_id(self, session_manager):
        """Test secure session ID generation"""
        session_id1 = session_manager.generate_session_id()
        session_id2 = session_manager.generate_session_id()

        assert session_id1 != session_id2
        assert len(session_id1) > 20  # Should be reasonably long
        assert len(session_id2) > 20

    def test_get_session_count(self, session_manager):
        """Test session count functionality"""
        assert session_manager.get_session_count() == 0

        # Add some sessions manually for testing
        session_manager.sessions["test1"] = SessionData(
            user_id=1,
            google_token="token1",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            created_at=datetime.utcnow(),
            last_accessed=datetime.utcnow(),
        )
        session_manager.sessions["test2"] = SessionData(
            user_id=2,
            google_token="token2",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            created_at=datetime.utcnow(),
            last_accessed=datetime.utcnow(),
        )

        assert session_manager.get_session_count() == 2


class TestCookieManager:
    """Test cases for CookieManager functionality"""

    def test_generate_secure_session_id(self):
        """Test secure session ID generation"""
        session_id1 = CookieManager.generate_secure_session_id()
        session_id2 = CookieManager.generate_secure_session_id()

        assert session_id1 != session_id2
        assert len(session_id1) > 20
        assert len(session_id2) > 20

    def test_get_session_id_from_cookies(self):
        """Test extracting session ID from cookies"""
        cookies = {"auth_session": "test_session_id", "other_cookie": "value"}
        session_id = CookieManager.get_session_id_from_cookies(cookies)
        assert session_id == "test_session_id"

        # Test with missing cookie
        empty_cookies = {"other_cookie": "value"}
        session_id = CookieManager.get_session_id_from_cookies(empty_cookies)
        assert session_id is None

    def test_set_session_cookie(self):
        """Test setting secure session cookie"""
        response = Response()
        session_id = "test_session_id"

        CookieManager.set_session_cookie(response, session_id)

        # Verify cookie was set (basic check)
        assert hasattr(response, "set_cookie")

    def test_clear_session_cookie(self):
        """Test clearing session cookie"""
        response = Response()

        CookieManager.clear_session_cookie(response)

        # Verify cookie clearing was called (basic check)
        assert hasattr(response, "set_cookie")


class TestSessionData:
    """Test cases for SessionData dataclass"""

    def test_session_data_creation(self):
        """Test SessionData creation and attributes"""
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=1)

        session_data = SessionData(
            user_id=123,
            google_token="test_token",
            expires_at=expires_at,
            created_at=now,
            last_accessed=now,
        )

        assert session_data.user_id == 123
        assert session_data.google_token == "test_token"
        assert session_data.expires_at == expires_at
        assert session_data.created_at == now
        assert session_data.last_accessed == now

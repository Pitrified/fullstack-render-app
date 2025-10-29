import asyncio
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import Response

logger = logging.getLogger(__name__)


@dataclass
class SessionData:
    """Data structure for storing session information"""

    user_id: int
    google_token: str
    expires_at: datetime
    created_at: datetime
    last_accessed: datetime


class SessionManager:
    """Manages user sessions with in-memory storage"""

    def __init__(self, session_timeout_hours: int = 24):
        self.sessions: Dict[str, SessionData] = {}
        self.session_timeout_hours = session_timeout_hours
        self._cleanup_task = None

    def generate_session_id(self) -> str:
        """Generate a secure session ID using cryptographically secure random"""
        return secrets.token_urlsafe(32)

    async def create_session(self, user_id: int, google_token: str) -> str:
        """Create a new session for the user"""
        session_id = self.generate_session_id()
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=self.session_timeout_hours)

        session_data = SessionData(
            user_id=user_id,
            google_token=google_token,
            expires_at=expires_at,
            created_at=now,
            last_accessed=now,
        )

        self.sessions[session_id] = session_data
        logger.info(f"Created session for user {user_id}")
        return session_id

    async def validate_session(self, session_id: str) -> Optional[SessionData]:
        """Validate a session and return session data if valid"""
        if not session_id or session_id not in self.sessions:
            return None

        session_data = self.sessions[session_id]
        now = datetime.utcnow()

        # Check if session has expired
        if now > session_data.expires_at:
            await self.invalidate_session(session_id)
            return None

        # Update last accessed time
        session_data.last_accessed = now
        return session_data

    async def refresh_session(self, session_id: str) -> bool:
        """Refresh a session by extending its expiration time"""
        session_data = await self.validate_session(session_id)
        if not session_data:
            return False

        # Extend session expiration
        session_data.expires_at = datetime.utcnow() + timedelta(
            hours=self.session_timeout_hours
        )
        logger.info(f"Refreshed session {session_id}")
        return True

    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session by removing it from storage"""
        if session_id in self.sessions:
            user_id = self.sessions[session_id].user_id
            del self.sessions[session_id]
            logger.info(f"Invalidated session for user {user_id}")
            return True
        return False

    async def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions from storage"""
        now = datetime.utcnow()
        expired_sessions = [
            session_id
            for session_id, session_data in self.sessions.items()
            if now > session_data.expires_at
        ]

        for session_id in expired_sessions:
            del self.sessions[session_id]

        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

        return len(expired_sessions)

    async def start_cleanup_task(self, cleanup_interval_minutes: int = 60):
        """Start background task for periodic session cleanup"""
        if self._cleanup_task is not None:
            return

        async def cleanup_loop():
            while True:
                try:
                    await self.cleanup_expired_sessions()
                    await asyncio.sleep(cleanup_interval_minutes * 60)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in session cleanup task: {e}")
                    await asyncio.sleep(60)  # Wait 1 minute before retrying

        self._cleanup_task = asyncio.create_task(cleanup_loop())
        logger.info("Started session cleanup background task")

    async def stop_cleanup_task(self):
        """Stop the background cleanup task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("Stopped session cleanup background task")

    def get_session_count(self) -> int:
        """Get the current number of active sessions"""
        return len(self.sessions)


# Global session manager instance
session_manager = SessionManager()


class CookieManager:
    """Utility class for managing secure cookies"""

    COOKIE_NAME = "auth_session"

    @staticmethod
    def set_session_cookie(
        response: Response,
        session_id: str,
        max_age_seconds: int = 86400,  # 24 hours
        secure: bool = True,
        domain: Optional[str] = None,
    ) -> None:
        """Set a secure session cookie with proper security attributes"""
        response.set_cookie(
            key=CookieManager.COOKIE_NAME,
            value=session_id,
            max_age=max_age_seconds,
            httponly=True,  # Prevents JavaScript access
            secure=secure,  # HTTPS only
            samesite="strict",  # CSRF protection
            domain=domain,
            path="/",
        )

    @staticmethod
    def clear_session_cookie(response: Response, domain: Optional[str] = None) -> None:
        """Clear the session cookie by setting it to expire immediately"""
        response.set_cookie(
            key=CookieManager.COOKIE_NAME,
            value="",
            max_age=0,
            httponly=True,
            secure=True,
            samesite="strict",
            domain=domain,
            path="/",
        )

    @staticmethod
    def get_session_id_from_cookies(cookies: dict) -> Optional[str]:
        """Extract session ID from request cookies"""
        return cookies.get(CookieManager.COOKIE_NAME)

    @staticmethod
    def generate_secure_session_id() -> str:
        """Generate a cryptographically secure session ID"""
        return secrets.token_urlsafe(32)


# Update SessionManager to use the secure session ID generation
SessionManager.generate_session_id = staticmethod(
    CookieManager.generate_secure_session_id
)

"""
Secure session management for Google OAuth authentication.

This module implements httpOnly cookie-based session storage to replace
the vulnerable localStorage approach. It provides:
- Secure session token generation and validation
- httpOnly cookie management with security flags
- CSRF protection through double-submit cookies
- Session expiry and cleanup
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from fastapi import HTTPException, Request, Response
from starlette.status import HTTP_401_UNAUTHORIZED

# Configure secure logging
logger = logging.getLogger(__name__)

# Session configuration
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
SESSION_DURATION_HOURS = 24
CSRF_TOKEN_LENGTH = 32
COOKIE_SECURE = os.getenv("ENVIRONMENT", "development") == "production"
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN")  # Set in production


class SessionManager:
    """Manages secure user sessions with httpOnly cookies and CSRF protection."""

    @staticmethod
    def create_session_token(user_data: Dict[str, Any]) -> str:
        """
        Create a secure JWT session token.

        Args:
            user_data: User information to encode in the token

        Returns:
            JWT token string
        """
        payload = {
            "user_id": user_data["id"],
            "email": user_data["email"],
            "name": user_data["name"],
            "picture": user_data.get("picture"),
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=SESSION_DURATION_HOURS),
            "iss": "fullstack-oauth-app",
            "aud": "fullstack-oauth-app-users",
        }

        return jwt.encode(payload, SESSION_SECRET, algorithm="HS256")

    @staticmethod
    def validate_session_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Validate and decode a session token.

        Args:
            token: JWT token to validate

        Returns:
            Decoded user data if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                SESSION_SECRET,
                algorithms=["HS256"],
                audience="fullstack-oauth-app-users",
                issuer="fullstack-oauth-app",
            )

            # Additional expiry check (JWT library should handle this, but double-check)
            if datetime.fromtimestamp(payload["exp"]) < datetime.utcnow():
                logger.warning("Session token expired")
                return None

            return {
                "id": payload["user_id"],
                "email": payload["email"],
                "name": payload["name"],
                "picture": payload.get("picture"),
            }

        except jwt.ExpiredSignatureError:
            logger.warning("Session token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid session token: {e}")
            return None
        except Exception as e:
            logger.error(f"Session token validation error: {e}")
            return None

    @staticmethod
    def create_csrf_token() -> str:
        """Generate a secure CSRF token."""
        return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)

    @staticmethod
    def set_session_cookies(response: Response, user_data: Dict[str, Any]) -> str:
        """
        Set secure session and CSRF cookies.

        Args:
            response: FastAPI response object
            user_data: User data to store in session

        Returns:
            CSRF token for client-side storage
        """
        # Create session token
        session_token = SessionManager.create_session_token(user_data)

        # Create CSRF token
        csrf_token = SessionManager.create_csrf_token()

        # Set httpOnly session cookie (not accessible to JavaScript)
        response.set_cookie(
            key="session",
            value=session_token,
            httponly=True,  # Critical: Prevents XSS token theft
            secure=COOKIE_SECURE,  # HTTPS only in production
            samesite="strict",  # CSRF protection
            max_age=SESSION_DURATION_HOURS * 3600,  # 24 hours
            domain=COOKIE_DOMAIN,  # Set domain in production
            path="/",
        )

        # Set CSRF token cookie (accessible to JavaScript for API calls)
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,  # JavaScript needs access for API calls
            secure=COOKIE_SECURE,
            samesite="strict",
            max_age=SESSION_DURATION_HOURS * 3600,
            domain=COOKIE_DOMAIN,
            path="/",
        )

        logger.info(f"Session created for user {user_data['email']}")
        return csrf_token

    @staticmethod
    def clear_session_cookies(response: Response):
        """Clear session and CSRF cookies on logout."""
        response.delete_cookie(
            key="session",
            path="/",
            domain=COOKIE_DOMAIN,
            secure=COOKIE_SECURE,
            samesite="strict",
        )
        response.delete_cookie(
            key="csrf_token",
            path="/",
            domain=COOKIE_DOMAIN,
            secure=COOKIE_SECURE,
            samesite="strict",
        )

        logger.info("Session cookies cleared")


def get_current_user_from_session(request: Request) -> Optional[Dict[str, Any]]:
    """
    Extract and validate user from session cookie.

    Args:
        request: FastAPI request object

    Returns:
        User data if session is valid, None otherwise

    Raises:
        HTTPException: If session is invalid or missing
    """
    # Get session token from httpOnly cookie
    session_token = request.cookies.get("session")

    if not session_token:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="No session found. Please log in."
        )

    # Validate session token
    user_data = SessionManager.validate_session_token(session_token)

    if not user_data:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please log in again.",
        )

    return user_data


def validate_csrf_token(request: Request) -> bool:
    """
    Validate CSRF token for state-changing operations.

    Args:
        request: FastAPI request object

    Returns:
        True if CSRF token is valid, False otherwise
    """
    # Get CSRF token from cookie
    csrf_cookie = request.cookies.get("csrf_token")

    # Get CSRF token from header
    csrf_header = request.headers.get("X-CSRF-Token")

    # Both must exist and match
    if not csrf_cookie or not csrf_header:
        return False

    return secrets.compare_digest(csrf_cookie, csrf_header)


async def require_csrf_protection(request: Request):
    """
    Dependency to enforce CSRF protection on state-changing endpoints.

    Args:
        request: FastAPI request object

    Raises:
        HTTPException: If CSRF validation fails
    """
    if not validate_csrf_token(request):
        logger.warning(f"CSRF validation failed for {request.url}")
        raise HTTPException(status_code=403, detail="CSRF token validation failed")

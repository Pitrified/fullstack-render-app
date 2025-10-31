import os

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from google.auth.transport import requests
from google.oauth2 import id_token
from sqlalchemy import select
from starlette.status import HTTP_401_UNAUTHORIZED

from .database import get_db
from .models import User
from .secure_logger import get_secure_logger
from .security_logger import (
    log_authentication_attempt,
    log_security_violation,
    log_session_event,
)
from .session import CookieManager, session_manager

logger = get_secure_logger(__name__)

load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


async def validate_google_token_and_get_user(
    google_token: str, db, request: Request = None
):
    """Validate Google token and return user data, creating user if needed"""
    try:
        idinfo = id_token.verify_oauth2_token(
            google_token, requests.Request(), CLIENT_ID
        )
    except ValueError:
        # Log security event without exposing token details
        logger.warning("Google token validation failed")
        if request:
            log_authentication_attempt(request, False, reason="invalid_google_token")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication failed"
        )
    except Exception:
        # Log unexpected errors
        logger.error("Unexpected error during token validation")
        if request:
            log_security_violation(request, "token_validation_error")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication failed"
        )

    try:
        stmt = select(User).where(User.google_sub == idinfo["sub"])
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user:
            user = User(
                google_sub=idinfo["sub"],
                email=idinfo["email"],
                name=idinfo.get("name"),
                picture=idinfo.get("picture"),
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        # Log successful authentication
        if request:
            log_authentication_attempt(request, True, user.id)

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
    except Exception:
        logger.error("Database error during user creation/retrieval")
        if request:
            log_security_violation(request, "database_error")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication failed"
        )


async def get_current_user_from_session(request: Request, db=Depends(get_db)):
    """Validate session from cookies and return current user"""
    try:
        # Get session ID from cookies
        session_id = CookieManager.get_session_id_from_cookies(request.cookies)
        if not session_id:
            log_authentication_attempt(request, False, reason="no_session_cookie")
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
            )

        # Validate session
        session_data = await session_manager.validate_session(session_id)
        if not session_data:
            log_authentication_attempt(request, False, reason="invalid_session")
            log_security_violation(
                request, "invalid_session_access", f"Session: {session_id[:8]}..."
            )
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
            )

        # Get user from database
        stmt = select(User).where(User.id == session_data.user_id)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user:
            # Session references non-existent user, invalidate it
            await session_manager.invalidate_session(session_id)
            log_security_violation(
                request, "orphaned_session", f"User ID: {session_data.user_id}"
            )
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
            )

        # Log successful session validation
        log_session_event(request, "validated", user.id, session_id)

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
    except HTTPException:
        raise
    except Exception:
        logger.error("Unexpected error during session validation")
        log_security_violation(request, "session_validation_error")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

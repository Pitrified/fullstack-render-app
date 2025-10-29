import logging
import os

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from google.auth.transport import requests
from google.oauth2 import id_token
from sqlalchemy import select
from starlette.status import HTTP_401_UNAUTHORIZED

from .database import get_db
from .models import User
from .session import CookieManager, session_manager

logger = logging.getLogger(__name__)

load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


async def validate_google_token_and_get_user(google_token: str, db):
    """Validate Google token and return user data, creating user if needed"""
    try:
        idinfo = id_token.verify_oauth2_token(
            google_token, requests.Request(), CLIENT_ID
        )
    except ValueError as e:
        logger.warning(f"Google token validation failed: {e}")
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid token")

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

    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
    }


async def get_current_user_from_session(request: Request, db=Depends(get_db)):
    """Validate session from cookies and return current user"""
    try:
        # Get session ID from cookies
        session_id = CookieManager.get_session_id_from_cookies(request.cookies)
        if not session_id:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
            )

        # Validate session
        session_data = await session_manager.validate_session(session_id)
        if not session_data:
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
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
            )

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Session validation failed: {e}")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )


async def get_current_user(request: Request, db=Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    token = auth_header.removeprefix("Bearer ").strip()
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
    except ValueError as e:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}"
        )

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

    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
    }

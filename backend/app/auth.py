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
from .session import get_current_user_from_session

load_dotenv()

# Configure secure logging
logger = logging.getLogger(__name__)

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


async def verify_google_token_and_get_user(request: Request, db=Depends(get_db)):
    """
    Verify Google OAuth token and create/retrieve user.

    This function handles the initial OAuth verification for login.
    After successful verification, the session system takes over.

    Args:
        request: FastAPI request object
        db: Database session

    Returns:
        User data dictionary

    Raises:
        HTTPException: If token is invalid or verification fails
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning("Missing or invalid Authorization header")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    token = auth_header.removeprefix("Bearer ").strip()

    try:
        # Verify Google OAuth token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

        # Log successful verification (no sensitive data)
        logger.info(f"Google token verified for user: {idinfo.get('email')}")

    except ValueError as e:
        # Log detailed error internally, return generic message for security
        logger.warning(f"Google token verification failed: {e}")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication failed"
        )
    except Exception as e:
        # Catch any other verification errors
        logger.error(f"Unexpected error during token verification: {e}")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Authentication failed"
        )

    # Get or create user in database
    try:
        stmt = select(User).where(User.google_sub == idinfo["sub"])
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user:
            # Create new user
            user = User(
                google_sub=idinfo["sub"],
                email=idinfo["email"],
                name=idinfo.get("name"),
                picture=idinfo.get("picture"),
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

            logger.info(f"New user created: {user.email}")
        else:
            logger.info(f"Existing user logged in: {user.email}")

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
        }

    except Exception as e:
        logger.error(f"Database error during user creation/retrieval: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Alias for backward compatibility and session-based authentication
get_current_user = get_current_user_from_session

import logging

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from .auth import get_current_user, verify_google_token_and_get_user
from .database import engine, get_db
from .models import Base
from .session import SessionManager, require_csrf_protection

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secure OAuth App", version="1.0.0")

# CORS configuration with specific methods and headers for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Local development frontend
        "https://react-frontend-t2b1.onrender.com",  # Render frontend
    ],
    allow_credentials=True,  # Required for cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Specific methods only
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-CSRF-Token",
    ],  # Specific headers only
)


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created successfully")


@app.post("/auth/login")
async def secure_login(request: Request, response: Response, db=Depends(get_db)):
    """
    Secure login endpoint that exchanges Google OAuth token for secure session.

    This endpoint:
    1. Verifies the Google OAuth token
    2. Creates or retrieves the user from database
    3. Sets secure httpOnly session cookies
    4. Returns user data and CSRF token
    """
    try:
        # Verify Google token and get/create user
        user_data = await verify_google_token_and_get_user(request, db)

        # Create secure session cookies
        csrf_token = SessionManager.set_session_cookies(response, user_data)

        logger.info(f"Secure session created for user: {user_data['email']}")

        return {
            "user": user_data,
            "csrf_token": csrf_token,
            "message": "Login successful",
        }

    except HTTPException:
        # Re-raise HTTP exceptions (auth failures, etc.)
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}")
        raise HTTPException(status_code=500, detail="Login failed")


@app.post("/auth/logout")
async def secure_logout(response: Response):
    """
    Secure logout endpoint that clears session cookies.
    """
    SessionManager.clear_session_cookies(response)
    logger.info("User logged out, session cookies cleared")

    return {"message": "Logout successful"}


@app.get("/auth/me")
async def get_current_user_info(current_user=Depends(get_current_user)):
    """
    Get current user information from secure session.

    This endpoint demonstrates session-based authentication.
    No token needed in Authorization header - uses httpOnly cookies.
    """
    return {"user": current_user, "authenticated": True}


@app.post("/auth/refresh")
async def refresh_session(
    request: Request, response: Response, current_user=Depends(get_current_user)
):
    """
    Refresh user session with new expiry time.

    This endpoint allows extending the session without full re-authentication.
    Requires CSRF protection for security.
    """
    # Validate CSRF token for this state-changing operation
    await require_csrf_protection(request)

    # Create new session with extended expiry
    csrf_token = SessionManager.set_session_cookies(response, current_user)

    logger.info(f"Session refreshed for user: {current_user['email']}")

    return {
        "user": current_user,
        "csrf_token": csrf_token,
        "message": "Session refreshed successfully",
    }


# Legacy endpoint for backward compatibility (will be deprecated)
@app.post("/login")
async def legacy_login(user=Depends(get_current_user)):
    """
    Legacy login endpoint for backward compatibility.

    WARNING: This endpoint is deprecated and will be removed.
    Use /auth/login for secure session-based authentication.
    """
    logger.warning("Legacy login endpoint used - consider migrating to /auth/login")
    return user


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy", "message": "Secure OAuth App is running"}

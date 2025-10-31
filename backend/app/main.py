from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .auth import get_current_user_from_session
from .config import get_app_config
from .database import engine, get_db
from .models import Base
from .rate_limiter import (
    check_auth_rate_limit,
    check_login_rate_limit,
    check_refresh_rate_limit,
)
from .secure_logger import get_secure_logger_manager
from .security_logger import (
    log_authentication_attempt,
    log_security_violation,
    log_session_event,
)
from .session import CookieManager, session_manager

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Local development frontend
        "https://react-frontend-t2b1.onrender.com",  # Render frontend
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


@app.on_event("startup")
async def startup():
    # Initialize secure logging infrastructure
    config = get_app_config()
    logger_manager = get_secure_logger_manager()
    logger = logger_manager.get_logger(__name__)

    # Log application startup with environment info
    logger.info(f"Application starting in {config.environment} mode")

    # Validate production configuration
    if config.is_production():
        validation_errors = config.validate_production_config()
        if validation_errors:
            logger.error("Production configuration validation failed:")
            for error in validation_errors:
                logger.error(f"  - {error}")
            raise RuntimeError(
                "Invalid production configuration - see logs for details"
            )
        else:
            logger.info("Production configuration validation passed")

    # Configure database logging with security considerations
    logger_manager.configure_database_logging(engine)

    # Log safe database connection info
    if config.is_development():
        logger.info(f"Database configured: {config.get_safe_database_info()}")
    else:
        logger.info("Database connection established")

    # Initialize database tables
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

    # Start session cleanup background task
    try:
        await session_manager.start_cleanup_task()
        logger.info("Session cleanup task started")
    except Exception as e:
        logger.error(f"Failed to start session cleanup task: {str(e)}")
        raise

    logger.info("Application startup completed successfully")


@app.on_event("shutdown")
async def shutdown():
    # Get logger for shutdown events
    logger_manager = get_secure_logger_manager()
    logger = logger_manager.get_logger(__name__)

    logger.info("Application shutdown initiated")

    # Stop session cleanup background task
    try:
        await session_manager.stop_cleanup_task()
        logger.info("Session cleanup task stopped")
    except Exception as e:
        logger.error(f"Error stopping session cleanup task: {str(e)}")

    logger.info("Application shutdown completed")


# Request models
class LoginRequest(BaseModel):
    google_token: str


@app.post("/auth/login")
async def login_with_session(
    request: LoginRequest, response: Response, http_request: Request, db=Depends(get_db)
):
    """Create a session from Google token and set httpOnly cookie"""
    # Apply rate limiting for login attempts
    check_login_rate_limit(http_request)

    try:
        # Validate Google token and get/create user
        from .auth import validate_google_token_and_get_user

        user = await validate_google_token_and_get_user(
            request.google_token, db, http_request
        )

        # Create session
        session_id = await session_manager.create_session(
            user_id=user["id"], google_token=request.google_token
        )

        # Set secure cookie
        CookieManager.set_session_cookie(response, session_id)

        # Log successful session creation
        log_session_event(http_request, "created", user["id"], session_id)

        return {"message": "Login successful", "user": user}
    except HTTPException:
        raise
    except Exception:
        # Log unexpected errors without exposing details
        log_security_violation(http_request, "login_error")
        raise HTTPException(status_code=401, detail="Authentication failed")


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    """Invalidate session and clear cookies"""
    try:
        session_id = CookieManager.get_session_id_from_cookies(request.cookies)
        if session_id:
            # Get user ID before invalidating session for logging
            session_data = await session_manager.validate_session(session_id)
            user_id = session_data.user_id if session_data else None

            await session_manager.invalidate_session(session_id)

            # Log successful logout
            log_session_event(request, "destroyed", user_id, session_id)

        # Clear cookie regardless of session validity
        CookieManager.clear_session_cookie(response)

        return {"message": "Logout successful"}
    except Exception:
        # Always clear cookie and return success for logout
        # Log the attempt but don't expose errors
        log_session_event(request, "logout_attempt")
        CookieManager.clear_session_cookie(response)
        return {"message": "Logout successful"}


async def rate_limited_auth_dependency(request: Request, db=Depends(get_db)):
    """Apply rate limiting before authentication"""
    check_auth_rate_limit(request)
    return await get_current_user_from_session(request, db)


@app.get("/auth/me")
async def get_current_user_info(user=Depends(rate_limited_auth_dependency)):
    """Return current user from session"""
    return user


@app.post("/auth/refresh")
async def refresh_session(request: Request, response: Response):
    """Refresh session if needed"""
    # Apply rate limiting for refresh attempts
    check_refresh_rate_limit(request)

    try:
        session_id = CookieManager.get_session_id_from_cookies(request.cookies)
        if not session_id:
            log_authentication_attempt(request, False, reason="no_session_for_refresh")
            raise HTTPException(status_code=401, detail="No session found")

        # Get user ID for logging
        session_data = await session_manager.validate_session(session_id)
        user_id = session_data.user_id if session_data else None

        success = await session_manager.refresh_session(session_id)
        if not success:
            log_authentication_attempt(
                request, False, user_id, "session_refresh_failed"
            )
            raise HTTPException(status_code=401, detail="Session refresh failed")

        # Reset cookie with new expiration
        CookieManager.set_session_cookie(response, session_id)

        # Log successful refresh
        log_session_event(request, "refreshed", user_id, session_id)

        return {"message": "Session refreshed successfully"}
    except HTTPException:
        raise
    except Exception:
        # Log unexpected errors
        log_security_violation(request, "session_refresh_error")
        raise HTTPException(status_code=401, detail="Authentication required")

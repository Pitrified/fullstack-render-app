from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .auth import get_current_user, get_current_user_from_session
from .database import engine, get_db
from .models import Base
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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Start session cleanup background task
    await session_manager.start_cleanup_task()


@app.on_event("shutdown")
async def shutdown():
    # Stop session cleanup background task
    await session_manager.stop_cleanup_task()


# Request models
class LoginRequest(BaseModel):
    google_token: str


@app.post("/auth/login")
async def login_with_session(
    request: LoginRequest, response: Response, db=Depends(get_db)
):
    """Create a session from Google token and set httpOnly cookie"""
    try:
        # Validate Google token and get/create user
        from .auth import validate_google_token_and_get_user

        user = await validate_google_token_and_get_user(request.google_token, db)

        # Create session
        session_id = await session_manager.create_session(
            user_id=user["id"], google_token=request.google_token
        )

        # Set secure cookie
        CookieManager.set_session_cookie(response, session_id)

        return {"message": "Login successful", "user": user}
    except Exception:
        raise HTTPException(status_code=401, detail="Authentication failed")


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    """Invalidate session and clear cookies"""
    try:
        session_id = CookieManager.get_session_id_from_cookies(request.cookies)
        if session_id:
            await session_manager.invalidate_session(session_id)

        # Clear cookie regardless of session validity
        CookieManager.clear_session_cookie(response)

        return {"message": "Logout successful"}
    except Exception:
        # Always clear cookie and return success for logout
        CookieManager.clear_session_cookie(response)
        return {"message": "Logout successful"}


@app.get("/auth/me")
async def get_current_user_info(user=Depends(get_current_user_from_session)):
    """Return current user from session"""
    return user


@app.post("/auth/refresh")
async def refresh_session(request: Request, response: Response):
    """Refresh session if needed"""
    try:
        session_id = CookieManager.get_session_id_from_cookies(request.cookies)
        if not session_id:
            raise HTTPException(status_code=401, detail="No session found")

        success = await session_manager.refresh_session(session_id)
        if not success:
            raise HTTPException(status_code=401, detail="Session refresh failed")

        # Reset cookie with new expiration
        CookieManager.set_session_cookie(response, session_id)

        return {"message": "Session refreshed successfully"}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Session refresh failed")


# Keep existing login endpoint for backward compatibility during transition
@app.post("/login")
async def login(user=Depends(get_current_user)):
    return user

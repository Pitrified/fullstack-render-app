import os
from fastapi import Request, HTTPException, Depends
from starlette.status import HTTP_401_UNAUTHORIZED
from google.oauth2 import id_token
from google.auth.transport import requests
from sqlalchemy import select
from .database import get_db
from .models import User
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

async def get_current_user(request: Request, db=Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    token = auth_header.removeprefix("Bearer ").strip()
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
    except ValueError as e:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")

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
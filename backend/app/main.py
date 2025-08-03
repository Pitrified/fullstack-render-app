from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from .auth import get_current_user
from .database import engine
from .models import Base

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.post("/login")
async def login(user=Depends(get_current_user)):
    return user
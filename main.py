from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base
from routers import users
from auth.github import auth_github_router

app = FastAPI()


app.include_router(users.router)
app.include_router(auth_github_router)

# Middleware для CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/setup")
async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    return {"message": "ok"}

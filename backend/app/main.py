from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.database.connection import connect_to_mongo, close_mongo_connection
from app.routers import auth
from app.security.dependencies import get_current_active_user
from app.models.user import User
from fastapi import Depends
from contextlib import asynccontextmanager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up CyberSentinel AI Backend...")
    await connect_to_mongo()
    yield
    # Shutdown
    logger.info("Shutting down CyberSentinel AI Backend...")
    await close_mongo_connection()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

# Register routers
app.include_router(auth.router, prefix=settings.API_V1_STR)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Update with specific frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.PROJECT_NAME} API", "status": "online"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get(f"{settings.API_V1_STR}/protected", tags=["Test"])
async def protected_route(current_user: User = Depends(get_current_active_user)):
    """A temporary protected endpoint for verifying JWT authentication flow."""
    return {"message": "Protected route accessed successfully", "user": current_user.email}

from fastapi import FastAPI, Depends, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.database.connection import connect_to_mongo, close_mongo_connection, check_mongo_health
from app.routers import auth, posture, scan, dashboard
from app.security.dependencies import get_current_active_user
from app.models.user import User
from contextlib import asynccontextmanager
from app.core.logger import setup_logging
from app.core.handlers import setup_exception_handlers
from app.middleware.correlation import CorrelationIdMiddleware
import logging

setup_logging()
logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects defensive HTTP security headers into all responses."""
    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


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

# Setup RFC 7807 Exception Handlers
setup_exception_handlers(app)

# Register Middleware (Security Headers, Correlation ID, CORS)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CorrelationIdMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(posture.router, prefix=settings.API_V1_STR)
app.include_router(scan.router, prefix=settings.API_V1_STR)
app.include_router(dashboard.router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "version": settings.VERSION,
        "status": "online"
    }


@app.get("/health")
async def health_check():
    """Liveness probe confirming API service execution."""
    return {"status": "healthy", "version": settings.VERSION}


@app.get("/ready")
async def readiness_check():
    """Readiness probe validating database connectivity."""
    db_ok = await check_mongo_health()
    if db_ok:
        return {"status": "ready", "database": "connected"}
    return JSONResponse(
        status_code=503,
        content={"status": "not_ready", "database": "disconnected"}
    )


@app.get(f"{settings.API_V1_STR}/protected", tags=["Test"])
async def protected_route(current_user: User = Depends(get_current_active_user)):
    """A temporary protected endpoint for verifying JWT authentication flow."""
    return {"message": "Protected route accessed successfully", "user": current_user.email}

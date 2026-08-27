import logging
from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.exceptions import (
    CyberSentinelException,
    InvalidCredentialsException,
    UserAlreadyExistsException,
    EmailAlreadyExistsException,
    AccountLockedException,
    InactiveAccountException,
    DeletedAccountException,
)

logger = logging.getLogger(__name__)

async def custom_exception_handler(request: Request, exc: CyberSentinelException) -> JSONResponse:
    """
    Global exception handler that formats errors according to RFC 7807 (Problem Details).
    """
    status_code = 500
    title = "Internal Server Error"
    detail = getattr(exc, "detail", "An unexpected error occurred.")

    # Map specific exceptions to HTTP status codes and RFC 7807 titles
    if isinstance(exc, (InvalidCredentialsException, InactiveAccountException, DeletedAccountException)):
        status_code = 401
        title = "Authentication Error"
    elif isinstance(exc, AccountLockedException):
        status_code = 403
        title = "Account Locked"
    elif isinstance(exc, (UserAlreadyExistsException, EmailAlreadyExistsException)):
        status_code = 409
        title = "Conflict"
    else:
        # Generic Custom Exception mapping
        status_code = 400
        title = "Bad Request"

    logger.error(f"Handled exception: {title} - {detail}", exc_info=True, extra={"request_id": getattr(request.state, "request_id", None)})

    # RFC 7807 format
    content = {
        "type": f"about:blank", # In a real system, point to documentation URL
        "title": title,
        "status": status_code,
        "detail": detail,
        "instance": request.url.path
    }

    return JSONResponse(status_code=status_code, content=content)

async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Fallback handler for unhandled exceptions to ensure RFC 7807 format.
    """
    logger.exception(f"Unhandled exception during request {request.url.path}")

    content = {
        "type": "about:blank",
        "title": "Internal Server Error",
        "status": 500,
        "detail": "An unexpected error occurred. Please try again later.",
        "instance": request.url.path
    }
    return JSONResponse(status_code=500, content=content)

def setup_exception_handlers(app) -> None:
    """
    Registers exception handlers onto the FastAPI app.
    """
    app.add_exception_handler(CyberSentinelException, custom_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

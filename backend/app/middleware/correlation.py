import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate a new correlation ID for this request
        request_id = str(uuid.uuid4())

        # Attach it to the request state so the logger can read it
        request.state.request_id = request_id

        # Process the request
        response = await call_next(request)

        # Inject the request ID into the response headers
        response.headers["X-Request-ID"] = request_id

        return response

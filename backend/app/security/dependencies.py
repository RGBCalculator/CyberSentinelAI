from datetime import datetime, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from pydantic import ValidationError
from beanie import PydanticObjectId

from app.core.config import settings
from app.models.user import User
from app.security.jwt_handler import decode_token

# Define the OAuth2 scheme which will automatically extract the Bearer token from headers.
# tokenUrl defines where Swagger UI should send requests to get a token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Extracts the JWT, validates it, and fetches the associated user from the database.
    Enforces security checks like soft-deletes and lockouts.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode token and extract payload
        payload = decode_token(token)
        user_id: str = payload.get("sub")
        # In our jwt_handler, we didn't explicitly set "type" for access tokens, 
        # so we default to "access" if not present. Refresh tokens have "type": "refresh".
        token_type: str = payload.get("type", "access")
        
        if user_id is None:
            raise credentials_exception
            
        if token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type. Access token required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
    except (JWTError, ValidationError):
        raise credentials_exception

    # Database lookup
    try:
        user = await User.get(PydanticObjectId(user_id))
    except Exception:
        raise credentials_exception
        
    if user is None:
        raise credentials_exception

    # Security Validations
    if user.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account has been deleted."
        )
        
    if user.locked_until is not None and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account is temporarily locked due to multiple failed login attempts."
        )

    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Ensures the authenticated user is currently active.
    This acts as a second layer of defense.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account is inactive."
        )
    return current_user

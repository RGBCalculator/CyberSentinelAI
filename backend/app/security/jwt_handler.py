import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from app.core.config import settings

def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a short-lived JSON Web Token for API authentication.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    now = datetime.now(timezone.utc)
    to_encode = {
        "sub": str(subject),
        "iat": now,
        "nbf": now,
        "exp": expire,
        "jti": str(uuid.uuid4())
    }
    
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a longer-lived JSON Web Token used specifically to request new access tokens.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    now = datetime.now(timezone.utc)
    to_encode = {
        "sub": str(subject),
        "iat": now,
        "nbf": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "type": "refresh"  # Custom claim to distinguish token types
    }
    
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT against the application's secret key and algorithm.
    Throws jose.JWTError if the token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError as e:
        # Re-raise to be handled by the dependency injection layer
        raise e

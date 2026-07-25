from pydantic import BaseModel
from app.schemas.user import UserRead

class RegisterResponse(BaseModel):
    """
    Standard response schema for successful registration.
    """
    message: str
    user: UserRead

class LoginResponse(BaseModel):
    """
    Standard response schema for successful authentication.
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserRead

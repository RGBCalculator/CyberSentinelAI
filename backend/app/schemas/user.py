from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from beanie import PydanticObjectId

from app.models.user import UserRole


class UserBase(BaseModel):
    """
    Base properties shared across multiple user schemas to reduce duplication.
    """
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    full_name: Optional[str] = None
    profile_picture: Optional[str] = None

    @field_validator("email", mode="before")
    @classmethod
    def lowercase_email(cls, v: str) -> str:
        if isinstance(v, str):
            return v.lower()
        return v


class UserCreate(UserBase):
    """
    Schema for creating a new user account.
    Expects a strong plaintext password which will be hashed by the service layer.
    """
    password: str = Field(..., min_length=8, max_length=128)


class UserLogin(BaseModel):
    """
    Schema explicitly for the login endpoint.
    """
    email: EmailStr
    password: str = Field(...)

    @field_validator("email", mode="before")
    @classmethod
    def lowercase_email(cls, v: str) -> str:
        if isinstance(v, str):
            return v.lower()
        return v


class UserUpdate(BaseModel):
    """
    Schema for updating a user profile.
    All fields are optional. Internal fields (role, created_at, etc.) are strictly excluded.
    """
    full_name: Optional[str] = None
    profile_picture: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8, max_length=128)


class UserRead(UserBase):
    """
    Comprehensive schema for reading user data internally or returning to the authorized user.
    Excludes all sensitive security fields like hashed_password or lockouts.
    """
    id: PydanticObjectId
    role: UserRole
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    # Allows Pydantic to read from Beanie Document attributes (e.g. user.id)
    model_config = ConfigDict(from_attributes=True)


class UserPublic(BaseModel):
    """
    Schema for public-facing profiles (e.g., displaying the author of a report).
    Exposes absolute minimum data.
    """
    username: str
    profile_picture: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

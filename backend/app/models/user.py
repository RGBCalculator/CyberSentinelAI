from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from beanie import Document, Indexed, Insert, Replace, Save, before_event
from pydantic import EmailStr, Field, field_validator

class UserRole(str, Enum):
    """
    Defines the role-based access control (RBAC) levels.
    """
    ADMIN = "admin"
    USER = "user"

class User(Document):
    """
    Represents a user in the CyberSentinel AI platform.
    Maps to the 'users' collection in MongoDB.
    """
    username: Indexed(str, unique=True)
    email: Indexed(EmailStr, unique=True)
    hashed_password: str
    
    full_name: Optional[str] = None
    role: UserRole = Field(default=UserRole.USER)
    
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    profile_picture: Optional[str] = None
    
    failed_login_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = None
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    deleted_at: Optional[datetime] = None

    @field_validator("email", mode="before")
    @classmethod
    def lowercase_email(cls, v: str) -> str:
        if isinstance(v, str):
            return v.lower()
        return v

    class Settings:
        name = "users"

    @before_event(Insert, Replace, Save)
    def update_timestamp(self):
        """
        Automatically updates the `updated_at` field right before 
        the document is saved or replaced in the database.
        """
        self.updated_at = datetime.now(timezone.utc)

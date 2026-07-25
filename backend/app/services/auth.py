from datetime import datetime, timedelta, timezone
from typing import Tuple

from app.core.config import settings
from app.core.exceptions import (
    AccountLockedException,
    DeletedAccountException,
    EmailAlreadyExistsException,
    InactiveAccountException,
    InvalidCredentialsException,
    UserAlreadyExistsException,
)
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin
from app.security.hashing import hash_password, verify_password
from app.security.jwt_handler import create_access_token, create_refresh_token

class AuthService:
    """
    Handles core business logic for authentication and user management.
    Designed to be completely decoupled from HTTP protocols (no HTTPExceptions).
    """

    @staticmethod
    async def register_user(user_in: UserCreate) -> User:
        """
        Validates uniqueness constraints, hashes the password, and provisions a new User document.
        """
        # Validate uniqueness
        if await User.find_one(User.email == user_in.email):
            raise EmailAlreadyExistsException("Email is already registered.")
            
        if await User.find_one(User.username == user_in.username):
            raise UserAlreadyExistsException("Username is already taken.")
            
        hashed_password = hash_password(user_in.password)
        
        # Create user (defaults like role, is_active, etc. are handled by the model)
        user = User(
            email=user_in.email,
            username=user_in.username,
            full_name=user_in.full_name,
            hashed_password=hashed_password
        )
        
        await user.insert()
        return user

    @staticmethod
    async def authenticate_user(login_data: UserLogin) -> Tuple[User, str, str]:
        """
        Verifies credentials, manages brute-force lockouts, updates audit timestamps, 
        and issues JWT access & refresh tokens.
        """
        user = await User.find_one(User.email == login_data.email)
        
        if not user:
            # We raise InvalidCredentials even if the user isn't found to prevent email enumeration
            raise InvalidCredentialsException("Invalid email or password.")
            
        # Security state validations before checking password
        if user.deleted_at is not None:
            raise DeletedAccountException("Account has been deleted.")
            
        if not user.is_active:
            raise InactiveAccountException("Account is inactive.")
            
        if user.locked_until is not None and user.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise AccountLockedException("Account is temporarily locked.")
            
        # Verify Password
        if not verify_password(login_data.password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCOUNT_LOCK_DURATION_MINUTES)
            await user.save()
            raise InvalidCredentialsException("Invalid email or password.")
            
        # Successful Authentication
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        await user.save()
        
        # Mint tokens
        access_token = create_access_token(subject=str(user.id))
        refresh_token = create_refresh_token(subject=str(user.id))
        
        return user, access_token, refresh_token

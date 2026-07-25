from fastapi import Depends, HTTPException, status

from app.models.user import User, UserRole
from app.security.dependencies import get_current_active_user

async def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Dependency that explicitly enforces the ADMIN role.
    Prevents standard users from accessing sensitive management routes.
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges. Administrator access required."
        )
    return current_user

async def require_user(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Dependency that ensures the current active user possesses at least USER privileges.
    Since admins also act as users, both UserRole.USER and UserRole.ADMIN are permitted.
    """
    if current_user.role not in [UserRole.USER, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges."
        )
    return current_user

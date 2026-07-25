from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from app.schemas.auth import LoginResponse, RegisterResponse
from app.schemas.user import UserCreate, UserLogin
from app.services.auth import AuthService
from app.core.exceptions import (
    AccountLockedException,
    DeletedAccountException,
    EmailAlreadyExistsException,
    InactiveAccountException,
    InvalidCredentialsException,
    UserAlreadyExistsException,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post(
    "/register", 
    response_model=RegisterResponse, 
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Registers a new user by validating uniqueness constraints, hashing the password, and storing the user document."
)
async def register(user_in: UserCreate):
    try:
        user = await AuthService.register_user(user_in)
        return RegisterResponse(message="User registered successfully.", user=user)
    except (UserAlreadyExistsException, EmailAlreadyExistsException) as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, 
            detail=str(e)
        )

@router.post(
    "/login", 
    response_model=LoginResponse, 
    status_code=status.HTTP_200_OK,
    summary="Authenticate a user",
    description="Verifies user credentials, handles brute-force protection, and issues JWT access and refresh tokens."
)
async def login(login_data: UserLogin):
    try:
        user, access_token, refresh_token = await AuthService.authenticate_user(login_data)
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            user=user
        )
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )
    except AccountLockedException as e:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED, 
            detail=str(e)
        )
    except (InactiveAccountException, DeletedAccountException) as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=str(e)
        )

# =========================================================
# FUTURE ENDPOINTS (Prepared for later implementation)
# =========================================================
#
# @router.post("/refresh", summary="Refresh access token")
# async def refresh_token():
#     pass
#
# @router.post("/logout", summary="Invalidate tokens")
# async def logout():
#     pass
#
# @router.post("/forgot-password", summary="Initiate password reset")
# async def forgot_password():
#     pass
#
# @router.post("/reset-password", summary="Reset password using token")
# async def reset_password():
#     pass
#
# @router.post("/verify-email", summary="Verify email address using token")
# async def verify_email():
#     pass

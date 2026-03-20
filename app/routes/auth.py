from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from app.schemas.user import (
    RegisterModel, VerifyEmailModel, LoginModel,
    RefreshTokenModel, ForgotPasswordModel, ResetPasswordModel
)
from app.database.session import get_db
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.core.config import settings
from app.core.email import send_otp_email
from app.crud.user import create_user, get_user, get_user_by_email, verify_password, update_password
from app.services.otp import OTPService
from app.models.user import User

router = APIRouter()


@router.get("/")
def root():
    return {"message": "FastAPI Server is running!"}


# ─────────────────────────────────────────
# Registration
# ─────────────────────────────────────────

@router.post("/register")
async def register(data: RegisterModel, db: Session = Depends(get_db)):

    if get_user(db, data.username):
        raise HTTPException(status_code=400, detail="Username already exists")

    if get_user_by_email(db, data.email):
        raise HTTPException(status_code=400, detail="Email already exists")

    new_user = create_user(db, data.username, data.email, data.password)

    code = OTPService.send_registration_otp(db, new_user)
    await send_otp_email(new_user.email, code, purpose="registration")

    return {"message": "Registered successfully. Check your email for the OTP."}


@router.post("/verify-email")
def verify_email(data: VerifyEmailModel, db: Session = Depends(get_db)):

    user = get_user_by_email(db, data.email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not OTPService.verify(user, data.code):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user.is_verified = True
    OTPService.clear(db, user)

    return {"message": "Email verified successfully"}


# ─────────────────────────────────────────
# Login
# ─────────────────────────────────────────

@router.post("/login")
def login(data: LoginModel, db: Session = Depends(get_db)):

    user = get_user_by_email(db, data.email)

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    if user.disabled:
        raise HTTPException(status_code=403, detail="Account disabled")

    return {
        "access_token": create_access_token({"sub": user.email}),
        "refresh_token": create_refresh_token({"sub": user.email}),
        "token_type": "bearer"
    }


# ─────────────────────────────────────────
# Refresh Token
# ─────────────────────────────────────────

@router.post("/refresh")
def refresh_token(data: RefreshTokenModel, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(data.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email = payload.get("sub")
        token_type = payload.get("type")

        if email is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        user = get_user_by_email(db, email)

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        if user.disabled:
            raise HTTPException(status_code=403, detail="Account disabled")

        return {
            "access_token": create_access_token({"sub": email}),
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


# ─────────────────────────────────────────
# Profile
# ─────────────────────────────────────────

@router.get("/profile")
def profile(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "message": "Authenticated successfully"
    }


# ─────────────────────────────────────────
# Password Reset
# ─────────────────────────────────────────

@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordModel, db: Session = Depends(get_db)):

    user = get_user_by_email(db, data.email)

    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    code = OTPService.send_reset_otp(db, user)
    await send_otp_email(user.email, code, purpose="reset")

    return {"message": "Reset OTP sent to your email"}


@router.post("/reset-password")
def reset_password(data: ResetPasswordModel, db: Session = Depends(get_db)):

    user = get_user_by_email(db, data.email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not OTPService.verify(user, data.code):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    update_password(db, user, data.new_password)
    OTPService.clear(db, user)

    return {"message": "Password reset successfully"}
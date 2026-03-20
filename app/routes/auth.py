from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from app.schemas.user import LoginModel, RegisterModel, RefreshTokenModel,ForgotPasswordModel,VerifyCodeModel,ResetPasswordModel
from app.database.session import get_db
from app.crud.user import create_user, get_user, authenticate_user
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.core.config import settings
from app.models.user import User
from app.crud.user import set_reset_code, update_password
from app.crud.user import create_user, get_user, get_user_by_email, verify_password

router = APIRouter()


@router.get("/")
def root():
    return {"message": "FastAPI Server is running!"}


@router.post("/register")
def register(user: RegisterModel, db: Session = Depends(get_db)):

    existing_user = get_user(db, user.username)

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    create_user(db, user.username, user.email, user.password)

    return {"message": "User registered successfully"}

@router.post("/login")
def login(data: LoginModel, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.disabled:
        raise HTTPException(status_code=403, detail="Account disabled")

    return {
        "access_token": create_access_token({"sub": user.email}),
        "token_type": "bearer"
    }



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
@router.get("/profile")
def profile(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "message": "Authenticated successfully"
    }


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordModel, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    code = set_reset_code(db, user)

    return {
        "message": "Reset code sent",
       # "code": code
    }

@router.post("/verify-reset-code")
def verify_code(data: VerifyCodeModel, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user or user.reset_code != data.code:
        raise HTTPException(status_code=400, detail="Invalid code")

    return {
        "message": "Code verified"
    }

@router.post("/reset-password")
def reset_password(data: ResetPasswordModel, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data.email).first()

    if not user or user.reset_code != data.code:
        raise HTTPException(status_code=400, detail="Invalid code")

    update_password(db, user, data.new_password)

    return {
        "message": "Password reset successfully"
    }
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from app.schemas.user import LoginModel, RegisterModel, RefreshTokenModel
from app.database.session import get_db
from app.crud.user import create_user, get_user, authenticate_user
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.core.config import settings
from app.models.user import User

router = APIRouter()


@router.get("/")
def root():
    return {"message": "Server is running!"}


@router.post("/register")
def register(user: RegisterModel, db: Session = Depends(get_db)):
    existing_user = get_user(db, user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    create_user(db, user.username, user.password)
    return {"message": "User registered successfully"}


@router.post("/login")
def login(data: LoginModel, db: Session = Depends(get_db)):
    user = authenticate_user(db, data.username, data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "access_token": create_access_token({"sub": user.username}),
        "refresh_token": create_refresh_token({"sub": user.username}),
        "token_type": "bearer"
    }


@router.post("/refresh")
def refresh_token(data: RefreshTokenModel, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(data.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload.get("sub")
        token_type = payload.get("type")

        if username is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if not get_user(db, username):
            raise HTTPException(status_code=401, detail="User not found")

        return {
            "access_token": create_access_token({"sub": username}),
            "refresh_token": create_refresh_token({"sub": username}),
            "token_type": "bearer"
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.get("/profile")
def profile(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "message": "Authenticated successfully"
    }

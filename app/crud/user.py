from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def create_user(db: Session, username: str, email: str, password: str):
    user = User(
        username=username,
        email=email,
        hashed_password=pwd_context.hash(password),
        disabled=False,
        is_verified=False
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def update_password(db: Session, user: User, new_password: str):
    user.hashed_password = pwd_context.hash(new_password)
    db.commit()
    return user
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user import User
import random


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def create_user(db: Session, username: str, email: str ,password: str):
    hashed_password = pwd_context.hash(password)

    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
        disabled=False
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user

def set_reset_code(db: Session, user: User):

    code = str(random.randint(1000, 9999))

    user.reset_code = code
    db.commit()

    return code

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def update_password(db: Session, user: User, new_password: str):

    hashed_password = pwd_context.hash(new_password)

    user.hashed_password = hashed_password
    user.reset_code = None

    db.commit()

    return user
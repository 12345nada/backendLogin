import secrets
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.user import User

OTP_EXPIRE_MINUTES = 10


class OTPService:

    @staticmethod
    def generate() -> str:
        return str(secrets.randbelow(9000) + 1000)  # 4-digit secure OTP

    @staticmethod
    def send_registration_otp(db: Session, user: User) -> str:
        code = OTPService.generate()
        user.otp_code = code
        user.otp_expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
        user.is_verified = False
        db.commit()
        return code

    @staticmethod
    def send_reset_otp(db: Session, user: User) -> str:
        code = OTPService.generate()
        user.otp_code = code
        user.otp_expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
        db.commit()
        return code

    @staticmethod
    def verify(user: User, code: str) -> bool:
        if not user.otp_code or not user.otp_expires:
            return False
        if user.otp_code != code:
            return False
        if datetime.utcnow() > user.otp_expires:
            return False
        return True

    @staticmethod
    def clear(db: Session, user: User):
        user.otp_code = None
        user.otp_expires = None
        db.commit()
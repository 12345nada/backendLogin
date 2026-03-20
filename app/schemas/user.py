from pydantic import BaseModel, EmailStr


class RegisterModel(BaseModel):
    username: str
    email: EmailStr
    password: str


class VerifyEmailModel(BaseModel):
    email: EmailStr
    code: str


class LoginModel(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenModel(BaseModel):
    refresh_token: str


class ForgotPasswordModel(BaseModel):
    email: EmailStr


class ResetPasswordModel(BaseModel):
    email: EmailStr
    code: str
    new_password: str
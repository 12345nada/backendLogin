from pydantic import BaseModel


class RegisterModel(BaseModel):
    username: str
    password: str


class LoginModel(BaseModel):
    username: str
    password: str


class RefreshTokenModel(BaseModel):
    refresh_token: str

# user/schemas.py
from ninja import Schema
from pydantic import Field
from typing import Optional

class UserOut(Schema):
    id: int
    username: str
    email: str
    role: str
    phone: Optional[str] = None
    is_verified: bool
    is_active: bool

class UserRegister(Schema):
    username: str
    email: str
    password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)
    role: str = "b2c"
    phone: Optional[str] = None

class UserLogin(Schema):
    email: str
    password: str

class SetNewPassword(Schema):
    password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)
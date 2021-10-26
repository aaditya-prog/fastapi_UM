from typing import Any, Dict, List

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    username: str
    full_name: str
    email: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        orm_mode = True


class UserLogin(BaseModel):
    email: str
    password: str


class ChangePassword(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


class EmailSchema(BaseModel):
    email: List[EmailStr]
    body: Dict[str, Any]

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

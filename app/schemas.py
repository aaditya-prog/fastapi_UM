from pydantic import BaseModel


class User(BaseModel):
    username: str
    full_name: str
    email: str

    class Config:
        orm_mode = True


class UserCreate(BaseModel):
    full_name: str
    email: str
    username: str
    password: str


class AuthDetails(BaseModel):
    username: str
    password: str

from app.database import Base

from sqlalchemy import Column, Integer, String


class Login(Base):
    __tablename__ = "login"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    full_name = Column(String(255))
    email = Column(String(255))
    username = Column(String(20))
    password = Column(String(20))

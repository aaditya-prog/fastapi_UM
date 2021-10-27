from datetime import datetime, timedelta

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app import models, schemas


class AuthHandler:
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = "SECRET"

    def get_password_hash(self, password):
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)

    def check_password(self, password, hash_password) -> str:
        return self.pwd_context.verify(password, hash_password)

    def check_reset_password(self, new_password: str, id: int, db: Session):
        hashed_password = self.get_password_hash(new_password)
        db_user_to_update = db.query(models.User).filter(models.User.id == id).first()
        db_user_to_update.hashed_password = hashed_password
        db.add(db_user_to_update)
        db.commit()
        db.refresh(db_user_to_update)
        return db_user_to_update

    @staticmethod
    def get_user_by_email(db: Session, email: str):
        return db.query(models.User).filter(models.User.email == email).first()

    @staticmethod
    def get_user_by_username(db, username: str):
        return db.query(models.User).filter(models.User.username == username).first()

    def create_user(self, db: Session, user: schemas.UserCreate):
        hashed_password = self.get_password_hash(user.password)
        db_user = models.User(
            email=user.email,
            hashed_password=hashed_password,
            full_name=user.full_name,
            username=user.username,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    def create_super_user(self, db: Session, user: schemas.UserCreate):
        hashed_password = self.get_password_hash(user.password)
        db_user = models.User(
            email=user.email,
            hashed_password=hashed_password,
            full_name=user.full_name,
            is_admin=True,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

    def encode_token(self, user_id):
        payload = {
            "exp": datetime.utcnow() + timedelta(days=0, minutes=5),
            "iat": datetime.utcnow(),
            "sub": user_id,
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="Invalid token")

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)

    # Function to validate the password
    @staticmethod
    def validate_password(passwd):

        special_sym = ["$", "@", "#", "%", "!", "&"]
        val = True

        if len(passwd) < 6:
            val = False

        if len(passwd) > 20:
            val = False

        if not any(char.isdigit() for char in passwd):
            val = False

        if not any(char.isupper() for char in passwd):
            val = False

        if not any(char.islower() for char in passwd):
            val = False

        if not any(char in special_sym for char in passwd):
            val = False
        if val:
            return val

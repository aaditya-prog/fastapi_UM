from typing import List, Optional
from starlette.routing import Host
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Path, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from app import crud, models, schemas
from app.database import SessionLocal, engine
from sqlalchemy.orm import Session
from fastapi.encoders import jsonable_encoder
from app.crud import AuthHandler
from app.schemas import AuthDetails, Login

models.Base.metadata.create_all(bind=engine)


description = """
These API endpoints allow us to register, login, check user profile and update profile. ✔️

## Users

You will be able to:

* **Register.**
* **Login.**
* **Profile.**
* **Update Profile.**

"""
app = FastAPI(
    title="User registration, login and profile.",
    description=description,
    # version="0.0.1",
    # terms_of_service="http://example.com/terms/",
    contact={
        "name": "Aaditya Dulal",
        "url": "https://aadityadulal.com",
        "email": "artdityadulal@gmail.com",
    },
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


users = []
auth_handler = AuthHandler()


@app.post("/register/", response_model=schemas.User)
def add_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    return crud.register(db, user)


@app.post('/add-user', status_code=201)
def adduser(auth_details: AuthDetails):
    if any(x['username'] == auth_details.username for x in users):
        raise HTTPException(status_code=400, detail='Username is taken')
    if any(x['email'] == auth_details.email for x in users):
        raise HTTPException(status_code=400, detail='Email is taken')
    hashed_password = auth_handler.get_password_hash(auth_details.password)
    users.append({
        'full_name': auth_details.full_name,
        'email': auth_details.email,
        'username': auth_details.username,
        'password': hashed_password
    })
    return {'message':'User registered.'}


@app.post('/login')
def login(login: Login):
    user = None
    for x in users:
        if x['username'] == login.username:
            user = x
            break

    if (user is None) or (not auth_handler.verify_password(login.password, user['password'])):
        raise HTTPException(status_code=401, detail='Invalid username and/or password')
    token = auth_handler.encode_token(user['username'])
    return {'token': token}


@app.get('/unprotected')
def unprotected():
    return {'hello': 'world'}


@app.get('/protected')
def protected(username=Depends(auth_handler.auth_wrapper)):
    return {'name': username}


if __name__ == "__main__":
    uvicorn.run(app, port=8000, host="127.0.0.1", reload=True)

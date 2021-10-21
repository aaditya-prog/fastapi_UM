import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from email_validator import validate_email, EmailNotValidError

from app import models, schemas
from app.crud import AuthHandler
from app.database import SessionLocal, engine

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


@app.post("/register/", response_model=schemas.User, tags=["User"])
async def register(
        user: schemas.UserCreate,
        db: Session = Depends(get_db),
):
    db_username = auth_handler.get_user_by_username(db, username=user.username)
    db_email = auth_handler.get_user_by_email(db, email=user.email)
    if db_username:
        raise HTTPException(status_code=400, detail=f"User with the username '{user.username}' already exists.")
    if db_email:
        raise HTTPException(status_code=400, detail=f"User with the email '{user.email}' already exists.")
        # Validate.
    try:
        valid = validate_email(user.email)
        # Update with the normalized form.
        email = valid.email
    except EmailNotValidError as e:
        raise HTTPException(
            status_code=422,
            detail=str(e),
        )
    if not auth_handler.validate_password(user.password):
        raise HTTPException(
            status_code=401,
            detail=f"Password not accepted. It must contain one uppercase letter, one lowercase letter, one numeral, "
                   f"one special character and should be longer than 6 characters and shorter than 20 characters",
        )
    user = auth_handler.create_user(db=db, user=user)
    raise HTTPException(
        status_code=200,
        detail=f"User account with the email {user.email} created successfully.",
    )


@app.post("/login", tags=["Authentication"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth_handler.get_user_by_email(db, form_data.username)
    email = user.email
    password = user.hashed_password
    verify_password = auth_handler.verify_password(form_data.password, password)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email is incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect Password, try again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_handler.encode_token(email)
    return {"token": token, "token_type": "Bearer"}


@app.get('/protected')
def protected(username=Depends(auth_handler.auth_wrapper)):
    return {'name': username}


if __name__ == "__main__":
    uvicorn.run(app, port=8000, host="127.0.0.1", reload=True)

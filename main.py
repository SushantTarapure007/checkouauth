from fastapi import FastAPI, Depends, HTTPException, status
from .models import UserDB
from .schemas import User, UserCreate, UserUpdate
from .auth import authenticate_user, get_current_user, create_access_token
from .crud import create_user, update_user, delete_user
from .dependencies import oauth2_scheme
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from pydantic import BaseModel


class UserDB(BaseModel):
    username: str
    password: str
    role: str
    permissions: List[str]


class UserInDB(UserDB):
    id: str

    class Config:
        orm_mode = True

app = FastAPI()


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/user/me", response_model=User)
async def read_users_me(current_user: UserDB = Depends(get_current_user)):
    return current_user


@app.post("/user/", response_model=User)
async def create_user(user_data: UserCreate, current_user: UserDB = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admin can create users")
    user_id = create_user(user_data)
    user_data.id = user_id
    return user_data


@app.put("/user/me", response_model=User)
async def update_user(user_data: UserUpdate, current_user: UserDB = Depends(get_current_user)):
    update_user(current_user['username'], user_data)
    return user_data


@app.delete("/user/me")
async def delete_user(current_user: UserDB = Depends(get_current_user)):
    delete_user(current_user['username'])
    return {"message": "User deleted successfully"}

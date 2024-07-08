from pydantic import BaseModel
from typing import List


class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    permissions: List[str]


class UserUpdate(BaseModel):
    password: str
    role: str
    permissions: List[str]


class User(BaseModel):
    username: str
    role: str
    permissions: List[str]

    class Config:
        orm_mode = True
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

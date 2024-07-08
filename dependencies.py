from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .auth import verify_password, get_password_hash

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

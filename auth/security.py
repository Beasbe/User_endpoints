
from authx import AuthX, AuthXConfig
from passlib.context import CryptContext
from typing import Optional



ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
config = AuthXConfig(
     JWT_ALGORITHM = "HS256",
     JWT_SECRET_KEY = "0fa2c243ssdas29abe51a99d24a61c84ae1b6b799fd97",
     JWT_TOKEN_LOCATION = ["headers"],
)
auth = AuthX(config=config)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(username) -> str:
    return auth.create_access_token(uid=username)

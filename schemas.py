from pydantic import BaseModel, EmailStr, Field, validator, ConfigDict
from typing import Optional, List
from datetime import datetime
import re


class UserBase(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=100, description="Имя пользователя")
    last_name: str = Field(..., min_length=2, max_length=100, description="Фамилия пользователя")
    patronymic: Optional[str] = Field(None, max_length=100, description="Отчество (необязательно)")
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100,
                          description="Пароль должен содержать минимум 8 символов")
    password_confirm: str = Field(..., min_length=8, max_length=100)

    @validator('first_name', 'last_name', 'patronymic')
    def validate_name(cls, v):
        if v is None:
            return v
        if not re.match(r'^[a-zA-Zа-яА-ЯёЁ\- ]+$', v):
            raise ValueError('Имя может содержать только буквы, дефисы и пробелы')
        return v.strip()

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Пароль должен содержать минимум 8 символов')
        if not any(char.isdigit() for char in v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        if not any(char.isalpha() for char in v):
            raise ValueError('Пароль должен содержать хотя бы одну букву')
        return v

    @validator('password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Пароли не совпадают')
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=100)


class UserResponse(UserBase):
    id: int
    is_active: bool
    role_id: Optional[int]
    role_name: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=2, max_length=100)
    last_name: Optional[str] = Field(None, min_length=2, max_length=100)
    patronymic: Optional[str] = Field(None, max_length=100)

    @validator('first_name', 'last_name', 'patronymic')
    def validate_name(cls, v):
        if v is None:
            return v
        if not re.match(r'^[a-zA-Zа-яА-ЯёЁ\- ]+$', v):
            raise ValueError('Имя может содержать только буквы, дефисы и пробелы')
        return v.strip()


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    user_id: Optional[int] = None
    email: Optional[str] = None


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int


class PasswordChange(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=100)
    new_password: str = Field(..., min_length=8, max_length=100)
    new_password_confirm: str = Field(..., min_length=8, max_length=100)

    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Новый пароль должен содержать минимум 8 символов')
        if not any(char.isdigit() for char in v):
            raise ValueError('Новый пароль должен содержать хотя бы одну цифру')
        if not any(char.isalpha() for char in v):
            raise ValueError('Новый пароль должен содержать хотя бы одну букву')
        return v

    @validator('new_password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Новые пароли не совпадают')
        return v
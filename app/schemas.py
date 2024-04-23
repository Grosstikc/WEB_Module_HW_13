from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import date

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True

class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birthday: date
    additional_info: Optional[str] = None

class ContactCreate(ContactBase):
    pass

class ContactInDB(ContactBase):
    id: int

    @classmethod
    def from_orm(cls, db_obj):
        return cls(**db_obj.__dict__)


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
